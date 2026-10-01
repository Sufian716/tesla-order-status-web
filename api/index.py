"""
Tesla Order Status Web – Backend für Vercel (Python Serverless Function, Flask/WSGI).

Grundsätze
- Keine Zugangsdaten im Code: alles kommt aus Umgebungsvariablen (siehe .env.example).
- Kein Server-Speicher: Tesla-Token liegen AES-GCM-verschlüsselt in httpOnly-Cookies
  des Browsers, die Änderungs-Historie im localStorage des Browsers.
- Tesla-API-Wissen (Endpunkte, Header, PKCE-Flow) nach wjlc60/tesla-order-status (MIT)
  und chrisi51/tesla-order-status (TOST). Inoffizielle Endpunkte, können sich ändern.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from curl_cffi import requests as tls_requests
from flask import Flask, jsonify, request, send_from_directory

# ---------- Konfiguration (ausschließlich Umgebungsvariablen) ----------
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
SESSION_SECRET = os.environ.get("SESSION_SECRET", "")
TESLA_COUNTRY = os.environ.get("TESLA_COUNTRY", "DE")
TESLA_LANGUAGE = os.environ.get("TESLA_LANGUAGE", "de")
TESLA_ORDER_RN = os.environ.get("TESLA_ORDER_RN", "")
APP_SESSION_DAYS = int(os.environ.get("APP_SESSION_DAYS", "30") or 30)
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") != "0"  # nur für lokale http-Tests auf 0 setzen

MIN_PASSWORD_LEN = 10
MIN_SECRET_LEN = 32

# ---------- Tesla ----------
AUTH_URL = "https://auth.tesla.com/oauth2/v3/authorize"
TOKEN_URL = "https://auth.tesla.com/oauth2/v3/token"
CLIENT_ID = "ownerapi"
REDIRECT_URI = "tesla://auth/callback"
SCOPE = "openid email offline_access"
TASKS_URL = "https://akamai-apigateway-vfx.tesla.com/tasks"
ORDER_URL = "https://akamai-apigateway-vfx.tesla.com/order"
ACCOUNT_ORDERS_URL = "https://owner-api.teslamotors.com/api/1/users/orders"
APP_VERSION = "9.99.9-9999"  # absichtlich hoch: besteht die Mindestversions-Prüfung des Gateways
USER_AGENT = "Tesla/4.55.5 (com.teslamotors.tesla; build:4193; Android 14)"
X_USER_AGENT = "TeslaApp/4.55.5-4193/4193/android/14"
TIMEOUT = 25

APP_COOKIE = "tos_app"
TESLA_COOKIE = "tos_tesla"
PKCE_COOKIE = "tos_pkce"
PKCE_TTL = 20 * 60
TESLA_COOKIE_DAYS = 90
MAX_CHUNKS = 8
CHUNK = 3500  # Browser-Limit ~4096 Byte pro Cookie

PUBLIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "public")
app = Flask(__name__, static_folder=PUBLIC_DIR, static_url_path="")


class _VercelPathFix:
    """Vercel schreibt /api/<rest> auf /api/index?__path=<rest> um (vercel.json) und reicht der
    Function den umgeschriebenen Pfad weiter. Hier wird der Original-Pfad wiederhergestellt,
    damit die Flask-Routen (/api/auth/login, /api/orders, …) greifen."""

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        query = environ.get("QUERY_STRING", "")
        if "__path=" in query:
            params = parse_qsl(query, keep_blank_values=True)
            original = next((v for k, v in params if k == "__path"), None)
            if original is not None:
                environ["PATH_INFO"] = "/api/" + original.strip("/")
                environ["QUERY_STRING"] = urlencode([(k, v) for k, v in params if k != "__path"])
        return self.wsgi_app(environ, start_response)


app.wsgi_app = _VercelPathFix(app.wsgi_app)


class TeslaError(Exception):
    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


# ---------- Verschlüsselte Cookies ----------
def _key(purpose: str) -> bytes:
    return hashlib.sha256(f"{purpose}|{SESSION_SECRET}".encode()).digest()


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def seal(purpose: str, obj) -> str:
    nonce = secrets.token_bytes(12)
    data = json.dumps(obj, separators=(",", ":")).encode()
    return _b64e(nonce + AESGCM(_key(purpose)).encrypt(nonce, data, purpose.encode()))


def unseal(purpose: str, token: str | None):
    if not token:
        return None
    try:
        raw = _b64d(token)
        return json.loads(AESGCM(_key(purpose)).decrypt(raw[:12], raw[12:], purpose.encode()))
    except Exception:
        return None


def _set_cookie(resp, name: str, value: str, max_age: int) -> None:
    resp.set_cookie(name, value, max_age=max_age, httponly=True, secure=COOKIE_SECURE, samesite="Lax", path="/")


def _del_cookie(resp, name: str) -> None:
    resp.delete_cookie(name, path="/", httponly=True, secure=COOKIE_SECURE, samesite="Lax")


def set_chunked(resp, name: str, value: str, max_age: int) -> None:
    chunks = [value[i:i + CHUNK] for i in range(0, len(value), CHUNK)]
    if len(chunks) > MAX_CHUNKS:
        raise TeslaError("Token zu groß für Cookies.", 500)
    for i, chunk in enumerate(chunks):
        _set_cookie(resp, f"{name}.{i}", chunk, max_age)
    for i in range(len(chunks), MAX_CHUNKS):
        if f"{name}.{i}" in request.cookies:
            _del_cookie(resp, f"{name}.{i}")


def get_chunked(name: str) -> str | None:
    parts = []
    for i in range(MAX_CHUNKS):
        chunk = request.cookies.get(f"{name}.{i}")
        if chunk is None:
            break
        parts.append(chunk)
    return "".join(parts) or None


def clear_chunked(resp, name: str) -> None:
    for i in range(MAX_CHUNKS):
        if f"{name}.{i}" in request.cookies:
            _del_cookie(resp, f"{name}.{i}")


# ---------- App-Login ----------
def config_problems() -> list[str]:
    problems = []
    if len(APP_PASSWORD) < MIN_PASSWORD_LEN:
        problems.append(f"APP_PASSWORD (mind. {MIN_PASSWORD_LEN} Zeichen)")
    if len(SESSION_SECRET) < MIN_SECRET_LEN:
        problems.append(f"SESSION_SECRET (mind. {MIN_SECRET_LEN} Zeichen)")
    return problems


def app_session_valid() -> bool:
    data = unseal("app", request.cookies.get(APP_COOKIE))
    return bool(data) and (time.time() - float(data.get("iat", 0))) < APP_SESSION_DAYS * 86400


@app.before_request
def guard():
    if not request.path.startswith("/api/"):
        return None
    if request.path == "/api/health":
        return None
    problems = config_problems()
    if problems:
        return jsonify(error="server_not_configured",
                       message="Fehlende Umgebungsvariablen in Vercel: " + ", ".join(problems)), 500
    if request.path == "/api/auth/login":
        return None
    if request.method == "POST" and not request.is_json:
        return jsonify(error="json_required"), 415  # CSRF-Schutz: nur JSON-Requests
    if not app_session_valid():
        return jsonify(error="app_login_required"), 401
    return None


@app.after_request
def security_headers(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Robots-Tag"] = "noindex, nofollow"
    return resp


@app.get("/api/health")
def health():
    problems = config_problems()
    return jsonify(ok=not problems, missing=problems)


@app.post("/api/auth/login")
def auth_login():
    body = request.get_json(silent=True) or {}
    password = str(body.get("password", ""))
    if not hmac.compare_digest(password.encode(), APP_PASSWORD.encode()):
        time.sleep(1.0)  # bremst Durchprobieren
        return jsonify(error="wrong_password", message="Falsches Passwort."), 401
    resp = jsonify(ok=True)
    _set_cookie(resp, APP_COOKIE, seal("app", {"iat": time.time(), "n": secrets.token_hex(8)}), APP_SESSION_DAYS * 86400)
    return resp


@app.post("/api/auth/logout")
def auth_logout():
    resp = jsonify(ok=True)
    _del_cookie(resp, APP_COOKIE)
    _del_cookie(resp, PKCE_COOKIE)
    clear_chunked(resp, TESLA_COOKIE)
    return resp


@app.get("/api/session")
def session_info():
    tokens = unseal("tesla", get_chunked(TESLA_COOKIE))
    return jsonify(app=True, tesla=bool(tokens and tokens.get("refresh_token")),
                   expiresAt=(tokens or {}).get("expires_at"))


# ---------- Tesla-Login (OAuth2 + PKCE) ----------
@app.get("/api/tesla/login/start")
def tesla_login_start():
    verifier = _b64e(secrets.token_bytes(32))
    challenge = _b64e(hashlib.sha256(verifier.encode()).digest())
    state = _b64e(secrets.token_bytes(16))
    url = AUTH_URL + "?" + urlencode({
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": SCOPE,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    resp = jsonify(url=url, state=state)
    _set_cookie(resp, PKCE_COOKIE, seal("pkce", {"v": verifier, "s": state, "at": time.time()}), PKCE_TTL)
    return resp


def _extract_code_state(text: str) -> tuple[str | None, str | None]:
    text = text.strip()
    code = state = None
    try:
        parsed = urlparse(text)
        if parsed.query:
            query = parse_qs(parsed.query)
            code = (query.get("code") or [None])[0]
            state = (query.get("state") or [None])[0]
    except ValueError:
        pass
    if not code and re.fullmatch(r"[A-Za-z0-9._-]{10,}", text):
        code = text  # nur der Code wurde eingefügt
    return code, state


@app.post("/api/tesla/login/finish")
def tesla_login_finish():
    body = request.get_json(silent=True) or {}
    code, state = _extract_code_state(str(body.get("input", "")))
    if not code:
        return jsonify(error="no_code", message="Kein „code“ gefunden. Bitte die komplette Weiterleitungs-Adresse einfügen (beginnt mit tesla://auth/callback?code=…)."), 400
    pkce = unseal("pkce", request.cookies.get(PKCE_COOKIE))
    if not pkce or time.time() - float(pkce.get("at", 0)) > PKCE_TTL:
        return jsonify(error="pkce_expired", message="Die Login-Sitzung ist abgelaufen. Bitte Schritt 1 erneut ausführen und direkt danach die Adresse einfügen."), 400
    if state and not hmac.compare_digest(state, pkce["s"]):
        return jsonify(error="state_mismatch", message="Die Adresse gehört zu einem anderen Login-Versuch. Bitte Schritt 1 erneut ausführen."), 400
    if hmac.compare_digest(code, pkce["s"]):
        return jsonify(error="state_not_code", message="Das ist der state-Wert aus dem Login-Link, nicht der Code. Bitte erst bei Tesla anmelden und danach die komplette Adresse der Fehlerseite einfügen (sie enthält code=… und state=…)."), 400
    elapsed = int(time.time() - float(pkce.get("at", 0)))
    try:
        tokens = exchange_code(code, pkce["v"])
    except TeslaError as err:
        hint = ""
        if "invalid_auth_code" in str(err):
            hint = (f" – Zeit zwischen Schritt 1 und jetzt: {elapsed} s. Tesla-Codes verfallen nach kurzer Zeit und gelten nur einmal:"
                    " „Link neu erzeugen“ klicken, Login wiederholen und die Adresse sofort einfügen.")
        return jsonify(error="tesla_error", message=str(err) + hint, elapsed=elapsed), err.status
    resp = jsonify(ok=True)
    set_chunked(resp, TESLA_COOKIE, seal("tesla", tokens), TESLA_COOKIE_DAYS * 86400)
    _del_cookie(resp, PKCE_COOKIE)
    return resp


@app.post("/api/tesla/logout")
def tesla_logout():
    resp = jsonify(ok=True)
    clear_chunked(resp, TESLA_COOKIE)
    return resp


def post_token(body: dict) -> dict:
    # auth.tesla.com prüft den TLS-Fingerabdruck: Token, die ein „normaler“ Client holt,
    # lehnt owner-api später mit 403 ab. Deshalb Chrome-Impersonation (wie TOST).
    try:
        r = tls_requests.post(TOKEN_URL, json=body, impersonate="chrome", timeout=TIMEOUT)
    except Exception as err:  # Netzwerk/TLS
        raise TeslaError(f"Tesla-Login-Server nicht erreichbar: {err}") from err
    if not 200 <= r.status_code < 300:
        status = 400 if r.status_code in (400, 401) else 502
        raise TeslaError(f"Tesla SSO antwortete {r.status_code}: {r.text[:300]}", status)
    try:
        return r.json()
    except Exception as err:
        raise TeslaError(f"Unerwartete Antwort von Tesla SSO: {r.text[:200]}") from err


def _normalize(data: dict, fallback_refresh: str | None = None) -> dict:
    if not data.get("access_token"):
        raise TeslaError("Die Antwort von Tesla enthielt kein access_token.")
    return {
        "access_token": data["access_token"],
        # Tesla rotiert das refresh_token nicht immer: fehlt es, bleibt das alte gültig.
        "refresh_token": data.get("refresh_token") or fallback_refresh,
        "expires_at": int(time.time()) + int(data.get("expires_in") or 28800),
    }


def exchange_code(code: str, verifier: str) -> dict:
    return _normalize(post_token({
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": verifier,
    }))


def refresh_tokens(refresh_token: str) -> dict:
    return _normalize(post_token({
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "refresh_token": refresh_token,
        "scope": SCOPE,
    }), refresh_token)


# ---------- Bestelldaten ----------
def tesla_get(url: str, token: str) -> dict:
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": USER_AGENT,
        "X-Tesla-User-Agent": X_USER_AGENT,
        "X-Request-Id": str(uuid.uuid4()),
        "Accept": "application/json",
    }
    try:
        r = tls_requests.get(url, headers=headers, timeout=TIMEOUT)
    except Exception as err:
        raise TeslaError(f"Tesla nicht erreichbar: {err}") from err
    if r.status_code == 401:
        raise TeslaError("Tesla akzeptiert das Zugriffs-Token nicht mehr (401).", 401)
    if r.status_code != 200:
        hint = " (Referenznummer prüfen)" if r.status_code == 400 else ""
        raise TeslaError(f"Tesla antwortete {r.status_code}{hint}: {r.text[:300]}")
    try:
        return r.json()
    except Exception as err:
        raise TeslaError(f"Keine JSON-Antwort von Tesla: {r.text[:200]}") from err


def build_url(base: str, reference_number: str) -> str:
    return base + "?" + urlencode({
        "deviceLanguage": TESLA_LANGUAGE,
        "deviceCountry": TESLA_COUNTRY,
        "referenceNumber": reference_number,
        "appVersion": APP_VERSION,
    })


def fetch_everything(token: str) -> dict:
    # Konto-Übersicht: liefert die VIN sofort nach Zuweisung. Scheitert sie, geht es
    # ohne weiter (dann braucht es TESLA_ORDER_RN).
    try:
        account = tesla_get(ACCOUNT_ORDERS_URL, token).get("response") or []
    except TeslaError as err:
        if err.status == 401:
            raise
        account = []
    refs = [x.strip() for x in TESLA_ORDER_RN.split(",") if x.strip()] \
        or [o.get("referenceNumber") for o in account if o.get("referenceNumber")]
    if not refs:
        raise TeslaError("Keine Bestellung im Tesla-Konto gefunden. Falls es eine gibt: Referenznummer (RN…) als TESLA_ORDER_RN in Vercel hinterlegen.", 404)
    orders = []
    for rn in refs:
        acc = next((o for o in account if o.get("referenceNumber") == rn), None)
        try:
            details = tesla_get(build_url(TASKS_URL, rn), token)
            try:
                meta = tesla_get(build_url(ORDER_URL, rn), token)
            except TeslaError as err:
                if err.status == 401:
                    raise
                meta = None
            orders.append({"referenceNumber": rn, "details": details, "meta": meta, "account": acc})
        except TeslaError as err:
            if err.status == 401:
                raise
            orders.append({"referenceNumber": rn, "details": None, "meta": None, "account": acc, "error": str(err)})
    return {"fetchedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "orders": orders}


@app.get("/api/orders")
def orders():
    tokens = unseal("tesla", get_chunked(TESLA_COOKIE))
    if not tokens or not tokens.get("refresh_token"):
        return jsonify(error="tesla_login_required"), 401
    refreshed = False
    try:
        if time.time() > float(tokens.get("expires_at", 0)) - 60:
            tokens = refresh_tokens(tokens["refresh_token"])
            refreshed = True
        try:
            data = fetch_everything(tokens["access_token"])
        except TeslaError as err:
            if err.status != 401 or refreshed:
                raise
            tokens = refresh_tokens(tokens["refresh_token"])  # Token vorzeitig ungültig: einmal erneuern
            refreshed = True
            data = fetch_everything(tokens["access_token"])
    except TeslaError as err:
        if err.status in (400, 401):
            resp = jsonify(error="tesla_login_required", message=str(err))
            clear_chunked(resp, TESLA_COOKIE)
            return resp, 401
        return jsonify(error="tesla_error", message=str(err)), err.status
    resp = jsonify(**data, cached=False)
    if refreshed:
        set_chunked(resp, TESLA_COOKIE, seal("tesla", tokens), TESLA_COOKIE_DAYS * 86400)
    return resp


# ---------- nur für lokale Entwicklung (auf Vercel liefert Vercel public/ direkt) ----------
@app.get("/")
def index_page():
    return send_from_directory(PUBLIC_DIR, "index.html")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5050")), debug=False)
