# Tesla-Bestellstatus (Web, Vercel)

Zeigt den Status einer Tesla-Bestellung im Browser: voraussichtliches Lieferfenster,
VIN sobald zugewiesen, Bestellschritte und eine Änderungs-Historie. Läuft komplett
auf Vercel (Static + Python Serverless Function), ohne eigenen Server und ohne Datenbank.

> Inoffiziell. Nutzt interne Endpunkte der Tesla-App (wie TOST / tesla-order-status),
> die Tesla jederzeit ändern kann. Keine Verbindung zu Tesla, Inc.

## Sicherheit in Kürze

- **Keine Zugangsdaten im Code.** Passwort und Schlüssel kommen ausschließlich aus
  Vercel-Umgebungsvariablen.
- **Kein Server-Speicher.** Das Tesla-Zugriffs-Token liegt AES-GCM-verschlüsselt in einem
  httpOnly-Cookie deines Browsers. Die Änderungs-Historie liegt im localStorage des Browsers.
- Die Web-Oberfläche ist mit einem Passwort geschützt (Anmeldung 30 Tage gültig).
- Dein Tesla-Passwort wird nie hier eingegeben: der Login läuft bei Tesla selbst (OAuth2 + PKCE).

## Auf Vercel hosten (ca. 3 Minuten)

1. Dieses Repository in Vercel importieren: **Add New → Project → Import** (GitHub).
2. Framework Preset: **Other**. Build Command und Output Directory leer lassen.
3. Unter **Environment Variables** eintragen:

   | Variable | Wert |
   |---|---|
   | `APP_PASSWORD` | dein Passwort für die Seite (mind. 10 Zeichen) |
   | `SESSION_SECRET` | zufälliger Schlüssel, mind. 32 Zeichen, z. B. aus `openssl rand -base64 48` |
   | `TESLA_COUNTRY` | optional, Standard `DE` |
   | `TESLA_LANGUAGE` | optional, Standard `de` |
   | `TESLA_ORDER_RN` | optional, Referenznummer(n) falls das Konto die Bestellung nicht liefert |

4. **Deploy** klicken. Danach die Projekt-URL öffnen (`https://<projekt>.vercel.app`).

Variablen später ändern: Settings → Environment Variables → danach **Redeploy**.

## Benutzung

1. Seite öffnen und mit `APP_PASSWORD` anmelden.
2. „Tesla-Konto verbinden“: Tesla-Login öffnen, bei Tesla anmelden (inkl. 2FA).
3. Der Browser zeigt danach eine Fehlerseite. Das ist richtig: die komplette Adresse aus der
   Adressleiste kopieren (beginnt mit `tesla://auth/callback?code=…`) und einfügen.
4. Das Dashboard lädt die Bestellung. „Aktualisieren“ fragt Tesla sofort neu ab, sonst werden
   Daten bis zu 5 Minuten aus dem Browser-Cache gezeigt.

Jeder Browser (Handy, Laptop) verbindet sein Tesla-Konto einmal selbst, weil das Token nur im
jeweiligen Browser liegt. Die Historie ist ebenfalls pro Browser.

## Lokal ausprobieren

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
COOKIE_SECURE=0 APP_PASSWORD=test-passwort-123 SESSION_SECRET=$(openssl rand -base64 48) python api/index.py
# → http://127.0.0.1:5050
```

## Aufbau

- `api/index.py` – Flask-Backend (Vercel Python Runtime): App-Login, Tesla-OAuth, Bestellabruf.
- `public/` – statische Oberfläche: `index.html` (Dashboard), `login.html`, `tesla-login.html`, `app.css`.
- `vercel.json` – leitet `/api/*` auf die Function, setzt Sicherheits-Header.
- `requirements.txt` – `flask`, `curl_cffi` (Tesla verlangt beim Token-Tausch einen Browser-TLS-Fingerabdruck), `cryptography`.

## Umgebungsvariablen

Siehe `.env.example`. Ohne `APP_PASSWORD` und `SESSION_SECRET` antwortet die API mit
`server_not_configured` und nennt die fehlenden Variablen (`/api/health` zeigt den Status).

## Lizenz

MIT. Tesla-API-Logik nach [wjlc60/tesla-order-status](https://github.com/wjlc60/tesla-order-status)
und [chrisi51/tesla-order-status](https://github.com/chrisi51/tesla-order-status) (TOST).
