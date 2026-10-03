# Password Vault

A local, offline password manager and password strength checker built with Flask.
Your credentials are stored on your own machine in a SQLite database, with the
sensitive fields encrypted using a key derived from your master password.

## Features

- **Master password:** set once on first run; required to unlock the vault
- **Encrypted storage:** usernames, passwords and notes are encrypted with Fernet
- **Password strength checker:** live feedback and crack-time estimates via zxcvbn
- **Password generator:** length 4–64, choice of character classes, option to exclude ambiguous characters
- **Search, filter and sort:** search by title or URL; filter by category or favorites; sort by last updated, title or date added
- **Categories:** four defaults, plus your own (custom icon and colour)
- **Favorites:** star important entries
- **Copy to clipboard:** with a best-effort auto-clear after 30 seconds
- **Auto-lock:** locks after 5 minutes of inactivity, with a warning 30 seconds before
- **Brute-force protection:** 5 failed unlock attempts trigger a 30-second cooldown
- **Light and dark themes**
- **Fully offline:** Bootstrap, Bootstrap Icons and zxcvbn are bundled locally; no CDN requests

## Quick start

Requires Python 3.10 or newer.

```bash
git clone https://github.com/atharvachauhan25/password-vault.git
cd password-vault

python -m venv venv
# Windows:      venv\Scripts\activate
# macOS/Linux:  source venv/bin/activate

pip install -r requirements.txt
python run.py
```

Open <http://127.0.0.1:5000>. On first run you'll be asked to create a master password.

> [!WARNING]
> There is no password recovery. If you forget your master password, the encrypted
> data in your vault cannot be decrypted by anyone.

## Configuration

Copy `.env.example` to `.env` and adjust as needed. All settings are optional.

| Variable | Default | Purpose |
|---|---|---|
| `FLASK_SECRET_KEY` | random per start | Signs the session cookie. If unset, every restart logs you out. |
| `FLASK_DEBUG` | `0` | Development only. Enables the Flask debugger: never enable for real use. |
| `INACTIVITY_TIMEOUT` | `300` | Seconds of inactivity before the vault auto-locks |
| `CLIPBOARD_CLEAR_SECONDS` | `30` | Seconds before copied values are cleared from the clipboard |
| `MAX_UNLOCK_ATTEMPTS` | `5` | Failed unlock attempts before a cooldown starts |
| `UNLOCK_COOLDOWN_SECONDS` | `30` | Length of the cooldown |

## How the security works

### Key derivation

Your master password is never stored. When you create the vault:

1. A random 16-byte salt is generated.
2. A 32-byte key is derived from your master password and the salt using
   **PBKDF2-HMAC-SHA256 with 600,000 iterations**.
3. A known "canary" value is encrypted with that key and stored alongside the salt.

To unlock, the key is re-derived from the password you type and used to decrypt
the canary. If decryption succeeds, the password was correct.

### What is and isn't encrypted

**SQLite itself is not encrypted.** Instead, sensitive fields are encrypted
individually with [Fernet](https://cryptography.io/en/latest/fernet/)
(AES-128-CBC with HMAC-SHA256 authentication) before they're written to the database.

| Field | Stored as |
|---|---|
| Username | Encrypted |
| Password | Encrypted |
| Notes | Encrypted |
| Title | **Plain text** (so it can be searched) |
| URL | **Plain text** (so it can be searched) |
| Category, favorite flag, timestamps | **Plain text** |

Someone with a copy of `instance/vault.db` cannot read your passwords, but *can*
see which sites you have accounts on.

### Password strength checking

There are two separate checks, and they are deliberately different:

- **In the browser:** [zxcvbn](https://github.com/dropbox/zxcvbn) gives detailed
  feedback, warnings and crack-time estimates as you type.
- **On the server:** a lightweight **rule-based** check (length, plus a mix of
  upper/lower case, digits and symbols) enforces a minimum standard for the
  master password. It is not an entropy estimate.

### Session and web protections

- Sessions are stored server-side; the browser only holds a random session ID.
- The session is cleared and recreated on every successful unlock (prevents session fixation).
- Session cookies are `HttpOnly` and `SameSite=Lax`.
- Every response sends `Content-Security-Policy`, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff` and `Referrer-Policy` headers.
- Pages shown while unlocked are sent with `Cache-Control: no-store`.
- Inactivity timeout is enforced on the server, not just by the browser timer.

## Known limitations

This is a personal, single-user project designed to run on your own computer.
Be aware of the following before trusting it with important credentials:

- **The derived key sits on disk while the vault is unlocked.** Server-side session
  files in `flask_session/` hold the encryption key until you lock the vault or the
  session expires. Anyone with access to your machine during that window could read it.
  Lock the vault when you're done.
- **Decrypted passwords are sent to the browser** when you view the dashboard, so they
  are present in the page while it's open.
- **No CSRF tokens.** `SameSite=Lax` cookies block the common cross-site attacks in
  modern browsers, but forms do not carry dedicated CSRF tokens.
- **Brute-force counter is in memory**, so restarting the server resets it.
- **Clipboard auto-clear is best-effort.** Browsers may refuse to clear the clipboard
  if the tab isn't focused, and it can't remove entries from clipboard-history tools.
- **Plain HTTP on localhost only.** Don't expose the server to a network.
- **No master password change or export/import** yet.

## Running the tests

```bash
python -m pytest tests/ -v
```

98 tests across four files:

| File | Covers |
|---|---|
| `tests/test_crypto.py` | Key derivation, encryption round-trips, canary verification |
| `tests/test_generator.py` | Password generation and rule-based strength scoring |
| `tests/test_auth.py` | Setup, unlock, lock, brute-force cooldown, security headers, session fixation |
| `tests/test_vault.py` | CRUD, encrypted storage, search/filter/sort, categories, API, inactivity timeout |

## Project structure

```
password-vault/
├── app/
│   ├── __init__.py        # App factory, security headers, inactivity check
│   ├── config.py          # Settings (loaded from .env)
│   ├── crypto.py          # PBKDF2 key derivation, Fernet encryption, canary
│   ├── database.py        # SQLite connection and schema setup
│   ├── generator.py       # Password generator and rule-based strength check
│   ├── schema.sql         # Tables, indexes, default categories
│   ├── routes/
│   │   ├── auth.py        # Setup, unlock, lock, brute-force protection
│   │   ├── vault.py       # Dashboard, entries, categories, generator page
│   │   └── api.py         # /api/generate, /api/check-strength
│   ├── templates/         # Jinja2 templates
│   └── static/
│       ├── css/style.css
│       ├── js/            # Dashboard, clipboard and generator logic
│       └── vendor/        # Bootstrap 5.3.3, Bootstrap Icons 1.11.3, zxcvbn 4.4.2
├── tests/
├── run.py                 # Entry point
├── requirements.txt
└── .env.example
```

Created at runtime and git-ignored: `instance/vault.db` (your vault) and
`flask_session/` (session files).

## Tech stack

Flask · Flask-Session (CacheLib backend) · SQLite · cryptography (Fernet, PBKDF2) ·
Bootstrap 5 · Bootstrap Icons · zxcvbn · pytest
