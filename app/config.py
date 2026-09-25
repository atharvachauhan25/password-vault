import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Application configuration loaded from environment variables with sensible defaults."""

    # Flask secret key for session cookie signing.
    # Auto-generated if not set, but sessions won't persist across server restarts.
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32).hex()

    # Server-side session configuration (Flask-Session)
    SESSION_TYPE = "filesystem"
    SESSION_FILE_DIR = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "flask_session",
    )
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True

    # Database
    DATABASE_PATH = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "instance",
        "vault.db",
    )

    # Inactivity auto-lock timeout in seconds (default: 5 minutes)
    INACTIVITY_TIMEOUT = int(os.environ.get("INACTIVITY_TIMEOUT", 300))

    # Clipboard auto-clear timeout in seconds (default: 30 seconds)
    CLIPBOARD_CLEAR_SECONDS = int(os.environ.get("CLIPBOARD_CLEAR_SECONDS", 30))
