import os

from cachelib import FileSystemCache
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Application configuration loaded from environment variables with sensible defaults."""

    # Flask secret key for session cookie signing.
    # Auto-generated if not set, but sessions won't persist across server restarts.
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32).hex()

    # Server-side session configuration (Flask-Session 0.8+)
    # Use CacheLib backend directly to avoid deprecation warnings.
    SESSION_TYPE = "cachelib"
    SESSION_CACHELIB = FileSystemCache(
        cache_dir=os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "flask_session",
        ),
        threshold=500,
    )
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = False  # Deprecated in 0.8, disable to suppress warning

    # Session cookie settings
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

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

    # Max failed unlock attempts before cooldown (brute-force protection)
    MAX_UNLOCK_ATTEMPTS = int(os.environ.get("MAX_UNLOCK_ATTEMPTS", 5))
    UNLOCK_COOLDOWN_SECONDS = int(os.environ.get("UNLOCK_COOLDOWN_SECONDS", 30))
