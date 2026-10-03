"""Authentication routes: vault setup, unlock, and lock."""

import time

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from ..crypto import create_canary, derive_fernet_key, generate_salt, verify_master_password
from ..database import get_db
from ..generator import check_password_strength

auth = Blueprint("auth", __name__, url_prefix="/auth")

# In-memory brute-force tracking (per-process; sufficient for single-user local app)
_unlock_attempts = {"count": 0, "last_attempt": 0, "locked_until": 0}


def is_vault_initialized():
    """Check whether a vault has been set up (vault_meta row exists)."""
    db = get_db()
    row = db.execute("SELECT id FROM vault_meta WHERE id = 1").fetchone()
    return row is not None


def _check_rate_limit():
    """Check if unlock attempts are rate-limited. Returns seconds remaining, or 0."""
    now = time.time()
    if now < _unlock_attempts["locked_until"]:
        return int(_unlock_attempts["locked_until"] - now) + 1
    return 0


def _record_failed_attempt():
    """Record a failed unlock attempt and trigger cooldown if threshold reached."""
    max_attempts = current_app.config.get("MAX_UNLOCK_ATTEMPTS", 5)
    cooldown = current_app.config.get("UNLOCK_COOLDOWN_SECONDS", 30)

    _unlock_attempts["count"] += 1
    _unlock_attempts["last_attempt"] = time.time()

    if _unlock_attempts["count"] >= max_attempts:
        _unlock_attempts["locked_until"] = time.time() + cooldown


def _reset_attempts():
    """Reset attempt counter after successful unlock."""
    _unlock_attempts["count"] = 0
    _unlock_attempts["last_attempt"] = 0
    _unlock_attempts["locked_until"] = 0


@auth.route("/setup", methods=["GET", "POST"])
def setup():
    """First-time vault creation: set a master password."""
    if is_vault_initialized():
        return redirect(url_for("auth.unlock"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        # Validate
        if not password:
            flash("Master password is required.", "danger")
            return render_template("setup.html")

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("setup.html")

        # Rule-based server-side strength check
        strength = check_password_strength(password)
        if strength["score"] < 2:
            flash("Master password is too weak. Use at least 8 characters with "
                  "multiple character types.", "danger")
            return render_template("setup.html")

        # Create the vault
        salt = generate_salt()
        fernet_key = derive_fernet_key(password, salt)
        canary = create_canary(fernet_key)

        db = get_db()
        db.execute(
            "INSERT INTO vault_meta (id, salt, canary) VALUES (1, ?, ?)",
            (salt, canary),
        )
        db.commit()

        # Establish authenticated session (clear first to prevent session fixation)
        session.clear()
        session["fernet_key"] = fernet_key.decode("utf-8")
        session["last_activity"] = time.time()

        flash("Vault created successfully!", "success")
        return redirect(url_for("auth.unlock"))

    return render_template("setup.html")


@auth.route("/unlock", methods=["GET", "POST"])
def unlock():
    """Master password login to unlock the vault."""
    if not is_vault_initialized():
        return redirect(url_for("auth.setup"))

    # Already unlocked
    if "fernet_key" in session:
        return redirect(url_for("vault.dashboard"))

    expired = request.args.get("expired", False)

    if request.method == "POST":
        # Brute-force rate limiting
        wait = _check_rate_limit()
        if wait > 0:
            flash(f"Too many failed attempts. Please wait {wait} seconds.", "danger")
            return render_template("unlock.html", rate_limited=True, wait_seconds=wait)

        password = request.form.get("password", "")

        if not password:
            flash("Please enter your master password.", "danger")
            return render_template("unlock.html")

        db = get_db()
        meta = db.execute("SELECT salt, canary FROM vault_meta WHERE id = 1").fetchone()

        is_valid, fernet_key = verify_master_password(
            password, meta["salt"], meta["canary"]
        )

        if is_valid:
            # Reset brute-force counter
            _reset_attempts()

            # Establish a fresh authenticated session (session fixation protection)
            session.clear()
            session["fernet_key"] = fernet_key.decode("utf-8")
            session["last_activity"] = time.time()
            return redirect(url_for("vault.dashboard"))
        else:
            _record_failed_attempt()
            remaining_wait = _check_rate_limit()
            if remaining_wait > 0:
                flash(f"Too many failed attempts. Locked for {remaining_wait} seconds.", "danger")
                return render_template("unlock.html", rate_limited=True, wait_seconds=remaining_wait)
            else:
                max_attempts = current_app.config.get("MAX_UNLOCK_ATTEMPTS", 5)
                remaining = max_attempts - _unlock_attempts["count"]
                flash(f"Invalid master password. {remaining} attempts remaining.", "danger")
            return render_template("unlock.html")

    return render_template("unlock.html", expired=expired)


@auth.route("/lock", methods=["POST"])
def lock():
    """Lock the vault by clearing the session."""
    session.clear()
    flash("Vault locked.", "info")
    return redirect(url_for("auth.unlock"))
