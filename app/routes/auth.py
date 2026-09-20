"""Authentication routes: vault setup, unlock, and lock."""

import time

from flask import (
    Blueprint,
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


def is_vault_initialized():
    """Check whether a vault has been set up (vault_meta row exists)."""
    db = get_db()
    row = db.execute("SELECT id FROM vault_meta WHERE id = 1").fetchone()
    return row is not None


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

        # Establish authenticated session
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
            # Establish a fresh authenticated session
            session.clear()
            session["fernet_key"] = fernet_key.decode("utf-8")
            session["last_activity"] = time.time()
            return redirect(url_for("vault.dashboard"))
        else:
            flash("Invalid master password.", "danger")
            return render_template("unlock.html")

    return render_template("unlock.html", expired=expired)


@auth.route("/lock", methods=["POST"])
def lock():
    """Lock the vault by clearing the session."""
    session.clear()
    flash("Vault locked.", "info")
    return redirect(url_for("auth.unlock"))
