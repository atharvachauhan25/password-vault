"""Vault routes: password entry CRUD operations."""

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from ..crypto import decrypt_text, encrypt_text
from ..database import get_db

vault = Blueprint("vault", __name__, url_prefix="/vault")


def login_required(f):
    """Decorator that redirects to unlock if the session has no fernet_key."""
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        if "fernet_key" not in session:
            return redirect(url_for("auth.unlock"))
        return f(*args, **kwargs)

    return decorated


def get_fernet_key() -> bytes:
    """Retrieve the Fernet key from the session as bytes."""
    return session["fernet_key"].encode("utf-8")


@vault.route("/")
@login_required
def dashboard():
    """Main vault dashboard — lists all password entries."""
    db = get_db()
    fernet_key = get_fernet_key()

    # Get filter parameters
    category_id = request.args.get("category", type=int)
    favorites_only = request.args.get("favorites") == "1"
    search_query = request.args.get("q", "").strip()

    # Build query
    query = "SELECT * FROM vault_entries WHERE 1=1"
    params = []

    if category_id:
        query += " AND category_id = ?"
        params.append(category_id)

    if favorites_only:
        query += " AND is_favorite = 1"

    if search_query:
        query += " AND title LIKE ?"
        params.append(f"%{search_query}%")

    query += " ORDER BY updated_at DESC"

    rows = db.execute(query, params).fetchall()

    # Decrypt sensitive fields for display
    entries = []
    for row in rows:
        entry = dict(row)
        try:
            entry["username"] = decrypt_text(row["username_enc"], fernet_key) if row["username_enc"] else ""
            entry["password"] = decrypt_text(row["password_enc"], fernet_key)
            entry["notes"] = decrypt_text(row["notes_enc"], fernet_key) if row["notes_enc"] else ""
        except Exception:
            entry["username"] = "[decryption error]"
            entry["password"] = "[decryption error]"
            entry["notes"] = "[decryption error]"
        entries.append(entry)

    # Get categories for sidebar
    categories = db.execute(
        "SELECT c.*, COUNT(v.id) as entry_count "
        "FROM categories c LEFT JOIN vault_entries v ON c.id = v.category_id "
        "GROUP BY c.id ORDER BY c.name"
    ).fetchall()

    total_count = db.execute("SELECT COUNT(*) FROM vault_entries").fetchone()[0]
    fav_count = db.execute("SELECT COUNT(*) FROM vault_entries WHERE is_favorite = 1").fetchone()[0]

    return render_template(
        "vault.html",
        entries=entries,
        categories=categories,
        total_count=total_count,
        fav_count=fav_count,
        active_category=category_id,
        favorites_only=favorites_only,
        search_query=search_query,
    )


@vault.route("/add", methods=["POST"])
@login_required
def add_entry():
    """Add a new password entry to the vault."""
    fernet_key = get_fernet_key()
    db = get_db()

    title = request.form.get("title", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    url = request.form.get("url", "").strip()
    notes = request.form.get("notes", "").strip()
    category_id = request.form.get("category_id", type=int)

    if not title or not password:
        flash("Title and password are required.", "danger")
        return redirect(url_for("vault.dashboard"))

    # Encrypt sensitive fields
    username_enc = encrypt_text(username, fernet_key) if username else None
    password_enc = encrypt_text(password, fernet_key)
    notes_enc = encrypt_text(notes, fernet_key) if notes else None

    db.execute(
        "INSERT INTO vault_entries (title, username_enc, password_enc, url, notes_enc, category_id) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (title, username_enc, password_enc, url or None, notes_enc, category_id or None),
    )
    db.commit()

    flash(f"'{title}' added to vault.", "success")
    return redirect(url_for("vault.dashboard"))


@vault.route("/edit/<int:entry_id>", methods=["POST"])
@login_required
def edit_entry(entry_id):
    """Edit an existing password entry."""
    fernet_key = get_fernet_key()
    db = get_db()

    # Verify the entry exists
    existing = db.execute("SELECT id FROM vault_entries WHERE id = ?", (entry_id,)).fetchone()
    if not existing:
        flash("Entry not found.", "danger")
        return redirect(url_for("vault.dashboard"))

    title = request.form.get("title", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    url = request.form.get("url", "").strip()
    notes = request.form.get("notes", "").strip()
    category_id = request.form.get("category_id", type=int)

    if not title or not password:
        flash("Title and password are required.", "danger")
        return redirect(url_for("vault.dashboard"))

    # Encrypt sensitive fields
    username_enc = encrypt_text(username, fernet_key) if username else None
    password_enc = encrypt_text(password, fernet_key)
    notes_enc = encrypt_text(notes, fernet_key) if notes else None

    db.execute(
        "UPDATE vault_entries SET title=?, username_enc=?, password_enc=?, url=?, "
        "notes_enc=?, category_id=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (title, username_enc, password_enc, url or None, notes_enc, category_id or None, entry_id),
    )
    db.commit()

    flash(f"'{title}' updated.", "success")
    return redirect(url_for("vault.dashboard"))


@vault.route("/delete/<int:entry_id>", methods=["POST"])
@login_required
def delete_entry(entry_id):
    """Delete a password entry."""
    db = get_db()

    entry = db.execute("SELECT title FROM vault_entries WHERE id = ?", (entry_id,)).fetchone()
    if not entry:
        flash("Entry not found.", "danger")
        return redirect(url_for("vault.dashboard"))

    db.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
    db.commit()

    flash(f"'{entry['title']}' deleted.", "info")
    return redirect(url_for("vault.dashboard"))


@vault.route("/toggle-favorite/<int:entry_id>", methods=["POST"])
@login_required
def toggle_favorite(entry_id):
    """Toggle the favorite status of a password entry."""
    db = get_db()

    entry = db.execute("SELECT id, is_favorite FROM vault_entries WHERE id = ?", (entry_id,)).fetchone()
    if not entry:
        flash("Entry not found.", "danger")
        return redirect(url_for("vault.dashboard"))

    new_status = 0 if entry["is_favorite"] else 1
    db.execute(
        "UPDATE vault_entries SET is_favorite = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (new_status, entry_id),
    )
    db.commit()

    return redirect(url_for("vault.dashboard"))
