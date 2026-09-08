import os
import sqlite3

from flask import current_app, g


def get_db():
    """Get a database connection for the current request.

    Stores the connection on Flask's `g` object so it's reused within
    a single request and properly closed afterward.
    """
    if "db" not in g:
        db_path = current_app.config["DATABASE_PATH"]
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")

    return g.db


def close_db(e=None):
    """Close the database connection at the end of the request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Initialize the database schema from schema.sql.

    Safe to call on every startup - all CREATE statements use IF NOT EXISTS
    and INSERT statements use OR IGNORE.
    """
    db = get_db()
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, "r") as f:
        db.executescript(f.read())


def init_app(app):
    """Register database lifecycle hooks with the Flask app."""
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()
