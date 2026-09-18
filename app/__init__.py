import time

from flask import Flask, redirect, render_template, session, url_for
from flask_session import Session

from .config import Config


def create_app(config_class=Config):
    """Flask application factory."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize server-side sessions
    Session(app)

    # Initialize database
    from . import database
    database.init_app(app)

    # Register blueprints
    from .routes.auth import auth
    app.register_blueprint(auth)

    # Temporary vault dashboard placeholder (replaced in Milestone 7)
    @app.route("/vault/")
    def vault_dashboard_placeholder():
        if "fernet_key" not in session:
            return redirect(url_for("auth.unlock"))
        return ("<h2>Vault Dashboard</h2>"
                "<p>Placeholder - the full dashboard is coming in Milestone 7.</p>"
                '<a href="/auth/lock" onclick="fetch(\'/auth/lock\', {method:\'POST\'})">Lock</a>')

    # Root redirect
    @app.route("/")
    def index():
        return redirect(url_for("auth.setup"))

    # Inactivity timeout check
    @app.before_request
    def check_inactivity():
        from flask import request
        # Skip for static files and auth routes
        if request.endpoint and (
            request.endpoint == "static"
            or request.endpoint.startswith("auth.")
        ):
            return

        if "fernet_key" in session:
            last = session.get("last_activity", 0)
            now = time.time()
            timeout = app.config.get("INACTIVITY_TIMEOUT", 300)
            if now - last > timeout:
                session.clear()
                return redirect(url_for("auth.unlock", expired=1))
            session["last_activity"] = now

    return app
