import time

from flask import Flask, redirect, session, url_for
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
    from .routes.vault import vault
    from .routes.api import api

    app.register_blueprint(auth)
    app.register_blueprint(vault)
    app.register_blueprint(api)

    # Root redirect
    @app.route("/")
    def index():
        if "fernet_key" in session:
            return redirect(url_for("vault.dashboard"))
        return redirect(url_for("auth.setup"))

    # Inactivity timeout check
    @app.before_request
    def check_inactivity():
        from flask import request
        # Skip for static files and auth routes
        if request.endpoint and (
            request.endpoint == "static"
            or request.endpoint.startswith("auth.")
            or request.endpoint.startswith("api.")
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
