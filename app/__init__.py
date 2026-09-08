from flask import Flask
from .config import Config


def create_app(config_class=Config):
    """Flask application factory."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Placeholder route — replaced in Milestone 5 with proper auth redirects
    @app.route("/")
    def index():
        return app.send_static_file("placeholder.html")

    return app
