import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # Debug mode is OFF by default: the Werkzeug debugger allows arbitrary code
    # execution from the browser, which is unacceptable for a password vault.
    # Opt in for development with FLASK_DEBUG=1.
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=5000, debug=debug)
