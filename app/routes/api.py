"""API routes: password generation and strength checking (JSON responses)."""

from flask import Blueprint, jsonify, request, session

from ..generator import check_password_strength, generate_password

api = Blueprint("api", __name__, url_prefix="/api")


@api.route("/generate", methods=["POST"])
def generate():
    """Generate a password with the given parameters.

    Expects JSON body with optional keys:
        length (int), use_upper (bool), use_lower (bool),
        use_digits (bool), use_symbols (bool), exclude_similar (bool)
    """
    if "fernet_key" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}

    try:
        password = generate_password(
            length=data.get("length", 16),
            use_upper=data.get("use_upper", True),
            use_lower=data.get("use_lower", True),
            use_digits=data.get("use_digits", True),
            use_symbols=data.get("use_symbols", True),
            exclude_similar=data.get("exclude_similar", False),
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({"password": password})


@api.route("/check-strength", methods=["POST"])
def check_strength():
    """Check password strength using rule-based server-side validation.

    Expects JSON body with key: password (str)
    """
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    result = check_password_strength(password)
    return jsonify(result)
