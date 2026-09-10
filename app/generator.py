"""Cryptographically secure password generator.

Uses Python's `secrets` module (backed by the OS CSPRNG) to generate
passwords with configurable length, character sets, and optional
exclusion of visually ambiguous characters.
"""

import secrets
import string


# Characters that look alike in many fonts and cause confusion
AMBIGUOUS_CHARS = set("il1Lo0O")


def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_similar: bool = False,
) -> str:
    """Generate a cryptographically secure random password.

    Guarantees at least one character from each enabled character class
    by reserving one slot per class, then filling the rest randomly from
    the full pool.

    Args:
        length: Total password length (minimum 4, clamped if needed).
        use_upper: Include uppercase letters (A-Z).
        use_lower: Include lowercase letters (a-z).
        use_digits: Include digits (0-9).
        use_symbols: Include special characters.
        exclude_similar: Remove visually ambiguous characters (i, l, 1, L, o, 0, O).

    Returns:
        A random password string of the requested length.

    Raises:
        ValueError: If no character classes are enabled.
    """
    pools = []

    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append("!@#$%^&*()_+-=[]{}|;:,.<>?")

    if not pools:
        raise ValueError("At least one character class must be enabled.")

    # Filter out ambiguous characters if requested
    if exclude_similar:
        pools = ["".join(c for c in pool if c not in AMBIGUOUS_CHARS) for pool in pools]

    # Ensure minimum length can satisfy one-per-class guarantee
    min_length = len(pools)
    length = max(length, min_length)

    # Guarantee one character from each enabled class
    guaranteed = [secrets.choice(pool) for pool in pools]

    # Build the combined pool and fill remaining slots
    combined = "".join(pools)
    remaining = [secrets.choice(combined) for _ in range(length - len(guaranteed))]

    # Combine and shuffle securely (Fisher-Yates with secrets.randbelow)
    password_chars = guaranteed + remaining
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


def check_password_strength(password: str) -> dict:
    """Rule-based server-side password strength assessment.

    Used for master password validation. This is intentionally rule-based,
    not entropy-based. Client-side zxcvbn.js provides detailed heuristic
    feedback separately.

    Args:
        password: The password to evaluate.

    Returns:
        A dict with 'score' (0-4), 'label', 'checks' dict, and 'feedback' list.
    """
    checks = {
        "length_8": len(password) >= 8,
        "length_12": len(password) >= 12,
        "has_upper": any(c.isupper() for c in password),
        "has_lower": any(c.islower() for c in password),
        "has_digit": any(c.isdigit() for c in password),
        "has_symbol": any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?~`\"'\\/" for c in password),
    }

    # Count how many character classes are present
    char_classes = sum([checks["has_upper"], checks["has_lower"],
                        checks["has_digit"], checks["has_symbol"]])

    # Score calculation
    score = 0
    if checks["length_8"]:
        score += 1
    if checks["length_12"]:
        score += 1
    if char_classes >= 2:
        score += 1
    if char_classes >= 4:
        score += 1

    labels = {0: "Weak", 1: "Weak", 2: "Fair", 3: "Good", 4: "Strong"}

    # Actionable feedback
    feedback = []
    if not checks["length_8"]:
        feedback.append("Use at least 8 characters.")
    if not checks["length_12"]:
        feedback.append("Use 12 or more characters for better security.")
    if not checks["has_upper"]:
        feedback.append("Add uppercase letters.")
    if not checks["has_lower"]:
        feedback.append("Add lowercase letters.")
    if not checks["has_digit"]:
        feedback.append("Add numbers.")
    if not checks["has_symbol"]:
        feedback.append("Add special characters.")

    return {
        "score": score,
        "label": labels[score],
        "checks": checks,
        "feedback": feedback,
    }
