"""Cryptographic core for the password vault.

Handles master password key derivation (PBKDF2), Fernet encryption/decryption,
and canary-based master password verification. This module has no Flask
dependency and can be tested independently.
"""

import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 600_000
CANARY_PLAINTEXT = b"VAULT_CANARY_OK"


def generate_salt() -> bytes:
    """Generate a 16-byte cryptographically secure random salt."""
    return os.urandom(16)


def derive_fernet_key(master_password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a master password and salt.

    Uses PBKDF2-HMAC-SHA256 with 600,000 iterations to derive a 32-byte key,
    then base64-encodes it for use with Fernet.

    Args:
        master_password: The user's master password.
        salt: A 16-byte random salt (stored in the database).

    Returns:
        A 44-byte URL-safe base64-encoded key suitable for Fernet.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    derived = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(derived)


def create_canary(fernet_key: bytes) -> str:
    """Encrypt the canary plaintext to create a verification token.

    The canary is stored in the database. On unlock, we attempt to decrypt it
    with the candidate key — if it succeeds, the master password is correct.

    Args:
        fernet_key: A valid Fernet key (from derive_fernet_key).

    Returns:
        The encrypted canary as a UTF-8 string.
    """
    cipher = Fernet(fernet_key)
    return cipher.encrypt(CANARY_PLAINTEXT).decode("utf-8")


def verify_master_password(
    candidate_password: str, salt: bytes, canary_ciphertext: str
) -> tuple[bool, bytes | None]:
    """Verify a master password by attempting to decrypt the stored canary.

    Args:
        candidate_password: The password to verify.
        salt: The salt stored in vault_meta.
        canary_ciphertext: The encrypted canary stored in vault_meta.

    Returns:
        A tuple of (is_valid, fernet_key). If the password is wrong,
        returns (False, None).
    """
    try:
        fernet_key = derive_fernet_key(candidate_password, salt)
        cipher = Fernet(fernet_key)
        decrypted = cipher.decrypt(canary_ciphertext.encode("utf-8"))
        if decrypted == CANARY_PLAINTEXT:
            return True, fernet_key
    except InvalidToken:
        pass
    return False, None


def encrypt_text(plaintext: str, fernet_key: bytes) -> str:
    """Encrypt a plaintext string with Fernet.

    Args:
        plaintext: The string to encrypt.
        fernet_key: A valid Fernet key.

    Returns:
        The ciphertext as a UTF-8 string.
    """
    cipher = Fernet(fernet_key)
    return cipher.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_text(ciphertext: str, fernet_key: bytes) -> str:
    """Decrypt a Fernet ciphertext back to a plaintext string.

    Args:
        ciphertext: The Fernet-encrypted string.
        fernet_key: The same Fernet key used for encryption.

    Returns:
        The decrypted plaintext string.

    Raises:
        cryptography.fernet.InvalidToken: If the key is wrong or data is tampered.
    """
    cipher = Fernet(fernet_key)
    return cipher.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
