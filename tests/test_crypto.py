"""Tests for the cryptographic core (app/crypto.py)."""

import pytest
from cryptography.fernet import InvalidToken

from app.crypto import (
    CANARY_PLAINTEXT,
    create_canary,
    decrypt_text,
    derive_fernet_key,
    encrypt_text,
    generate_salt,
    verify_master_password,
)


class TestSaltGeneration:
    def test_salt_is_16_bytes(self):
        salt = generate_salt()
        assert isinstance(salt, bytes)
        assert len(salt) == 16

    def test_salts_are_unique(self):
        salts = {generate_salt() for _ in range(10)}
        assert len(salts) == 10, "Generated salts should be unique"


class TestKeyDerivation:
    def test_derives_valid_fernet_key(self):
        salt = generate_salt()
        key = derive_fernet_key("test_password", salt)
        # Fernet keys are 44 bytes of URL-safe base64
        assert isinstance(key, bytes)
        assert len(key) == 44

    def test_same_inputs_produce_same_key(self):
        salt = generate_salt()
        key1 = derive_fernet_key("same_password", salt)
        key2 = derive_fernet_key("same_password", salt)
        assert key1 == key2

    def test_different_passwords_produce_different_keys(self):
        salt = generate_salt()
        key1 = derive_fernet_key("password_one", salt)
        key2 = derive_fernet_key("password_two", salt)
        assert key1 != key2

    def test_different_salts_produce_different_keys(self):
        salt1 = generate_salt()
        salt2 = generate_salt()
        key1 = derive_fernet_key("same_password", salt1)
        key2 = derive_fernet_key("same_password", salt2)
        assert key1 != key2


class TestEncryptDecrypt:
    @pytest.fixture
    def fernet_key(self):
        salt = generate_salt()
        return derive_fernet_key("test_password", salt)

    def test_round_trip(self, fernet_key):
        original = "my_secret_password_123!"
        encrypted = encrypt_text(original, fernet_key)
        decrypted = decrypt_text(encrypted, fernet_key)
        assert decrypted == original

    def test_ciphertext_differs_from_plaintext(self, fernet_key):
        original = "visible_text"
        encrypted = encrypt_text(original, fernet_key)
        assert encrypted != original

    def test_same_plaintext_produces_different_ciphertext(self, fernet_key):
        """Fernet includes a timestamp and IV, so encryptions are non-deterministic."""
        original = "same_text"
        enc1 = encrypt_text(original, fernet_key)
        enc2 = encrypt_text(original, fernet_key)
        assert enc1 != enc2

    def test_wrong_key_fails_to_decrypt(self, fernet_key):
        encrypted = encrypt_text("secret", fernet_key)
        wrong_key = derive_fernet_key("wrong_password", generate_salt())
        with pytest.raises(InvalidToken):
            decrypt_text(encrypted, wrong_key)

    def test_empty_string_round_trip(self, fernet_key):
        encrypted = encrypt_text("", fernet_key)
        assert decrypt_text(encrypted, fernet_key) == ""

    def test_unicode_round_trip(self, fernet_key):
        original = "pässwörd with ünïcödé 🔐"
        encrypted = encrypt_text(original, fernet_key)
        assert decrypt_text(encrypted, fernet_key) == original


class TestCanaryVerification:
    def test_correct_password_verifies(self):
        password = "correct_master_password"
        salt = generate_salt()
        key = derive_fernet_key(password, salt)
        canary = create_canary(key)

        is_valid, returned_key = verify_master_password(password, salt, canary)
        assert is_valid is True
        assert returned_key == key

    def test_wrong_password_rejected(self):
        password = "correct_password"
        salt = generate_salt()
        key = derive_fernet_key(password, salt)
        canary = create_canary(key)

        is_valid, returned_key = verify_master_password("wrong_password", salt, canary)
        assert is_valid is False
        assert returned_key is None

    def test_canary_is_not_plaintext(self):
        salt = generate_salt()
        key = derive_fernet_key("password", salt)
        canary = create_canary(key)
        assert CANARY_PLAINTEXT.decode("utf-8") not in canary

    def test_tampered_canary_rejected(self):
        password = "password"
        salt = generate_salt()
        key = derive_fernet_key(password, salt)
        canary = create_canary(key)

        # Tamper with the canary
        tampered = canary[:-5] + "XXXXX"
        is_valid, returned_key = verify_master_password(password, salt, tampered)
        assert is_valid is False
        assert returned_key is None
