"""Tests for the password generator and strength checker (app/generator.py)."""

import string

import pytest

from app.generator import (
    AMBIGUOUS_CHARS,
    check_password_strength,
    generate_password,
)


class TestPasswordGeneration:
    def test_default_length(self):
        password = generate_password()
        assert len(password) == 16

    def test_custom_length(self):
        for length in [8, 12, 20, 32, 64]:
            password = generate_password(length=length)
            assert len(password) == length

    def test_minimum_length_clamped(self):
        """Length can't be less than the number of enabled character classes."""
        password = generate_password(length=1, use_upper=True, use_lower=True,
                                     use_digits=True, use_symbols=True)
        assert len(password) >= 4

    def test_contains_all_enabled_classes(self):
        """Each enabled character class must have at least one representative."""
        for _ in range(20):  # Run multiple times due to randomness
            password = generate_password(length=12)
            assert any(c in string.ascii_uppercase for c in password), "Missing uppercase"
            assert any(c in string.ascii_lowercase for c in password), "Missing lowercase"
            assert any(c.isdigit() for c in password), "Missing digit"
            assert any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password), "Missing symbol"

    def test_only_lowercase(self):
        password = generate_password(length=20, use_upper=False, use_lower=True,
                                     use_digits=False, use_symbols=False)
        assert all(c in string.ascii_lowercase for c in password)

    def test_only_digits(self):
        password = generate_password(length=20, use_upper=False, use_lower=False,
                                     use_digits=True, use_symbols=False)
        assert all(c.isdigit() for c in password)

    def test_no_classes_raises(self):
        with pytest.raises(ValueError, match="At least one character class"):
            generate_password(use_upper=False, use_lower=False,
                              use_digits=False, use_symbols=False)

    def test_exclude_ambiguous(self):
        for _ in range(20):
            password = generate_password(length=30, exclude_similar=True)
            for char in password:
                assert char not in AMBIGUOUS_CHARS, f"Ambiguous char '{char}' found"

    def test_passwords_are_unique(self):
        passwords = {generate_password() for _ in range(20)}
        assert len(passwords) == 20, "Generated passwords should be unique"


class TestPasswordStrength:
    def test_empty_password_is_weak(self):
        result = check_password_strength("")
        assert result["score"] == 0
        assert result["label"] == "Weak"

    def test_short_password(self):
        result = check_password_strength("abc")
        assert result["score"] <= 1
        assert not result["checks"]["length_8"]

    def test_fair_password(self):
        result = check_password_strength("Abcdefgh1")
        assert result["score"] >= 2
        assert result["checks"]["length_8"]
        assert result["checks"]["has_upper"]
        assert result["checks"]["has_lower"]
        assert result["checks"]["has_digit"]

    def test_strong_password(self):
        result = check_password_strength("MyStr0ng!Pass#99")
        assert result["score"] == 4
        assert result["label"] == "Strong"
        assert all(result["checks"].values())

    def test_feedback_for_weak_password(self):
        result = check_password_strength("abc")
        assert len(result["feedback"]) > 0
        assert any("8 characters" in f for f in result["feedback"])

    def test_no_feedback_for_strong_password(self):
        result = check_password_strength("MyStr0ng!Pass#99")
        assert len(result["feedback"]) == 0

    def test_returns_expected_keys(self):
        result = check_password_strength("test")
        assert "score" in result
        assert "label" in result
        assert "checks" in result
        assert "feedback" in result
