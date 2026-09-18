"""Tests for authentication flow (app/routes/auth.py)."""

import os
import tempfile

import pytest

from app import create_app
from app.config import Config


class AppTestConfig(Config):
    """Test configuration with a temporary database."""
    TESTING = True
    SESSION_TYPE = "filesystem"

    def __init__(self, db_path, session_dir):
        self.DATABASE_PATH = db_path
        self.SESSION_FILE_DIR = session_dir


@pytest.fixture
def app(tmp_path):
    """Create a test app with a fresh temporary database."""
    db_path = str(tmp_path / "test_vault.db")
    session_dir = str(tmp_path / "sessions")
    os.makedirs(session_dir, exist_ok=True)

    config = AppTestConfig(db_path, session_dir)
    app = create_app(config_class=config)
    return app


@pytest.fixture
def client(app):
    return app.test_client()


STRONG_PASSWORD = "MyStr0ng!Pass#99"


class TestSetupFlow:
    def test_root_redirects_to_setup(self, client):
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/auth/setup" in resp.location

    def test_setup_page_renders(self, client):
        resp = client.get("/auth/setup")
        assert resp.status_code == 200
        assert b"Create Your Vault" in resp.data

    def test_setup_creates_vault(self, client):
        resp = client.post("/auth/setup", data={
            "password": STRONG_PASSWORD,
            "confirm": STRONG_PASSWORD,
        }, follow_redirects=False)
        # Should redirect to unlock (which then redirects to vault dashboard)
        assert resp.status_code == 302
        # Session should now have fernet_key (vault is unlocked)
        with client.session_transaction() as sess:
            assert "fernet_key" in sess

    def test_setup_rejects_mismatched_passwords(self, client):
        resp = client.post("/auth/setup", data={
            "password": STRONG_PASSWORD,
            "confirm": "different",
        }, follow_redirects=True)
        assert b"do not match" in resp.data

    def test_setup_rejects_weak_password(self, client):
        resp = client.post("/auth/setup", data={
            "password": "abc",
            "confirm": "abc",
        }, follow_redirects=True)
        assert b"too weak" in resp.data

    def test_setup_rejects_empty_password(self, client):
        resp = client.post("/auth/setup", data={
            "password": "",
            "confirm": "",
        }, follow_redirects=True)
        assert b"required" in resp.data

    def test_setup_redirects_if_vault_exists(self, client):
        # Create vault first
        client.post("/auth/setup", data={
            "password": STRONG_PASSWORD,
            "confirm": STRONG_PASSWORD,
        })
        # Clear session to simulate fresh visit
        client.get("/auth/lock", follow_redirects=True)
        # Try setup again
        resp = client.get("/auth/setup", follow_redirects=False)
        assert resp.status_code == 302
        assert "/auth/unlock" in resp.location


class TestUnlockFlow:
    @pytest.fixture(autouse=True)
    def setup_vault(self, client):
        """Create a vault before each test in this class."""
        client.post("/auth/setup", data={
            "password": STRONG_PASSWORD,
            "confirm": STRONG_PASSWORD,
        })
        # Lock the vault so we're starting from locked state
        client.post("/auth/lock")

    def test_unlock_page_renders(self, client):
        resp = client.get("/auth/unlock")
        assert resp.status_code == 200
        assert b"Unlock Vault" in resp.data

    def test_correct_password_unlocks(self, client):
        resp = client.post("/auth/unlock", data={
            "password": STRONG_PASSWORD,
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert "/vault" in resp.location

    def test_wrong_password_rejected(self, client):
        resp = client.post("/auth/unlock", data={
            "password": "wrong_password_123!",
        }, follow_redirects=True)
        assert b"Invalid master password" in resp.data

    def test_empty_password_rejected(self, client):
        resp = client.post("/auth/unlock", data={
            "password": "",
        }, follow_redirects=True)
        assert b"enter your master password" in resp.data

    def test_session_established_after_unlock(self, client):
        """Verify that a fresh session is established on successful unlock."""
        with client.session_transaction() as sess:
            assert "fernet_key" not in sess

        client.post("/auth/unlock", data={"password": STRONG_PASSWORD})

        with client.session_transaction() as sess:
            assert "fernet_key" in sess
            assert "last_activity" in sess

    def test_expired_flag_shows_warning(self, client):
        resp = client.get("/auth/unlock?expired=1")
        assert b"Session expired" in resp.data


class TestLockFlow:
    @pytest.fixture(autouse=True)
    def setup_and_unlock(self, client):
        """Create and unlock a vault before each test."""
        client.post("/auth/setup", data={
            "password": STRONG_PASSWORD,
            "confirm": STRONG_PASSWORD,
        })

    def test_lock_clears_session(self, client):
        # Verify we're unlocked
        with client.session_transaction() as sess:
            assert "fernet_key" in sess

        # Lock
        client.post("/auth/lock")

        # Verify session is cleared
        with client.session_transaction() as sess:
            assert "fernet_key" not in sess

    def test_lock_redirects_to_unlock(self, client):
        resp = client.post("/auth/lock", follow_redirects=False)
        assert resp.status_code == 302
        assert "/auth/unlock" in resp.location
