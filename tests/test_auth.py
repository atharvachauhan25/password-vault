"""Tests for authentication flow (app/routes/auth.py)."""

import os
import tempfile

import pytest
from cachelib import FileSystemCache

from app import create_app
from app.config import Config


class AppTestConfig(Config):
    """Test configuration with a temporary database."""
    TESTING = True
    SESSION_TYPE = "cachelib"
    SESSION_USE_SIGNER = False

    def __init__(self, db_path, session_dir):
        self.DATABASE_PATH = db_path
        self.SESSION_CACHELIB = FileSystemCache(cache_dir=session_dir, threshold=500)


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


@pytest.fixture
def setup_client(client):
    """A client with the vault initialized (master password set) but not unlocked."""
    from app.routes.auth import _reset_attempts
    _reset_attempts()  # Reset rate limiter between tests
    client.post("/auth/setup", data={
        "password": STRONG_PASSWORD,
        "confirm": STRONG_PASSWORD,
    })
    client.post("/auth/lock")
    return client


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


class TestBruteForceProtection:
    """Tests for unlock rate limiting."""

    def test_failed_attempts_show_remaining(self, setup_client):
        """Failed unlock should show remaining attempts."""
        resp = setup_client.post("/auth/unlock", data={
            "password": "wrong_password",
        }, follow_redirects=True)
        assert b"attempts remaining" in resp.data

    def test_rate_limit_after_max_attempts(self, setup_client, app):
        """After max failed attempts, should show cooldown."""
        from app.routes.auth import _reset_attempts
        _reset_attempts()  # Reset state from other tests

        max_attempts = app.config.get("MAX_UNLOCK_ATTEMPTS", 5)
        for _ in range(max_attempts):
            setup_client.post("/auth/unlock", data={"password": "wrong"})

        resp = setup_client.post("/auth/unlock", data={
            "password": "wrong_again",
        }, follow_redirects=True)
        assert b"Too many failed attempts" in resp.data or b"Locked out" in resp.data

    def test_successful_unlock_resets_attempts(self, setup_client):
        """Successful unlock should reset the attempt counter."""
        from app.routes.auth import _unlock_attempts, _reset_attempts
        _reset_attempts()

        # Fail a few times
        setup_client.post("/auth/unlock", data={"password": "wrong"})
        setup_client.post("/auth/unlock", data={"password": "wrong"})

        # Succeed
        setup_client.post("/auth/unlock", data={"password": STRONG_PASSWORD})

        assert _unlock_attempts["count"] == 0


class TestSecurityHeaders:
    """Tests for security response headers."""

    def test_x_frame_options(self, setup_client):
        resp = setup_client.get("/auth/unlock")
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_x_content_type_options(self, setup_client):
        resp = setup_client.get("/auth/unlock")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_referrer_policy(self, setup_client):
        resp = setup_client.get("/auth/unlock")
        assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    def test_content_security_policy(self, setup_client):
        resp = setup_client.get("/auth/unlock")
        csp = resp.headers.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp

    def test_cache_control_on_authenticated_pages(self, setup_client):
        """Authenticated pages should have no-cache headers."""
        setup_client.post("/auth/unlock", data={"password": STRONG_PASSWORD})
        resp = setup_client.get("/vault/")
        assert "no-store" in resp.headers.get("Cache-Control", "")


class TestSessionFixation:
    """Verify session fixation protection."""

    def test_session_cleared_on_unlock(self, setup_client):
        """session.clear() is called before setting fernet_key (verified by fresh session)."""
        # Inject a marker into the pre-auth session
        with setup_client.session_transaction() as sess:
            sess["pre_auth_marker"] = "should_be_gone"

        # Unlock
        setup_client.post("/auth/unlock", data={"password": STRONG_PASSWORD})

        # The marker should be gone (session was cleared)
        with setup_client.session_transaction() as sess:
            assert "pre_auth_marker" not in sess
            assert "fernet_key" in sess
