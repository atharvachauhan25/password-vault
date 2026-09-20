"""Tests for vault CRUD operations and API endpoints."""

import os
import sqlite3

import pytest

from app import create_app
from app.config import Config


class AppTestConfig(Config):
    TESTING = True
    SESSION_TYPE = "filesystem"

    def __init__(self, db_path, session_dir):
        self.DATABASE_PATH = db_path
        self.SESSION_FILE_DIR = session_dir


STRONG_PASSWORD = "MyStr0ng!Pass#99"


@pytest.fixture
def app(tmp_path):
    db_path = str(tmp_path / "test_vault.db")
    session_dir = str(tmp_path / "sessions")
    os.makedirs(session_dir, exist_ok=True)
    config = AppTestConfig(db_path, session_dir)
    app = create_app(config_class=config)
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def authed_client(client):
    """A client that has set up and unlocked the vault."""
    client.post("/auth/setup", data={
        "password": STRONG_PASSWORD,
        "confirm": STRONG_PASSWORD,
    })
    return client


class TestVaultCRUD:
    def test_add_entry(self, authed_client):
        resp = authed_client.post("/vault/add", data={
            "title": "GitHub",
            "username": "user@example.com",
            "password": "gh_secret_123",
            "url": "https://github.com",
            "notes": "My GitHub account",
            "category_id": "1",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"GitHub" in resp.data
        assert b"added to vault" in resp.data

    def test_add_entry_requires_title_and_password(self, authed_client):
        resp = authed_client.post("/vault/add", data={
            "title": "",
            "password": "",
        }, follow_redirects=True)
        assert b"required" in resp.data

    def test_edit_entry(self, authed_client):
        # Add first
        authed_client.post("/vault/add", data={
            "title": "Old Title",
            "password": "old_pass",
        })
        # Edit
        resp = authed_client.post("/vault/edit/1", data={
            "title": "New Title",
            "username": "new_user",
            "password": "new_pass",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"New Title" in resp.data
        assert b"updated" in resp.data

    def test_edit_nonexistent_entry(self, authed_client):
        resp = authed_client.post("/vault/edit/999", data={
            "title": "Test",
            "password": "test",
        }, follow_redirects=True)
        assert b"not found" in resp.data

    def test_delete_entry(self, authed_client):
        # Add first
        authed_client.post("/vault/add", data={
            "title": "To Delete",
            "password": "delete_me",
        })
        # Delete
        resp = authed_client.post("/vault/delete/1", follow_redirects=True)
        assert resp.status_code == 200
        assert b"deleted" in resp.data

    def test_delete_nonexistent_entry(self, authed_client):
        resp = authed_client.post("/vault/delete/999", follow_redirects=True)
        assert b"not found" in resp.data

    def test_toggle_favorite(self, authed_client):
        authed_client.post("/vault/add", data={
            "title": "Fav Test",
            "password": "fav_pass",
        })
        # Toggle on
        resp = authed_client.post("/vault/toggle-favorite/1", follow_redirects=True)
        assert resp.status_code == 200

    def test_dashboard_requires_auth(self, client):
        resp = client.get("/vault/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/auth/unlock" in resp.location

    def test_add_requires_auth(self, client):
        resp = client.post("/vault/add", data={
            "title": "Test", "password": "test"
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert "/auth/unlock" in resp.location


class TestEncryptedStorage:
    def test_sensitive_fields_are_encrypted(self, authed_client, app):
        """Verify that username, password, and notes are stored as Fernet ciphertext."""
        authed_client.post("/vault/add", data={
            "title": "Plaintext Title",
            "username": "my_username",
            "password": "my_secret_password",
            "notes": "secret notes here",
        })

        # Read directly from the database
        conn = sqlite3.connect(app.config["DATABASE_PATH"])
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM vault_entries WHERE id = 1").fetchone()
        conn.close()

        # Title should be plaintext (for search)
        assert row["title"] == "Plaintext Title"

        # Sensitive fields should NOT contain the plaintext
        assert "my_username" not in row["username_enc"]
        assert "my_secret_password" not in row["password_enc"]
        assert "secret notes here" not in row["notes_enc"]

        # They should look like Fernet tokens (start with gAAAAA)
        assert row["password_enc"].startswith("gAAAAA")


class TestAPI:
    def test_generate_password(self, authed_client):
        resp = authed_client.post("/api/generate",
                                  json={"length": 20},
                                  content_type="application/json")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "password" in data
        assert len(data["password"]) == 20

    def test_generate_requires_auth(self, client):
        resp = client.post("/api/generate",
                           json={"length": 16},
                           content_type="application/json")
        assert resp.status_code == 401

    def test_check_strength(self, client):
        resp = client.post("/api/check-strength",
                           json={"password": "MyStr0ng!Pass#99"},
                           content_type="application/json")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["score"] == 4
        assert data["label"] == "Strong"

    def test_check_strength_weak(self, client):
        resp = client.post("/api/check-strength",
                           json={"password": "abc"},
                           content_type="application/json")
        data = resp.get_json()
        assert data["score"] == 0
        assert data["label"] == "Weak"
