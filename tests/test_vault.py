"""Tests for vault CRUD, categories, search/filter/sort, API, and app config."""

import os
import sqlite3
import time

import pytest

from app import create_app
from app.config import Config


class AppTestConfig(Config):
    TESTING = True
    SESSION_TYPE = "filesystem"
    INACTIVITY_TIMEOUT = 300
    CLIPBOARD_CLEAR_SECONDS = 30

    def __init__(self, db_path, session_dir):
        self.DATABASE_PATH = db_path
        self.SESSION_FILE_DIR = session_dir


class ShortTimeoutConfig(AppTestConfig):
    """Config with a very short inactivity timeout for testing auto-lock."""
    INACTIVITY_TIMEOUT = 1


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


@pytest.fixture
def short_timeout_app(tmp_path):
    """App with 1-second inactivity timeout."""
    db_path = str(tmp_path / "test_vault.db")
    session_dir = str(tmp_path / "sessions")
    os.makedirs(session_dir, exist_ok=True)
    config = ShortTimeoutConfig(db_path, session_dir)
    app = create_app(config_class=config)
    return app


# ========== VAULT CRUD ==========

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

    def test_add_entry_without_optional_fields(self, authed_client):
        """Title and password only — username, url, notes, category are optional."""
        resp = authed_client.post("/vault/add", data={
            "title": "Minimal Entry",
            "password": "min_pass",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Minimal Entry" in resp.data

    def test_edit_entry(self, authed_client):
        authed_client.post("/vault/add", data={
            "title": "Old Title", "password": "old_pass",
        })
        resp = authed_client.post("/vault/edit/1", data={
            "title": "New Title",
            "username": "new_user",
            "password": "new_pass",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"New Title" in resp.data
        assert b"updated" in resp.data

    def test_edit_requires_title_and_password(self, authed_client):
        authed_client.post("/vault/add", data={
            "title": "Test", "password": "test",
        })
        resp = authed_client.post("/vault/edit/1", data={
            "title": "", "password": "",
        }, follow_redirects=True)
        assert b"required" in resp.data

    def test_edit_nonexistent_entry(self, authed_client):
        resp = authed_client.post("/vault/edit/999", data={
            "title": "Test", "password": "test",
        }, follow_redirects=True)
        assert b"not found" in resp.data

    def test_delete_entry(self, authed_client):
        authed_client.post("/vault/add", data={
            "title": "To Delete", "password": "delete_me",
        })
        resp = authed_client.post("/vault/delete/1", follow_redirects=True)
        assert resp.status_code == 200
        assert b"deleted" in resp.data

    def test_delete_nonexistent_entry(self, authed_client):
        resp = authed_client.post("/vault/delete/999", follow_redirects=True)
        assert b"not found" in resp.data

    def test_toggle_favorite_on(self, authed_client, app):
        authed_client.post("/vault/add", data={
            "title": "Fav Test", "password": "fav_pass",
        })
        authed_client.post("/vault/toggle-favorite/1", follow_redirects=True)
        conn = sqlite3.connect(app.config["DATABASE_PATH"])
        row = conn.execute("SELECT is_favorite FROM vault_entries WHERE id = 1").fetchone()
        conn.close()
        assert row[0] == 1

    def test_toggle_favorite_off(self, authed_client, app):
        authed_client.post("/vault/add", data={
            "title": "Fav Test", "password": "fav_pass",
        })
        # Toggle on then off
        authed_client.post("/vault/toggle-favorite/1")
        authed_client.post("/vault/toggle-favorite/1")
        conn = sqlite3.connect(app.config["DATABASE_PATH"])
        row = conn.execute("SELECT is_favorite FROM vault_entries WHERE id = 1").fetchone()
        conn.close()
        assert row[0] == 0

    def test_toggle_favorite_nonexistent(self, authed_client):
        resp = authed_client.post("/vault/toggle-favorite/999", follow_redirects=True)
        assert b"not found" in resp.data

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


# ========== ENCRYPTED STORAGE ==========

class TestEncryptedStorage:
    def test_sensitive_fields_are_encrypted(self, authed_client, app):
        """Verify username, password, notes stored as Fernet ciphertext."""
        authed_client.post("/vault/add", data={
            "title": "Plaintext Title",
            "username": "my_username",
            "password": "my_secret_password",
            "notes": "secret notes here",
        })
        conn = sqlite3.connect(app.config["DATABASE_PATH"])
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM vault_entries WHERE id = 1").fetchone()
        conn.close()

        assert row["title"] == "Plaintext Title"
        assert "my_username" not in row["username_enc"]
        assert "my_secret_password" not in row["password_enc"]
        assert "secret notes here" not in row["notes_enc"]
        assert row["password_enc"].startswith("gAAAAA")

    def test_null_optional_encrypted_fields(self, authed_client, app):
        """Username and notes can be empty — stored as NULL, not encrypted."""
        authed_client.post("/vault/add", data={
            "title": "No User", "password": "pass123",
        })
        conn = sqlite3.connect(app.config["DATABASE_PATH"])
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM vault_entries WHERE id = 1").fetchone()
        conn.close()
        assert row["username_enc"] is None
        assert row["notes_enc"] is None
        assert row["password_enc"].startswith("gAAAAA")


# ========== SEARCH, FILTER & SORT ==========

class TestSearchFilterSort:
    def test_search_by_title(self, authed_client):
        authed_client.post("/vault/add", data={"title": "Netflix", "password": "p1"})
        authed_client.post("/vault/add", data={"title": "GitHub", "password": "p2"})
        resp = authed_client.get("/vault/?q=Net")
        # Netflix should be in an entry card, GitHub should not
        assert b"Netflix" in resp.data
        # The search should filter out GitHub — check it's not in a card-title
        assert b'GitHub</a>' not in resp.data and b'>GitHub<' not in resp.data

    def test_search_by_url(self, authed_client):
        authed_client.post("/vault/add", data={
            "title": "XuniqueTarget", "password": "p1", "url": "https://example.com",
        })
        authed_client.post("/vault/add", data={
            "title": "XuniqueOther", "password": "p2", "url": "https://other.org",
        })
        resp = authed_client.get("/vault/?q=example")
        data = resp.data.decode()
        cards_start = data.index("Password Cards")
        cards_section = data[cards_start:]
        assert "XuniqueTarget" in cards_section
        assert "XuniqueOther" not in cards_section

    def test_search_no_results(self, authed_client):
        authed_client.post("/vault/add", data={"title": "Test", "password": "p1"})
        resp = authed_client.get("/vault/?q=nonexistent")
        assert b"No passwords" in resp.data

    def test_filter_by_category(self, authed_client):
        authed_client.post("/vault/add", data={
            "title": "XcatSocial", "password": "p1", "category_id": "1",
        })
        authed_client.post("/vault/add", data={
            "title": "XcatBank", "password": "p2", "category_id": "2",
        })
        resp = authed_client.get("/vault/?category=1")
        data = resp.data.decode()
        cards_start = data.index("Password Cards")
        cards_section = data[cards_start:]
        assert "XcatSocial" in cards_section
        assert "XcatBank" not in cards_section

    def test_filter_favorites_only(self, authed_client):
        authed_client.post("/vault/add", data={"title": "FavEntry", "password": "p1"})
        authed_client.post("/vault/add", data={"title": "RegularEntry", "password": "p2"})
        authed_client.post("/vault/toggle-favorite/1")
        resp = authed_client.get("/vault/?favorites=1")
        assert b"FavEntry" in resp.data
        assert b"No passwords" not in resp.data

    def test_sort_by_title(self, authed_client):
        """When sorted by title ASC, entries should be alphabetical."""
        authed_client.post("/vault/add", data={"title": "Xsort_Zeta", "password": "p1"})
        authed_client.post("/vault/add", data={"title": "Xsort_Alpha", "password": "p2"})
        resp = authed_client.get("/vault/?sort=title")
        data = resp.data.decode()
        # Look only in the cards section (after the "Password Cards" comment)
        cards_start = data.index("Password Cards")
        cards_section = data[cards_start:]
        assert cards_section.index("Xsort_Alpha") < cards_section.index("Xsort_Zeta")

    def test_sort_default_is_updated(self, authed_client):
        """Default sort = updated_at DESC. Most recently added appears first."""
        authed_client.post("/vault/add", data={"title": "Xdefault_First", "password": "p1"})
        authed_client.post("/vault/add", data={"title": "Xdefault_Second", "password": "p2"})
        resp = authed_client.get("/vault/")
        data = resp.data.decode()
        cards_start = data.index("Password Cards")
        cards_section = data[cards_start:]
        assert cards_section.index("Xdefault_Second") < cards_section.index("Xdefault_First")


# ========== CATEGORY MANAGEMENT ==========

class TestCategoryManagement:
    def test_add_category(self, authed_client):
        resp = authed_client.post("/vault/categories/add", data={
            "name": "Entertainment",
            "icon": "bi-film",
            "badge_color": "info",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Entertainment" in resp.data
        assert b"created" in resp.data

    def test_add_category_requires_name(self, authed_client):
        resp = authed_client.post("/vault/categories/add", data={
            "name": "",
        }, follow_redirects=True)
        assert b"required" in resp.data

    def test_add_duplicate_category(self, authed_client):
        authed_client.post("/vault/categories/add", data={"name": "Custom"})
        resp = authed_client.post("/vault/categories/add", data={
            "name": "Custom",
        }, follow_redirects=True)
        assert b"already exists" in resp.data

    def test_delete_category(self, authed_client):
        authed_client.post("/vault/categories/add", data={"name": "ToDelete"})
        # Get the ID of the new category (after 4 seeded ones)
        resp = authed_client.post("/vault/categories/delete/5", follow_redirects=True)
        assert resp.status_code == 200
        assert b"deleted" in resp.data

    def test_delete_nonexistent_category(self, authed_client):
        resp = authed_client.post("/vault/categories/delete/999", follow_redirects=True)
        assert b"not found" in resp.data

    def test_delete_category_uncategorizes_entries(self, authed_client, app):
        """Deleting a category should set entries' category_id to NULL."""
        authed_client.post("/vault/categories/add", data={"name": "Temp"})
        authed_client.post("/vault/add", data={
            "title": "Orphan", "password": "p1", "category_id": "5",
        })
        authed_client.post("/vault/categories/delete/5")
        conn = sqlite3.connect(app.config["DATABASE_PATH"])
        row = conn.execute("SELECT category_id FROM vault_entries WHERE title = 'Orphan'").fetchone()
        conn.close()
        assert row[0] is None

    def test_category_requires_auth(self, client):
        resp = client.post("/vault/categories/add", data={
            "name": "Test",
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert "/auth/unlock" in resp.location


# ========== GENERATOR PAGE ==========

class TestGeneratorPage:
    def test_generator_page_renders(self, authed_client):
        resp = authed_client.get("/vault/generator")
        assert resp.status_code == 200
        assert b"Password Generator" in resp.data

    def test_generator_requires_auth(self, client):
        resp = client.get("/vault/generator", follow_redirects=False)
        assert resp.status_code == 302
        assert "/auth/unlock" in resp.location


# ========== API ENDPOINTS ==========

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

    def test_generate_with_options(self, authed_client):
        resp = authed_client.post("/api/generate", json={
            "length": 12,
            "use_upper": False,
            "use_lower": True,
            "use_digits": False,
            "use_symbols": False,
        }, content_type="application/json")
        data = resp.get_json()
        assert len(data["password"]) == 12
        assert data["password"].islower()

    def test_generate_no_classes_returns_error(self, authed_client):
        resp = authed_client.post("/api/generate", json={
            "use_upper": False, "use_lower": False,
            "use_digits": False, "use_symbols": False,
        }, content_type="application/json")
        assert resp.status_code == 400
        assert "error" in resp.get_json()

    def test_generate_default_params(self, authed_client):
        """Empty JSON body should use defaults (length=16, all classes)."""
        resp = authed_client.post("/api/generate",
                                  json={},
                                  content_type="application/json")
        data = resp.get_json()
        assert len(data["password"]) == 16

    def test_check_strength_strong(self, client):
        resp = client.post("/api/check-strength",
                           json={"password": "MyStr0ng!Pass#99"},
                           content_type="application/json")
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

    def test_check_strength_empty(self, client):
        resp = client.post("/api/check-strength",
                           json={"password": ""},
                           content_type="application/json")
        data = resp.get_json()
        assert data["score"] == 0

    def test_check_strength_no_auth_required(self, client):
        """Strength checking is public (used for master password setup)."""
        resp = client.post("/api/check-strength",
                           json={"password": "test"},
                           content_type="application/json")
        assert resp.status_code == 200


# ========== INACTIVITY TIMEOUT ==========

class TestInactivityTimeout:
    def test_session_expires_after_timeout(self, short_timeout_app):
        client = short_timeout_app.test_client()
        client.post("/auth/setup", data={
            "password": STRONG_PASSWORD,
            "confirm": STRONG_PASSWORD,
        })
        # Session should be active
        resp = client.get("/vault/")
        assert resp.status_code == 200

        # Wait for timeout to expire
        time.sleep(1.5)

        # Next request should redirect to unlock with expired flag
        resp = client.get("/vault/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/auth/unlock" in resp.location
        assert "expired=1" in resp.location


# ========== CONTEXT PROCESSOR ==========

class TestContextProcessor:
    def test_timeout_values_in_template(self, authed_client):
        """Config values should be available in rendered templates."""
        resp = authed_client.get("/vault/")
        data = resp.data.decode()
        # The body tag should have the clipboard-clear data attribute
        assert 'data-clipboard-clear="30"' in data
        # The auto-lock script should contain the timeout value
        assert "INACTIVITY_TIMEOUT" in data or "const TIMEOUT = 300" in data

