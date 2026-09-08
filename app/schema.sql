PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- Vault metadata: stores salt and canary for master password verification.
-- Constrained to a single row (id must be 1).
CREATE TABLE IF NOT EXISTS vault_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    salt BLOB NOT NULL,
    canary TEXT NOT NULL,
    iterations INTEGER NOT NULL DEFAULT 600000,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Password categories / tags.
CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    icon TEXT NOT NULL DEFAULT 'bi-folder',
    badge_color TEXT NOT NULL DEFAULT 'secondary',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Vault entries: each row is one stored credential.
-- title and url are plaintext for search; sensitive fields are Fernet-encrypted.
CREATE TABLE IF NOT EXISTS vault_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    username_enc TEXT,
    password_enc TEXT NOT NULL,
    url TEXT,
    notes_enc TEXT,
    category_id INTEGER,
    is_favorite INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_entries_category ON vault_entries(category_id);
CREATE INDEX IF NOT EXISTS idx_entries_favorite ON vault_entries(is_favorite);
CREATE INDEX IF NOT EXISTS idx_entries_title ON vault_entries(title);

-- Seed default categories (idempotent via OR IGNORE).
INSERT OR IGNORE INTO categories (name, icon, badge_color) VALUES
    ('Banking & Finance', 'bi-wallet2', 'success'),
    ('Work & Productivity', 'bi-briefcase', 'primary'),
    ('Social Media', 'bi-chat-dots', 'info'),
    ('Personal', 'bi-person', 'secondary');
