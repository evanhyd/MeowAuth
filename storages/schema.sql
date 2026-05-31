PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS user_profile (
    user_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    language INTEGER NOT NULL DEFAULT 0,
    registration_date INTEGER NOT NULL -- Unix
);

CREATE TABLE IF NOT EXISTS user_credential (
    user_id TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES user_profile(user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_session (
    session_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL, -- Unix
    expires_at INTEGER NOT NULL, -- Unix
    FOREIGN KEY(user_id) REFERENCES user_profile(user_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_session_token ON user_session(token);