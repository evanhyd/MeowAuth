PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS user_profile (
    user_id TEXT NOT NULL,
    username TEXT NOT NULL,
    language INTEGER NOT NULL DEFAULT 0,
    registration_date INTEGER NOT NULL, -- Unix

    PRIMARY KEY(user_id)
);

CREATE TABLE IF NOT EXISTS user_credential (
    user_id TEXT NOT NULL,
    password_hash TEXT NOT NULL,

    PRIMARY KEY(user_id),
    FOREIGN KEY(user_id) REFERENCES user_profile(user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_session (
    token TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL, -- Unix
    expires_at INTEGER NOT NULL, -- Unix

    PRIMARY KEY(token),
    FOREIGN KEY(user_id) REFERENCES user_profile(user_id) ON DELETE CASCADE
);
