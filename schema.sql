-- Database schema for the Login System (with roles)
-- ------------------------------------------------------
-- Created automatically by app.py (see utils/db.py: init_db()) - you do
-- not need to run this file manually. Kept here so the structure is easy
-- to read and present separately (e.g. for a viva).

CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,                       -- full name
    username   TEXT NOT NULL UNIQUE COLLATE NOCASE,  -- login name, case-insensitive & unique
    email      TEXT,                                -- contact email
    password   TEXT NOT NULL,                        -- hashed with werkzeug.security
    status     TEXT NOT NULL DEFAULT 'Pending',       -- Pending | Approved | Rejected | Disabled
    role       TEXT NOT NULL DEFAULT 'user',          -- user | admin
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
