-- Database schema for the Login System
-- ---------------------------------------
-- This table is created automatically by app.py 

CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name     TEXT NOT NULL,                    -- full name
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,  -- login name, case-insensitive & unique
    email    TEXT,                             -- contact email
    password TEXT NOT NULL,                    -- plain text (see README security note)
    status   TEXT NOT NULL DEFAULT 'Pending'   -- Pending | Approved | Rejected | Disabled
);
