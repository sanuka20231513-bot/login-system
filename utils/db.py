import os
import sqlite3
from contextlib import contextmanager

from werkzeug.security import generate_password_hash, check_password_hash

from .constants import ROLES, DEFAULT_ROLE, USER_STATUSES, SETTING_DEFAULTS

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# LOGIN_SYSTEM_DB lets the automated tests use a throw-away database.
DB_FILE = os.environ.get("LOGIN_SYSTEM_DB") or os.path.join(BASE_DIR, "users.db")
LEGACY_USERS_FILE = os.path.join(BASE_DIR, "users.txt")  # one-time import only

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    username   TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email      TEXT,
    password   TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'Pending',
    role       TEXT NOT NULL DEFAULT 'officer',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tasks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    assigned_to     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_by      INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    status          TEXT NOT NULL DEFAULT 'Pending'
                    CHECK (status IN ('Pending','In Progress','Submitted','Approved','Rejected')),
    priority        TEXT NOT NULL DEFAULT 'Medium'
                    CHECK (priority IN ('Low','Medium','High')),
    progress        INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    due_date        TEXT,
    progress_note   TEXT,
    submission_note TEXT,
    feedback        TEXT,
    submitted_at    TEXT,
    reviewed_at     TEXT,
    reviewed_by     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_tasks_assigned   ON tasks(assigned_to, status);
CREATE INDEX IF NOT EXISTS idx_tasks_created_by ON tasks(created_by, status);

CREATE TABLE IF NOT EXISTS notifications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    message    TEXT NOT NULL,
    link       TEXT,
    is_read    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read);

CREATE TABLE IF NOT EXISTS activity_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    actor_name TEXT NOT NULL,
    action     TEXT NOT NULL,
    details    TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


@contextmanager
def connect():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _column_exists(conn, table, column):
    return column in [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]


def group_counts(conn, sql, params=()):
    """Run a 'SELECT key, COUNT(*) ... GROUP BY key' query -> {key: count}."""
    return {r[0]: r[1] for r in conn.execute(sql, params).fetchall()}


# =====================================================================
# Create / upgrade the database
# =====================================================================

def init_db():
    with connect() as conn:
        conn.executescript(SCHEMA)

        # --- upgrade a database created by an older version -------------
        if not _column_exists(conn, "users", "role"):
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'officer'")
        if not _column_exists(conn, "users", "created_at"):
            # SQLite refuses ALTER TABLE ... DEFAULT CURRENT_TIMESTAMP, so
            # add a plain column and back-fill it.
            conn.execute("ALTER TABLE users ADD COLUMN created_at TEXT")
            conn.execute("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")

        # The earlier version only had 'user' and 'admin'. Anything that is
        # not a known role becomes 'officer' (the lowest-privilege role) so
        # nobody is ever silently upgraded.
        placeholders = ", ".join("?" for _ in ROLES)
        conn.execute(
            f"UPDATE users SET role = ? WHERE role NOT IN ({placeholders})",
            (DEFAULT_ROLE, *ROLES),
        )

        # --- one-time import from the very first (text file) version ----
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0 and os.path.exists(LEGACY_USERS_FILE):
            with open(LEGACY_USERS_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) != 4:
                        continue
                    name, username, password, status = parts
                    if status not in USER_STATUSES:
                        status = "Pending"
                    conn.execute(
                        "INSERT OR IGNORE INTO users (name, username, email, password, status, role) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (name, username, "", password, status, DEFAULT_ROLE),
                    )

        # --- default settings ------------------------------------------
        for key, value in SETTING_DEFAULTS.items():
            conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value))

        # --- guarantee at least one admin exists -----------------------
        admin_count = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]
        if admin_count == 0:
            existing = conn.execute(
                "SELECT id FROM users WHERE username = ?", (DEFAULT_ADMIN_USERNAME,)
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE users SET role = 'admin', status = 'Approved' WHERE id = ?",
                    (existing["id"],),
                )
            else:
                conn.execute(
                    "INSERT INTO users (name, username, email, password, status, role) "
                    "VALUES (?, ?, ?, ?, 'Approved', 'admin')",
                    ("Administrator", DEFAULT_ADMIN_USERNAME, "",
                     generate_password_hash(DEFAULT_ADMIN_PASSWORD)),
                )


# =====================================================================
# Passwords
# =====================================================================

def verify_password(user, plain_password):
    """Check a password against the stored hash. Legacy plaintext values
    (from the very first version) still work once and are immediately
    re-saved as a proper hash."""
    stored = user["password"]
    if stored.startswith(("pbkdf2:", "scrypt:")):
        return check_password_hash(stored, plain_password)

    if stored == plain_password:
        with connect() as conn:
            conn.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (generate_password_hash(plain_password), user["id"]),
            )
        return True
    return False


# =====================================================================
# Users - lookups
# =====================================================================

def find_user_by_username(username):
    with connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None


def find_user_by_id(user_id):
    with connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def count_admins(conn):
    """Number of Approved (i.e. able to log in) administrators."""
    return conn.execute(
        "SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'Approved'"
    ).fetchone()[0]


# =====================================================================
# Users - writes
# =====================================================================

def create_user(name, username, email, password_plain, role=DEFAULT_ROLE, status="Pending"):
    if role not in ROLES:
        raise ValueError("Unknown role")
    if status not in USER_STATUSES:
        raise ValueError("Unknown status")
    with connect() as conn:
        conn.execute(
            "INSERT INTO users (name, username, email, password, status, role) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (name, username, email, generate_password_hash(password_plain), status, role),
        )


def update_password(user_id, new_password_plain):
    with connect() as conn:
        conn.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (generate_password_hash(new_password_plain), user_id),
        )


def update_profile(user_id, name, email):
    """Self-service edit. Only name and email can ever change here -
    role, status, username and password are never touched."""
    with connect() as conn:
        conn.execute("UPDATE users SET name = ?, email = ? WHERE id = ?", (name, email, user_id))


def update_user_admin(user_id, name, username, email, role, new_password=None):
    """Admin edit of any account. Returns (ok, message)."""
    if role not in ROLES:
        return False, "Invalid role selected."
    with connect() as conn:
        target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            return False, "User not found."

        clash = conn.execute(
            "SELECT id FROM users WHERE username = ? AND id != ?", (username, user_id)
        ).fetchone()
        if clash:
            return False, f"Username '{username}' is already taken by another user."

        if (target["role"] == "admin" and target["status"] == "Approved"
                and role != "admin" and count_admins(conn) <= 1):
            return False, "Cannot remove the admin role: at least one active administrator must remain."

        conn.execute(
            "UPDATE users SET name = ?, username = ?, email = ?, role = ? WHERE id = ?",
            (name, username, email, role, user_id),
        )
        if new_password:
            conn.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (generate_password_hash(new_password), user_id),
            )
    return True, f"User '{username}' updated successfully."


def change_user_role(user_id, new_role):
    """Change only the role. Returns (ok, message)."""
    if new_role not in ROLES:
        return False, "Invalid role selected."
    with connect() as conn:
        target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            return False, "User not found."
        if (target["role"] == "admin" and target["status"] == "Approved"
                and new_role != "admin" and count_admins(conn) <= 1):
            return False, "Cannot remove the admin role: at least one active administrator must remain."
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    return True, f"Role for '{target['username']}' is now {new_role}."


def set_status_guarded(user_id, new_status, only_role=None):
    """Approve / reject / disable / enable. Refuses to leave the system
    without an active administrator. `only_role` restricts which accounts
    the caller may touch (managers can only touch officers).
    Returns (ok, message)."""
    if new_status not in USER_STATUSES:
        return False, "Invalid status."
    with connect() as conn:
        target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            return False, "User not found."
        if only_role and target["role"] != only_role:
            return False, "You are not allowed to change this account."
        if (target["role"] == "admin" and target["status"] == "Approved"
                and new_status != "Approved" and count_admins(conn) <= 1):
            return False, "Cannot change status: at least one active administrator must remain."
        conn.execute("UPDATE users SET status = ? WHERE id = ?", (new_status, user_id))
    return True, "Status updated."


def delete_user(user_id):
    """Returns (ok, message)."""
    with connect() as conn:
        target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            return False, "User not found."

        if (target["role"] == "admin" and target["status"] == "Approved"
                and count_admins(conn) <= 1):
            return False, "Cannot delete the last administrator account."

        created = conn.execute(
            "SELECT COUNT(*) FROM tasks WHERE created_by = ?", (user_id,)
        ).fetchone()[0]
        if created:
            return False, (f"Cannot delete '{target['username']}': they created {created} task(s). "
                           "Disable the account instead, or delete those tasks first.")

        # Work that was in flight goes back to the pool, unassigned.
        conn.execute(
            "UPDATE tasks SET assigned_to = NULL, status = 'Pending', progress = 0, "
            "submission_note = NULL, submitted_at = NULL, updated_at = datetime('now') "
            "WHERE assigned_to = ? AND status != 'Approved'",
            (user_id,),
        )
        try:
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        except sqlite3.IntegrityError:
            conn.rollback()
            return False, "This user is still referenced by other records and cannot be deleted."
    return True, f"User '{target['username']}' deleted."


# =====================================================================
# Settings
# =====================================================================

def get_setting(key):
    with connect() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else SETTING_DEFAULTS.get(key)


def set_setting(key, value):
    if key not in SETTING_DEFAULTS:
        raise ValueError("Unknown setting")
    with connect() as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )


# =====================================================================
# Activity log
# =====================================================================

def log_activity(actor, action, details=""):
    """`actor` is a user dict, or None for an anonymous request (e.g. a
    failed login)."""
    actor_id = actor["id"] if actor else None
    actor_name = actor["username"] if actor else "anonymous"
    with connect() as conn:
        # The sub-select stores NULL if the actor no longer exists (e.g. an
        # admin who just deleted their own account) instead of failing the
        # foreign key. actor_name keeps the entry readable either way.
        conn.execute(
            "INSERT INTO activity_logs (actor_id, actor_name, action, details) "
            "VALUES ((SELECT id FROM users WHERE id = ?), ?, ?, ?)",
            (actor_id, actor_name, action, (details or "")[:500]),
        )


# =====================================================================
# Notifications
# =====================================================================

def create_notification(user_id, message, link=None, conn=None):
    sql = "INSERT INTO notifications (user_id, message, link) VALUES (?, ?, ?)"
    if conn is not None:
        conn.execute(sql, (user_id, message, link))
        return
    with connect() as own:
        own.execute(sql, (user_id, message, link))


def count_unread(user_id):
    with connect() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0", (user_id,)
        ).fetchone()[0]


def recent_notifications(user_id, limit=5):
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def mark_all_read(user_id):
    with connect() as conn:
        conn.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (user_id,))
