
import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_FILE = os.path.join(BASE_DIR, "users.db")
LEGACY_USERS_FILE = os.path.join(BASE_DIR, "users.txt")  # one-time import only

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123"

USERS_PER_PAGE = 10


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def _column_exists(conn, table, column):
    return column in [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]


def init_db():
    """Create the table (fresh installs), add new columns to an older
    database (upgrades), import legacy users.txt data once, and make
    sure a default admin account always exists."""
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL,
            username   TEXT NOT NULL UNIQUE COLLATE NOCASE,
            email      TEXT,
            password   TEXT NOT NULL,
            status     TEXT NOT NULL DEFAULT 'Pending',
            role       TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()

    # Upgrade path for a database created before role/created_at existed
    if not _column_exists(conn, "users", "role"):
        conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
    if not _column_exists(conn, "users", "created_at"):
        conn.execute("ALTER TABLE users ADD COLUMN created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP")
    conn.commit()

    # One-time import from the old pipe-delimited users.txt file
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
                conn.execute(
                    "INSERT OR IGNORE INTO users (name, username, email, password, status, role) "
                    "VALUES (?, ?, ?, ?, ?, 'user')",
                    (name, username, "", password, status),
                )
        conn.commit()

    # Guarantee at least one admin account exists
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
        conn.commit()

    conn.close()


# =====================================================================
# Password helpers
# =====================================================================

def verify_password(user, plain_password):
    """Check a plaintext password against the stored hash.

    Supports a one-time fallback for legacy plaintext passwords that came
    from the old users.txt file: if the stored value isn't a Werkzeug
    hash but matches exactly, the login succeeds AND the password is
    immediately re-saved as a proper hash (lazy migration)."""
    stored = user["password"]
    if stored.startswith(("pbkdf2:", "scrypt:")):
        return check_password_hash(stored, plain_password)

    if stored == plain_password:
        conn = get_db()
        conn.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (generate_password_hash(plain_password), user["id"]),
        )
        conn.commit()
        conn.close()
        return True

    return False


# =====================================================================
# Lookups
# =====================================================================

def find_user_by_username(username):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def find_user_by_id(user_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def count_admins(conn=None):
    """Number of Approved admin accounts. Reuses an open connection if
    one is passed in (so callers already inside a transaction don't open
    a second one), otherwise opens and closes its own."""
    owns_conn = conn is None
    if owns_conn:
        conn = get_db()
    total = conn.execute(
        "SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'Approved'"
    ).fetchone()[0]
    if owns_conn:
        conn.close()
    return total


# =====================================================================
# Writes
# =====================================================================

def create_user(name, username, email, password_plain, role="user", status="Pending"):
    conn = get_db()
    conn.execute(
        "INSERT INTO users (name, username, email, password, status, role) VALUES (?, ?, ?, ?, ?, ?)",
        (name, username, email, generate_password_hash(password_plain), status, role),
    )
    conn.commit()
    conn.close()


def update_password(user_id, new_password_plain):
    conn = get_db()
    conn.execute(
        "UPDATE users SET password = ? WHERE id = ?",
        (generate_password_hash(new_password_plain), user_id),
    )
    conn.commit()
    conn.close()


def update_profile(user_id, name, email):
    """Self-service profile edit. Deliberately only ever touches name and
    email - username, password, role and status are never read or
    written here, no matter what a user submits in the POST body."""
    conn = get_db()
    conn.execute("UPDATE users SET name = ?, email = ? WHERE id = ?", (name, email, user_id))
    conn.commit()
    conn.close()


def update_user_admin(user_id, name, username, email, role):
    """Admin edit of another account: name, username, email, and role.
    Returns (ok, message)."""
    conn = get_db()

    clash = conn.execute(
        "SELECT id FROM users WHERE username = ? AND id != ?", (username, user_id)
    ).fetchone()
    if clash:
        conn.close()
        return False, f"Username '{username}' is already taken by another user."

    target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if target and target["role"] == "admin" and target["status"] == "Approved" and role != "admin":
        if count_admins(conn) <= 1:
            conn.close()
            return False, "Cannot remove admin role: at least one administrator must remain."

    conn.execute(
        "UPDATE users SET name = ?, username = ?, email = ?, role = ? WHERE id = ?",
        (name, username, email, role, user_id),
    )
    conn.commit()
    conn.close()
    return True, f"User '{username}' updated successfully."


def set_status_guarded(user_id, new_status):
    """Used by approve / reject / disable / enable. Blocks the change if
    it would leave the system with no active administrator. Returns
    (ok, message)."""
    conn = get_db()
    target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target:
        conn.close()
        return False, "User not found."

    if (target["role"] == "admin" and target["status"] == "Approved"
            and new_status != "Approved" and count_admins(conn) <= 1):
        conn.close()
        return False, "Cannot change status: at least one active administrator must remain."

    conn.execute("UPDATE users SET status = ? WHERE id = ?", (new_status, user_id))
    conn.commit()
    conn.close()
    return True, "Status updated."


def delete_user(user_id):
    conn = get_db()
    target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target:
        conn.close()
        return False, "User not found."

    if target["role"] == "admin" and target["status"] == "Approved" and count_admins(conn) <= 1:
        conn.close()
        return False, "Cannot delete the last administrator account."

    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return True, f"User '{target['username']}' deleted."
