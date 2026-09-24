"""
Simple Login System with Admin Approval (SQLite version)
==========================================================
User accounts are stored in a small SQLite database: users.db
(created automatically next to this file the first time you run it).

Table: users
    id       INTEGER  primary key, auto-increment
    name     TEXT     full name
    username TEXT     unique login name (case-insensitive)
    email    TEXT     contact email
    password TEXT     plain-text password (see security note in README)
    status   TEXT     Pending / Approved / Rejected / Disabled

See schema.sql for the raw CREATE TABLE statement.

HOW TO RUN
----------
1. Install Flask (only dependency):
       pip install -r requirements.txt
2. Start the server:
       python app.py
3. Open in your browser:
       http://127.0.0.1:5000/          -> user login page
       http://127.0.0.1:5000/register  -> create a new account
       http://127.0.0.1:5000/admin     -> admin login (approve/reject/edit users)

DEFAULT ADMIN LOGIN
--------------------
   username: admin
   password: admin123
(Change ADMIN_USERNAME / ADMIN_PASSWORD below before real use.)
"""

import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = "change-this-secret-key-in-production"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "users.db")
LEGACY_USERS_FILE = os.path.join(BASE_DIR, "users.txt")  # only used for a one-time import

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"


# =====================================================================
# Database helpers  (SQLite)
# =====================================================================

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the users table if it doesn't exist yet, and (only the very
    first time, when the table is empty) import any accounts found in the
    old users.txt file so existing demo data isn't lost."""
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            name     TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            email    TEXT,
            password TEXT NOT NULL,
            status   TEXT NOT NULL DEFAULT 'Pending'
        )
    """)
    conn.commit()

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
                    "INSERT OR IGNORE INTO users (name, username, email, password, status) VALUES (?, ?, ?, ?, ?)",
                    (name, username, "", password, status),
                )
        conn.commit()

    conn.close()


def read_users():
    conn = get_db()
    rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def find_user(username):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def add_user(name, username, email, password):
    conn = get_db()
    conn.execute(
        "INSERT INTO users (name, username, email, password, status) VALUES (?, ?, ?, ?, 'Pending')",
        (name, username, email, password),
    )
    conn.commit()
    conn.close()


def update_user_status(username, status):
    conn = get_db()
    conn.execute("UPDATE users SET status = ? WHERE username = ?", (status, username))
    conn.commit()
    conn.close()


def update_user_password(username, new_password):
    conn = get_db()
    conn.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, username))
    conn.commit()
    conn.close()


def update_user_details(original_username, name, new_username, email):
    """Admin edit: change name/username/email. Returns False if the new
    username is already used by a *different* account."""
    conn = get_db()
    clash = conn.execute(
        "SELECT id FROM users WHERE username = ? AND username != ?",
        (new_username, original_username),
    ).fetchone()
    if clash:
        conn.close()
        return False

    conn.execute(
        "UPDATE users SET name = ?, username = ?, email = ? WHERE username = ?",
        (name, new_username, email, original_username),
    )
    conn.commit()
    conn.close()
    return True


def remove_user(username):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()


# =====================================================================
# Routes: Login / Register / Dashboard / Logout
# =====================================================================

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Please enter both username and password.", "error")
            return render_template("login.html")

        user = find_user(username)
        if not user or user["password"] != password:
            flash("Incorrect username or password.", "error")
            return render_template("login.html")

        if user["status"] == "Pending":
            flash("Your account is waiting for administrator approval.", "error")
            return render_template("login.html")

        if user["status"] == "Rejected":
            flash("Your account request was rejected. Please contact the administrator.", "error")
            return render_template("login.html")

        if user["status"] == "Disabled":
            flash("Your account has been disabled. Please contact the administrator.", "error")
            return render_template("login.html")

        # status == "Approved" -> success
        session["username"] = user["username"]
        session["name"] = user["name"]
        session["email"] = user["email"]
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not name or not username or not email or not password or not confirm:
            flash("All fields are required.", "error")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        if find_user(username):
            flash("That username is already taken. Please choose another.", "error")
            return render_template("register.html")

        add_user(name, username, email, password)
        flash("Account created! Please wait for administrator approval before logging in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template(
        "dashboard.html",
        name=session.get("name"),
        username=session.get("username"),
        email=session.get("email"),
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# =====================================================================
# Routes: Forgot Password (no email, no external database)
# =====================================================================

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        if not username:
            flash("Please enter your username.", "error")
            return render_template("forgot_password.html")

        user = find_user(username)
        if not user:
            flash("No account found with that username.", "error")
            return render_template("forgot_password.html")

        session["reset_username"] = user["username"]
        return redirect(url_for("reset_password"))

    return render_template("forgot_password.html")


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    username = session.get("reset_username")
    if not username:
        flash("Please verify your username first.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        if not new_password or not confirm:
            flash("Please fill in both password fields.", "error")
            return render_template("reset_password.html", username=username)

        if new_password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("reset_password.html", username=username)

        update_user_password(username, new_password)
        session.pop("reset_username", None)
        flash("Password updated successfully! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", username=username)


# =====================================================================
# Routes: Admin Panel
# =====================================================================

@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["is_admin"] = True
            return redirect(url_for("admin_panel"))

        flash("Incorrect admin username or password.", "error")
        return render_template("admin_login.html")

    return render_template("admin_login.html")


@app.route("/admin/panel")
def admin_panel():
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))

    users = read_users()
    pending = [u for u in users if u["status"] == "Pending"]
    approved = [u for u in users if u["status"] == "Approved"]
    others = [u for u in users if u["status"] not in ("Pending", "Approved")]

    return render_template("admin_panel.html", pending=pending, approved=approved, others=others)


@app.route("/admin/edit/<username>", methods=["GET", "POST"])
def admin_edit(username):
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))

    user = find_user(username)
    if not user:
        flash(f"User '{username}' not found.", "error")
        return redirect(url_for("admin_panel"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        new_username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()

        if not name or not new_username:
            flash("Name and username cannot be empty.", "error")
            return render_template("edit_user.html", user=user)

        updated = update_user_details(username, name, new_username, email)
        if not updated:
            flash(f"Username '{new_username}' is already taken by another user.", "error")
            return render_template("edit_user.html", user=user)

        flash(f"User '{new_username}' updated successfully.", "success")
        return redirect(url_for("admin_panel"))

    return render_template("edit_user.html", user=user)


@app.route("/admin/approve/<username>", methods=["POST"])
def admin_approve(username):
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))
    update_user_status(username, "Approved")
    flash(f"User '{username}' approved.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/reject/<username>", methods=["POST"])
def admin_reject(username):
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))
    update_user_status(username, "Rejected")
    flash(f"User '{username}' rejected.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/disable/<username>", methods=["POST"])
def admin_disable(username):
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))
    update_user_status(username, "Disabled")
    flash(f"User '{username}' disabled.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/remove/<username>", methods=["POST"])
def admin_remove(username):
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))
    remove_user(username)
    flash(f"User '{username}' permanently removed.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("admin_login"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
