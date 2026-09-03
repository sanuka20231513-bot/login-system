import os
import threading
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = "change-this-secret-key-in-production"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.txt")
file_lock = threading.Lock()  # keeps file writes safe if two requests happen at once

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

SEP = " | "  

# Helper functions user.txt file


def ensure_users_file():
    """Create users.txt if it doesn't exist yet."""
    if not os.path.exists(USERS_FILE):
        open(USERS_FILE, "w", encoding="utf-8").close()

def read_users():
    """Read users from users.txt and return a list of (username, password) tuples."""
    ensure_users_file()
    users = []
    with file_lock:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split("|")]
                if len(parts) != 4:
                    continue  # skip malformed lines
                name, username, password, status = parts
                users.append({
                    "name": name,
                    "username": username,
                    "password": password,
                    "status": status,
                })
    return users


def write_users(users):
    """Overwrite the list of users to users.txt."""
    with file_lock:
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            for u in users:
                f.write(f"{u['name']}{SEP}{u['username']}{SEP}{u['password']}{SEP}{u['status']}\n")

def find_user(username):
    for u in read_users():
        if u["username"].lower() == username.lower():
            return u
    return None

def add_user(name, username, password):
    users = read_users()
    users.append({"name": name, "username": username, "password": password, "status": "Pending"})
    write_users(users)

def update_user_status(username, status):
    users = read_users()
    for u in users:
        if u["username"].lower() == username.lower():
            u["status"] = status
    write_users(users)

def update_user_password(username, new_password):
    users = read_users()
    for u in users:
        if u["username"].lower() == username.lower():
            u["password"] = new_password
    write_users(users)

# Flask routes: Login, Register, Dashboard,Logout
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

# basic empty-field validation (server-side, in addition to the
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
        return redirect(url_for("dashboard"))

    return render_template("login.html")

def remove_user(username):
    users = [u for u in read_users() if u["username"].lower() != username.lower()]
    write_users(users)
