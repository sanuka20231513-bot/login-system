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

def remove_user(username):
    users = [u for u in read_users() if u["username"].lower() != username.lower()]
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

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not name or not username or not password or not confirm:
            flash("All fields are required.", "error")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        if find_user(username):
            flash("That username is already taken. Please choose another.", "error")
            return render_template("register.html")

        add_user(name, username, password)
        flash("Account created! Please wait for administrator approval before logging in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", name=session.get("name"), username=session.get("username"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

#Routes : Forget Password, Reset Password(no email,no database)

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

        # Remember which account was verified, then move on to reset step
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

#route for admin dashboard and user management
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
    ensure_users_file()
    app.run(debug=True)


    
