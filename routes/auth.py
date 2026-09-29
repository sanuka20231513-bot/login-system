"""
Public authentication routes: login, register, logout, forgot/reset password.
These are the only pages a not-logged-in visitor can reach.
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, flash

from utils.db import find_user_by_username, find_user_by_id, create_user, verify_password, update_password
from utils.auth import get_current_user

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Please enter both username and password.", "error")
            return render_template("login.html")

        user = find_user_by_username(username)
        if not user or not verify_password(user, password):
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
        session.clear()
        session["user_id"] = user["id"]
        flash(f"Welcome back, {user['name']}!", "success")

        if user["role"] == "admin":
            return redirect(url_for("admin.dashboard"))
        return redirect(url_for("user.dashboard"))

    return render_template("login.html")


@auth_bp.route("/admin")
def admin_shortcut():
    """Kept only so an old bookmark to /admin doesn't 404 - roles now
    share a single login page instead of a separate admin login form."""
    user = get_current_user()
    if user and user["role"] == "admin":
        return redirect(url_for("admin.dashboard"))
    flash("Admins now log in from the same page as everyone else.", "error")
    return redirect(url_for("auth.login"))


@auth_bp.route("/register", methods=["GET", "POST"])
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

        if find_user_by_username(username):
            flash("That username is already taken. Please choose another.", "error")
            return render_template("register.html")

        # Self-registration always creates a plain "user", never an admin.
        create_user(name, username, email, password, role="user", status="Pending")
        flash("Account created! Please wait for administrator approval before logging in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        if not username:
            flash("Please enter your username.", "error")
            return render_template("forgot_password.html")

        user = find_user_by_username(username)
        if not user:
            flash("No account found with that username.", "error")
            return render_template("forgot_password.html")

        session["reset_user_id"] = user["id"]
        return redirect(url_for("auth.reset_password"))

    return render_template("forgot_password.html")


@auth_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    user_id = session.get("reset_user_id")
    user = find_user_by_id(user_id) if user_id else None
    if not user:
        session.pop("reset_user_id", None)
        flash("Please verify your username first.", "error")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        if not new_password or not confirm:
            flash("Please fill in both password fields.", "error")
            return render_template("reset_password.html", username=user["username"])

        if new_password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("reset_password.html", username=user["username"])

        update_password(user["id"], new_password)
        session.pop("reset_user_id", None)
        flash("Password updated successfully! You can now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("reset_password.html", username=user["username"])
