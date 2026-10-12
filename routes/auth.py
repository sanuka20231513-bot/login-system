import sqlite3

from flask import Blueprint, render_template, request, redirect, url_for, session, flash

from utils.constants import DEFAULT_ROLE
from utils.db import (
    find_user_by_username, find_user_by_id, create_user, verify_password,
    update_password, log_activity,
)
from utils.permissions import get_current_user, home_url_for, reset_current_user_cache
from utils.validators import validate_name, validate_username, validate_email, validate_password

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        current = get_current_user()
        if current:
            return redirect(home_url_for(current))
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        flash("Please enter both username and password.", "error")
        return render_template("login.html")

    user = find_user_by_username(username)
    if not user or not verify_password(user, password):
        log_activity(None, "login_failed", f"username={username[:50]}")
        flash("Incorrect username or password.", "error")
        return render_template("login.html")

    # Account status is read from the database, never from the browser.
    blocked = {
        "Pending": "Your account is waiting for administrator approval.",
        "Rejected": "Your account request was rejected. Please contact the administrator.",
        "Disabled": "Your account has been disabled. Please contact the administrator.",
    }
    if user["status"] in blocked:
        log_activity(None, "login_blocked", f"username={username[:50]} status={user['status']}")
        flash(blocked[user["status"]], "error")
        return render_template("login.html")

    session.clear()  # drop any old session data (also rotates the CSRF token)
    session["user_id"] = user["id"]
    session.permanent = True
    reset_current_user_cache()
    log_activity(user, "login")
    flash(f"Welcome back, {user['name']}!", "success")
    return redirect(home_url_for(user))


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        error = (validate_name(name) or validate_username(username)
                 or validate_email(email, required=True) or validate_password(password))
        if error:
            flash(error, "error")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        if find_user_by_username(username):
            flash("That username is already taken. Please choose another.", "error")
            return render_template("register.html")

        # Self-registration can only ever create the lowest role, as Pending.
        # The role is NOT read from the form at all.
        try:
            create_user(name, username, email, password, role=DEFAULT_ROLE, status="Pending")
        except sqlite3.IntegrityError:
            flash("That username is already taken. Please choose another.", "error")
            return render_template("register.html")

        new_user = find_user_by_username(username)
        log_activity(new_user, "register", f"{username} registered (Pending approval)")
        flash("Account created! Please wait for administrator approval before logging in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/logout")
def logout():
    user = get_current_user()
    if user:
        log_activity(user, "logout")
    session.clear()
    reset_current_user_cache()
    return redirect(url_for("auth.login"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        if not username or not email:
            flash("Please enter your username and the email address on your account.", "error")
            return render_template("forgot_password.html")

        # Both must match what is stored. Knowing a username alone must never
        # be enough to take over an account (especially an admin account).
        user = find_user_by_username(username)
        stored_email = ((user or {}).get("email") or "").strip().lower()
        if not user or not stored_email or stored_email != email:
            log_activity(None, "password_reset_failed", f"username={username[:50]}")
            flash("No account matches those details. If your account has no email on file, "
                  "ask an administrator to reset your password.", "error")
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
        flash("Please verify your account details first.", "error")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        error = validate_password(new_password)
        if error:
            flash(error, "error")
            return render_template("reset_password.html", username=user["username"])

        if new_password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("reset_password.html", username=user["username"])

        update_password(user["id"], new_password)
        session.pop("reset_user_id", None)
        log_activity(user, "password_reset", "Password reset via forgot-password")
        flash("Password updated successfully! You can now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("reset_password.html", username=user["username"])
