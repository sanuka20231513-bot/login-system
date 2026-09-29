"""
Routes for any logged-in user (dashboard, own profile).
No role check here beyond @login_required - both "user" and "admin"
roles can reach these pages.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash

from utils.auth import login_required, get_current_user
from utils.db import update_profile

user_bp = Blueprint("user", __name__)


@user_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=get_current_user())


@user_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = get_current_user()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()

        if not name:
            flash("Name cannot be empty.", "error")
            return render_template("profile.html", user=user)

        # Only name/email are ever read from this form. Username, role
        # and status are never parsed here, so there is no code path by
        # which a user could smuggle a "role=admin" field into effect.
        update_profile(user["id"], name, email)
        flash("Profile updated successfully.", "success")
        return redirect(url_for("user.profile"))

    return render_template("profile.html", user=user)
