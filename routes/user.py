"""
Routes for any logged-in user, whatever their role: the generic /dashboard
redirect, own profile, change password, notifications.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash

from utils.constants import NOTIFICATIONS_PER_PAGE
from utils.db import (
    connect, update_profile, update_password, verify_password, log_activity,
    mark_all_read,
)
from utils.pagination import paginate
from utils.permissions import login_required, get_current_user, home_url_for
from utils.validators import validate_name, validate_email, validate_password, to_int

user_bp = Blueprint("user", __name__)


@user_bp.route("/dashboard")
@login_required
def dashboard():
    """Sends each person to the dashboard for their own role."""
    return redirect(home_url_for(get_current_user()))


@user_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = get_current_user()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()

        error = validate_name(name) or validate_email(email)
        if error:
            flash(error, "error")
            return render_template("profile.html", user=user)

        # Only name/email are ever read from this form. Role, status and
        # username are never parsed here, so there is no code path by which
        # a user could smuggle "role=admin" into effect.
        update_profile(user["id"], name, email)
        flash("Profile updated successfully.", "success")
        return redirect(url_for("user.profile"))

    return render_template("profile.html", user=user)


@user_bp.route("/profile/password", methods=["POST"])
@login_required
def change_password():
    user = get_current_user()
    current = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")

    if not verify_password(user, current):
        flash("Your current password is incorrect.", "error")
    elif validate_password(new_password):
        flash(validate_password(new_password), "error")
    elif new_password != confirm:
        flash("The new passwords do not match.", "error")
    else:
        update_password(user["id"], new_password)
        log_activity(user, "password_changed")
        flash("Password changed successfully.", "success")
    return redirect(url_for("user.profile"))


@user_bp.route("/notifications")
@login_required
def notifications():
    user = get_current_user()
    page = to_int(request.args.get("page")) or 1
    with connect() as conn:
        rows, pagination = paginate(
            conn,
            "SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC",
            "SELECT COUNT(*) FROM notifications WHERE user_id = ?",
            (user["id"],), page, NOTIFICATIONS_PER_PAGE,
        )
        items = [dict(r) for r in rows]
    return render_template("notifications.html", items=items, pagination=pagination)


@user_bp.route("/notifications/read", methods=["POST"])
@login_required
def notifications_read():
    mark_all_read(get_current_user()["id"])
    flash("All notifications marked as read.", "success")
    return redirect(url_for("user.notifications"))
