"""
Authentication / authorization helpers.
========================================
get_current_user() re-reads the user from the database on every single
request instead of trusting the session blindly. That's what makes an
admin's changes (disabling someone, changing a role) take effect on that
user's very next request - not just the next time they happen to log in.
"""

from functools import wraps
from flask import session, redirect, url_for, flash, abort

from .db import find_user_by_id


def get_current_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None

    user = find_user_by_id(user_id)
    if user is None:
        session.clear()
        return None

    if user["status"] != "Approved":
        # Covers: admin disabled/rejected this account while they were
        # still logged in - the session is invalidated immediately.
        session.clear()
        return None

    return user


def login_required(view):
    """Require any logged-in, Approved user."""
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if get_current_user() is None:
            flash("Please log in to continue.", "error")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped_view


def role_required(*allowed_roles):
    """Require a logged-in, Approved user whose role is one of
    allowed_roles. Usage:

        @role_required("admin")
        @role_required("admin", "manager")
    """
    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            user = get_current_user()
            if user is None:
                flash("Please log in to continue.", "error")
                return redirect(url_for("auth.login"))
            if user["role"] not in allowed_roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped_view
    return decorator
