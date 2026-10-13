from functools import wraps

from flask import abort, flash, g, redirect, request, session, url_for

from .constants import ROLES
from .db import find_user_by_id, get_setting, log_activity

ROLE_HOME = {
    "admin": "admin.dashboard",
    "manager": "manager.dashboard",
    "officer": "officer.dashboard",
}

_UNSET = object()


def get_current_user():
    cached = g.get("_current_user", _UNSET)
    if cached is not _UNSET:
        return cached

    user = None
    user_id = session.get("user_id")
    if user_id is not None:
        found = find_user_by_id(user_id)
        # A disabled/rejected/deleted account, or an unknown role, loses
        # access immediately and the session is wiped.
        if found and found["status"] == "Approved" and found["role"] in ROLES:
            user = found
        else:
            session.clear()
    g._current_user = user
    return user


def reset_current_user_cache():
    g.pop("_current_user", None)


def home_url_for(user):
    return url_for(ROLE_HOME[user["role"]])


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if get_current_user() is None:
            flash("Please log in to continue.", "error")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped_view


def role_required(*allowed_roles):
    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            user = get_current_user()
            if user is None:
                flash("Please log in to continue.", "error")
                return redirect(url_for("auth.login"))
            if user["role"] not in allowed_roles:
                log_activity(user, "access_denied", f"{request.method} {request.path}")
                abort(403)
            return view(*args, **kwargs)
        return wrapped_view
    return decorator


# ---------------------------------------------------------------------
# Record-level rules for tasks
# ---------------------------------------------------------------------

def can_view_task(user, task):
    if user["role"] == "admin":
        return True
    if user["role"] == "manager":
        return task["created_by"] == user["id"]
    if user["role"] == "officer":
        return task["assigned_to"] == user["id"]
    return False


def can_manage_task(user, task):
    """Edit / review: an admin, or the manager who created the task."""
    if user["role"] == "admin":
        return True
    return user["role"] == "manager" and task["created_by"] == user["id"]


def is_task_assignee(user, task):
    return user["role"] == "officer" and task["assigned_to"] == user["id"]


# ---------------------------------------------------------------------
# Configurable policy
# ---------------------------------------------------------------------

def manager_can_manage_officers():
    """Admin > Settings switch. Off by default (safe default)."""
    return get_setting("manager_can_manage_officers") == "1"
