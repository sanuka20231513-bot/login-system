import re
from datetime import datetime

from .constants import PRIORITIES

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_name(value):
    if not value:
        return "Name is required."
    if len(value) > 100:
        return "Name must be 100 characters or fewer."
    return None


def validate_username(value):
    if not USERNAME_RE.match(value or ""):
        return "Username must be 3-30 characters: letters, numbers, dot, dash or underscore."
    return None


def validate_email(value, required=False):
    if not value:
        return "Email is required." if required else None
    if len(value) > 120 or not EMAIL_RE.match(value):
        return "Please enter a valid email address."
    return None


def validate_password(value):
    if not value or len(value) < 6:
        return "Password must be at least 6 characters."
    if len(value) > 128:
        return "Password must be 128 characters or fewer."
    return None


def parse_date(value):
    """'' -> (None, None); valid -> ('YYYY-MM-DD', None); invalid -> (None, error)."""
    if not value:
        return None, None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date().isoformat(), None
    except ValueError:
        return None, "Dates must use the format YYYY-MM-DD."


def to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def validate_task_form(form):
    """Returns (clean_dict, None) or (None, error_message)."""
    title = (form.get("title") or "").strip()
    description = (form.get("description") or "").strip()
    priority = (form.get("priority") or "Medium").strip()

    if not title:
        return None, "Title is required."
    if len(title) > 150:
        return None, "Title must be 150 characters or fewer."
    if len(description) > 2000:
        return None, "Description must be 2000 characters or fewer."
    if priority not in PRIORITIES:
        return None, "Invalid priority."

    due_date, error = parse_date((form.get("due_date") or "").strip())
    if error:
        return None, error

    return {
        "title": title,
        "description": description,
        "priority": priority,
        "due_date": due_date,
    }, None
