import sqlite3

from flask import Blueprint, render_template, request, redirect, url_for, flash

from utils.constants import (
    ROLES, USER_STATUSES, PRIORITIES, TASK_STATUSES,
    USERS_PER_PAGE, TASKS_PER_PAGE, LOGS_PER_PAGE,
)
from utils.db import (
    connect, group_counts, find_user_by_id, create_user, update_user_admin,
    change_user_role, set_status_guarded, delete_user, get_setting, set_setting,
    log_activity,
)
from utils.pagination import paginate
from utils.permissions import role_required, get_current_user
from utils.security import redirect_back
from utils.tasks import (
    list_tasks, get_task, update_task_admin, delete_task, task_counts,
    task_report, list_assignable_officers,
)
from utils.validators import (
    validate_name, validate_username, validate_email, validate_password,
    validate_task_form, parse_date, to_int,
)

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

# Sorting is whitelisted: the browser sends a key, we map it to a column.
USER_SORT_COLUMNS = {
    "name": "name",
    "username": "username",
    "role": "role",
    "status": "status",
    "created": "created_at",
}


def _page():
    return to_int(request.args.get("page")) or 1


# =====================================================================
# Dashboard
# =====================================================================

@admin_bp.route("/")
@role_required("admin")
def index():
    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/dashboard")
@role_required("admin")
def dashboard():
    user = get_current_user()
    with connect() as conn:
        users_by_status = group_counts(conn, "SELECT status, COUNT(*) FROM users GROUP BY status")
        users_by_role = group_counts(conn, "SELECT role, COUNT(*) FROM users GROUP BY role")
        recent_logs = [dict(r) for r in conn.execute(
            "SELECT * FROM activity_logs ORDER BY id DESC LIMIT 8").fetchall()]
    return render_template(
        "admin_dashboard.html",
        total_users=sum(users_by_status.values()),
        users_by_status=users_by_status,
        users_by_role=users_by_role,
        counts=task_counts(user),
        recent_logs=recent_logs,
    )


# =====================================================================
# User management: list / search / filter / sort / paginate
# =====================================================================

def _query_users():
    """Shared by User Management and Role Management."""
    search = request.args.get("search", "").strip()[:100]
    status = request.args.get("status", "").strip()
    role = request.args.get("role", "").strip()
    status = status if status in USER_STATUSES else ""
    role = role if role in ROLES else ""

    sort = request.args.get("sort", "created")
    if sort not in USER_SORT_COLUMNS:
        sort = "created"
    direction = "asc" if request.args.get("dir") == "asc" else "desc"

    conditions, params = [], []
    if search:
        conditions.append("(name LIKE ? OR username LIKE ?)")
        like = f"%{search}%"
        params += [like, like]
    if status:
        conditions.append("status = ?")
        params.append(status)
    if role:
        conditions.append("role = ?")
        params.append(role)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    order = f"ORDER BY {USER_SORT_COLUMNS[sort]} {direction.upper()}, id DESC"
    base_query = f"SELECT * FROM users {where} {order}"
    count_query = f"SELECT COUNT(*) FROM users {where}"

    with connect() as conn:
        rows, pagination = paginate(conn, base_query, count_query, tuple(params), _page(), USERS_PER_PAGE)
        users = [dict(r) for r in rows]

    # Column-header links keep every active filter and jump back to page 1.
    sort_links = {}
    for key in USER_SORT_COLUMNS:
        args = request.args.to_dict()
        args.update(sort=key, dir="desc" if (sort == key and direction == "asc") else "asc", page=1)
        sort_links[key] = {"url": url_for(request.endpoint, **args), "active": sort == key}

    return {
        "users": users, "pagination": pagination, "search": search, "status": status,
        "role": role, "sort": sort, "direction": direction, "sort_links": sort_links,
        "statuses": USER_STATUSES, "roles": ROLES,
    }


@admin_bp.route("/users")
@role_required("admin")
def users_list():
    return render_template("admin_panel.html", **_query_users())


@admin_bp.route("/roles")
@role_required("admin")
def roles():
    with connect() as conn:
        users_by_role = group_counts(conn, "SELECT role, COUNT(*) FROM users GROUP BY role")
    return render_template("admin_roles.html", users_by_role=users_by_role, **_query_users())


# =====================================================================
# User management: create / edit / role / status / delete
# =====================================================================

@admin_bp.route("/users/create", methods=["GET", "POST"])
@role_required("admin")
def new_user():
    values = {"name": "", "username": "", "email": "", "role": "officer", "status": "Approved"}
    if request.method == "POST":
        values.update({k: request.form.get(k, "").strip() for k in values})
        password = request.form.get("password", "")

        error = (validate_name(values["name"]) or validate_username(values["username"])
                 or validate_email(values["email"]) or validate_password(password))
        if not error and values["role"] not in ROLES:
            error = "Invalid role selected."
        if not error and values["status"] not in USER_STATUSES:
            error = "Invalid status selected."

        if not error:
            try:
                create_user(values["name"], values["username"], values["email"], password,
                            role=values["role"], status=values["status"])
            except sqlite3.IntegrityError:
                error = "That username is already taken."

        if error:
            flash(error, "error")
        else:
            log_activity(get_current_user(), "user_created",
                         f"{values['username']} created as {values['role']} ({values['status']})")
            flash(f"User '{values['username']}' created.", "success")
            return redirect(url_for("admin.users_list"))

    return render_template("create_user.html", values=values, roles=ROLES, statuses=USER_STATUSES)


@admin_bp.route("/users/edit/<int:user_id>", methods=["GET", "POST"])
@role_required("admin")
def edit_user(user_id):
    target = find_user_by_id(user_id)
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("admin.users_list"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        role = request.form.get("role", "").strip()
        new_password = request.form.get("new_password", "")

        error = validate_name(name) or validate_username(username) or validate_email(email)
        if not error and role not in ROLES:  # never trust the submitted role
            error = "Invalid role selected."
        if not error and new_password:
            error = validate_password(new_password)

        if error:
            flash(error, "error")
            return render_template("edit_user.html", user=target, roles=ROLES)

        ok, message = update_user_admin(user_id, name, username, email, role, new_password or None)
        flash(message, "success" if ok else "error")
        if not ok:
            return render_template("edit_user.html", user=target, roles=ROLES)

        actor = get_current_user()
        log_activity(actor, "user_updated", f"{username} (id {user_id})")
        if role != target["role"]:
            log_activity(actor, "role_changed", f"{username}: {target['role']} -> {role}")
        if new_password:
            log_activity(actor, "password_reset_by_admin", f"{username} (id {user_id})")
        return redirect(url_for("admin.users_list"))

    return render_template("edit_user.html", user=target, roles=ROLES)


@admin_bp.route("/users/role/<int:user_id>", methods=["POST"])
@role_required("admin")
def change_role(user_id):
    new_role = request.form.get("role", "").strip()
    target = find_user_by_id(user_id)
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("admin.roles"))

    ok, message = change_user_role(user_id, new_role)
    flash(message, "success" if ok else "error")
    if ok and new_role != target["role"]:
        log_activity(get_current_user(), "role_changed",
                     f"{target['username']}: {target['role']} -> {new_role}")
    return redirect_back("admin.roles")


def _status_action(user_id, new_status, action, past):
    target = find_user_by_id(user_id)
    ok, message = set_status_guarded(user_id, new_status)
    if ok and target:
        message = f"User '{target['username']}' {past}."
        log_activity(get_current_user(), f"user_{action}", f"{target['username']} (id {user_id})")
    flash(message, "success" if ok else "error")
    return redirect_back("admin.users_list")


@admin_bp.route("/users/approve/<int:user_id>", methods=["POST"])
@role_required("admin")
def approve_user(user_id):
    return _status_action(user_id, "Approved", "approved", "approved")


@admin_bp.route("/users/reject/<int:user_id>", methods=["POST"])
@role_required("admin")
def reject_user(user_id):
    return _status_action(user_id, "Rejected", "rejected", "rejected")


@admin_bp.route("/users/disable/<int:user_id>", methods=["POST"])
@role_required("admin")
def disable_user(user_id):
    return _status_action(user_id, "Disabled", "disabled", "disabled")


@admin_bp.route("/users/enable/<int:user_id>", methods=["POST"])
@role_required("admin")
def enable_user(user_id):
    return _status_action(user_id, "Approved", "enabled", "enabled")


@admin_bp.route("/users/delete/<int:user_id>", methods=["POST"])
@role_required("admin")
def remove_user(user_id):
    target = find_user_by_id(user_id)
    ok, message = delete_user(user_id)
    if ok and target:
        log_activity(get_current_user(), "user_deleted", f"{target['username']} (id {user_id})")
    flash(message, "success" if ok else "error")
    return redirect_back("admin.users_list")


# =====================================================================
# Task management (all tasks, system-wide)
# =====================================================================

@admin_bp.route("/tasks")
@role_required("admin")
def tasks_list():
    tasks, pagination, filters = list_tasks(get_current_user(), request.args, _page(), TASKS_PER_PAGE)
    return render_template(
        "tasks_list.html", page_title="Task Management", mode="admin",
        intro="Every task in the system, created by any manager.",
        tasks=tasks, pagination=pagination, filters=filters,
        officers=list_assignable_officers(), show_status_filter=True,
    )


@admin_bp.route("/tasks/edit/<int:task_id>", methods=["GET", "POST"])
@role_required("admin")
def edit_task(task_id):
    task = get_task(task_id)
    if not task:
        flash("Task not found.", "error")
        return redirect(url_for("admin.tasks_list"))

    values = dict(task)
    if request.method == "POST":
        data, error = validate_task_form(request.form)
        status = request.form.get("status", "").strip()
        raw_assignee = request.form.get("assigned_to", "").strip()
        assigned_to = to_int(raw_assignee) if raw_assignee else None
        if not error and status not in TASK_STATUSES:
            error = "Invalid status."
        if not error and raw_assignee and assigned_to is None:
            error = "Invalid officer."

        if not error:
            ok, message = update_task_admin(task_id, data, assigned_to, status)
            if ok:
                log_activity(get_current_user(), "task_updated", f"task {task_id}: {data['title']}")
                flash(message, "success")
                return redirect(url_for("admin.tasks_list"))
            error = message

        flash(error, "error")
        values.update(request.form.to_dict())

    return render_template(
        "task_form.html", heading="Edit Task (Admin)", values=values,
        priorities=PRIORITIES, officers=list_assignable_officers(),
        show_assignee=True, show_status=True, statuses=TASK_STATUSES,
        cancel_url=url_for("admin.tasks_list"),
    )


@admin_bp.route("/tasks/delete/<int:task_id>", methods=["POST"])
@role_required("admin")
def remove_task(task_id):
    task = get_task(task_id)
    ok, message = delete_task(task_id)
    if ok and task:
        log_activity(get_current_user(), "task_deleted", f"task {task_id}: {task['title']}")
    flash(message, "success" if ok else "error")
    return redirect_back("admin.tasks_list")


# Activity logs
# =====================================================================

@admin_bp.route("/logs")
@role_required("admin")
def logs():
    search = request.args.get("search", "").strip()[:100]
    action = request.args.get("action", "").strip()[:50]
    date_from, err_from = parse_date(request.args.get("date_from", "").strip())
    date_to, err_to = parse_date(request.args.get("date_to", "").strip())
    date_from = None if err_from else date_from
    date_to = None if err_to else date_to

    conditions, params = [], []
    if search:
        conditions.append("(actor_name LIKE ? OR details LIKE ? OR action LIKE ?)")
        like = f"%{search}%"
        params += [like, like, like]
    if action:
        conditions.append("action = ?")
        params.append(action)
    if date_from:
        conditions.append("date(created_at) >= ?")
        params.append(date_from)
    if date_to:
        conditions.append("date(created_at) <= ?")
        params.append(date_to)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    with connect() as conn:
        rows, pagination = paginate(
            conn, f"SELECT * FROM activity_logs {where} ORDER BY id DESC",
            f"SELECT COUNT(*) FROM activity_logs {where}", tuple(params), _page(), LOGS_PER_PAGE,
        )
        entries = [dict(r) for r in rows]
        actions = [r[0] for r in conn.execute(
            "SELECT DISTINCT action FROM activity_logs ORDER BY action").fetchall()]

    return render_template(
        "admin_logs.html", entries=entries, pagination=pagination, actions=actions,
        search=search, action=action, date_from=date_from or "", date_to=date_to or "",
    )


# =====================================================================
# Settings
# =====================================================================

@admin_bp.route("/settings", methods=["GET", "POST"])
@role_required("admin")
def settings():
    if request.method == "POST":
        enabled = "1" if request.form.get("manager_can_manage_officers") == "on" else "0"
        set_setting("manager_can_manage_officers", enabled)
        log_activity(get_current_user(), "settings_updated",
                     f"manager_can_manage_officers = {enabled}")
        flash("Settings saved.", "success")
        return redirect(url_for("admin.settings"))

    return render_template(
        "admin_settings.html",
        manager_can_manage_officers=get_setting("manager_can_manage_officers") == "1",
    )


# =====================================================================
# Reports
# =====================================================================

@admin_bp.route("/reports")
@role_required("admin")
def reports():
    user = get_current_user()
    with connect() as conn:
        users_by_status = group_counts(conn, "SELECT status, COUNT(*) FROM users GROUP BY status")
        users_by_role = group_counts(conn, "SELECT role, COUNT(*) FROM users GROUP BY role")
    return render_template(
        "reports.html", title="System Reports",
        scope_note="System-wide figures across all managers, officers and tasks.",
        counts=task_counts(user), report=task_report(user),
        user_stats={"by_status": users_by_status, "by_role": users_by_role},
        statuses=TASK_STATUSES, user_statuses=USER_STATUSES, roles=ROLES,
    )
