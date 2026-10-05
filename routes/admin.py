from flask import Blueprint, render_template, request, redirect, url_for, flash

from utils.auth import role_required
from utils.db import (
    get_db, find_user_by_id, update_user_admin, set_status_guarded,
    delete_user, USERS_PER_PAGE,
)
from utils.pagination import paginate

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/")
@role_required("admin")
def dashboard():
    conn = get_db()
    counts = {
        "total": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "pending": conn.execute("SELECT COUNT(*) FROM users WHERE status='Pending'").fetchone()[0],
        "approved": conn.execute("SELECT COUNT(*) FROM users WHERE status='Approved'").fetchone()[0],
        "rejected": conn.execute("SELECT COUNT(*) FROM users WHERE status='Rejected'").fetchone()[0],
        "disabled": conn.execute("SELECT COUNT(*) FROM users WHERE status='Disabled'").fetchone()[0],
        "admins": conn.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0],
    }
    conn.close()
    return render_template("admin_dashboard.html", counts=counts)


@admin_bp.route("/users")
@role_required("admin")
def users_list():
    search = request.args.get("search", "").strip()
    status = request.args.get("status", "").strip()
    role = request.args.get("role", "").strip()
    try:
        page = int(request.args.get("page", 1))
    except ValueError:
        page = 1

    conditions = []
    params = []
    if search:
        conditions.append("(name LIKE ? OR username LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like])
    if status:
        conditions.append("status = ?")
        params.append(status)
    if role:
        conditions.append("role = ?")
        params.append(role)

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    base_query = f"SELECT * FROM users {where_clause} ORDER BY id DESC"
    count_query = f"SELECT COUNT(*) FROM users {where_clause}"

    conn = get_db()
    rows, pagination = paginate(conn, base_query, count_query, tuple(params), page, USERS_PER_PAGE)
    users = [dict(r) for r in rows]
    conn.close()

    return render_template(
        "admin_panel.html",
        users=users,
        pagination=pagination,
        search=search,
        status=status,
        role=role,
    )


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
        role = request.form.get("role", "user").strip()

        if not name or not username:
            flash("Name and username cannot be empty.", "error")
            return render_template("edit_user.html", user=target)

        # Never trust the role value blindly - it must be one of the
        # roles this system actually knows about.
        if role not in ("user", "admin"):
            flash("Invalid role selected.", "error")
            return render_template("edit_user.html", user=target)

        ok, message = update_user_admin(user_id, name, username, email, role)
        flash(message, "success" if ok else "error")
        if ok:
            return redirect(url_for("admin.users_list"))
        return render_template("edit_user.html", user=target)

    return render_template("edit_user.html", user=target)


def _change_status(user_id, new_status):
    ok, message = set_status_guarded(user_id, new_status)
    flash(message, "success" if ok else "error")
    return redirect(request.referrer or url_for("admin.users_list"))


@admin_bp.route("/users/approve/<int:user_id>", methods=["POST"])
@role_required("admin")
def approve_user(user_id):
    return _change_status(user_id, "Approved")


@admin_bp.route("/users/reject/<int:user_id>", methods=["POST"])
@role_required("admin")
def reject_user(user_id):
    return _change_status(user_id, "Rejected")


@admin_bp.route("/users/disable/<int:user_id>", methods=["POST"])
@role_required("admin")
def disable_user(user_id):
    return _change_status(user_id, "Disabled")


@admin_bp.route("/users/enable/<int:user_id>", methods=["POST"])
@role_required("admin")
def enable_user(user_id):
    return _change_status(user_id, "Approved")


@admin_bp.route("/users/delete/<int:user_id>", methods=["POST"])
@role_required("admin")
def remove_user(user_id):
    ok, message = delete_user(user_id)
    flash(message, "success" if ok else "error")
    return redirect(request.referrer or url_for("admin.users_list"))
