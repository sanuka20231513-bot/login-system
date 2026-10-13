from flask import url_for

from .constants import TASK_STATUSES, PRIORITIES
from .db import connect, create_notification
from .pagination import paginate
from .validators import parse_date

TASK_SELECT = """
SELECT t.*,
       a.name AS assignee_name, a.username AS assignee_username,
       c.name AS creator_name,
       CASE WHEN t.due_date IS NOT NULL AND t.due_date < date('now')
                 AND t.status != 'Approved' THEN 1 ELSE 0 END AS overdue
FROM tasks t
LEFT JOIN users a ON a.id = t.assigned_to
LEFT JOIN users c ON c.id = t.created_by
"""

OPEN_STATUSES = ("Pending", "In Progress", "Rejected")  # officer can still work on these


def _task_link(task_id):
    return url_for("tasks.task_details", task_id=task_id)


# =====================================================================
# Scope - which tasks a role is allowed to see at all
# =====================================================================

def scope_clause(user, alias="t"):
    role = user["role"]
    if role == "admin":
        return "1 = 1", []
    if role == "manager":
        return f"{alias}.created_by = ?", [user["id"]]
    if role == "officer":
        return f"{alias}.assigned_to = ?", [user["id"]]
    return "1 = 0", []


# =====================================================================
# Reading
# =====================================================================

def get_task(task_id):
    with connect() as conn:
        row = conn.execute(TASK_SELECT + " WHERE t.id = ?", (task_id,)).fetchone()
        return dict(row) if row else None


def list_assignable_officers():
    with connect() as conn:
        rows = conn.execute(
            "SELECT id, name, username FROM users "
            "WHERE role = 'officer' AND status = 'Approved' ORDER BY name"
        ).fetchall()
        return [dict(r) for r in rows]


def clean_task_filters(args):
    """Turn raw query-string values into safe, validated filter values."""
    status = (args.get("status") or "").strip()
    if status not in TASK_STATUSES:
        status = ""
    priority = (args.get("priority") or "").strip()
    if priority not in PRIORITIES:
        priority = ""
    assigned = (args.get("assigned") or "").strip()
    if assigned != "unassigned" and not assigned.isdigit():
        assigned = ""
    date_from, err_from = parse_date((args.get("date_from") or "").strip())
    date_to, err_to = parse_date((args.get("date_to") or "").strip())
    return {
        "search": (args.get("search") or "").strip()[:100],
        "status": status,
        "priority": priority,
        "assigned": assigned,
        "date_from": "" if err_from else (date_from or ""),
        "date_to": "" if err_to else (date_to or ""),
    }


def list_tasks(user, args, page, per_page, fixed_status=None, extra_condition=None):
    """One page of tasks the user is allowed to see, with filters.
    Pagination happens in SQL (LIMIT/OFFSET), never in Python.

    fixed_status    tuple of statuses that this page is limited to
    extra_condition a constant SQL snippet (no user input) such as
                    "t.feedback IS NOT NULL"
    Returns (tasks, pagination_info, filters)."""
    filters = clean_task_filters(args)

    scope_sql, params = scope_clause(user)
    conditions = [scope_sql]

    if fixed_status:
        conditions.append("t.status IN (%s)" % ", ".join("?" for _ in fixed_status))
        params += list(fixed_status)
    elif filters["status"]:
        conditions.append("t.status = ?")
        params.append(filters["status"])

    if extra_condition:
        conditions.append(extra_condition)
    if filters["priority"]:
        conditions.append("t.priority = ?")
        params.append(filters["priority"])
    if filters["assigned"] == "unassigned":
        conditions.append("t.assigned_to IS NULL")
    elif filters["assigned"]:
        conditions.append("t.assigned_to = ?")
        params.append(int(filters["assigned"]))
    if filters["search"]:
        conditions.append("(t.title LIKE ? OR t.description LIKE ?)")
        like = f"%{filters['search']}%"
        params += [like, like]
    if filters["date_from"]:
        conditions.append("t.due_date >= ?")
        params.append(filters["date_from"])
    if filters["date_to"]:
        conditions.append("t.due_date <= ?")
        params.append(filters["date_to"])

    where = " AND ".join(conditions)
    base_query = f"{TASK_SELECT} WHERE {where} ORDER BY t.updated_at DESC, t.id DESC"
    count_query = f"SELECT COUNT(*) FROM tasks t WHERE {where}"

    with connect() as conn:
        rows, pagination = paginate(conn, base_query, count_query, tuple(params), page, per_page)
        return [dict(r) for r in rows], pagination, filters


def recent_tasks(user, statuses=None, limit=5):
    scope_sql, params = scope_clause(user)
    conditions = [scope_sql]
    if statuses:
        conditions.append("t.status IN (%s)" % ", ".join("?" for _ in statuses))
        params += list(statuses)
    sql = f"{TASK_SELECT} WHERE {' AND '.join(conditions)} ORDER BY t.updated_at DESC, t.id DESC LIMIT ?"
    with connect() as conn:
        return [dict(r) for r in conn.execute(sql, tuple(params) + (limit,)).fetchall()]


def task_counts(user):
    scope_sql, params = scope_clause(user)
    with connect() as conn:
        by_status = {s: 0 for s in TASK_STATUSES}
        for row in conn.execute(
            f"SELECT status, COUNT(*) FROM tasks t WHERE {scope_sql} GROUP BY status", params
        ):
            by_status[row[0]] = row[1]
        overdue = conn.execute(
            f"SELECT COUNT(*) FROM tasks t WHERE {scope_sql} AND t.due_date IS NOT NULL "
            "AND t.due_date < date('now') AND t.status != 'Approved'", params
        ).fetchone()[0]
        unassigned = conn.execute(
            f"SELECT COUNT(*) FROM tasks t WHERE {scope_sql} AND t.assigned_to IS NULL", params
        ).fetchone()[0]
    return {
        "total": sum(by_status.values()),
        "by_status": by_status,
        "overdue": overdue,
        "unassigned": unassigned,
    }


def task_report(user):
    scope_sql, params = scope_clause(user)
    with connect() as conn:
        by_priority = {p: 0 for p in PRIORITIES}
        for row in conn.execute(
            f"SELECT priority, COUNT(*) FROM tasks t WHERE {scope_sql} GROUP BY priority", params
        ):
            by_priority[row[0]] = row[1]

        per_officer = [dict(r) for r in conn.execute(
            f"""
            SELECT u.id, u.name, u.username,
                   COUNT(t.id) AS total,
                   SUM(CASE WHEN t.status = 'Pending'     THEN 1 ELSE 0 END) AS pending,
                   SUM(CASE WHEN t.status = 'In Progress' THEN 1 ELSE 0 END) AS in_progress,
                   SUM(CASE WHEN t.status = 'Submitted'   THEN 1 ELSE 0 END) AS submitted,
                   SUM(CASE WHEN t.status = 'Approved'    THEN 1 ELSE 0 END) AS approved,
                   SUM(CASE WHEN t.status = 'Rejected'    THEN 1 ELSE 0 END) AS rejected,
                   SUM(CASE WHEN t.due_date IS NOT NULL AND t.due_date < date('now')
                                 AND t.status != 'Approved' THEN 1 ELSE 0 END) AS overdue
            FROM tasks t JOIN users u ON u.id = t.assigned_to
            WHERE {scope_sql}
            GROUP BY u.id ORDER BY total DESC, u.name
            """, params
        ).fetchall()]
    return {"by_priority": by_priority, "per_officer": per_officer}


# =====================================================================
# Writing - Manager / Admin side
# =====================================================================

def _valid_officer(conn, officer_id):
    return conn.execute(
        "SELECT id, name FROM users WHERE id = ? AND role = 'officer' AND status = 'Approved'",
        (officer_id,),
    ).fetchone()


def create_task(creator, data, assigned_to=None):
    """Returns (task_id, message); task_id is None on failure."""
    with connect() as conn:
        if assigned_to is not None and not _valid_officer(conn, assigned_to):
            return None, "The selected officer is not available."
        cur = conn.execute(
            "INSERT INTO tasks (title, description, assigned_to, created_by, priority, due_date) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (data["title"], data["description"], assigned_to, creator["id"],
             data["priority"], data["due_date"]),
        )
        task_id = cur.lastrowid
        if assigned_to is not None:
            create_notification(assigned_to, f"New task assigned to you: {data['title']}",
                                _task_link(task_id), conn=conn)
    return task_id, "Task created."


def update_task_manager(manager_id, task_id, data):
    """A manager can edit only tasks they created, and not once approved."""
    with connect() as conn:
        cur = conn.execute(
            "UPDATE tasks SET title = ?, description = ?, priority = ?, due_date = ?, "
            "updated_at = datetime('now') "
            "WHERE id = ? AND created_by = ? AND status != 'Approved'",
            (data["title"], data["description"], data["priority"], data["due_date"],
             task_id, manager_id),
        )
        if cur.rowcount == 0:
            return False, "You cannot edit this task (not yours, or already approved)."
    return True, "Task updated."


def update_task_admin(task_id, data, assigned_to, status):
    if status not in TASK_STATUSES:
        return False, "Invalid status."
    with connect() as conn:
        current = conn.execute("SELECT assigned_to FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not current:
            return False, "Task not found."
        # Keeping the existing assignee is always fine; a *new* one must be
        # an approved officer.
        if (assigned_to is not None and assigned_to != current["assigned_to"]
                and not _valid_officer(conn, assigned_to)):
            return False, "The selected officer is not available."
        conn.execute(
            "UPDATE tasks SET title = ?, description = ?, priority = ?, due_date = ?, "
            "assigned_to = ?, status = ?, updated_at = datetime('now') WHERE id = ?",
            (data["title"], data["description"], data["priority"], data["due_date"],
             assigned_to, status, task_id),
        )
        if assigned_to is not None and assigned_to != current["assigned_to"]:
            create_notification(assigned_to, f"A task was assigned to you: {data['title']}",
                                _task_link(task_id), conn=conn)
    return True, "Task updated."


def assign_task(manager_id, task_id, officer_id):
    """A manager can (re)assign their own task only while it is still
    Pending - once work has started, ownership of the work stays put."""
    with connect() as conn:
        if not _valid_officer(conn, officer_id):
            return False, "The selected officer is not available."
        task = conn.execute("SELECT title FROM tasks WHERE id = ?", (task_id,)).fetchone()
        cur = conn.execute(
            "UPDATE tasks SET assigned_to = ?, updated_at = datetime('now') "
            "WHERE id = ? AND created_by = ? AND status = 'Pending'",
            (officer_id, task_id, manager_id),
        )
        if cur.rowcount == 0:
            return False, "This task can no longer be assigned (not yours, or work already started)."
        create_notification(officer_id, f"New task assigned to you: {task['title']}",
                            _task_link(task_id), conn=conn)
    return True, "Task assigned."


def review_task(reviewer, task_id, decision, feedback):
    """Approve or reject submitted work.
    * a manager can only review tasks they created
    * nobody can review a task assigned to themselves
    * only tasks in 'Submitted' state can be reviewed"""
    if decision not in ("approve", "reject"):
        return False, "Invalid decision."
    feedback = (feedback or "").strip()
    if decision == "reject" and not feedback:
        return False, "Please give feedback explaining what needs to be corrected."
    if len(feedback) > 1000:
        return False, "Feedback must be 1000 characters or fewer."

    new_status = "Approved" if decision == "approve" else "Rejected"
    with connect() as conn:
        task = conn.execute(
            "SELECT title, assigned_to, created_by FROM tasks WHERE id = ?", (task_id,)
        ).fetchone()
        if not task:
            return False, "Task not found."

        sql = ("UPDATE tasks SET status = ?, feedback = ?, reviewed_by = ?, "
               "reviewed_at = datetime('now'), updated_at = datetime('now') "
               "WHERE id = ? AND status = 'Submitted' "
               "AND (assigned_to IS NULL OR assigned_to != ?)")
        args = [new_status, feedback or None, reviewer["id"], task_id, reviewer["id"]]
        if reviewer["role"] != "admin":
            sql += " AND created_by = ?"
            args.append(reviewer["id"])

        cur = conn.execute(sql, args)
        if cur.rowcount == 0:
            return False, "This task cannot be reviewed (not submitted, or not yours to review)."

        if task["assigned_to"]:
            word = "approved" if decision == "approve" else "returned for corrections"
            create_notification(task["assigned_to"], f"Your work was {word}: {task['title']}",
                                _task_link(task_id), conn=conn)
    return True, f"Work {new_status.lower()}."


def delete_task(task_id):
    with connect() as conn:
        cur = conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        if cur.rowcount == 0:
            return False, "Task not found."
    return True, "Task deleted."


# =====================================================================
# Writing - Officer side
# =====================================================================

def officer_update_progress(officer_id, task_id, progress, note):
    with connect() as conn:
        cur = conn.execute(
            "UPDATE tasks SET status = 'In Progress', progress = ?, progress_note = ?, "
            "updated_at = datetime('now') "
            "WHERE id = ? AND assigned_to = ? AND status IN ('Pending', 'In Progress', 'Rejected')",
            (progress, note or None, task_id, officer_id),
        )
        if cur.rowcount == 0:
            return False, "You cannot update this task."
    return True, "Progress saved."


def officer_submit(officer, task_id, note):
    with connect() as conn:
        task = conn.execute(
            "SELECT title, created_by FROM tasks WHERE id = ? AND assigned_to = ?",
            (task_id, officer["id"]),
        ).fetchone()
        cur = conn.execute(
            "UPDATE tasks SET status = 'Submitted', progress = 100, submission_note = ?, "
            "submitted_at = datetime('now'), updated_at = datetime('now') "
            "WHERE id = ? AND assigned_to = ? AND status IN ('In Progress', 'Rejected')",
            (note or None, task_id, officer["id"]),
        )
        if cur.rowcount == 0:
            return False, "You cannot submit this task (start it first, or it was already submitted)."
        create_notification(task["created_by"],
                            f"{officer['name']} submitted work for review: {task['title']}",
                            _task_link(task_id), conn=conn)
    return True, "Work submitted for review."
