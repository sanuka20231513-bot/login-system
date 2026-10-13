import os
import re
import sqlite3
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

_TMP = tempfile.mkdtemp(prefix="login_system_tests_")
os.environ["LOGIN_SYSTEM_DB"] = os.path.join(_TMP, "boot.db")
os.environ["SECRET_KEY"] = "test-secret-key"

from werkzeug.security import generate_password_hash as _real_hash  # noqa: E402

from app import app  # noqa: E402
from utils import db  # noqa: E402
from utils.pagination import paginate  # noqa: E402

PASSWORD = "secret1"


def generate_password_hash(password):
    """Real hashing, just with few iterations so the suite runs quickly."""
    return _real_hash(password, method="pbkdf2:sha256:1000")


db.generate_password_hash = generate_password_hash


def _token(client):
    with client.session_transaction() as sess:
        sess.setdefault("_csrf_token", "test-token")
        return sess["_csrf_token"]


def post(client, url, data=None, **kwargs):
    data = dict(data or {})
    data["csrf_token"] = _token(client)
    return client.post(url, data=data, **kwargs)


class Base(unittest.TestCase):
    def setUp(self):
        db.DB_FILE = os.path.join(_TMP, re.sub(r"\W", "_", self.id()) + ".db")
        db.LEGACY_USERS_FILE = os.path.join(_TMP, "no_legacy_users.txt")  # never import the real users.txt
        if os.path.exists(db.DB_FILE):
            os.remove(db.DB_FILE)
        db.init_db()
        app.config["TESTING"] = True
        # init_db() seeds one admin; use it as our known administrator "boss".
        with db.connect() as conn:
            conn.execute("UPDATE users SET username = 'boss', name = 'Boss', email = 'boss@example.com', "
                         "password = ? WHERE username = 'admin'", (generate_password_hash(PASSWORD),))
        self.admin = self.uid("boss")

    # ---- helpers --------------------------------------------------------
    def make_user(self, username, role, status="Approved", email=None, name=None):
        db.create_user(name or username.title(), username, email if email is not None else f"{username}@example.com",
                       PASSWORD, role=role, status=status)
        return db.find_user_by_username(username)["id"]

    def login(self, username, password=PASSWORD):
        client = app.test_client()
        response = post(client, "/", {"username": username, "password": password})
        return client, response

    def client_for(self, username):
        client, _ = self.login(username)
        return client

    def uid(self, username):
        return db.find_user_by_username(username)["id"]

    def role_of(self, username):
        return db.find_user_by_username(username)["role"]

    def status_of(self, username):
        return db.find_user_by_username(username)["status"]

    def insert_task(self, created_by, assigned_to=None, title="Task", priority="Medium",
                    status="Pending", due=None):
        with db.connect() as conn:
            cur = conn.execute(
                "INSERT INTO tasks (title, assigned_to, created_by, priority, status, due_date) "
                "VALUES (?, ?, ?, ?, ?, ?)", (title, assigned_to, created_by, priority, status, due))
            return cur.lastrowid

    def task(self, task_id):
        with db.connect() as conn:
            return dict(conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone())

    def new_task_via_form(self, client, officer_id, title="Write report", **extra):
        data = {"title": title, "description": "details", "priority": "High",
                "due_date": "2030-01-31", "assigned_to": str(officer_id) if officer_id else ""}
        data.update(extra)
        post(client, "/manager/tasks/new", data)
        with db.connect() as conn:
            row = conn.execute("SELECT id FROM tasks WHERE title = ? ORDER BY id DESC", (title,)).fetchone()
        return row["id"] if row else None


# =====================================================================
# Authentication and redirection
# =====================================================================

class AuthenticationTests(Base):
    def test_login_redirects_each_role_to_its_own_dashboard(self):
        self.make_user("mary", "manager")
        self.make_user("oscar", "officer")
        for username, target in (("boss", "/admin/dashboard"), ("mary", "/manager/dashboard"),
                                 ("oscar", "/officer/dashboard")):
            _, response = self.login(username)
            self.assertEqual(response.status_code, 302)
            self.assertTrue(response.headers["Location"].endswith(target), username)

    def test_generic_dashboard_url_redirects_by_role(self):
        self.make_user("oscar", "officer")
        client = self.client_for("oscar")
        self.assertTrue(client.get("/dashboard").headers["Location"].endswith("/officer/dashboard"))

    def test_wrong_password_is_rejected(self):
        _, response = self.login("boss", "not-the-password")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Incorrect username or password", response.data)

    def test_pending_rejected_and_disabled_accounts_cannot_log_in(self):
        expectations = {
            "Pending": b"waiting for administrator approval",
            "Rejected": b"rejected",
            "Disabled": b"disabled",
        }
        for status, message in expectations.items():
            name = f"user_{status.lower()}"
            self.make_user(name, "officer", status=status)
            client, response = self.login(name)
            self.assertEqual(response.status_code, 200, status)
            self.assertIn(message, response.data, status)
            self.assertEqual(client.get("/officer/dashboard").status_code, 302, status)  # still logged out

    def test_logged_out_visitor_is_sent_to_login_for_every_protected_page(self):
        client = app.test_client()
        for url in ("/dashboard", "/profile", "/notifications", "/admin/dashboard", "/admin/users",
                    "/manager/dashboard", "/manager/tasks", "/officer/dashboard", "/officer/tasks",
                    "/tasks/1"):
            response = client.get(url)
            self.assertEqual(response.status_code, 302, url)
            self.assertIn("/", response.headers["Location"], url)
            self.assertNotIn("/admin", response.headers["Location"], url)

    def test_post_without_csrf_token_is_rejected(self):
        client = app.test_client()
        response = client.post("/", data={"username": "boss", "password": PASSWORD})
        self.assertEqual(response.status_code, 400)

    def test_post_with_wrong_csrf_token_is_rejected(self):
        client = app.test_client()
        _token(client)
        response = client.post("/", data={"username": "boss", "password": PASSWORD, "csrf_token": "forged"})
        self.assertEqual(response.status_code, 400)

    def test_csrf_failure_shows_a_friendly_page_without_details(self):
        response = app.test_client().post("/", data={"username": "boss", "password": PASSWORD})
        self.assertIn(b"Invalid or Expired Form", response.data)
        self.assertNotIn(b"Traceback", response.data)

    def test_security_headers_are_sent_and_private_pages_are_not_cached(self):
        client = self.client_for("boss")
        response = client.get("/admin/dashboard")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        cookie = [h for h in client.get("/").headers.getlist("Set-Cookie")] or                  [h for h in self.login("boss")[1].headers.getlist("Set-Cookie")]
        self.assertTrue(any("HttpOnly" in c and "SameSite=Lax" in c for c in cookie), cookie)

    def test_old_admin_url_still_works_and_is_protected(self):
        self.assertEqual(self.client_for("boss").get("/admin", follow_redirects=True).status_code, 200)
        self.make_user("oscar", "officer")
        self.assertEqual(self.client_for("oscar").get("/admin", follow_redirects=True).status_code, 403)
        self.assertEqual(app.test_client().get("/admin", follow_redirects=True).status_code, 200)  # login page

    def test_unknown_pages_show_a_404_page(self):
        response = self.client_for("boss").get("/no/such/page")
        self.assertEqual(response.status_code, 404)
        self.assertIn(b"Page Not Found", response.data)

    def test_failed_logins_are_logged_without_the_password(self):
        self.login("boss", "totally-wrong-password")
        with db.connect() as conn:
            rows = [dict(r) for r in conn.execute("SELECT * FROM activity_logs WHERE action = 'login_failed'")]
        self.assertEqual(len(rows), 1)
        self.assertNotIn("totally-wrong-password", str(rows))

    def test_registration_always_creates_a_pending_officer(self):
        client = app.test_client()
        post(client, "/register", {
            "name": "Sneaky", "username": "sneaky", "email": "s@example.com",
            "password": PASSWORD, "confirm_password": PASSWORD,
            "role": "admin", "status": "Approved",  # attempted privilege escalation
        })
        self.assertEqual(self.role_of("sneaky"), "officer")
        self.assertEqual(self.status_of("sneaky"), "Pending")

    def test_registration_validates_input(self):
        client = app.test_client()
        bad = [
            {"username": "ab"},                      # too short
            {"username": "has space"},               # bad characters
            {"email": "not-an-email"},
            {"password": "123", "confirm_password": "123"},
        ]
        for override in bad:
            data = {"name": "N", "username": "valid_name", "email": "n@example.com",
                    "password": PASSWORD, "confirm_password": PASSWORD}
            data.update(override)
            post(client, "/register", data)
            self.assertIsNone(db.find_user_by_username(data["username"]) if "username" not in override
                              else db.find_user_by_username(override["username"]), override)

    def test_passwords_are_stored_hashed(self):
        stored = db.find_user_by_username("boss")["password"]
        self.assertTrue(stored.startswith(("scrypt:", "pbkdf2:")))
        self.assertNotIn(PASSWORD, stored)

    def test_forgot_password_needs_username_and_matching_email(self):
        self.make_user("oscar", "officer", email="oscar@example.com")
        self.make_user("noemail", "officer", email="")
        client = app.test_client()

        post(client, "/forgot-password", {"username": "oscar", "email": "wrong@example.com"})
        self.assertEqual(client.get("/reset-password").status_code, 302)  # not verified

        post(client, "/forgot-password", {"username": "noemail", "email": ""})
        self.assertEqual(client.get("/reset-password").status_code, 302)

        # Knowing just an admin's username must never allow a reset.
        post(client, "/forgot-password", {"username": "boss", "email": "anything@example.com"})
        self.assertEqual(client.get("/reset-password").status_code, 302)

        response = post(client, "/forgot-password", {"username": "oscar", "email": "OSCAR@example.com"})
        self.assertTrue(response.headers["Location"].endswith("/reset-password"))
        self.assertEqual(client.get("/reset-password").status_code, 200)
        post(client, "/reset-password", {"new_password": "brand-new1", "confirm_password": "brand-new1"})
        _, response = self.login("oscar", "brand-new1")
        self.assertEqual(response.status_code, 302)


# =====================================================================
# Page access per role
# =====================================================================

class PageAccessTests(Base):
    def setUp(self):
        super().setUp()
        self.make_user("mary", "manager")
        self.make_user("oscar", "officer")
        self.admin_client = self.client_for("boss")
        self.manager_client = self.client_for("mary")
        self.officer_client = self.client_for("oscar")

    ADMIN_PAGES = ("/admin/dashboard", "/admin/users", "/admin/roles", "/admin/tasks", "/admin/logs",
                   "/admin/settings", "/admin/reports", "/admin/users/create")
    MANAGER_PAGES = ("/manager/dashboard", "/manager/officers", "/manager/tasks", "/manager/tasks/new",
                     "/manager/assignments", "/manager/approvals", "/manager/reports")
    OFFICER_PAGES = ("/officer/dashboard", "/officer/tasks", "/officer/submitted", "/officer/feedback",
                     "/officer/history")
    COMMON_PAGES = ("/profile", "/notifications")

    def assertAll(self, client, urls, code):
        for url in urls:
            self.assertEqual(client.get(url).status_code, code, url)

    def test_admin_reaches_admin_pages_and_all_three_dashboards(self):
        self.assertAll(self.admin_client, self.ADMIN_PAGES + self.COMMON_PAGES, 200)
        self.assertAll(self.admin_client, ("/manager/dashboard", "/officer/dashboard"), 200)

    def test_manager_reaches_manager_pages(self):
        self.assertAll(self.manager_client, self.MANAGER_PAGES + self.COMMON_PAGES, 200)

    def test_officer_reaches_officer_pages(self):
        self.assertAll(self.officer_client, self.OFFICER_PAGES + self.COMMON_PAGES, 200)

    def test_manager_is_blocked_from_admin_and_officer_pages(self):
        self.assertAll(self.manager_client, self.ADMIN_PAGES, 403)
        self.assertAll(self.manager_client, self.OFFICER_PAGES, 403)

    def test_officer_is_blocked_from_admin_and_manager_pages(self):
        self.assertAll(self.officer_client, self.ADMIN_PAGES, 403)
        self.assertAll(self.officer_client, self.MANAGER_PAGES, 403)

    def test_blocked_attempts_are_written_to_the_activity_log(self):
        self.officer_client.get("/admin/users")
        with db.connect() as conn:
            row = conn.execute("SELECT * FROM activity_logs WHERE action = 'access_denied'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["actor_name"], "oscar")

    def test_forbidden_page_is_friendly_and_does_not_leak_details(self):
        response = self.officer_client.get("/admin/users")
        self.assertIn(b"Access Denied", response.data)
        self.assertNotIn(b"Traceback", response.data)

    def test_navigation_only_shows_links_the_role_may_use(self):
        admin_html = self.admin_client.get("/admin/dashboard").data
        manager_html = self.manager_client.get("/manager/dashboard").data
        officer_html = self.officer_client.get("/officer/dashboard").data
        self.assertIn(b"Role Management", admin_html)
        self.assertIn(b"Activity Logs", admin_html)
        self.assertIn(b"Work Approvals", manager_html)
        self.assertNotIn(b"Role Management", manager_html)
        self.assertNotIn(b"/admin/", manager_html)
        self.assertIn(b"My Tasks", officer_html)
        self.assertNotIn(b"Work Approvals", officer_html)
        self.assertNotIn(b"/admin/", officer_html)
        self.assertNotIn(b"Role Management", officer_html)

    def test_unauthorised_post_to_admin_actions_is_rejected_and_changes_nothing(self):
        victim = self.uid("oscar")
        for client in (self.officer_client, self.manager_client):
            for action in ("delete", "disable", "approve", "reject", "enable"):
                self.assertEqual(post(client, f"/admin/users/{action}/{victim}").status_code, 403, action)
            self.assertEqual(post(client, f"/admin/users/role/{victim}", {"role": "admin"}).status_code, 403)
            self.assertEqual(post(client, f"/admin/users/edit/{victim}",
                                  {"name": "x", "username": "oscar", "role": "admin"}).status_code, 403)
        self.assertEqual(self.role_of("oscar"), "officer")
        self.assertEqual(self.status_of("oscar"), "Approved")


# =====================================================================
# Roles
# =====================================================================

class RoleAssignmentTests(Base):
    def setUp(self):
        super().setUp()
        self.make_user("mary", "manager")
        self.make_user("oscar", "officer")
        self.admin_client = self.client_for("boss")

    def test_admin_can_assign_every_role(self):
        oid = self.uid("oscar")
        for role in ("manager", "admin", "officer"):
            post(self.admin_client, f"/admin/users/role/{oid}", {"role": role})
            self.assertEqual(self.role_of("oscar"), role)

    def test_admin_cannot_assign_an_unknown_role(self):
        oid = self.uid("oscar")
        post(self.admin_client, f"/admin/users/role/{oid}", {"role": "superuser"})
        post(self.admin_client, f"/admin/users/edit/{oid}",
             {"name": "Oscar", "username": "oscar", "email": "", "role": "root"})
        self.assertEqual(self.role_of("oscar"), "officer")

    def test_role_change_is_recorded_in_the_activity_log(self):
        post(self.admin_client, f"/admin/users/role/{self.uid('oscar')}", {"role": "manager"})
        with db.connect() as conn:
            row = conn.execute("SELECT * FROM activity_logs WHERE action = 'role_changed'").fetchone()
        self.assertIn("officer -> manager", row["details"])

    def test_manager_cannot_promote_themselves_or_anyone_to_admin(self):
        manager = self.client_for("mary")
        for target in ("mary", "oscar"):
            self.assertEqual(post(manager, f"/admin/users/role/{self.uid(target)}",
                                  {"role": "admin"}).status_code, 403)
        self.assertEqual(self.role_of("mary"), "manager")
        self.assertEqual(self.role_of("oscar"), "officer")

    def test_officer_cannot_promote_themselves_via_profile_form(self):
        officer = self.client_for("oscar")
        post(officer, "/profile", {"name": "Oscar", "email": "o@example.com", "role": "admin",
                                   "status": "Approved", "username": "hacker"})
        user = db.find_user_by_username("oscar")
        self.assertEqual(user["role"], "officer")
        self.assertEqual(user["username"], "oscar")

    def test_role_change_applies_to_an_existing_session_immediately(self):
        officer = self.client_for("oscar")
        self.assertEqual(officer.get("/officer/tasks").status_code, 200)
        self.assertEqual(officer.get("/manager/dashboard").status_code, 403)

        post(self.admin_client, f"/admin/users/role/{self.uid('oscar')}", {"role": "manager"})

        self.assertEqual(officer.get("/officer/tasks").status_code, 403)       # old powers gone
        self.assertEqual(officer.get("/manager/dashboard").status_code, 200)   # new powers active
        self.assertEqual(officer.get("/admin/users").status_code, 403)

    def test_demoted_admin_loses_admin_pages_at_once(self):
        second = self.make_user("boss2", "admin")
        second_client = self.client_for("boss2")
        self.assertEqual(second_client.get("/admin/users").status_code, 200)
        post(self.admin_client, f"/admin/users/role/{second}", {"role": "officer"})
        self.assertEqual(second_client.get("/admin/users").status_code, 403)

    def test_admin_can_create_a_user_with_a_role(self):
        post(self.admin_client, "/admin/users/create", {
            "name": "New Manager", "username": "newmgr", "email": "n@example.com",
            "password": PASSWORD, "role": "manager", "status": "Approved"})
        self.assertEqual(self.role_of("newmgr"), "manager")
        _, response = self.login("newmgr")
        self.assertTrue(response.headers["Location"].endswith("/manager/dashboard"))

    def test_admin_edit_changes_details_and_can_reset_a_password(self):
        oid = self.uid("oscar")
        post(self.admin_client, f"/admin/users/edit/{oid}", {
            "name": "Oscar Renamed", "username": "oscar", "email": "new@example.com",
            "role": "officer", "new_password": "changed-pw1"})
        self.assertEqual(db.find_user_by_id(oid)["name"], "Oscar Renamed")
        _, response = self.login("oscar", "changed-pw1")
        self.assertEqual(response.status_code, 302)

    def test_duplicate_usernames_are_refused(self):
        post(self.admin_client, f"/admin/users/edit/{self.uid('oscar')}", {
            "name": "Oscar", "username": "MARY", "email": "", "role": "officer"})  # case-insensitive clash
        self.assertEqual(db.find_user_by_id(self.uid("oscar"))["username"], "oscar")


class ManagerOfficerPolicyTests(Base):
    def setUp(self):
        super().setUp()
        self.make_user("mary", "manager")
        self.make_user("maria", "manager")
        self.officer_id = self.make_user("oscar", "officer", status="Pending")
        self.admin_client = self.client_for("boss")
        self.manager = self.client_for("mary")

    def test_policy_is_off_by_default_so_managers_cannot_manage_officers(self):
        response = post(self.manager, f"/manager/officers/{self.officer_id}/status", {"action": "approve"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.status_of("oscar"), "Pending")

    def test_admin_can_switch_the_policy_on_and_off(self):
        post(self.admin_client, "/admin/settings", {"manager_can_manage_officers": "on"})
        self.assertEqual(db.get_setting("manager_can_manage_officers"), "1")
        post(self.admin_client, "/admin/settings", {})
        self.assertEqual(db.get_setting("manager_can_manage_officers"), "0")

    def test_manager_cannot_change_settings(self):
        self.assertEqual(post(self.manager, "/admin/settings", {"manager_can_manage_officers": "on"}).status_code, 403)
        self.assertEqual(db.get_setting("manager_can_manage_officers"), "0")

    def test_with_policy_on_manager_can_manage_officers_but_nothing_else(self):
        post(self.admin_client, "/admin/settings", {"manager_can_manage_officers": "on"})

        post(self.manager, f"/manager/officers/{self.officer_id}/status", {"action": "approve"})
        self.assertEqual(self.status_of("oscar"), "Approved")
        post(self.manager, f"/manager/officers/{self.officer_id}/status", {"action": "disable"})
        self.assertEqual(self.status_of("oscar"), "Disabled")

        # An attempt to smuggle a role change in the same request is ignored...
        post(self.manager, f"/manager/officers/{self.officer_id}/status", {"action": "enable", "role": "admin"})
        self.assertEqual(self.role_of("oscar"), "officer")
        # ...and admin / manager accounts are untouchable.
        for target in ("boss", "maria", "mary"):
            post(self.manager, f"/manager/officers/{self.uid(target)}/status", {"action": "disable"})
            self.assertEqual(self.status_of(target), "Approved", target)


# =====================================================================
# Last administrator
# =====================================================================

class LastAdminTests(Base):
    def test_the_last_admin_cannot_be_deleted_disabled_rejected_or_demoted(self):
        client = self.client_for("boss")
        aid = self.admin
        post(client, f"/admin/users/delete/{aid}")
        post(client, f"/admin/users/disable/{aid}")
        post(client, f"/admin/users/reject/{aid}")
        post(client, f"/admin/users/role/{aid}", {"role": "officer"})
        post(client, f"/admin/users/edit/{aid}", {"name": "B", "username": "boss", "email": "", "role": "manager"})
        user = db.find_user_by_username("boss")
        self.assertEqual((user["role"], user["status"]), ("admin", "Approved"))

    def test_refusal_is_explained_to_the_admin(self):
        client = self.client_for("boss")
        post(client, f"/admin/users/delete/{self.admin}")
        page = client.get("/admin/users").data
        self.assertIn(b"last administrator", page)

    def test_with_two_admins_one_can_be_removed_but_not_both(self):
        second = self.make_user("boss2", "admin")
        client = self.client_for("boss")
        post(client, f"/admin/users/disable/{second}")
        self.assertEqual(self.status_of("boss2"), "Disabled")
        post(client, f"/admin/users/disable/{self.admin}")          # now the last one
        self.assertEqual(self.status_of("boss"), "Approved")

    def test_an_admin_can_delete_their_own_account_when_another_admin_exists(self):
        """Regression: logging the deletion used to hit a foreign-key error (HTTP 500)."""
        self.make_user("boss2", "admin")
        client = self.client_for("boss")
        response = post(client, f"/admin/users/delete/{self.admin}")
        self.assertEqual(response.status_code, 302)
        self.assertIsNone(db.find_user_by_username("boss"))
        with db.connect() as conn:
            row = conn.execute("SELECT * FROM activity_logs WHERE action = 'user_deleted'").fetchone()
        self.assertEqual(row["actor_name"], "boss")      # readable even though the account is gone
        self.assertIsNone(row["actor_id"])
        self.assertEqual(client.get("/admin/users").status_code, 302)   # their session is dead


# =====================================================================
# Account status
# =====================================================================

class AccountStatusTests(Base):
    def test_disabling_a_logged_in_user_cuts_off_their_next_request(self):
        oid = self.make_user("oscar", "officer")
        officer = self.client_for("oscar")
        admin = self.client_for("boss")
        self.assertEqual(officer.get("/officer/dashboard").status_code, 200)

        post(admin, f"/admin/users/disable/{oid}")
        response = officer.get("/officer/dashboard")
        self.assertEqual(response.status_code, 302)                  # sent to login
        self.assertEqual(officer.get("/profile").status_code, 302)   # session is gone

        _, response = self.login("oscar")
        self.assertIn(b"disabled", response.data)

        post(admin, f"/admin/users/enable/{oid}")
        _, response = self.login("oscar")
        self.assertEqual(response.status_code, 302)

    def test_deleting_a_logged_in_user_ends_their_session(self):
        oid = self.make_user("oscar", "officer")
        officer = self.client_for("oscar")
        post(self.client_for("boss"), f"/admin/users/delete/{oid}")
        self.assertEqual(officer.get("/officer/dashboard").status_code, 302)

    def test_admin_approves_a_pending_registration(self):
        oid = self.make_user("newbie", "officer", status="Pending")
        self.assertIn(b"waiting for administrator approval", self.login("newbie")[1].data)
        post(self.client_for("boss"), f"/admin/users/approve/{oid}")
        self.assertEqual(self.login("newbie")[1].status_code, 302)


# =====================================================================
# Task workflow
# =====================================================================

class TaskWorkflowTests(Base):
    def setUp(self):
        super().setUp()
        self.mary = self.make_user("mary", "manager")
        self.maria = self.make_user("maria", "manager")
        self.oscar = self.make_user("oscar", "officer")
        self.olive = self.make_user("olive", "officer")
        self.manager = self.client_for("mary")
        self.other_manager = self.client_for("maria")
        self.officer = self.client_for("oscar")
        self.other_officer = self.client_for("olive")
        self.admin_client = self.client_for("boss")

    def test_full_workflow_create_assign_progress_submit_reject_resubmit_approve(self):
        tid = self.new_task_via_form(self.manager, self.oscar)
        self.assertEqual(self.task(tid)["status"], "Pending")
        self.assertEqual(self.task(tid)["assigned_to"], self.oscar)

        # Officer is notified and sees the task.
        self.assertIn(b"Write report", self.officer.get("/officer/tasks").data)
        self.assertIn(b"New task assigned", self.officer.get("/notifications").data)

        # Officer cannot submit before starting; progress starts the work.
        post(self.officer, f"/officer/tasks/{tid}/submit", {"note": "done"})
        self.assertEqual(self.task(tid)["status"], "Pending")
        post(self.officer, f"/officer/tasks/{tid}/progress", {"progress": "40", "note": "halfway"})
        self.assertEqual((self.task(tid)["status"], self.task(tid)["progress"]), ("In Progress", 40))

        # Submit; manager is notified and sees it under Work Approvals.
        post(self.officer, f"/officer/tasks/{tid}/submit", {"note": "all done"})
        self.assertEqual(self.task(tid)["status"], "Submitted")
        self.assertIn(b"Write report", self.manager.get("/manager/approvals").data)
        self.assertIn(b"submitted work", self.manager.get("/notifications").data)
        self.assertIn(b"Write report", self.officer.get("/officer/submitted").data)

        # Rejecting needs feedback.
        post(self.manager, f"/manager/tasks/{tid}/review", {"decision": "reject", "feedback": ""})
        self.assertEqual(self.task(tid)["status"], "Submitted")
        post(self.manager, f"/manager/tasks/{tid}/review", {"decision": "reject", "feedback": "Add figures"})
        self.assertEqual(self.task(tid)["status"], "Rejected")
        self.assertIn(b"Add figures", self.officer.get("/officer/feedback").data)

        # Officer corrects and resubmits; manager approves.
        post(self.officer, f"/officer/tasks/{tid}/progress", {"progress": "80"})
        self.assertEqual(self.task(tid)["status"], "In Progress")
        post(self.officer, f"/officer/tasks/{tid}/submit", {"note": "fixed"})
        post(self.manager, f"/manager/tasks/{tid}/review", {"decision": "approve", "feedback": "Good"})
        self.assertEqual(self.task(tid)["status"], "Approved")
        self.assertIn(b"Write report", self.officer.get("/officer/history").data)

        # Approved work is locked.
        post(self.officer, f"/officer/tasks/{tid}/progress", {"progress": "10"})
        self.assertEqual(self.task(tid)["progress"], 100)
        post(self.manager, f"/manager/tasks/{tid}/edit", {"title": "Hacked", "priority": "Low"})
        self.assertEqual(self.task(tid)["title"], "Write report")

        # Admin sees everything.
        self.assertIn(b"Write report", self.admin_client.get("/admin/tasks").data)

    def test_officer_cannot_touch_another_officers_task(self):
        tid = self.insert_task(self.mary, self.oscar, status="In Progress", title="ZZ-private-task")
        post(self.other_officer, f"/officer/tasks/{tid}/progress", {"progress": "99"})
        post(self.other_officer, f"/officer/tasks/{tid}/submit", {"note": "stolen"})
        self.assertEqual(self.task(tid)["status"], "In Progress")
        self.assertEqual(self.task(tid)["progress"], 0)
        self.assertEqual(self.other_officer.get(f"/tasks/{tid}").status_code, 403)
        self.assertNotIn(b"ZZ-private-task", self.other_officer.get("/officer/tasks").data)
        self.assertNotIn(b"ZZ-private-task", self.other_officer.get("/officer/history").data)
        self.assertIn(b"ZZ-private-task", self.officer.get("/officer/tasks").data)   # the owner does see it

    def test_officer_cannot_approve_reject_or_reassign(self):
        tid = self.insert_task(self.mary, self.oscar, status="Submitted")
        for decision in ("approve", "reject"):
            self.assertEqual(post(self.officer, f"/manager/tasks/{tid}/review",
                                  {"decision": decision, "feedback": "x"}).status_code, 403)
        self.assertEqual(post(self.officer, f"/manager/tasks/{tid}/assign", {"officer_id": self.olive}).status_code, 403)
        self.assertEqual(self.task(tid)["status"], "Submitted")
        self.assertEqual(self.task(tid)["assigned_to"], self.oscar)

    def test_officer_cannot_create_tasks(self):
        self.assertEqual(self.officer.get("/manager/tasks/new").status_code, 403)
        self.assertEqual(post(self.officer, "/manager/tasks/new", {"title": "x"}).status_code, 403)

    def test_manager_cannot_see_or_change_another_managers_task(self):
        tid = self.insert_task(self.mary, self.oscar, status="Submitted", title="ZZ-marys-task")
        self.assertEqual(self.other_manager.get(f"/tasks/{tid}").status_code, 403)
        self.assertEqual(self.other_manager.get(f"/manager/tasks/{tid}/edit").status_code, 403)
        post(self.other_manager, f"/manager/tasks/{tid}/review", {"decision": "approve"})
        post(self.other_manager, f"/manager/tasks/{tid}/assign", {"officer_id": self.olive})
        self.assertEqual(self.task(tid)["status"], "Submitted")
        self.assertEqual(self.task(tid)["assigned_to"], self.oscar)
        for url in ("/manager/tasks", "/manager/approvals", "/manager/assignments", "/manager/dashboard"):
            self.assertNotIn(b"ZZ-marys-task", self.other_manager.get(url).data, url)
        self.assertIn(b"ZZ-marys-task", self.manager.get("/manager/approvals").data)   # the owner does see it

    def test_manager_can_assign_a_pending_task_but_not_after_work_started(self):
        tid = self.new_task_via_form(self.manager, None, title="Unassigned job")
        self.assertIsNone(self.task(tid)["assigned_to"])
        post(self.manager, f"/manager/tasks/{tid}/assign", {"officer_id": self.oscar})
        self.assertEqual(self.task(tid)["assigned_to"], self.oscar)
        post(self.manager, f"/manager/tasks/{tid}/assign", {"officer_id": self.olive})   # reassign while Pending
        self.assertEqual(self.task(tid)["assigned_to"], self.olive)

        post(self.other_officer, f"/officer/tasks/{tid}/progress", {"progress": "10"})
        post(self.manager, f"/manager/tasks/{tid}/assign", {"officer_id": self.oscar})   # too late
        self.assertEqual(self.task(tid)["assigned_to"], self.olive)

    def test_tasks_can_only_be_assigned_to_approved_officers(self):
        manager_id = self.mary
        pending_officer = self.make_user("pend", "officer", status="Pending")
        tid = self.insert_task(self.mary)
        for bad in (pending_officer, manager_id, self.admin):
            post(self.manager, f"/manager/tasks/{tid}/assign", {"officer_id": bad})
            self.assertIsNone(self.task(tid)["assigned_to"])
        self.assertIsNone(self.new_task_via_form(self.manager, pending_officer, title="Bad assign"))

    def test_manager_cannot_review_a_task_assigned_to_themselves(self):
        # e.g. a user who was an officer, got promoted, and still holds work
        tid = self.insert_task(self.mary, self.mary, status="Submitted")
        post(self.manager, f"/manager/tasks/{tid}/review", {"decision": "approve"})
        self.assertEqual(self.task(tid)["status"], "Submitted")

    def test_admin_can_edit_reassign_and_delete_any_task(self):
        tid = self.insert_task(self.mary, self.oscar, status="In Progress", title="Old title")
        post(self.admin_client, f"/admin/tasks/edit/{tid}", {
            "title": "New title", "description": "d", "priority": "Low", "due_date": "2031-05-05",
            "assigned_to": str(self.olive), "status": "Pending"})
        task = self.task(tid)
        self.assertEqual((task["title"], task["assigned_to"], task["status"]), ("New title", self.olive, "Pending"))
        post(self.admin_client, f"/admin/tasks/edit/{tid}", {
            "title": "X", "priority": "Low", "status": "Bogus"})
        self.assertEqual(self.task(tid)["title"], "New title")
        post(self.admin_client, f"/admin/tasks/delete/{tid}")
        with db.connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0], 0)

    def test_task_forms_are_validated(self):
        for bad in ({"title": ""}, {"title": "x" * 200}, {"priority": "Urgent"}, {"due_date": "31/01/2030"}):
            data = {"title": "ok", "priority": "High", "due_date": ""}
            data.update(bad)
            post(self.manager, "/manager/tasks/new", data)
        with db.connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0], 0)

    def test_progress_must_be_between_0_and_100(self):
        tid = self.insert_task(self.mary, self.oscar)
        for bad in ("-5", "101", "abc", ""):
            post(self.officer, f"/officer/tasks/{tid}/progress", {"progress": bad})
            self.assertEqual(self.task(tid)["status"], "Pending", bad)

    def test_deleting_users_who_hold_or_created_tasks(self):
        in_flight = self.insert_task(self.mary, self.oscar, status="In Progress")
        post(self.admin_client, f"/admin/users/delete/{self.oscar}")
        self.assertIsNone(db.find_user_by_id(self.oscar))
        task = self.task(in_flight)                       # goes back to the pool
        self.assertEqual((task["assigned_to"], task["status"]), (None, "Pending"))

        post(self.admin_client, f"/admin/users/delete/{self.mary}")   # created a task -> refused
        self.assertIsNotNone(db.find_user_by_id(self.mary))

    def test_reports_are_scoped_to_the_manager(self):
        self.insert_task(self.mary, self.oscar, title="Marys job", status="Approved")
        self.insert_task(self.maria, self.olive, title="Marias job", status="Approved")
        mary_report = self.manager.get("/manager/reports").data
        self.assertIn(b"oscar", mary_report)
        self.assertNotIn(b"olive", mary_report)
        admin_report = self.admin_client.get("/admin/reports").data
        self.assertIn(b"oscar", admin_report)
        self.assertIn(b"olive", admin_report)


# =====================================================================
# Profile, passwords, notifications
# =====================================================================

class ProfileTests(Base):
    def setUp(self):
        super().setUp()
        self.make_user("oscar", "officer")
        self.officer = self.client_for("oscar")

    def test_change_password_needs_the_current_password(self):
        post(self.officer, "/profile/password",
             {"current_password": "wrong", "new_password": "newpass1", "confirm_password": "newpass1"})
        self.assertEqual(self.login("oscar", "newpass1")[1].status_code, 200)   # still logged-out page
        post(self.officer, "/profile/password",
             {"current_password": PASSWORD, "new_password": "newpass1", "confirm_password": "newpass1"})
        self.assertEqual(self.login("oscar", "newpass1")[1].status_code, 302)
        self.assertEqual(self.login("oscar", PASSWORD)[1].status_code, 200)

    def test_new_password_must_match_and_be_long_enough(self):
        post(self.officer, "/profile/password",
             {"current_password": PASSWORD, "new_password": "abc", "confirm_password": "abc"})
        post(self.officer, "/profile/password",
             {"current_password": PASSWORD, "new_password": "newpass1", "confirm_password": "different"})
        self.assertEqual(self.login("oscar", PASSWORD)[1].status_code, 302)

    def test_profile_edit_changes_only_name_and_email(self):
        post(self.officer, "/profile", {"name": "Oscar Two", "email": "two@example.com"})
        user = db.find_user_by_username("oscar")
        self.assertEqual((user["name"], user["email"]), ("Oscar Two", "two@example.com"))
        post(self.officer, "/profile", {"name": "Oscar", "email": "bad-email"})
        self.assertEqual(db.find_user_by_username("oscar")["email"], "two@example.com")

    def test_notifications_can_be_marked_read(self):
        uid = self.uid("oscar")
        db.create_notification(uid, "Hello", None)
        self.assertEqual(db.count_unread(uid), 1)
        post(self.officer, "/notifications/read")
        self.assertEqual(db.count_unread(uid), 0)

    def test_html_in_user_input_is_escaped(self):
        post(self.officer, "/profile", {"name": "<script>alert(1)</script>", "email": ""})
        page = self.officer.get("/profile").data
        self.assertNotIn(b"<script>alert(1)</script>", page)
        self.assertIn(b"&lt;script&gt;", page)


# =====================================================================
# Pagination, search, filters, sorting
# =====================================================================

class PaginationTests(Base):
    def setUp(self):
        super().setUp()
        for i in range(1, 24):                       # 23 + admin = 24 users
            self.make_user(f"alice{i:02d}", "officer" if i % 2 else "manager",
                           status="Approved" if i % 3 else "Pending", name=f"Alice {i:02d}")
        self.client = self.client_for("boss")

    def rows(self, url):
        html = self.client.get(url).data.decode()
        body = html.split("<tbody>")[1].split("</tbody>")[0]
        return re.findall(r"<tr>", body)

    def test_first_page_has_ten_rows_and_the_last_page_the_remainder(self):
        self.assertEqual(len(self.rows("/admin/users")), 10)
        self.assertEqual(len(self.rows("/admin/users?page=2")), 10)
        self.assertEqual(len(self.rows("/admin/users?page=3")), 4)
        self.assertIn("Showing 21&ndash;24 of 24", self.client.get("/admin/users?page=3").data.decode())

    def test_out_of_range_and_garbage_page_numbers_are_safe(self):
        for url in ("/admin/users?page=999", "/admin/users?page=0", "/admin/users?page=-4",
                    "/admin/users?page=abc"):
            self.assertEqual(self.client.get(url).status_code, 200, url)

    def test_previous_is_disabled_on_first_page_and_next_on_last(self):
        first = self.client.get("/admin/users").data.decode()
        last = self.client.get("/admin/users?page=3").data.decode()
        self.assertIn('<span class="page-btn disabled">&larr; Previous</span>', first)
        self.assertNotIn('<span class="page-btn disabled">Next', first)
        self.assertIn('<span class="page-btn disabled">Next &rarr;</span>', last)
        self.assertIn('<span class="page-btn current">3</span>', last)

    def test_filters_are_kept_in_every_pagination_link(self):
        html = self.client.get("/admin/users?search=alice&status=Approved&sort=username&dir=asc").data.decode()
        links = [h for h in re.findall(r'href="([^"]+)"', html) if "page=" in h and "sort=" not in h.replace("sort=username", "")]
        pager = [h for h in re.findall(r'class="page-btn" href="([^"]+)"', html)]
        self.assertTrue(pager)
        for href in pager:
            for expected in ("search=alice", "status=Approved", "sort=username", "dir=asc"):
                self.assertIn(expected, href)

    def test_search_status_and_role_filters_combine_with_pagination(self):
        self.assertEqual(len(self.rows("/admin/users?search=alice01")), 1)
        self.assertEqual(len(self.rows("/admin/users?search=nobody-matches-this")), 1)  # the "no users" row
        with db.connect() as conn:
            expected = conn.execute(
                "SELECT COUNT(*) FROM users WHERE role='officer' AND status='Pending'").fetchone()[0]
        html = self.client.get("/admin/users?role=officer&status=Pending").data.decode()
        self.assertEqual(len(self.rows("/admin/users?role=officer&status=Pending")), expected)
        self.assertIn("officer", html)

    def test_sorting_works_and_unknown_sort_keys_are_ignored_safely(self):
        html = self.client.get("/admin/users?sort=username&dir=asc").data.decode()
        names = re.findall(r"<td>(alice\d\d|boss)</td>", html)
        self.assertEqual(names, sorted(names))
        html = self.client.get("/admin/users?sort=username&dir=desc").data.decode()
        names = re.findall(r"<td>(alice\d\d|boss)</td>", html)
        self.assertEqual(names, sorted(names, reverse=True))
        for evil in ("name; DROP TABLE users", "password", "1 OR 1=1", "(SELECT 1)"):
            self.assertEqual(self.client.get("/admin/users", query_string={"sort": evil}).status_code, 200)
        with db.connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 24)

    def test_sql_injection_in_search_is_harmless(self):
        for evil in ("' OR '1'='1", "'; DROP TABLE users; --", "%' UNION SELECT password,1,1,1,1,1,1,1 FROM users --"):
            response = self.client.get("/admin/users", query_string={"search": evil})
            self.assertEqual(response.status_code, 200)
            self.assertNotIn(b"scrypt:", response.data)
        with db.connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 24)

    def test_pagination_happens_in_sql_with_limit_and_offset(self):
        statements = []
        with db.connect() as conn:
            conn.set_trace_callback(statements.append)
            rows, info = paginate(conn, "SELECT * FROM users ORDER BY id", "SELECT COUNT(*) FROM users",
                                  (), 2, 10)
        self.assertEqual(len(rows), 10)                    # only one page was fetched
        self.assertEqual(info["total"], 24)
        self.assertEqual(info["total_pages"], 3)
        self.assertTrue(info["has_prev"] and info["has_next"])
        self.assertTrue(any("LIMIT" in s and "OFFSET" in s for s in statements), statements)

    def test_task_lists_paginate_filter_and_keep_filters(self):
        mary = self.make_user("mary", "manager")
        oscar = self.make_user("oscar", "officer")
        for i in range(25):
            self.insert_task(mary, oscar, title=f"Job {i:02d}", priority="High" if i % 5 == 0 else "Low",
                             status="Pending")
        manager = self.client_for("mary")

        html = manager.get("/manager/tasks").data.decode()
        self.assertEqual(len(re.findall(r"<tr>", html.split("<tbody>")[1].split("</tbody>")[0])), 10)
        self.assertIn("Showing 1&ndash;10 of 25", html)

        html = manager.get("/manager/tasks?priority=High").data.decode()
        self.assertIn("Job 00", html)
        self.assertNotIn("Job 01", html)                   # a Low task

        html = manager.get("/manager/tasks?priority=Low&page=2").data.decode()
        self.assertIn("Showing 11&ndash;20 of 20", html)
        for href in re.findall(r'class="page-btn" href="([^"]+)"', html):
            self.assertIn("priority=Low", href)

        self.assertIn("Job 07", manager.get("/manager/tasks?search=job 07").data.decode())
        self.assertNotIn("Job 08", manager.get("/manager/tasks?search=job 07").data.decode())
        for evil in ("status=Bogus", "assigned=abc", "date_from=not-a-date", "priority='; DROP TABLE tasks"):
            self.assertEqual(manager.get(f"/manager/tasks?{evil}").status_code, 200)

    def test_due_date_range_filter(self):
        mary = self.make_user("mary", "manager")
        self.insert_task(mary, None, title="Early", due="2030-01-10")
        self.insert_task(mary, None, title="Late", due="2030-12-10")
        manager = self.client_for("mary")
        html = manager.get("/manager/tasks?date_from=2030-06-01&date_to=2030-12-31").data.decode()
        self.assertIn("Late", html)
        self.assertNotIn("Early", html)

    def test_activity_log_is_paginated_and_filterable(self):
        for i in range(40):
            db.log_activity(self.db_user(), "demo_action", f"entry {i}")
        html = self.client.get("/admin/logs").data.decode()
        self.assertEqual(len(re.findall(r"<tr>", html.split("<tbody>")[1].split("</tbody>")[0])), 15)
        html = self.client.get("/admin/logs?action=demo_action&search=entry 3").data.decode()
        self.assertIn("entry 3", html)
        self.assertNotIn("entry 1<", html)

    def db_user(self):
        return db.find_user_by_username("boss")


# =====================================================================
# Database migration
# =====================================================================

class MigrationTests(Base):
    def _fresh_path(self, name):
        path = os.path.join(_TMP, name)
        if os.path.exists(path):
            os.remove(path)
        return path

    def _old_database(self, with_role_columns):
        path = self._fresh_path("old_with_roles.db" if with_role_columns else "very_old.db")
        conn = sqlite3.connect(path)
        extra = ", role TEXT NOT NULL DEFAULT 'user', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP" \
            if with_role_columns else ""
        conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, "
                     "username TEXT NOT NULL UNIQUE COLLATE NOCASE, email TEXT, password TEXT NOT NULL, "
                     f"status TEXT NOT NULL DEFAULT 'Pending'{extra})")
        rows = [("Sanu", "sanu", "s@example.com", generate_password_hash("54321"), "Disabled"),
                ("Kamal", "kamal", "", generate_password_hash("abc123"), "Approved"),
                ("Nimal", "nimal", "", "test123", "Approved"),                   # legacy plaintext
                ("Admin", "admin", "", generate_password_hash("admin123"), "Approved")]
        conn.executemany("INSERT INTO users (name, username, email, password, status) VALUES (?,?,?,?,?)", rows)
        if with_role_columns:
            conn.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")
        conn.commit()
        conn.close()
        return path

    def _check_upgraded(self, path):
        db.DB_FILE = path
        db.init_db()
        with db.connect() as conn:
            users = {r["username"]: dict(r) for r in conn.execute("SELECT * FROM users")}
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"users", "tasks", "notifications", "activity_logs", "settings"} <= tables)
        self.assertEqual(len(users), 4)                                         # nobody lost
        self.assertEqual({u["role"] for u in users.values()} - {"admin", "manager", "officer"}, set())
        self.assertEqual(users["admin"]["role"], "admin")
        self.assertEqual(users["kamal"]["role"], "officer")                     # 'user' -> lowest role
        self.assertEqual(users["sanu"]["status"], "Disabled")                   # status kept
        self.assertEqual(users["sanu"]["email"], "s@example.com")
        self.assertTrue(all(u["created_at"] for u in users.values()))
        # passwords still work, including the legacy plaintext one (and get hashed)
        self.assertEqual(self.login("kamal", "abc123")[1].status_code, 302)
        self.assertEqual(self.login("nimal", "test123")[1].status_code, 302)
        self.assertTrue(db.find_user_by_username("nimal")["password"].startswith(("scrypt:", "pbkdf2:")))
        self.assertEqual(self.login("admin", "admin123")[1].headers["Location"].endswith("/admin/dashboard"), True)

    def test_upgrade_from_the_previous_version_with_user_and_admin_roles(self):
        self._check_upgraded(self._old_database(with_role_columns=True))

    def test_upgrade_from_the_original_sqlite_version_without_role_columns(self):
        self._check_upgraded(self._old_database(with_role_columns=False))

    def test_init_db_is_safe_to_run_repeatedly(self):
        before = self.uid("boss")
        db.init_db()
        db.init_db()
        with db.connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0], 1)
        self.assertEqual(self.uid("boss"), before)

    def test_a_missing_admin_is_recreated_but_an_existing_one_is_never_duplicated(self):
        with db.connect() as conn:
            conn.execute("UPDATE users SET role = 'officer'")
        db.init_db()
        with db.connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0], 1)

    def test_foreign_keys_are_enforced(self):
        with self.assertRaises(sqlite3.IntegrityError):
            with db.connect() as conn:
                conn.execute("INSERT INTO tasks (title, created_by) VALUES ('x', 9999)")
        with db.connect() as conn:
            self.assertEqual(conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)

    def test_database_rejects_invalid_task_values(self):
        mary = self.make_user("mary", "manager")
        for column, value in (("status", "Done"), ("priority", "Urgent"), ("progress", 150)):
            with self.assertRaises(sqlite3.IntegrityError):
                with db.connect() as conn:
                    conn.execute(f"INSERT INTO tasks (title, created_by, {column}) VALUES ('x', ?, ?)", (mary, value))


if __name__ == "__main__":
    unittest.main()

