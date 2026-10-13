"""
Login System with Role-Based Access Control: Admin, Manager, Officer
====================================================================
Storage : SQLite (users.db). Passwords are hashed.
Roles   : admin, manager, officer   (see utils/permissions.py)

    pip install -r requirements.txt
    python app.py          ->  http://127.0.0.1:5000/

Default admin (created automatically the first time, password hashed):
    username: admin      password: admin123     <- change it after first login

See README.md for how permissions, pagination and the task workflow work.
"""

import os

from flask import Flask, render_template

from utils.constants import ROLE_LABELS
from utils.db import init_db, count_unread, BASE_DIR
from utils.permissions import get_current_user
from utils.security import init_security, load_secret_key
from routes.auth import auth_bp
from routes.user import user_bp
from routes.admin import admin_bp
from routes.manager import manager_bp
from routes.officer import officer_bp
from routes.tasks import tasks_bp


def create_app():
    app = Flask(__name__)
    app.secret_key = load_secret_key(BASE_DIR)
    init_security(app)  # session cookie settings, CSRF protection, security headers

    for blueprint in (auth_bp, user_bp, admin_bp, manager_bp, officer_bp, tasks_bp):
        app.register_blueprint(blueprint)

    @app.context_processor
    def inject_globals():
        # {{ current_user }} is available in every template (for role-aware
        # navigation); it is re-read from the database on every request.
        user = get_current_user()
        return {
            "current_user": user,
            "unread_notifications": count_unread(user["id"]) if user else 0,
            "ROLE_LABELS": ROLE_LABELS,
        }

    @app.errorhandler(400)
    def bad_request(_e):
        return render_template("400.html"), 400

    @app.errorhandler(403)
    def forbidden(_e):
        return render_template("403.html"), 403

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def server_error(_e):
        return render_template("500.html"), 500

    return app


app = create_app()
init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "1") == "1")
