from flask import Flask, render_template

from utils.db import init_db
from utils.auth import get_current_user
from routes.auth import auth_bp
from routes.user import user_bp
from routes.admin import admin_bp


def create_app():
    app = Flask(__name__)
    app.secret_key = "change-this-secret-key-in-production"

    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(admin_bp)

    @app.context_processor
    def inject_current_user():
        # Makes {{ current_user }} available in every template, e.g. to
        # show/hide the "Admin Dashboard" nav link based on role.
        return {"current_user": get_current_user()}

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
    app.run(debug=True)
