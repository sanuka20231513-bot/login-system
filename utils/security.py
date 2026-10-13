import hmac
import os
import secrets
from datetime import timedelta
from urllib.parse import urlparse

from flask import abort, redirect, request, session, url_for
from markupsafe import Markup, escape


def load_secret_key(base_dir):
    """Use the SECRET_KEY environment variable if set, otherwise create a
    random key once and keep it in secret_key.txt (ignored by git) so
    sessions survive a server restart."""
    from_env = os.environ.get("SECRET_KEY")
    if from_env:
        return from_env
    path = os.path.join(base_dir, "secret_key.txt")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            key = f.read().strip()
        if key:
            return key
    key = secrets.token_hex(32)
    with open(path, "w", encoding="utf-8") as f:
        f.write(key)
    return key


def get_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_hex(32)
        session["_csrf_token"] = token
    return token


def csrf_input():
    """Hidden form field - put {{ csrf_input() }} inside every POST form."""
    return Markup('<input type="hidden" name="csrf_token" value="%s">' % escape(get_csrf_token()))


def redirect_back(default_endpoint, **values):
    """Go back to the page the form was submitted from (so filters and the
    current page number are kept), but only if it is on this same site."""
    referrer = request.referrer
    if referrer and urlparse(referrer).netloc == request.host:
        return redirect(referrer)
    return redirect(url_for(default_endpoint, **values))


def init_security(app):
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # Turn on when serving over HTTPS:  set SESSION_COOKIE_SECURE=1
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        MAX_CONTENT_LENGTH=1024 * 1024,
    )

    app.jinja_env.globals["csrf_input"] = csrf_input
    app.jinja_env.globals["csrf_token"] = get_csrf_token

    @app.before_request
    def csrf_protect():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
            expected = session.get("_csrf_token", "")
            if not expected or not hmac.compare_digest(str(sent), str(expected)):
                abort(400)

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        if request.endpoint != "static":
            # Stops the browser showing a cached private page after logout.
            response.headers["Cache-Control"] = "no-store"
        return response
