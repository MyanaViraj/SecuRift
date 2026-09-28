import urllib.parse
from functools import wraps
from flask import Blueprint, render_template, redirect, url_for, request, flash, abort
from flask_login import login_user, logout_user, login_required, current_user
from models.models import User
from models import db

auth_bp = Blueprint("auth", __name__)


def is_safe_url(target):
    """
    Ensures that a redirect target is an internal URL on the same host
    to prevent open redirect vulnerabilities.
    """
    if not target:
        return False
    ref_url = urllib.parse.urlsplit(request.host_url)
    test_url = urllib.parse.urlsplit(target)
    # Check if relative path or matching scheme and host
    if not test_url.netloc and test_url.path.startswith("/"):
        return True
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


def role_required(*allowed_roles):
    """
    Decorator to restrict access to users having specified roles or Administrator.
    """
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for("auth.login"))
            user_role = (current_user.role or "").lower()
            allowed = [r.lower() for r in allowed_roles]
            if "administrator" not in allowed:
                allowed.append("administrator")
            if "lead security architect" not in allowed:
                allowed.append("lead security architect")

            if user_role not in allowed and not current_user.is_admin():
                flash(f"Access denied: This operation requires {', '.join(allowed_roles)} privileges.", "danger")
                return f"Access denied: This operation requires {', '.join(allowed_roles)} privileges.", 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash(f"Welcome back, {user.username}. Detection Console active.", "success")
            next_page = request.args.get("next")
            if next_page and is_safe_url(next_page):
                return redirect(next_page)
            return redirect(url_for("dashboard.index"))
        else:
            flash("Invalid authentication credentials. Please verify username and password.", "danger")

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Session terminated safely. You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/change-password", methods=["POST"])
@login_required
def change_password():
    new_password = request.form.get("new_password", "")
    if len(new_password) < 6:
        flash("Password must be at least 6 characters.", "warning")
    else:
        current_user.set_password(new_password)
        db.session.commit()
        flash("Operator password updated successfully.", "success")
    return redirect(url_for("dashboard.index"))

