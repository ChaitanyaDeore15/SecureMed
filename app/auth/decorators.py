from functools import wraps
from flask import abort, flash, redirect, url_for
from flask_login import current_user

def roles_required(*roles):
    """Decorator to enforce RBAC server-side on routes."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for("auth.login"))
            
            if current_user.role not in roles:
                flash("Access denied: You do not possess the required clinical authorization clearance.", "danger")
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator
