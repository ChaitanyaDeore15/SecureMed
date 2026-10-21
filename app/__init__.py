import os
from flask import Flask
from config import Config
from app.extensions import db, login_manager, csrf, limiter

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure required runtime instance folders exist
    os.makedirs(app.config.get("UPLOAD_FOLDER", "instance/uploads"), exist_ok=True)
    os.makedirs(app.config.get("CA_DIR", "instance/ca"), exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Register blueprints
    from app.auth.routes import auth_bp
    from app.reports.routes import reports_bp
    from app.departments.routes import departments_bp
    from app.audit.routes import audit_bp
    from app.patients.routes import patients_bp
    from app.admin.routes import admin_bp
    from app.demo.routes import demo_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(departments_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(patients_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(demo_bp)

    # Security Headers Hook
    @app.after_request
    def apply_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # CSP: allow alpine and tailwind via CDN, inline styles for rapid medical UI icons
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-eval' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        return response

    @app.route("/")
    def index():
        from flask import redirect, url_for
        return redirect(url_for("auth.login"))

    return app
