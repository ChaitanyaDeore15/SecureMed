from datetime import datetime, timezone, timedelta
import pyotp
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, session
from flask_login import login_user, logout_user, login_required, current_user
from app.extensions import db, limiter
from app.models import User, RoleEnum
from app.auth.forms import LoginForm, RegistrationForm
from app.audit.service import log_event

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("reports.inbox"))

    form = LoginForm()
    if form.validate_on_submit():
        identifier = form.username.data.strip()
        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier)
        ).first()

        # Generic failure message to prevent user enumeration
        generic_error = "Invalid credentials or account temporarily locked. Please check your details."

        if not user or not user.is_active:
            log_event("LOGIN_FAILED", target_resource=identifier, details={"reason": "User not found or inactive"})
            flash(generic_error, "danger")
            return render_template("auth/login.html", form=form)

        # Check account lockout
        if user.is_locked():
            remaining_minutes = int((user.locked_until.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).total_seconds() / 60) + 1
            log_event("LOGIN_LOCKED_ATTEMPT", target_resource=user.username, details={"user_id": user.id}, actor_id=user.id)
            flash(f"Account is locked due to multiple failed attempts. Please retry in {remaining_minutes} minute(s).", "warning")
            return render_template("auth/login.html", form=form)

        # Verify password
        if not user.verify_password(form.password.data):
            user.failed_login_attempts += 1
            max_attempts = current_app.config.get("MAX_FAILED_LOGIN_ATTEMPTS", 5)
            if user.failed_login_attempts >= max_attempts:
                lockout_duration = current_app.config.get("ACCOUNT_LOCKOUT_MINUTES", 15)
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_duration)
                log_event("ACCOUNT_LOCKED", target_resource=user.username, details={"attempts": user.failed_login_attempts}, actor_id=user.id)
                db.session.commit()
                flash(f"Security Alert: Maximum failed attempts exceeded ({max_attempts}). Account locked for {lockout_duration} minutes.", "danger")
                return render_template("auth/login.html", form=form)
            
            db.session.commit()
            log_event("LOGIN_FAILED", target_resource=user.username, details={"attempts": user.failed_login_attempts}, actor_id=user.id)
            flash(generic_error, "danger")
            return render_template("auth/login.html", form=form)

        # Check 2FA if enabled
        if user.totp_enabled and user.totp_secret:
            totp = pyotp.TOTP(user.totp_secret)
            token = form.totp_token.data.strip() if form.totp_token.data else ""
            if not token or not totp.verify(token):
                log_event("LOGIN_2FA_FAILED", target_resource=user.username, actor_id=user.id)
                flash("Invalid or missing 2FA Authenticator Code.", "danger")
                return render_template("auth/login.html", form=form)

        # Reset failed attempts on success
        user.failed_login_attempts = 0
        user.locked_until = None
        db.session.commit()

        login_user(user, remember=False)
        session.permanent = True
        
        # Cache plaintext password in session temporarily for client-side envelope decryption during active session
        # or store the derived key in session
        session["user_pwd_temp"] = form.password.data

        log_event("LOGIN_SUCCESS", target_resource=user.username, actor_id=user.id)
        flash(f"Welcome back, {user.full_name} ({user.role})", "success")

        next_page = request.args.get("next")
        if next_page and next_page.startswith("/"):
            return redirect(next_page)
        
        if user.role == RoleEnum.ADMIN:
            return redirect(url_for("admin.dashboard"))
        elif user.role == RoleEnum.PATIENT:
            return redirect(url_for("patients.portal"))
        return redirect(url_for("reports.inbox"))

    return render_template("auth/login.html", form=form)

@auth_bp.route("/logout")
@login_required
def logout():
    log_event("LOGOUT", target_resource=current_user.username, actor_id=current_user.id)
    session.clear()
    logout_user()
    flash("You have been securely signed out.", "info")
    return redirect(url_for("auth.login"))
