from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.extensions import db
from app.models import AuditLog, Patient, RoleEnum
from app.audit.service import log_event
from app.audit.analyzer import verify_audit_hash_chain, detect_security_anomalies
from app.audit.forms import BreakGlassForm
from app.auth.decorators import roles_required

audit_bp = Blueprint("audit", __name__, url_prefix="/audit")

@audit_bp.route("/logs")
@login_required
@roles_required(RoleEnum.ADMIN, RoleEnum.AUDITOR)
def logs():
    page = request.args.get("page", 1, type=int)
    action_filter = request.args.get("action", "")
    
    query = AuditLog.query.order_by(AuditLog.sequence_number.desc())
    if action_filter:
        query = query.filter_by(action=action_filter)
        
    pagination = query.paginate(page=page, per_page=20, error_out=False)
    distinct_actions = [r[0] for r in db.session.query(AuditLog.action).distinct()]
    
    return render_template("audit/logs.html", pagination=pagination, distinct_actions=distinct_actions, current_filter=action_filter)

@audit_bp.route("/verify-chain", methods=["POST"])
@login_required
@roles_required(RoleEnum.ADMIN, RoleEnum.AUDITOR)
def verify_chain():
    is_valid, message, errors = verify_audit_hash_chain()
    if is_valid:
        flash(f"Cryptographic Chain Intact: {message}", "success")
    else:
        flash(f"CRITICAL: {message}", "danger")
    return redirect(url_for("audit.logs"))

@audit_bp.route("/anomalies")
@login_required
@roles_required(RoleEnum.ADMIN, RoleEnum.AUDITOR)
def anomalies():
    alerts = detect_security_anomalies()
    return render_template("audit/anomalies.html", alerts=alerts)

@audit_bp.route("/break-glass", methods=["GET", "POST"])
@login_required
@roles_required(RoleEnum.DOCTOR, RoleEnum.ADMIN, RoleEnum.DEPT_HEAD)
def break_glass():
    form = BreakGlassForm()
    patients = Patient.query.all()
    form.patient_id.choices = [(p.id, f"{p.full_name} (MRN: {p.mrn})") for p in patients]

    if form.validate_on_submit():
        patient = Patient.query.get(form.patient_id.data)
        justification = form.reason.data.strip()
        
        # Log critical audit event with high priority
        log_event(
            "BREAK_GLASS_ACCESS",
            target_resource=f"Patient:{patient.id} ({patient.mrn})",
            details={
                "reason": justification,
                "doctor": current_user.full_name,
                "doctor_role": current_user.role
            },
            actor_id=current_user.id
        )

        flash(f"Emergency Break-Glass access granted for Patient {patient.full_name}. High-priority audit trail alerted to Compliance & Administration.", "warning")
        return redirect(url_for("reports.inbox"))

    return render_template("audit/break_glass.html", form=form)
