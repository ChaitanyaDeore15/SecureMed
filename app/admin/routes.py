import csv
import io
from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request, Response
from flask_login import login_required, current_user
from app.extensions import db
from app.models import User, Department, Certificate, Report, ReportRecipient, AuditLog, RoleEnum
from app.auth.decorators import roles_required
from app.audit.service import log_event

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

@admin_bp.route("/dashboard")
@login_required
@roles_required(RoleEnum.ADMIN)
def dashboard():
    total_users = User.query.count()
    total_departments = Department.query.count()
    total_reports = Report.query.count()
    total_certs = Certificate.query.count()
    
    # Cryptographic delivery analytics
    verified_count = ReportRecipient.query.filter_by(verification_status="VERIFIED").count()
    tampered_count = ReportRecipient.query.filter_by(verification_status="TAMPERED").count()
    pending_count = ReportRecipient.query.filter_by(verification_status="PENDING").count()
    
    recent_users = User.query.order_by(User.id.desc()).limit(5).all()
    recent_certs = Certificate.query.order_by(Certificate.id.desc()).limit(10).all()

    return render_template(
        "admin/dashboard.html",
        total_users=total_users,
        total_departments=total_departments,
        total_reports=total_reports,
        total_certs=total_certs,
        verified_count=verified_count,
        tampered_count=tampered_count,
        pending_count=pending_count,
        recent_users=recent_users,
        recent_certs=recent_certs
    )

@admin_bp.route("/certificates")
@login_required
@roles_required(RoleEnum.ADMIN)
def certificates():
    certs = Certificate.query.order_by(Certificate.id.desc()).all()
    return render_template("admin/certificates.html", certs=certs)

@admin_bp.route("/certificates/revoke/<int:cert_id>", methods=["POST"])
@login_required
@roles_required(RoleEnum.ADMIN)
def revoke_certificate(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    reason = request.form.get("reason", "Administrative key revocation")

    cert.is_revoked = True
    cert.revoked_at = datetime.now(timezone.utc)
    cert.revocation_reason = reason
    db.session.commit()

    log_event(
        "CERTIFICATE_REVOKED",
        target_resource=f"Cert:{cert.serial_number}",
        details={"serial": cert.serial_number, "reason": reason},
        actor_id=current_user.id
    )

    flash(f"Certificate serial {cert.serial_number} has been REVOKED and added to the CRL.", "warning")
    return redirect(url_for("admin.certificates"))

@admin_bp.route("/export-audit-csv")
@login_required
@roles_required(RoleEnum.ADMIN, RoleEnum.AUDITOR)
def export_audit_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Sequence", "Timestamp_UTC", "Actor_ID", "Action", "Target_Resource", "Previous_Hash", "Current_Hash", "IP_Address"])
    
    logs = AuditLog.query.order_by(AuditLog.sequence_number.asc()).all()
    for l in logs:
        writer.writerow([
            l.sequence_number,
            l.timestamp.isoformat(),
            l.actor_id,
            l.action,
            l.target_resource,
            l.prev_hash,
            l.curr_hash,
            l.ip_address
        ])
        
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=securemed_audit_ledger.csv"}
    )
