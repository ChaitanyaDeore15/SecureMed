import base64
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, abort
from flask_login import login_required, current_user
from app.extensions import db
from app.models import Report, ReportVersion, ReportRecipient, Patient, Department, ReportType, User, RoleEnum
from app.reports.forms import ComposeReportForm
from app.reports.service import create_and_send_report, decrypt_and_verify_report
from app.auth.decorators import roles_required

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")

@reports_bp.route("/inbox")
@login_required
def inbox():
    # Reports addressed to current user or to user's departments
    user_dept_ids = [d.id for d in current_user.departments]
    
    # Query recipient records
    recipient_entries = ReportRecipient.query.filter(
        ((ReportRecipient.recipient_type == "USER") & (ReportRecipient.recipient_id == current_user.id)) |
        ((ReportRecipient.recipient_type == "DEPARTMENT") & (ReportRecipient.recipient_id.in_(user_dept_ids)))
    ).order_by(ReportRecipient.id.desc()).all()
    
    return render_template("reports/inbox.html", recipient_entries=recipient_entries)

@reports_bp.route("/outbox")
@login_required
def outbox():
    authored_reports = Report.query.filter_by(author_id=current_user.id).order_by(Report.id.desc()).all()
    return render_template("reports/outbox.html", reports=authored_reports)

@reports_bp.route("/compose", methods=["GET", "POST"])
@login_required
@roles_required(RoleEnum.ADMIN, RoleEnum.DEPT_HEAD, RoleEnum.DOCTOR, RoleEnum.TECHNICIAN, RoleEnum.PHARMACIST)
def compose():
    form = ComposeReportForm()
    
    # Populate dropdown choices
    form.patient_id.choices = [(p.id, f"{p.full_name} (MRN: {p.mrn})") for p in Patient.query.all()]
    form.department_id.choices = [(d.id, d.name) for d in Department.query.filter_by(is_active=True).all()]
    form.report_type_id.choices = [(rt.id, f"{rt.name} ({rt.code})") for rt in ReportType.query.all()]
    form.recipient_departments.choices = [(d.id, d.name) for d in Department.query.filter_by(is_active=True).all()]
    form.recipient_users.choices = [(u.id, f"{u.full_name} ({u.role})") for u in User.query.filter(User.id != current_user.id).all()]

    if form.validate_on_submit():
        user_pwd = session.get("user_pwd_temp")
        if not user_pwd:
            flash("Session security token expired. Please re-enter your password to unlock your private signing key.", "warning")
            return redirect(url_for("auth.login"))

        recipients_targets = []
        for dept_id in form.recipient_departments.data:
            recipients_targets.append(("DEPARTMENT", dept_id))
        for uid in form.recipient_users.data:
            recipients_targets.append(("USER", uid))

        if not recipients_targets:
            flash("You must specify at least one department or clinician recipient.", "danger")
            return render_template("reports/compose.html", form=form)

        # Build payload dict
        attachment_b64 = None
        attachment_name = None
        if form.attachment.data:
            f = form.attachment.data
            attachment_name = f.filename
            attachment_b64 = base64.b64encode(f.read()).decode("utf-8")

        payload = {
            "title": form.title.data.strip(),
            "patient_id": form.patient_id.data,
            "clinical_notes": form.clinical_notes.data.strip(),
            "diagnostic_impression": form.diagnostic_impression.data.strip() if form.diagnostic_impression.data else "",
            "attachment_name": attachment_name,
            "attachment_b64": attachment_b64
        }

        try:
            report = create_and_send_report(
                sender=current_user,
                sender_password=user_pwd,
                patient_id=form.patient_id.data,
                department_id=form.department_id.data,
                report_type_id=form.report_type_id.data,
                title=form.title.data.strip(),
                payload_dict=payload,
                recipient_targets=recipients_targets,
                is_critical=form.is_critical.data
            )
            flash(f"Secure envelope successfully signed and encrypted with AES-256-GCM. Report #{report.id} dispatched.", "success")
            return redirect(url_for("reports.outbox"))
        except Exception as e:
            flash(f"Cryptographic dispatch error: {str(e)}", "danger")

    return render_template("reports/compose.html", form=form)

@reports_bp.route("/view/<int:version_id>")
@login_required
def view_report(version_id):
    version = ReportVersion.query.get_or_404(version_id)
    user_pwd = session.get("user_pwd_temp")

    if not user_pwd:
        flash("Re-authentication required to unlock private key for decryption.", "warning")
        return redirect(url_for("auth.login"))

    verification = decrypt_and_verify_report(version, current_user, user_pwd)
    return render_template("reports/view.html", version=version, verification=verification)
