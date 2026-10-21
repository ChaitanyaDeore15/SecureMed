from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from app.extensions import db
from app.models import Patient, Report, PatientConsent, Department, User, RoleEnum, AuditLog
from app.patients.forms import ConsentForm
from app.auth.decorators import roles_required
from app.audit.service import log_event

patients_bp = Blueprint("patients", __name__, url_prefix="/patients")

@patients_bp.route("/portal")
@login_required
@roles_required(RoleEnum.PATIENT, RoleEnum.ADMIN)
def portal():
    # If patient role, locate patient profile linked to current user
    patient = None
    if current_user.role == RoleEnum.PATIENT:
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if not patient:
            # Fallback for demo patients matching username
            patient = Patient.query.filter_by(mrn="MRN-100234").first()
    else:
        patient_id = request.args.get("id", type=int)
        patient = Patient.query.get(patient_id) if patient_id else Patient.query.first()

    if not patient:
        flash("No clinical patient profile found.", "warning")
        return redirect(url_for("reports.inbox"))

    reports = Report.query.filter_by(patient_id=patient.id).order_by(Report.id.desc()).all()
    consents = PatientConsent.query.filter_by(patient_id=patient.id).all()
    
    # "Who viewed my data" queries
    access_logs = AuditLog.query.filter(
        AuditLog.target_resource.like(f"%Patient:{patient.id}%") |
        AuditLog.details.like(f"%{patient.mrn}%")
    ).order_by(AuditLog.id.desc()).limit(20).all()

    return render_template("patients/portal.html", patient=patient, reports=reports, consents=consents, access_logs=access_logs)

@patients_bp.route("/consent/edit", methods=["GET", "POST"])
@login_required
@roles_required(RoleEnum.PATIENT, RoleEnum.ADMIN)
def edit_consent():
    form = ConsentForm()
    depts = Department.query.filter_by(is_active=True).all()
    docs = User.query.filter_by(role=RoleEnum.DOCTOR).all()

    form.department_id.choices = [(0, "-- None --")] + [(d.id, d.name) for d in depts]
    form.doctor_id.choices = [(0, "-- None --")] + [(u.id, u.full_name) for u in docs]

    patient = Patient.query.filter_by(user_id=current_user.id).first() or Patient.query.first()

    if form.validate_on_submit():
        dept_id = form.department_id.data if form.department_id.data != 0 else None
        doc_id = form.doctor_id.data if form.doctor_id.data != 0 else None

        consent = PatientConsent(
            patient_id=patient.id,
            department_id=dept_id,
            doctor_id=doc_id,
            can_view=form.can_view.data
        )
        db.session.add(consent)
        db.session.commit()

        log_event(
            "PATIENT_CONSENT_UPDATED",
            target_resource=f"Patient:{patient.id}",
            details={"dept_id": dept_id, "doc_id": doc_id, "can_view": form.can_view.data},
            actor_id=current_user.id
        )

        flash("Patient access consent policy updated successfully.", "success")
        return redirect(url_for("patients.portal"))

    return render_template("patients/consent.html", form=form)
