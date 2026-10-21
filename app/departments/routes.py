from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.extensions import db
from app.models import Department, User, RoleEnum, ReportType, DepartmentAccessMatrix, Certificate
from app.departments.forms import DepartmentForm, ReportTypeForm, AccessMatrixForm
from app.departments.service import create_department_with_keys
from app.auth.decorators import roles_required

departments_bp = Blueprint("departments", __name__, url_prefix="/departments")

@departments_bp.route("/")
@login_required
def index():
    departments = Department.query.all()
    matrix_rules = DepartmentAccessMatrix.query.all()
    return render_template("departments/index.html", departments=departments, matrix_rules=matrix_rules)

@departments_bp.route("/create", methods=["GET", "POST"])
@login_required
@roles_required(RoleEnum.ADMIN)
def create():
    form = DepartmentForm()
    users = User.query.filter(User.role.in_([RoleEnum.ADMIN, RoleEnum.DEPT_HEAD, RoleEnum.DOCTOR])).all()
    form.head_id.choices = [(0, "-- None Selected --")] + [(u.id, f"{u.full_name} ({u.role})") for u in users]

    if form.validate_on_submit():
        head_id = form.head_id.data if form.head_id.data != 0 else None
        try:
            dept = create_department_with_keys(
                name=form.name.data.strip(),
                code=form.code.data.strip(),
                description=form.description.data.strip() if form.description.data else "",
                head_id=head_id,
                initial_member_ids=[head_id] if head_id else []
            )
            flash(f"Department '{dept.name}' ({dept.code}) created with X.509 Certificate and RSA-2048 department key.", "success")
            return redirect(url_for("departments.index"))
        except Exception as e:
            flash(f"Failed to provision department: {str(e)}", "danger")

    return render_template("departments/create.html", form=form)

@departments_bp.route("/matrix", methods=["GET", "POST"])
@login_required
@roles_required(RoleEnum.ADMIN)
def matrix():
    form = AccessMatrixForm()
    depts = Department.query.filter_by(is_active=True).all()
    form.source_dept_id.choices = [(d.id, d.name) for d in depts]
    form.target_dept_id.choices = [(d.id, d.name) for d in depts]

    if form.validate_on_submit():
        rule = DepartmentAccessMatrix.query.filter_by(
            source_dept_id=form.source_dept_id.data,
            target_dept_id=form.target_dept_id.data
        ).first()

        if not rule:
            rule = DepartmentAccessMatrix(
                source_dept_id=form.source_dept_id.data,
                target_dept_id=form.target_dept_id.data,
                is_allowed=form.is_allowed.data
            )
            db.session.add(rule)
        else:
            rule.is_allowed = form.is_allowed.data

        db.session.commit()
        flash("Department Access Matrix policy updated successfully.", "success")
        return redirect(url_for("departments.matrix"))

    rules = DepartmentAccessMatrix.query.all()
    return render_template("departments/matrix.html", form=form, rules=rules, depts=depts)
