from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length

class DepartmentForm(FlaskForm):
    name = StringField("Department Name", validators=[DataRequired(), Length(min=2, max=120)])
    code = StringField("Department Code (e.g. RAD, PATH)", validators=[DataRequired(), Length(min=2, max=16)])
    description = TextAreaField("Description & Medical Scope")
    head_id = SelectField("Department Head", coerce=int)
    is_active = BooleanField("Department Active", default=True)
    submit = SubmitField("Save Department & Issue Cryptographic Certificate")

class ReportTypeForm(FlaskForm):
    department_id = SelectField("Department", coerce=int, validators=[DataRequired()])
    name = StringField("Report Type Name", validators=[DataRequired(), Length(max=120)])
    code = StringField("Code (e.g. CBC, MRI_BRAIN)", validators=[DataRequired(), Length(max=32)])
    schema_fields = TextAreaField("Template Form Fields (JSON format)")
    submit = SubmitField("Save Report Type Template")

class AccessMatrixForm(FlaskForm):
    source_dept_id = SelectField("Originating Department", coerce=int, validators=[DataRequired()])
    target_dept_id = SelectField("Destination Department", coerce=int, validators=[DataRequired()])
    is_allowed = BooleanField("Exchange Channel Permitted", default=True)
    submit = SubmitField("Update Access Policy Rule")
