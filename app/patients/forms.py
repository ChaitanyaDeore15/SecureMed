from flask_wtf import FlaskForm
from wtforms import SelectField, BooleanField, SubmitField
from wtforms.validators import DataRequired

class ConsentForm(FlaskForm):
    department_id = SelectField("Target Department", coerce=int)
    doctor_id = SelectField("Target Clinician", coerce=int)
    can_view = BooleanField("Permit Access to Clinical Record", default=True)
    submit = SubmitField("Save Consent Policy")
