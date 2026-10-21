from flask_wtf import FlaskForm
from wtforms import TextAreaField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length

class BreakGlassForm(FlaskForm):
    patient_id = SelectField("Emergency Patient Record", coerce=int, validators=[DataRequired()])
    reason = TextAreaField("Mandatory Emergency Clinical Justification", validators=[
        DataRequired(),
        Length(min=15, message="Mandatory justification must be at least 15 characters describing the clinical emergency.")
    ])
    submit = SubmitField("Execute Emergency Break-Glass Override")
