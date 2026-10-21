from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, TextAreaField, SelectField, SelectMultipleField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length

class ComposeReportForm(FlaskForm):
    title = StringField("Report Title", validators=[DataRequired(), Length(max=256)])
    patient_id = SelectField("Patient", coerce=int, validators=[DataRequired()])
    department_id = SelectField("Originating Department", coerce=int, validators=[DataRequired()])
    report_type_id = SelectField("Clinical Report Type", coerce=int, validators=[DataRequired()])
    
    # Clinical content
    clinical_notes = TextAreaField("Clinical Findings / Report Notes", validators=[DataRequired()])
    diagnostic_impression = TextAreaField("Diagnostic Impression / Recommendation")
    
    # Recipient Selection
    recipient_departments = SelectMultipleField("Recipient Departments", coerce=int)
    recipient_users = SelectMultipleField("Individual Clinical Recipients (Doctors/Staff)", coerce=int)
    
    # Security flags
    is_critical = BooleanField("Mark as Critical Medical Report (Multi-Sig Clearance Required)")
    
    # Optional file attachment (PDF/image) to be encrypted inside payload
    attachment = FileField("Confidential Attachment (PDF, PNG, JPG - max 16MB)", validators=[
        FileAllowed(["pdf", "png", "jpg", "jpeg"], "Only medical PDF/image documents permitted")
    ])
    
    submit = SubmitField("Sign, Encrypt & Dispatch Secure Envelope")
