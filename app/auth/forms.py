from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from app.models import RoleEnum

class LoginForm(FlaskForm):
    username = StringField("Username or Email", validators=[DataRequired(), Length(min=3, max=120)])
    password = PasswordField("Password", validators=[DataRequired()])
    totp_token = StringField("2FA Code (if enabled)", validators=[Length(min=0, max=6)])
    submit = SubmitField("Sign In to Terminal")

class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField("Email Address", validators=[DataRequired(), Email(), Length(max=120)])
    full_name = StringField("Full Name", validators=[DataRequired(), Length(min=2, max=120)])
    role = SelectField("Hospital Role", choices=[(r, r) for r in RoleEnum.ALL_ROLES], default=RoleEnum.DOCTOR)
    password = PasswordField("Master Password", validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long.")
    ])
    confirm_password = PasswordField("Confirm Password", validators=[
        DataRequired(),
        EqualTo("password", message="Passwords must match.")
    ])
    submit = SubmitField("Register & Generate Keypair")
