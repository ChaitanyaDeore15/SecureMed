import uuid
from datetime import datetime, timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask_login import UserMixin
from app.extensions import db, login_manager

ph = PasswordHasher()

class RoleEnum:
    ADMIN = "Admin"
    DEPT_HEAD = "Department Head"
    DOCTOR = "Doctor"
    TECHNICIAN = "Technician"
    PHARMACIST = "Pharmacist"
    BILLING = "Billing Staff"
    RECORDS_OFFICER = "Medical Records Officer"
    PATIENT = "Patient"
    AUDITOR = "Auditor"

    ALL_ROLES = [
        ADMIN, DEPT_HEAD, DOCTOR, TECHNICIAN, PHARMACIST,
        BILLING, RECORDS_OFFICER, PATIENT, AUDITOR
    ]

class UserDepartment(db.Model):
    __tablename__ = "user_departments"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey("departments.id", ondelete="CASCADE"), nullable=False)
    is_primary = db.Column(db.Boolean, default=True)

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(64), nullable=False, default=RoleEnum.DOCTOR)
    
    # 2FA
    totp_secret = db.Column(db.String(64), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False)
    
    # Cryptographic keys
    # Private key encrypted with scrypt-derived key from password (AES-256-GCM)
    encrypted_private_key = db.Column(db.Text, nullable=True)
    public_key_pem = db.Column(db.Text, nullable=True)
    key_algorithm = db.Column(db.String(16), default="RSA") # RSA or ECC
    
    # Security tracking
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    departments = db.relationship("Department", secondary="user_departments", back_populates="members")
    certificates = db.relationship("Certificate", backref="user", lazy="dynamic")
    authored_reports = db.relationship("Report", backref="author", foreign_keys="Report.author_id")

    def set_password(self, password: str):
        self.password_hash = ph.hash(password)

    def verify_password(self, password: str) -> bool:
        try:
            return ph.verify(self.password_hash, password)
        except VerifyMismatchError:
            return False

    def is_locked(self) -> bool:
        if self.locked_until:
            if datetime.now(timezone.utc) < self.locked_until.replace(tzinfo=timezone.utc if self.locked_until.tzinfo is None else None):
                return True
        return False

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Department(db.Model):
    __tablename__ = "departments"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    code = db.Column(db.String(32), unique=True, nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    head_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    
    # Department shared encryption keys
    public_key_pem = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    members = db.relationship("User", secondary="user_departments", back_populates="departments")
    report_types = db.relationship("ReportType", backref="department", cascade="all, delete-orphan")
    key_wraps = db.relationship("DepartmentKeyWrap", backref="department", cascade="all, delete-orphan")

class DepartmentKeyWrap(db.Model):
    """Department private key wrapped separately for each department member."""
    __tablename__ = "department_key_wraps"

    id = db.Column(db.Integer, primary_key=True)
    department_id = db.Column(db.Integer, db.ForeignKey("departments.id", ondelete="CASCADE"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    encrypted_dept_key = db.Column(db.Text, nullable=False) # JSON or Base64 wrapped blob
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship("User", backref="dept_key_wraps")

class Certificate(db.Model):
    __tablename__ = "certificates"

    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(64), unique=True, nullable=False, index=True)
    subject_type = db.Column(db.String(32), nullable=False) # 'USER' or 'DEPARTMENT'
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    department_id = db.Column(db.Integer, db.ForeignKey("departments.id", ondelete="CASCADE"), nullable=True)
    cert_pem = db.Column(db.Text, nullable=False)
    issued_at = db.Column(db.DateTime, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_revoked = db.Column(db.Boolean, default=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    revocation_reason = db.Column(db.String(128), nullable=True)

class DepartmentAccessMatrix(db.Model):
    __tablename__ = "department_access_matrix"

    id = db.Column(db.Integer, primary_key=True)
    source_dept_id = db.Column(db.Integer, db.ForeignKey("departments.id", ondelete="CASCADE"), nullable=False)
    target_dept_id = db.Column(db.Integer, db.ForeignKey("departments.id", ondelete="CASCADE"), nullable=False)
    is_allowed = db.Column(db.Boolean, default=True)

class ReportType(db.Model):
    __tablename__ = "report_types"

    id = db.Column(db.Integer, primary_key=True)
    department_id = db.Column(db.Integer, db.ForeignKey("departments.id", ondelete="CASCADE"), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    code = db.Column(db.String(64), nullable=False)
    schema_fields = db.Column(db.Text, nullable=True) # JSON array of fields

class Patient(db.Model):
    __tablename__ = "patients"

    id = db.Column(db.Integer, primary_key=True)
    mrn = db.Column(db.String(64), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(120), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(16), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    reports = db.relationship("Report", backref="patient", lazy="dynamic")
    consents = db.relationship("PatientConsent", backref="patient", cascade="all, delete-orphan")

class PatientConsent(db.Model):
    __tablename__ = "patient_consents"

    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id", ondelete="CASCADE"), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey("departments.id", ondelete="CASCADE"), nullable=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    can_view = db.Column(db.Boolean, default=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    report_uid = db.Column(db.String(64), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id", ondelete="CASCADE"), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    department_id = db.Column(db.Integer, db.ForeignKey("departments.id", ondelete="CASCADE"), nullable=False)
    report_type_id = db.Column(db.Integer, db.ForeignKey("report_types.id", ondelete="SET NULL"), nullable=True)
    
    title = db.Column(db.String(256), nullable=False)
    status = db.Column(db.String(32), default="SENT") # DRAFT, SENT, DELIVERED, VERIFIED, REJECTED
    case_id = db.Column(db.String(64), nullable=True, index=True) # Linked request-response case
    is_critical = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    department = db.relationship("Department")
    report_type = db.relationship("ReportType")
    versions = db.relationship("ReportVersion", backref="report", cascade="all, delete-orphan", order_by="ReportVersion.version_number")

class ReportVersion(db.Model):
    __tablename__ = "report_versions"

    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey("reports.id", ondelete="CASCADE"), nullable=False)
    version_number = db.Column(db.Integer, default=1)
    
    # Cryptographic Envelope
    ciphertext_path = db.Column(db.String(512), nullable=False)
    nonce = db.Column(db.String(64), nullable=False) # 96-bit AES-GCM nonce in hex
    sender_signature = db.Column(db.Text, nullable=False) # Base64 or Hex signature
    plaintext_sha256 = db.Column(db.String(64), nullable=False) # Hex digest
    message_nonce = db.Column(db.String(64), unique=True, nullable=False) # Anti-replay unique nonce
    timestamp_iso = db.Column(db.String(64), nullable=False) # UTC timestamp string at signing
    sender_cert_serial = db.Column(db.String(64), nullable=True)
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    recipients = db.relationship("ReportRecipient", backref="report_version", cascade="all, delete-orphan")

class ReportRecipient(db.Model):
    __tablename__ = "report_recipients"

    id = db.Column(db.Integer, primary_key=True)
    report_version_id = db.Column(db.Integer, db.ForeignKey("report_versions.id", ondelete="CASCADE"), nullable=False)
    recipient_type = db.Column(db.String(16), nullable=False) # 'USER' or 'DEPARTMENT'
    recipient_id = db.Column(db.Integer, nullable=False) # user_id or dept_id
    
    # Wrapped session key for this recipient
    wrapped_session_key = db.Column(db.Text, nullable=False) # Base64 wrapped key
    
    delivery_status = db.Column(db.String(32), default="DELIVERED")
    verification_status = db.Column(db.String(32), default="PENDING") # PENDING, VERIFIED, TAMPERED, REPLAY, REVOKED
    verification_notes = db.Column(db.Text, nullable=True)
    verified_at = db.Column(db.DateTime, nullable=True)

class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    sequence_number = db.Column(db.Integer, unique=True, nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action = db.Column(db.String(64), nullable=False) # LOGIN, ENCRYPT, DECRYPT, VERIFY_SUCCESS, VERIFY_FAIL, etc.
    target_resource = db.Column(db.String(128), nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    
    # Cryptographic Hash Chaining
    prev_hash = db.Column(db.String(64), nullable=False)
    curr_hash = db.Column(db.String(64), nullable=False)

    actor = db.relationship("User")

class ReplayNonce(db.Model):
    __tablename__ = "replay_nonces"

    id = db.Column(db.Integer, primary_key=True)
    nonce = db.Column(db.String(64), unique=True, nullable=False, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
