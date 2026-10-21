import os
from datetime import datetime, date, timezone
from app.extensions import db
from app.models import User, Department, Patient, ReportType, RoleEnum, Certificate
from app.crypto.keys import generate_rsa_keypair, encrypt_private_key_with_password, public_key_to_pem
from app.crypto.ca import get_or_create_root_ca, issue_certificate, cert_to_pem
from app.departments.service import create_department_with_keys

DEMO_USERS = [
    ("admin", "admin@securemed.local", "Admin User", RoleEnum.ADMIN, "AdminPass123!"),
    ("dr_alice", "alice@securemed.local", "Dr. Alice Smith", RoleEnum.DOCTOR, "DoctorPass123!"),
    ("dr_carol", "carol@securemed.local", "Dr. Carol Danvers", RoleEnum.DOCTOR, "DoctorPass123!"),
    ("tech_bob", "bob@securemed.local", "Bob Jones (Lab Tech)", RoleEnum.TECHNICIAN, "TechPass123!"),
    ("pharm_dave", "dave@securemed.local", "Dave Pharmacist", RoleEnum.PHARMACIST, "PharmPass123!"),
    ("auditor_eve", "eve@securemed.local", "Eve Auditor", RoleEnum.AUDITOR, "AuditorPass123!"),
    ("patient_john", "john@securemed.local", "John Doe (Patient)", RoleEnum.PATIENT, "PatientPass123!"),
]

DEMO_DEPTS = [
    ("Outpatient Department", "OPD", "General outpatient clinical consultations"),
    ("Pathology/Lab", "PATH", "Clinical laboratory testing & pathology"),
    ("Radiology", "RAD", "Diagnostic imaging (X-Ray, CT, MRI)"),
    ("Pharmacy", "PHARM", "Hospital medication fulfillment"),
    ("Surgery", "SURG", "Operating theaters & surgical care"),
    ("Emergency/ICU", "EMERG", "Acute trauma & intensive resuscitation"),
    ("Cardiology", "CARD", "Cardiovascular interventions & echo"),
    ("Billing/Insurance", "BILL", "Revenue cycle & healthcare claims"),
    ("Medical Records", "HIM", "Health information management & archiving"),
]

def seed_demo_data(app):
    """Seed comprehensive hospital demo data on startup if database is empty."""
    with app.app_context():
        if User.query.first():
            return # Already seeded

        print("--- [SecureMed] Initializing Demo Data & Mini Root CA ---")
        ca_dir = app.config.get("CA_DIR", "instance/ca")
        ca_cert, ca_key = get_or_create_root_ca(ca_dir)

        # 1. Seed Users
        created_users = {}
        for username, email, full_name, role, pwd in DEMO_USERS:
            priv, pub = generate_rsa_keypair(2048)
            enc_priv = encrypt_private_key_with_password(priv, pwd)
            pub_pem = public_key_to_pem(pub)

            user = User(
                username=username,
                email=email,
                full_name=full_name,
                role=role,
                encrypted_private_key=enc_priv,
                public_key_pem=pub_pem
            )
            user.set_password(pwd)
            db.session.add(user)
            db.session.flush()

            # Issue X.509 certificate
            cert = issue_certificate(full_name, pub, ca_cert, ca_key, 365, role)
            cert_rec = Certificate(
                serial_number=str(cert.serial_number),
                subject_type="USER",
                user_id=user.id,
                cert_pem=cert_to_pem(cert),
                issued_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc)
            )
            db.session.add(cert_rec)
            created_users[username] = user

        db.session.commit()

        # 2. Seed Departments
        created_depts = {}
        for name, code, desc in DEMO_DEPTS:
            dept = create_department_with_keys(
                name=name,
                code=code,
                description=desc,
                head_id=created_users["dr_alice"].id,
                initial_member_ids=[created_users["dr_alice"].id, created_users["tech_bob"].id]
            )
            created_depts[code] = dept

        # 3. Seed Patients
        p1 = Patient(
            mrn="MRN-100234",
            full_name="John Doe",
            dob=date(1985, 4, 12),
            gender="Male",
            user_id=created_users["patient_john"].id
        )
        p2 = Patient(
            mrn="MRN-100235",
            full_name="Jane Roe",
            dob=date(1992, 11, 3),
            gender="Female"
        )
        db.session.add_all([p1, p2])
        db.session.commit()

        # 4. Seed Report Types
        rtypes = [
            (created_depts["PATH"].id, "Complete Blood Count", "CBC"),
            (created_depts["RAD"].id, "Chest X-Ray Digital", "CXR"),
            (created_depts["CARD"].id, "Echocardiogram 2D", "ECHO"),
            (created_depts["OPD"].id, "Clinical Consultation Note", "CONSULT"),
        ]
        for dept_id, name, code in rtypes:
            rt = ReportType(department_id=dept_id, name=name, code=code)
            db.session.add(rt)

        db.session.commit()
        print("--- [SecureMed] Demo accounts & certificates seeded successfully. ---")
