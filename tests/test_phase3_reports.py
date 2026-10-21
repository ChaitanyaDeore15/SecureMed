import pytest
from datetime import datetime, date
from app import create_app
from config import TestConfig
from app.extensions import db
from app.models import (
    User, Department, Patient, ReportType, RoleEnum, Certificate
)
from app.crypto.keys import (
    generate_rsa_keypair,
    encrypt_private_key_with_password,
    public_key_to_pem
)
from app.crypto.ca import get_or_create_root_ca, issue_certificate, cert_to_pem
from app.reports.service import create_and_send_report, decrypt_and_verify_report

@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

def test_full_report_exchange_and_verify(app):
    with app.app_context():
        # Setup CA
        ca_cert, ca_key = get_or_create_root_ca(app.config["CA_DIR"])

        # 1. Setup Doctor Alice
        alice_pwd = "AliceDoctorPassword123!"
        alice_priv, alice_pub = generate_rsa_keypair(2048)
        alice_enc_priv = encrypt_private_key_with_password(alice_priv, alice_pwd)
        alice = User(
            username="dr_alice",
            email="alice@hospital.local",
            full_name="Dr. Alice Smith",
            role=RoleEnum.DOCTOR,
            encrypted_private_key=alice_enc_priv,
            public_key_pem=public_key_to_pem(alice_pub)
        )
        alice.set_password(alice_pwd)
        db.session.add(alice)
        db.session.commit()

        # Alice Certificate
        alice_cert = issue_certificate("Dr. Alice Smith", alice_pub, ca_cert, ca_key, 365, "Doctor")
        cert_record_a = Certificate(
            serial_number=str(alice_cert.serial_number),
            subject_type="USER",
            user_id=alice.id,
            cert_pem=cert_to_pem(alice_cert),
            issued_at=datetime.utcnow(),
            expires_at=datetime.utcnow()
        )
        db.session.add(cert_record_a)

        # 2. Setup Lab Tech Bob
        bob_pwd = "BobTechnicianPassword123!"
        bob_priv, bob_pub = generate_rsa_keypair(2048)
        bob_enc_priv = encrypt_private_key_with_password(bob_priv, bob_pwd)
        bob = User(
            username="tech_bob",
            email="bob@hospital.local",
            full_name="Bob Jones",
            role=RoleEnum.TECHNICIAN,
            encrypted_private_key=bob_enc_priv,
            public_key_pem=public_key_to_pem(bob_pub)
        )
        bob.set_password(bob_pwd)
        db.session.add(bob)
        db.session.commit()

        # Bob Certificate
        bob_cert = issue_certificate("Bob Jones", bob_pub, ca_cert, ca_key, 365, "Technician")
        cert_record_b = Certificate(
            serial_number=str(bob_cert.serial_number),
            subject_type="USER",
            user_id=bob.id,
            cert_pem=cert_to_pem(bob_cert),
            issued_at=datetime.utcnow(),
            expires_at=datetime.utcnow()
        )
        db.session.add(cert_record_b)

        # 3. Setup Department, Patient, ReportType
        dept = Department(name="Pathology/Lab", code="PATH", description="Clinical Pathology")
        patient = Patient(mrn="MRN-100234", full_name="John Doe", dob=date(1985, 4, 12), gender="Male")
        db.session.add_all([dept, patient])
        db.session.commit()

        rtype = ReportType(department_id=dept.id, name="Complete Blood Count", code="CBC")
        db.session.add(rtype)
        db.session.commit()

        # 4. Doctor Alice creates, encrypts, and sends report addressed to Bob
        payload = {
            "title": "STAT CBC Blood Count Result",
            "clinical_notes": "Hemoglobin 14.5 g/dL, Platelets normal. No abnormal blasts detected.",
            "diagnostic_impression": "Normal blood panel."
        }
        report = create_and_send_report(
            sender=alice,
            sender_password=alice_pwd,
            patient_id=patient.id,
            department_id=dept.id,
            report_type_id=rtype.id,
            title="STAT CBC Blood Count Result",
            payload_dict=payload,
            recipient_targets=[("USER", bob.id)]
        )

        assert report.id is not None
        version = report.versions[0]
        assert len(version.recipients) == 1
        assert version.plaintext_sha256 is not None

        # 5. Bob receives and decrypts/verifies report
        verification = decrypt_and_verify_report(version, bob, bob_pwd)
        assert verification["overall_status"] == "VERIFIED"
        assert verification["ca_cert_valid"] is True
        assert verification["replay_passed"] is True
        assert verification["decryption_passed"] is True
        assert verification["sha256_match"] is True
        assert verification["signature_valid"] is True
        assert verification["payload"]["clinical_notes"] == payload["clinical_notes"]
