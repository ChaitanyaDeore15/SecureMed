import pytest
from datetime import date
from app import create_app
from config import TestConfig
from app.extensions import db
from app.models import Patient, PatientConsent, Department, RoleEnum, User

@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

def test_patient_consent_flow(app):
    with app.app_context():
        patient_user = User(
            username="patient_john",
            email="john@patient.local",
            full_name="John Doe",
            role=RoleEnum.PATIENT
        )
        patient_user.set_password("PatientSecret123!")
        db.session.add(patient_user)
        db.session.commit()

        patient = Patient(
            mrn="MRN-8877",
            full_name="John Doe",
            dob=date(1990, 5, 20),
            gender="Male",
            user_id=patient_user.id
        )
        dept = Department(name="Dermatology", code="DERM")
        db.session.add_all([patient, dept])
        db.session.commit()

        # Create consent directive: Revoke consent from Dermatology
        consent = PatientConsent(
            patient_id=patient.id,
            department_id=dept.id,
            can_view=False
        )
        db.session.add(consent)
        db.session.commit()

        retrieved_consent = PatientConsent.query.filter_by(patient_id=patient.id, department_id=dept.id).first()
        assert retrieved_consent is not None
        assert retrieved_consent.can_view is False
