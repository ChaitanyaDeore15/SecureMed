import pytest
from app import create_app
from config import TestConfig
from app.extensions import db
from app.models import Department, Certificate, DepartmentAccessMatrix, RoleEnum, User
from app.crypto.keys import generate_rsa_keypair, encrypt_private_key_with_password, public_key_to_pem
from app.departments.service import create_department_with_keys, check_access_matrix_permission

@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

def test_dynamic_department_provisioning(app):
    with app.app_context():
        # Provision Head user
        head = User(
            username="head_cardio",
            email="head@cardio.local",
            full_name="Dr. Cardio Head",
            role=RoleEnum.DEPT_HEAD
        )
        priv, pub = generate_rsa_keypair(2048)
        head.encrypted_private_key = encrypt_private_key_with_password(priv, "HeadPassword123!")
        head.public_key_pem = public_key_to_pem(pub)
        head.set_password("HeadPassword123!")
        db.session.add(head)
        db.session.commit()

        # Dynamic creation of Cardiology department
        dept = create_department_with_keys(
            name="Cardiology",
            code="CARD",
            description="Cardiovascular Medicine",
            head_id=head.id,
            initial_member_ids=[head.id]
        )

        assert dept.id is not None
        assert dept.code == "CARD"
        assert dept.public_key_pem is not None

        # Verify X.509 cert issued
        cert = Certificate.query.filter_by(subject_type="DEPARTMENT", department_id=dept.id).first()
        assert cert is not None
        assert cert.serial_number is not None

        # Verify department key wrapped for head
        assert len(dept.key_wraps) == 1
        assert dept.key_wraps[0].user_id == head.id

def test_access_matrix_rules(app):
    with app.app_context():
        d1 = Department(name="Oncology", code="ONC")
        d2 = Department(name="Pharmacy", code="PHARM")
        db.session.add_all([d1, d2])
        db.session.commit()

        # Default allowed
        assert check_access_matrix_permission(d1.id, d2.id) is True

        # Explicit deny rule
        rule = DepartmentAccessMatrix(source_dept_id=d1.id, target_dept_id=d2.id, is_allowed=False)
        db.session.add(rule)
        db.session.commit()

        assert check_access_matrix_permission(d1.id, d2.id) is False
