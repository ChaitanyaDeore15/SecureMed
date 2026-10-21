import pytest
from app import create_app
from config import TestConfig
from app.extensions import db
from app.models import User, RoleEnum

@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

def test_user_password_hashing(app):
    with app.app_context():
        user = User(
            username="dr_alice",
            email="alice@securemed.local",
            full_name="Dr. Alice Smith",
            role=RoleEnum.DOCTOR
        )
        user.set_password("CorrectHorseBatteryStaple123!")
        db.session.add(user)
        db.session.commit()

        # Check Argon2 hashing
        assert user.password_hash.startswith("$argon2id$")
        assert user.verify_password("CorrectHorseBatteryStaple123!") is True
        assert user.verify_password("WrongPassword123") is False

def test_security_headers(client):
    response = client.get("/auth/login")
    assert response.status_code == 200
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "Strict-Transport-Security" in response.headers
    assert "Content-Security-Policy" in response.headers

def test_account_lockout(app, client):
    with app.app_context():
        user = User(
            username="dr_bob",
            email="bob@securemed.local",
            full_name="Dr. Bob Jones",
            role=RoleEnum.DOCTOR
        )
        user.set_password("Secret123!")
        db.session.add(user)
        db.session.commit()

        # Attempt 5 failed logins
        for i in range(5):
            client.post("/auth/login", data={
                "username": "dr_bob",
                "password": "wrongpassword"
            })
        
        updated_user = User.query.filter_by(username="dr_bob").first()
        assert updated_user.failed_login_attempts >= 5
        assert updated_user.is_locked() is True
