import pytest
from app import create_app
from config import TestConfig
from app.extensions import db
from app.models import AuditLog, User, RoleEnum
from app.audit.service import log_event
from app.audit.analyzer import verify_audit_hash_chain, detect_security_anomalies

@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

def test_hash_chain_integrity_and_tamper_detection(app):
    with app.app_context():
        # 1. Log several chained events
        log_event("LOGIN_SUCCESS", "User:alice", {"ip": "127.0.0.1"}, actor_id=1)
        log_event("REPORT_ENCRYPTED", "Report:42", {"sha256": "abcdef"}, actor_id=1)
        log_event("REPORT_DECRYPTED", "Report:42", {"status": "VERIFIED"}, actor_id=2)

        # 2. Check chain integrity
        valid, msg, errors = verify_audit_hash_chain()
        assert valid is True
        assert len(errors) == 0

        # 3. Simulate database tampering (modify details in row 2)
        entry2 = AuditLog.query.filter_by(sequence_number=2).first()
        entry2.action = "TAMPERED_ACTION_FORGED"
        db.session.commit()

        # 4. Re-verify chain - must detect tampering!
        tamper_valid, tamper_msg, tamper_errors = verify_audit_hash_chain()
        assert tamper_valid is False
        assert len(tamper_errors) > 0
        assert "Content tampering detected" in tamper_errors[0]["error"] or "Chain link broken" in tamper_errors[0]["error"]

def test_anomaly_detection_break_glass(app):
    with app.app_context():
        log_event("BREAK_GLASS_ACCESS", "Patient:99", {"reason": "Unresponsive trauma patient in ER"}, actor_id=5)
        log_event("VERIFICATION_FAILED_TAMPERED", "Report:101", {"reason": "AEAD tag mismatch"}, actor_id=6)

        alerts = detect_security_anomalies()
        assert len(alerts) >= 2
        titles = [a["title"] for a in alerts]
        assert "Emergency Break-Glass Access Executed" in titles
        assert "Ciphertext Tampering Detected" in titles
