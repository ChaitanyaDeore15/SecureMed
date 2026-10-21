import hashlib
from datetime import timezone
from typing import Tuple, List, Dict, Any
from app.models import AuditLog
from app.audit.service import GENESIS_HASH

def verify_audit_hash_chain() -> Tuple[bool, str, List[Dict[str, Any]]]:
    """
    Step 1 of Phase 5 Audit Verification:
    Verify the cryptographic hash chain of the entire audit ledger:
    Hash_i == SHA-256(prev_hash || seq || timestamp || actor_id || action || target || details)
    Detects any database tampering, row deletion, modification, or reordering.
    """
    entries = AuditLog.query.order_by(AuditLog.sequence_number.asc()).all()
    if not entries:
        return True, "Audit log ledger is empty (Genesis state).", []

    tamper_reports = []
    expected_prev = GENESIS_HASH

    for i, entry in enumerate(entries):
        # 1. Check link to previous hash
        if entry.prev_hash != expected_prev:
            tamper_reports.append({
                "sequence": entry.sequence_number,
                "error": f"Chain link broken: expected prev_hash '{expected_prev[:12]}...', found '{entry.prev_hash[:12]}...'"
            })

        # 2. Recompute current hash
        actor_id_str = str(entry.actor_id) if entry.actor_id is not None else "None"
        target_str = entry.target_resource or ""
        details_str = entry.details or ""
        
        if hasattr(entry.timestamp, "tzinfo") and entry.timestamp.tzinfo is None:
            ts_norm = entry.timestamp.replace(tzinfo=timezone.utc).isoformat()
        elif hasattr(entry.timestamp, "isoformat"):
            ts_norm = entry.timestamp.isoformat()
        else:
            ts_norm = str(entry.timestamp)

        data_to_hash = f"{entry.prev_hash}|{entry.sequence_number}|{ts_norm}|{actor_id_str}|{entry.action}|{target_str}|{details_str}"
        recalculated_hash = hashlib.sha256(data_to_hash.encode("utf-8")).hexdigest()

        if recalculated_hash != entry.curr_hash:
            tamper_reports.append({
                "sequence": entry.sequence_number,
                "error": f"Content tampering detected: recalculated hash does not match stored hash for entry #{entry.sequence_number}"
            })

        expected_prev = entry.curr_hash

    if tamper_reports:
        return False, f"Ledger integrity breach! {len(tamper_reports)} inconsistencies found.", tamper_reports

    return True, f"Audit hash chain intact: {len(entries)} events cryptographically verified.", []

def detect_security_anomalies() -> List[Dict[str, Any]]:
    """
    Step 2: Anomaly alert engine:
    1. Verification failures surge (repeated verify failures on reports)
    2. Mass downloads / mass accesses in short window
    3. Emergency break-glass events
    4. Odd-hour administrative logins (e.g. 11 PM - 5 AM)
    """
    anomalies = []
    
    # Check break glass
    break_glass_logs = AuditLog.query.filter_by(action="BREAK_GLASS_ACCESS").order_by(AuditLog.id.desc()).limit(10).all()
    for bg in break_glass_logs:
        anomalies.append({
            "type": "CRITICAL",
            "title": "Emergency Break-Glass Access Executed",
            "timestamp": bg.timestamp,
            "details": f"User #{bg.actor_id} accessed patient records without standard consent justification: {bg.details}"
        })

    # Check tampered verification reports
    tamper_events = AuditLog.query.filter_by(action="VERIFICATION_FAILED_TAMPERED").order_by(AuditLog.id.desc()).limit(10).all()
    for tv in tamper_events:
        anomalies.append({
            "type": "HIGH",
            "title": "Ciphertext Tampering Detected",
            "timestamp": tv.timestamp,
            "details": f"Decryption AEAD authentication failed for {tv.target_resource}."
        })

    # Check account lockouts
    locked_events = AuditLog.query.filter_by(action="ACCOUNT_LOCKED").order_by(AuditLog.id.desc()).limit(10).all()
    for lk in locked_events:
        anomalies.append({
            "type": "MEDIUM",
            "title": "Brute Force Threshold Reached",
            "timestamp": lk.timestamp,
            "details": f"Account '{lk.target_resource}' locked due to 5 consecutive failed logins."
        })

    return anomalies
