import json
import hashlib
from datetime import datetime, timezone
from flask import request
from flask_login import current_user
from app.extensions import db
from app.models import AuditLog

GENESIS_HASH = "0" * 64

def log_event(action: str, target_resource: str = None, details: dict = None, actor_id: int = None):
    """
    Append an event to the hash-chained audit log ledger.
    Hash_i = SHA-256(prev_hash || sequence_number || timestamp || actor_id || action || target || details)
    """
    last_entry = AuditLog.query.order_by(AuditLog.sequence_number.desc()).first()
    
    if last_entry:
        seq = last_entry.sequence_number + 1
        prev_hash = last_entry.curr_hash
    else:
        seq = 1
        prev_hash = GENESIS_HASH
        
    actual_actor_id = actor_id
    if actual_actor_id is None and current_user and current_user.is_authenticated:
        actual_actor_id = current_user.id
        
    details_str = json.dumps(details, sort_keys=True) if details else ""
    ip_addr = request.remote_addr if request else "127.0.0.1"
    now = datetime.now(timezone.utc)
    ts_str = now.isoformat()
    
    data_to_hash = f"{prev_hash}|{seq}|{ts_str}|{actual_actor_id}|{action}|{target_resource or ''}|{details_str}"
    curr_hash = hashlib.sha256(data_to_hash.encode("utf-8")).hexdigest()
    
    entry = AuditLog(
        sequence_number=seq,
        timestamp=now,
        actor_id=actual_actor_id,
        action=action,
        target_resource=target_resource,
        details=details_str,
        ip_address=ip_addr,
        prev_hash=prev_hash,
        curr_hash=curr_hash
    )
    db.session.add(entry)
    db.session.commit()
    return entry
