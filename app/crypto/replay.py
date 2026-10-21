import uuid
from datetime import datetime, timezone, timedelta
from typing import Tuple, Set

def generate_message_nonce() -> str:
    """Generate a high-entropy unique message nonce for anti-replay protection."""
    return f"{int(datetime.now(timezone.utc).timestamp())}-{uuid.uuid4().hex}"

def verify_freshness_and_nonce(
    timestamp_iso: str,
    message_nonce: str,
    seen_nonces: Set[str],
    allowed_window_seconds: int = 300
) -> Tuple[bool, str]:
    """
    Step 3 of Cryptographic Receiver side:
    Reject if:
    1. Timestamp is outside the allowed sliding window (+/- allowed_window_seconds).
    2. Message nonce was already used (replay protection).
    """
    try:
        msg_time = datetime.fromisoformat(timestamp_iso)
        if msg_time.tzinfo is None:
            msg_time = msg_time.replace(tzinfo=timezone.utc)
    except Exception:
        return False, "Invalid ISO timestamp format"

    now = datetime.now(timezone.utc)
    drift = abs((now - msg_time).total_seconds())

    if drift > allowed_window_seconds:
        return False, f"Timestamp is stale or outside allowed freshness window (drift: {drift:.1f}s > {allowed_window_seconds}s)"

    if message_nonce in seen_nonces:
        return False, f"Replay attack detected: Nonce '{message_nonce}' has already been processed"

    return True, "Freshness and anti-replay verification passed"
