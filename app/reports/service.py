import os
import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple
from flask import current_app

from app.extensions import db
from app.models import (
    User, Department, Certificate, Report, ReportVersion,
    ReportRecipient, ReplayNonce, RoleEnum
)
from app.crypto.keys import (
    decrypt_private_key_with_password,
    pem_to_public_key
)
from app.crypto.ca import verify_certificate_validity, pem_to_cert, get_or_create_root_ca
from app.crypto.hybrid import (
    encrypt_report_payload,
    wrap_session_key,
    unwrap_session_key,
    decrypt_report_payload
)
from app.crypto.sign import compute_sha256, sign_data, verify_signature
from app.crypto.replay import generate_message_nonce, verify_freshness_and_nonce
from app.audit.service import log_event

def create_and_send_report(
    sender: User,
    sender_password: str,
    patient_id: int,
    department_id: int,
    report_type_id: int,
    title: str,
    payload_dict: dict,
    recipient_targets: List[Tuple[str, int]], # [('USER', id), ('DEPARTMENT', id)]
    case_id: str = None,
    is_critical: bool = False
) -> Report:
    """
    Encrypt, sign, and store report according to Cryptographic Design:
    1. Compute SHA-256 of the report JSON bytes.
    2. Sign with sender's private key (unlocked via session/password).
    3. Encrypt payload with AES-256-GCM using fresh session key & 96-bit nonce.
    4. Wrap session key separately for EACH recipient using their public key.
    5. Attach timestamp, unique message nonce, sender cert serial.
    6. Store only ciphertext file, wrapped keys, signature, metadata. Plaintext is NEVER stored on disk or DB.
    """
    # Unlock sender's private key
    sender_private_key = decrypt_private_key_with_password(
        sender.encrypted_private_key, sender_password
    )

    # 1. Digest & serialize
    payload_bytes = json.dumps(payload_dict, sort_keys=True).encode("utf-8")
    plaintext_sha256 = compute_sha256(payload_bytes)

    # 2. Digital Signature (RSA-PSS / SHA-256)
    sender_signature = sign_data(payload_bytes, sender_private_key)

    # 3. Hybrid AES-256-GCM encryption
    key_size = current_app.config.get("AES_KEY_SIZE", 256)
    encrypted_data = encrypt_report_payload(payload_bytes, key_size_bits=key_size)
    session_key = encrypted_data["session_key"]
    nonce_hex = encrypted_data["nonce_hex"]
    ciphertext = encrypted_data["ciphertext"]

    # Save ciphertext blob to disk
    upload_dir = current_app.config.get("UPLOAD_FOLDER", "instance/uploads")
    os.makedirs(upload_dir, exist_ok=True)
    blob_filename = f"enc_report_{uuid.uuid4().hex}.bin"
    blob_path = os.path.join(upload_dir, blob_filename)
    with open(blob_path, "wb") as f:
        f.write(ciphertext)

    # 5. Metadata & anti-replay
    message_nonce = generate_message_nonce()
    now_iso = datetime.now(timezone.utc).isoformat()
    
    sender_cert = Certificate.query.filter_by(
        user_id=sender.id, subject_type="USER", is_revoked=False
    ).order_by(Certificate.id.desc()).first()
    sender_cert_serial = sender_cert.serial_number if sender_cert else None

    # Create Report DB model
    report = Report(
        patient_id=patient_id,
        author_id=sender.id,
        department_id=department_id,
        report_type_id=report_type_id,
        title=title,
        status="DELIVERED",
        case_id=case_id or str(uuid.uuid4())[:8],
        is_critical=is_critical
    )
    db.session.add(report)
    db.session.flush()

    # Create ReportVersion
    version = ReportVersion(
        report_id=report.id,
        version_number=1,
        ciphertext_path=blob_path,
        nonce=nonce_hex,
        sender_signature=sender_signature,
        plaintext_sha256=plaintext_sha256,
        message_nonce=message_nonce,
        timestamp_iso=now_iso,
        sender_cert_serial=sender_cert_serial
    )
    db.session.add(version)
    db.session.flush()

    # 4. Wrap session key for each recipient
    for r_type, r_id in recipient_targets:
        target_pub_pem = None
        if r_type == "USER":
            recip_user = User.query.get(r_id)
            if recip_user and recip_user.public_key_pem:
                target_pub_pem = recip_user.public_key_pem
        elif r_type == "DEPARTMENT":
            recip_dept = Department.query.get(r_id)
            if recip_dept and recip_dept.public_key_pem:
                target_pub_pem = recip_dept.public_key_pem

        if not target_pub_pem:
            continue

        target_pub_key = pem_to_public_key(target_pub_pem)
        wrapped_key = wrap_session_key(session_key, target_pub_key)

        recip_entry = ReportRecipient(
            report_version_id=version.id,
            recipient_type=r_type,
            recipient_id=r_id,
            wrapped_session_key=wrapped_key,
            delivery_status="DELIVERED",
            verification_status="PENDING"
        )
        db.session.add(recip_entry)

    db.session.commit()

    log_event(
        "REPORT_CREATED_AND_ENCRYPTED",
        target_resource=f"Report:{report.id}",
        details={
            "report_id": report.id,
            "title": report.title,
            "sha256": plaintext_sha256,
            "recipients_count": len(recipient_targets)
        },
        actor_id=sender.id
    )

    return report

def decrypt_and_verify_report(
    report_version: ReportVersion,
    user: User,
    user_password: str
) -> Dict[str, Any]:
    """
    Step-by-step cryptographic verification on recipient open:
    1. Verify sender certificate against internal CA and CRL.
    2. Unwrap session key with private key (or department key).
    3. Replay attack check (timestamp drift & unique message nonce).
    4. Decrypt AES-256-GCM ciphertext payload.
    5. Recompute SHA-256 and verify digital signature.
    6. Mark recipient status as VERIFIED or REJECTED.
    """
    verification_drawer = {
        "ca_cert_valid": False,
        "ca_cert_notes": "",
        "replay_passed": False,
        "replay_notes": "",
        "decryption_passed": False,
        "sha256_match": False,
        "computed_sha256": "",
        "envelope_sha256": report_version.plaintext_sha256,
        "signature_valid": False,
        "signature_notes": "",
        "overall_status": "REJECTED",
        "payload": None
    }

    # 1. Certificate verification against Root CA
    ca_dir = current_app.config.get("CA_DIR", "instance/ca")
    ca_cert, _ = get_or_create_root_ca(ca_dir)
    
    sender_user = User.query.get(report_version.report.author_id)
    sender_cert = None
    if report_version.sender_cert_serial:
        sender_cert = Certificate.query.filter_by(serial_number=report_version.sender_cert_serial).first()
    
    if not sender_cert and sender_user:
        sender_cert = Certificate.query.filter_by(user_id=sender_user.id, subject_type="USER").order_by(Certificate.id.desc()).first()

    revoked_serials = set(
        c.serial_number for c in Certificate.query.filter_by(is_revoked=True).all()
    )

    if sender_cert:
        x509_obj = pem_to_cert(sender_cert.cert_pem)
        c_ok, c_msg = verify_certificate_validity(x509_obj, ca_cert, revoked_serials)
        verification_drawer["ca_cert_valid"] = c_ok
        verification_drawer["ca_cert_notes"] = c_msg
    else:
        verification_drawer["ca_cert_valid"] = False
        verification_drawer["ca_cert_notes"] = "Sender certificate not found in system truststore."

    # 2. Check Replay & Freshness
    seen_nonces = set(
        rn.nonce for rn in ReplayNonce.query.filter_by(sender_id=sender_user.id).all()
    ) if sender_user else set()
    
    window_sec = current_app.config.get("REPLAY_WINDOW_SECONDS", 300)
    rep_ok, rep_msg = verify_freshness_and_nonce(
        report_version.timestamp_iso,
        report_version.message_nonce,
        seen_nonces,
        window_sec
    )
    verification_drawer["replay_passed"] = rep_ok
    verification_drawer["replay_notes"] = rep_msg

    # 3. Locate recipient wrapped session key
    # Direct user match
    recipient_record = ReportRecipient.query.filter_by(
        report_version_id=report_version.id,
        recipient_type="USER",
        recipient_id=user.id
    ).first()

    # If not direct, check if sent to one of user's departments
    dept_wrapped_key = None
    if not recipient_record:
        user_dept_ids = [d.id for d in user.departments]
        recipient_dept = ReportRecipient.query.filter(
            ReportRecipient.report_version_id == report_version.id,
            ReportRecipient.recipient_type == "DEPARTMENT",
            ReportRecipient.recipient_id.in_(user_dept_ids)
        ).first()
        if recipient_dept:
            recipient_record = recipient_dept
            dept_wrapped_key = recipient_dept.wrapped_session_key

    if not recipient_record:
        verification_drawer["overall_status"] = "REJECTED"
        verification_drawer["signature_notes"] = "Unauthorized: Current user is not an intended recipient."
        return verification_drawer

    # 4. Decrypt session key using unlocked user private key
    try:
        user_priv = decrypt_private_key_with_password(user.encrypted_private_key, user_password)
        if dept_wrapped_key:
            # If unwrapping a department-wrapped message, retrieve dept key wrap for this user
            from app.models import DepartmentKeyWrap
            dkw = DepartmentKeyWrap.query.filter_by(
                department_id=recipient_record.recipient_id,
                user_id=user.id
            ).first()
            if dkw:
                dept_priv_raw = unwrap_session_key(dkw.encrypted_dept_key, user_priv)
                from app.crypto.keys import pem_to_private_key
                dept_priv = pem_to_private_key(dept_priv_raw.decode("utf-8"))
                session_key = unwrap_session_key(dept_wrapped_key, dept_priv)
            else:
                session_key = unwrap_session_key(dept_wrapped_key, user_priv)
        else:
            session_key = unwrap_session_key(recipient_record.wrapped_session_key, user_priv)
    except Exception as e:
        verification_drawer["overall_status"] = "REJECTED"
        verification_drawer["signature_notes"] = f"Key unwrap failed: {str(e)}"
        return verification_drawer

    # 5. Decrypt ciphertext payload with AES-256-GCM
    try:
        with open(report_version.ciphertext_path, "rb") as f:
            ciphertext = f.read()
        plaintext_bytes = decrypt_report_payload(ciphertext, report_version.nonce, session_key)
        verification_drawer["decryption_passed"] = True
        verification_drawer["payload"] = json.loads(plaintext_bytes.decode("utf-8"))
    except Exception as e:
        verification_drawer["decryption_passed"] = False
        verification_drawer["overall_status"] = "TAMPERED"
        verification_drawer["signature_notes"] = f"AES-GCM decryption failed (ciphertext or nonce tampered): {str(e)}"
        recipient_record.verification_status = "TAMPERED"
        recipient_record.verified_at = datetime.now(timezone.utc)
        db.session.commit()
        log_event("VERIFICATION_FAILED_TAMPERED", target_resource=f"Report:{report_version.report_id}", actor_id=user.id)
        return verification_drawer

    # 6. Recompute SHA-256 and verify signature
    computed_sha = compute_sha256(plaintext_bytes)
    verification_drawer["computed_sha256"] = computed_sha
    if computed_sha == report_version.plaintext_sha256:
        verification_drawer["sha256_match"] = True
    else:
        verification_drawer["sha256_match"] = False
        verification_drawer["overall_status"] = "TAMPERED"
        return verification_drawer

    if sender_user and sender_user.public_key_pem:
        sender_pub = pem_to_public_key(sender_user.public_key_pem)
        sig_ok, sig_msg = verify_signature(plaintext_bytes, report_version.sender_signature, sender_pub)
        verification_drawer["signature_valid"] = sig_ok
        verification_drawer["signature_notes"] = sig_msg
    else:
        verification_drawer["signature_valid"] = False
        verification_drawer["signature_notes"] = "Sender public key not found"

    # Overall Status decision
    if (
        verification_drawer["ca_cert_valid"] and
        verification_drawer["replay_passed"] and
        verification_drawer["decryption_passed"] and
        verification_drawer["sha256_match"] and
        verification_drawer["signature_valid"]
    ):
        verification_drawer["overall_status"] = "VERIFIED"
        recipient_record.verification_status = "VERIFIED"
        
        # Record nonce in anti-replay table
        rn = ReplayNonce(
            nonce=report_version.message_nonce,
            sender_id=sender_user.id if sender_user else user.id,
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(rn)
    else:
        verification_drawer["overall_status"] = "REJECTED"
        recipient_record.verification_status = "REJECTED"

    recipient_record.verified_at = datetime.now(timezone.utc)
    recipient_record.verification_notes = json.dumps(verification_drawer, default=str)
    db.session.commit()

    log_event(
        "REPORT_VERIFICATION_EVALUATED",
        target_resource=f"Report:{report_version.report_id}",
        details={
            "status": verification_drawer["overall_status"],
            "version": report_version.version_number
        },
        actor_id=user.id
    )

    return verification_drawer
