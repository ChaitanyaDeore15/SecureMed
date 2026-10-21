import os
import json
from datetime import datetime, timezone
from typing import List, Tuple
from flask import current_app
from app.extensions import db
from app.models import Department, User, Certificate, DepartmentAccessMatrix, DepartmentKeyWrap
from app.crypto.keys import (
    generate_rsa_keypair,
    public_key_to_pem,
    private_key_to_pem,
    pem_to_public_key
)
from app.crypto.ca import get_or_create_root_ca, issue_certificate, cert_to_pem
from app.crypto.hybrid import wrap_session_key, encrypt_report_payload
from app.audit.service import log_event

def create_department_with_keys(
    name: str,
    code: str,
    description: str = None,
    head_id: int = None,
    initial_member_ids: List[int] = None
) -> Department:
    """
    Data-driven department provisioning:
    1. Generate dedicated RSA-2048 department key pair.
    2. Issue department X.509 certificate signed by Root CA.
    3. Wrap department private key for authorized members (DepartmentKeyWrap).
    4. Persist in database without requiring code changes.
    """
    dept_priv, dept_pub = generate_rsa_keypair(2048)
    dept_pub_pem = public_key_to_pem(dept_pub)
    dept_priv_pem_bytes = private_key_to_pem(dept_priv).encode("utf-8")

    dept = Department(
        name=name,
        code=code.upper().strip(),
        description=description,
        head_id=head_id,
        public_key_pem=dept_pub_pem,
        is_active=True
    )
    db.session.add(dept)
    db.session.flush()

    # Issue Department Certificate from Root CA
    ca_dir = current_app.config.get("CA_DIR", "instance/ca")
    ca_cert, ca_key = get_or_create_root_ca(ca_dir)
    dept_cert = issue_certificate(
        subject_common_name=f"SecureMed Dept {dept.name}",
        subject_public_key=dept_pub,
        ca_cert=ca_cert,
        ca_key=ca_key,
        validity_days=730,
        role="Department"
    )

    cert_record = Certificate(
        serial_number=str(dept_cert.serial_number),
        subject_type="DEPARTMENT",
        department_id=dept.id,
        cert_pem=cert_to_pem(dept_cert),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc)
    )
    db.session.add(cert_record)

    # Wrap department private key for members
    # Since RSA-OAEP 2048 cannot directly encrypt ~1.7KB RSA private key PEM,
    # we encrypt the dept private key with an AES-256-GCM envelope key, and wrap that envelope key for each member.
    if initial_member_ids:
        envelope = encrypt_report_payload(dept_priv_pem_bytes, 256)
        sym_key = envelope["session_key"]
        
        for mid in initial_member_ids:
            member = User.query.get(mid)
            if member and member.public_key_pem:
                member_pub = pem_to_public_key(member.public_key_pem)
                wrapped_sym_key = wrap_session_key(sym_key, member_pub)
                
                stored_payload = {
                    "wrapped_sym_key": wrapped_sym_key,
                    "nonce_hex": envelope["nonce_hex"],
                    "ciphertext": envelope["ciphertext"].hex()
                }
                
                dkw = DepartmentKeyWrap(
                    department_id=dept.id,
                    user_id=member.id,
                    encrypted_dept_key=json.dumps(stored_payload)
                )
                db.session.add(dkw)

    db.session.commit()

    log_event(
        "DEPARTMENT_CREATED",
        target_resource=f"Department:{dept.id}",
        details={"name": dept.name, "code": dept.code, "cert_serial": cert_record.serial_number}
    )

    return dept

def check_access_matrix_permission(source_dept_id: int, target_dept_id: int) -> bool:
    """Check if inter-department report transfer is permitted by the access matrix policy."""
    if source_dept_id == target_dept_id:
        return True # Intra-department exchanges always allowed
    
    rule = DepartmentAccessMatrix.query.filter_by(
        source_dept_id=source_dept_id,
        target_dept_id=target_dept_id
    ).first()

    # Default to permitted if no explicit deny rule exists
    if rule:
        return rule.is_allowed
    return True
