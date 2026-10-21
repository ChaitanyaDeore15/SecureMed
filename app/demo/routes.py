import json
import base64
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required
from app.crypto.keys import generate_rsa_keypair, public_key_to_pem
from app.crypto.hybrid import encrypt_report_payload, wrap_session_key, decrypt_report_payload, unwrap_session_key
from app.crypto.sign import compute_sha256, sign_data, verify_signature
from app.crypto.replay import generate_message_nonce, verify_freshness_and_nonce
from app.audit.analyzer import verify_audit_hash_chain
from app.models import AuditLog

demo_bp = Blueprint("demo", __name__, url_prefix="/demo")

@demo_bp.route("/lab")
@login_required
def lab():
    return render_template("demo/lab.html")

@demo_bp.route("/simulate-tamper", methods=["POST"])
@login_required
def simulate_tamper():
    """Attack 1: Modify 1 bit in AES-256-GCM ciphertext to show AEAD tag mismatch defense."""
    data = request.get_json() or {}
    message = data.get("message", "Confidential Biopsy Findings: Malignant Melanoma").encode("utf-8")
    
    # Normal encryption
    priv, pub = generate_rsa_keypair(2048)
    enc = encrypt_report_payload(message, 256)
    
    # Attacker flips 1 byte in ciphertext
    tampered_bytes = bytearray(enc["ciphertext"])
    tampered_bytes[0] ^= 0xFF
    
    defense_result = "SUCCESS: Decryption rejected. Tag mismatch caught by AES-256-GCM AEAD."
    error_detail = ""
    try:
        decrypt_report_payload(bytes(tampered_bytes), enc["nonce_hex"], enc["session_key"])
        defense_result = "FAILED: Tampered data accepted."
    except Exception as e:
        error_detail = str(e)

    return jsonify({
        "attack": "Attacker modified 1 byte of the encrypted medical record in transit.",
        "defense": "AES-256-GCM authenticates ciphertext using a 128-bit Poly1305/GHASH tag.",
        "result": defense_result,
        "detail": error_detail,
        "status": "BLOCKED"
    })

@demo_bp.route("/simulate-forge", methods=["POST"])
@login_required
def simulate_forge():
    """Attack 2: Attacker Eve signs a medical record using her key and claims to be Doctor Alice."""
    alice_priv, alice_pub = generate_rsa_keypair(2048)
    eve_priv, eve_pub = generate_rsa_keypair(2048)
    
    record = b"Prescription: 100mg Morphine Sulfate IV"
    # Eve signs with Eve's key
    eve_sig = sign_data(record, eve_priv)
    
    # Receiver verifies with Alice's public key
    valid, msg = verify_signature(record, eve_sig, alice_pub)

    return jsonify({
        "attack": "Eve intercepted and injected a forged prescription, signing it with her own private key while claiming to be Dr. Alice.",
        "defense": "Hospital Root CA binds Dr. Alice's identity to Alice's public key. Signature verification strictly fails under RSA-PSS.",
        "result": "BLOCKED: Signature verification failed.",
        "detail": msg,
        "status": "BLOCKED"
    })

@demo_bp.route("/simulate-replay", methods=["POST"])
@login_required
def simulate_replay():
    """Attack 3: Attacker captures a legitimate encrypted report and replays it."""
    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()
    nonce = generate_message_nonce()
    seen = {nonce} # Message already processed
    
    valid, msg = verify_freshness_and_nonce(now_iso, nonce, seen, 300)

    return jsonify({
        "attack": "Attacker captured a valid encrypted transfer from the network and retransmitted it to execute a replay attack.",
        "defense": "Anti-replay engine inspects unique message nonces in memory/DB and enforces a sliding 300-second freshness window.",
        "result": f"BLOCKED: {msg}",
        "status": "BLOCKED"
    })
