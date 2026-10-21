import pytest
import os
import shutil
import tempfile
from datetime import datetime, timezone, timedelta
from cryptography.exceptions import InvalidSignature

from app.crypto.keys import (
    generate_rsa_keypair,
    generate_ecc_keypair,
    encrypt_private_key_with_password,
    decrypt_private_key_with_password,
    public_key_to_pem,
    pem_to_public_key
)
from app.crypto.ca import (
    get_or_create_root_ca,
    issue_certificate,
    verify_certificate_validity,
    cert_to_pem,
    pem_to_cert
)
from app.crypto.hybrid import (
    encrypt_report_payload,
    wrap_session_key,
    unwrap_session_key,
    decrypt_report_payload
)
from app.crypto.sign import (
    compute_sha256,
    sign_data,
    verify_signature
)
from app.crypto.replay import (
    generate_message_nonce,
    verify_freshness_and_nonce
)

@pytest.fixture
def temp_ca_dir():
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)

# --- Test 1: Keys and Password Encryption ---
def test_password_encrypted_private_key():
    priv, pub = generate_rsa_keypair(2048)
    password = "CorrectStrongPassword!2026"
    
    encrypted_blob = encrypt_private_key_with_password(priv, password)
    assert "salt" in encrypted_blob
    assert "nonce" in encrypted_blob
    assert "ciphertext" in encrypted_blob
    
    # Decrypt with correct password
    restored_priv = decrypt_private_key_with_password(encrypted_blob, password)
    assert restored_priv is not None
    
    # Decrypt with wrong password must fail
    with pytest.raises(Exception):
        decrypt_private_key_with_password(encrypted_blob, "WrongPassword!")

# --- Test 2: Full End-to-End Hybrid Envelope ---
def test_hybrid_encryption_and_decryption_flow():
    alice_priv, alice_pub = generate_rsa_keypair(2048)
    bob_priv, bob_pub = generate_rsa_keypair(2048)
    
    report_content = b"CONFIDENTIAL MEDICAL REPORT: Patient has Type 2 Diabetes."
    
    # 1. Digest
    report_hash = compute_sha256(report_content)
    
    # 2. Alice signs
    signature = sign_data(report_content, alice_priv)
    
    # 3. Hybrid encrypt
    enc_data = encrypt_report_payload(report_content, key_size_bits=256)
    session_key = enc_data["session_key"]
    nonce_hex = enc_data["nonce_hex"]
    ciphertext = enc_data["ciphertext"]
    
    # 4. Wrap for Bob
    wrapped_for_bob = wrap_session_key(session_key, bob_pub)
    
    # 5. Bob unwraps and decrypts
    bob_unwrapped_key = unwrap_session_key(wrapped_for_bob, bob_priv)
    assert bob_unwrapped_key == session_key
    
    decrypted_report = decrypt_report_payload(ciphertext, nonce_hex, bob_unwrapped_key)
    assert decrypted_report == report_content
    
    # Verify hash and signature
    assert compute_sha256(decrypted_report) == report_hash
    valid_sig, sig_msg = verify_signature(decrypted_report, signature, alice_pub)
    assert valid_sig is True

# --- Test 3: Tampered Ciphertext Detected ---
def test_tampered_ciphertext_detection():
    alice_priv, alice_pub = generate_rsa_keypair(2048)
    bob_priv, bob_pub = generate_rsa_keypair(2048)
    
    report_content = b"Lab Test: Potassium Level 4.2 mEq/L"
    enc_data = encrypt_report_payload(report_content, 256)
    wrapped_key = wrap_session_key(enc_data["session_key"], bob_pub)
    
    # Tamper with 1 byte of ciphertext
    tampered_ciphertext = bytearray(enc_data["ciphertext"])
    tampered_ciphertext[0] ^= 0xFF
    
    unwrapped_key = unwrap_session_key(wrapped_key, bob_priv)
    
    with pytest.raises(Exception): # AES-GCM tag mismatch
        decrypt_report_payload(bytes(tampered_ciphertext), enc_data["nonce_hex"], unwrapped_key)

# --- Test 4: Forged Sender Rejected ---
def test_forged_sender_rejected():
    alice_priv, alice_pub = generate_rsa_keypair(2048)
    eve_priv, eve_pub = generate_rsa_keypair(2048)
    
    report_content = b"Prescription: 500mg Amoxicillin"
    # Eve signs with her key but claims to be Alice
    forged_sig = sign_data(report_content, eve_priv)
    
    # Receiver verifies against Alice's public key
    valid_sig, msg = verify_signature(report_content, forged_sig, alice_pub)
    assert valid_sig is False
    assert "Invalid signature" in msg

# --- Test 5: Wrong Recipient Key Rejected ---
def test_wrong_recipient_key_cannot_decrypt():
    charlie_priv, charlie_pub = generate_rsa_keypair(2048)
    bob_priv, bob_pub = generate_rsa_keypair(2048)
    
    enc_data = encrypt_report_payload(b"Radiology Scan Note", 256)
    # Wrapped exclusively for Bob
    wrapped_for_bob = wrap_session_key(enc_data["session_key"], bob_pub)
    
    # Charlie tries to unwrap
    with pytest.raises(Exception):
        unwrap_session_key(wrapped_for_bob, charlie_priv)

# --- Test 6: Replay Attack and Timestamp Window ---
def test_replay_protection():
    now_iso = datetime.now(timezone.utc).isoformat()
    nonce = generate_message_nonce()
    seen_nonces = set()
    
    # First arrival passes
    valid, msg = verify_freshness_and_nonce(now_iso, nonce, seen_nonces, 300)
    assert valid is True
    seen_nonces.add(nonce)
    
    # Replay of same nonce is rejected
    valid_replay, replay_msg = verify_freshness_and_nonce(now_iso, nonce, seen_nonces, 300)
    assert valid_replay is False
    assert "Replay attack detected" in replay_msg
    
    # Stale timestamp rejected
    old_time = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    valid_stale, stale_msg = verify_freshness_and_nonce(old_time, generate_message_nonce(), seen_nonces, 300)
    assert valid_stale is False
    assert "outside allowed freshness window" in stale_msg

# --- Test 7: Certificate Issuance, Expiry, and Revocation ---
def test_certificate_validation_lifecycle(temp_ca_dir):
    ca_cert, ca_key = get_or_create_root_ca(temp_ca_dir)
    user_priv, user_pub = generate_rsa_keypair(2048)
    
    cert = issue_certificate("Dr. Smith", user_pub, ca_cert, ca_key, validity_days=365)
    revoked_serials = set()
    
    # 1. Valid certificate
    valid, msg = verify_certificate_validity(cert, ca_cert, revoked_serials)
    assert valid is True
    
    # 2. Revoked certificate
    revoked_serials.add(str(cert.serial_number))
    valid_revoked, rev_msg = verify_certificate_validity(cert, ca_cert, revoked_serials)
    assert valid_revoked is False
    assert "REVOKED" in rev_msg
