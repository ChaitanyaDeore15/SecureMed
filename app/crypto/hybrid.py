import os
import json
import base64
from typing import Dict, Any, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.primitives import hashes
from app.crypto.keys import pem_to_public_key, pem_to_private_key

def encrypt_report_payload(plaintext_bytes: bytes, key_size_bits: int = 256) -> Dict[str, Any]:
    """
    Step 3 of Cryptographic Design:
    Encrypt the report payload with AES-GCM (128 or 256 bit) using a fresh random session key
    and a fresh random 96-bit (12-byte) nonce.
    """
    key_bytes_count = key_size_bits // 8
    session_key = os.urandom(key_bytes_count)
    nonce = os.urandom(12) # 96-bit nonce
    
    aesgcm = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    
    return {
        "session_key": session_key,
        "nonce_hex": nonce.hex(),
        "ciphertext": ciphertext
    }

def wrap_session_key(session_key: bytes, recipient_public_key) -> str:
    """
    Step 4 of Cryptographic Design:
    Wrap the session key separately for EACH recipient using RSA-OAEP with SHA-256 (or ECC ECDH).
    Returns Base64 encoded wrapped key.
    """
    if isinstance(recipient_public_key, rsa.RSAPublicKey):
        wrapped = recipient_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(wrapped).decode("utf-8")
    else:
        raise NotImplementedError("Only RSA recipient keys are currently wrapped via OAEP.")

def unwrap_session_key(wrapped_b64: str, recipient_private_key) -> bytes:
    """Unwrap the AES session key using the recipient's private key."""
    ciphertext = base64.b64decode(wrapped_b64)
    if isinstance(recipient_private_key, rsa.RSAPrivateKey):
        session_key = recipient_private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return session_key
    else:
        raise NotImplementedError("Only RSA recipient private keys are supported for OAEP unwrapping.")

def decrypt_report_payload(ciphertext: bytes, nonce_hex: str, session_key: bytes) -> bytes:
    """Decrypt the AES-GCM ciphertext using the unwrapped session key and nonce."""
    nonce = bytes.fromhex(nonce_hex)
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(nonce, ciphertext, None)
