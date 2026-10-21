import hashlib
import base64
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.exceptions import InvalidSignature

def compute_sha256(data: bytes) -> str:
    """Compute standard SHA-256 hex digest of data."""
    return hashlib.sha256(data).hexdigest()

def sign_data(data_bytes: bytes, sender_private_key) -> str:
    """
    Step 2 of Cryptographic Design:
    Sign data with sender's private key.
    - RSA: RSA-PSS with SHA-256 and MGF1-SHA-256, max salt length.
    - ECC: ECDSA with SHA-256.
    Returns Base64 encoded signature.
    """
    if isinstance(sender_private_key, rsa.RSAPrivateKey):
        signature = sender_private_key.sign(
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    elif isinstance(sender_private_key, ec.EllipticCurvePrivateKey):
        signature = sender_private_key.sign(
            data_bytes,
            ec.ECDSA(hashes.SHA256())
        )
    else:
        raise ValueError("Unsupported private key type for signing.")
        
    return base64.b64encode(signature).decode("utf-8")

def verify_signature(data_bytes: bytes, signature_b64: str, sender_public_key) -> Tuple[bool, str]:
    """Verify digital signature against data and sender public key."""
    try:
        raw_sig = base64.b64decode(signature_b64)
        if isinstance(sender_public_key, rsa.RSAPublicKey):
            sender_public_key.verify(
                raw_sig,
                data_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif isinstance(sender_public_key, ec.EllipticCurvePublicKey):
            sender_public_key.verify(
                raw_sig,
                data_bytes,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            return False, "Unsupported public key type"
        return True, "Digital signature is valid"
    except InvalidSignature:
        return False, "Invalid signature: Signature verification failed"
    except Exception as e:
        return False, f"Signature verification error: {str(e)}"
