import os
import json
import base64
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_rsa_keypair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate RSA private and public key pair (2048-bit standard)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    return private_key, private_key.public_key()

def generate_ecc_keypair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate ECC private and public key pair using SECP256R1 (P-256)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()

def public_key_to_pem(public_key) -> str:
    """Serialize public key to PEM string."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode("utf-8")

def pem_to_public_key(pem_str: str):
    """Load public key from PEM string."""
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))

def private_key_to_pem(private_key) -> str:
    """Serialize unencrypted private key to PKCS8 PEM string."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode("utf-8")

def pem_to_private_key(pem_str: str, password: str = None):
    """Load private key from PEM string."""
    pwd_bytes = password.encode("utf-8") if password else None
    return serialization.load_pem_private_key(pem_str.encode("utf-8"), password=pwd_bytes)

def encrypt_private_key_with_password(private_key, password: str) -> str:
    """
    Encrypt private key using scrypt key derivation and AES-256-GCM.
    Returns serialized JSON containing {salt, nonce, ciphertext}.
    The private key is NEVER stored in plaintext.
    """
    salt = os.urandom(16)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1
    )
    derived_aes_key = kdf.derive(password.encode("utf-8"))
    
    raw_pkcs8 = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    aesgcm = AESGCM(derived_aes_key)
    nonce = os.urandom(12) # 96-bit nonce
    ciphertext = aesgcm.encrypt(nonce, raw_pkcs8, None)
    
    envelope = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
    }
    return json.dumps(envelope)

def decrypt_private_key_with_password(encrypted_blob: str, password: str):
    """Decrypt encrypted private key envelope using password-derived scrypt key."""
    envelope = json.loads(encrypted_blob)
    salt = base64.b64decode(envelope["salt"])
    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1
    )
    derived_aes_key = kdf.derive(password.encode("utf-8"))
    aesgcm = AESGCM(derived_aes_key)
    raw_pkcs8 = aesgcm.decrypt(nonce, ciphertext, None)
    
    return serialization.load_pem_private_key(raw_pkcs8, password=None)
