import os
from datetime import datetime, timezone, timedelta
from typing import Tuple, Optional
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from app.crypto.keys import generate_rsa_keypair, private_key_to_pem, pem_to_private_key, public_key_to_pem

def get_or_create_root_ca(ca_dir: str) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """
    Ensure the internal Root CA certificate and private key exist.
    If not present, generate a self-signed Root CA (RSA-4096, 10-year validity).
    """
    os.makedirs(ca_dir, exist_ok=True)
    cert_path = os.path.join(ca_dir, "root_ca.crt")
    key_path = os.path.join(ca_dir, "root_ca.key")

    if os.path.exists(cert_path) and os.path.exists(key_path):
        with open(cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        with open(key_path, "rb") as f:
            ca_key = pem_to_private_key(f.read().decode("utf-8"))
        return ca_cert, ca_key

    # Generate fresh Root CA key pair
    ca_key, ca_pub = generate_rsa_keypair(key_size=4096)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMed Hospital Authority"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureMed Root Certification Authority"),
    ])

    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    with open(cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    return ca_cert, ca_key

def issue_certificate(
    subject_common_name: str,
    subject_public_key,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    validity_days: int = 365,
    role: str = "Staff"
) -> x509.Certificate:
    """Issue a signed X.509 certificate for a user or hospital department."""
    now = datetime.now(timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMed Hospital"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, role),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_common_name),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(subject_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert

def cert_to_pem(cert: x509.Certificate) -> str:
    """Convert X.509 certificate to PEM string."""
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

def pem_to_cert(pem_str: str) -> x509.Certificate:
    """Load X.509 certificate from PEM string."""
    return x509.load_pem_x509_certificate(pem_str.encode("utf-8"))

def verify_certificate_validity(cert: x509.Certificate, ca_cert: x509.Certificate, revoked_serials: set) -> Tuple[bool, str]:
    """
    Verify certificate against Root CA:
    1. Check revocation list (CRL)
    2. Check expiration dates (not_valid_before and not_valid_after)
    3. Check cryptographic signature using CA public key
    """
    serial_str = str(cert.serial_number)
    if serial_str in revoked_serials:
        return False, f"Certificate serial {serial_str} has been REVOKED"

    now = datetime.now(timezone.utc)
    if now < cert.not_valid_before_utc:
        return False, "Certificate is not yet valid"
    if now > cert.not_valid_after_utc:
        return False, "Certificate has EXPIRED"

    try:
        ca_public_key = ca_cert.public_key()
        from cryptography.hazmat.primitives.asymmetric import padding
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
    except Exception as e:
        return False, f"Invalid Certificate Authority signature: {str(e)}"

    return True, "Certificate is trusted and valid"
