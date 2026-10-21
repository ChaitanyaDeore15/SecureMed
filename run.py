import os
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app import create_app
from app.extensions import db
from app.seed import seed_demo_data

def generate_dev_tls_certs(cert_dir: str):
    """Generate self-signed TLS cert and private key for local HTTPS execution."""
    os.makedirs(cert_dir, exist_ok=True)
    cert_path = os.path.join(cert_dir, "localhost.crt")
    key_path = os.path.join(cert_dir, "localhost.key")

    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    print("Generating local development TLS certificate for HTTPS...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMed Dev"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    return cert_path, key_path

app = create_app()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        seed_demo_data(app)

    # Prepare dev TLS certificate
    certs_dir = os.path.join(os.path.dirname(__file__), "instance", "certs")
    cert_file, key_file = generate_dev_tls_certs(certs_dir)

    print("\n=======================================================")
    print("   [+] SecureMed - Cryptographic Healthcare Exchange")
    print("   [*] Listening securely on https://127.0.0.1:5000")
    print("   [*] Demo Accounts available in README.md")
    print("=======================================================\n")

    app.run(
        host="127.0.0.1",
        port=5000,
        ssl_context=(cert_file, key_file),
        debug=False
    )
