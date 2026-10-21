import os
import secrets
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    # Secret Key for sessions and CSRF
    SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'instance' / 'securemed.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Upload storage for encrypted blobs
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", str(BASE_DIR / "instance" / "uploads"))
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB limit
    
    # Session & Cookie Security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=20)  # Inactivity timeout
    
    # Account Security
    MAX_FAILED_LOGIN_ATTEMPTS = 5
    ACCOUNT_LOCKOUT_MINUTES = 15
    
    # Cryptographic policy
    CRYPTO_POLICY_ALGORITHM = os.environ.get("CRYPTO_POLICY_ALGORITHM", "RSA") # RSA or ECC
    AES_KEY_SIZE = int(os.environ.get("AES_KEY_SIZE", "256")) # 128 or 256
    REPLAY_WINDOW_SECONDS = 300 # 5 minutes message freshness window
    
    # Rate Limiting
    RATELIMIT_DEFAULT = "100 per minute"
    RATELIMIT_STORAGE_URI = "memory://"
    
    # CA paths
    CA_DIR = BASE_DIR / "instance" / "ca"
    ROOT_CA_CERT_PATH = CA_DIR / "root_ca.crt"
    ROOT_CA_KEY_PATH = CA_DIR / "root_ca.key"

class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False
    RATELIMIT_ENABLED = False
