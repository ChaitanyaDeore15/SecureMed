# SecureMed - Cryptographic Hospital Patient-Report Exchange System
### Cryptography and Network Security (CNS) Final Project

SecureMed is a production-grade, multi-department hospital clinical report exchange system. It solves the clinical information interception and tampering problem by strictly implementing zero-knowledge envelope encryption, digital signatures, anti-replay protections, and a hash-chained audit ledger.

---

## 🚀 One-Command Launch

### Standard Local Execution:
```bash
python run.py
```
* **Auto-creates SQLite database** in `instance/securemed.db`
* **Generates internal Root CA** and issues certificates to hospital staff and departments
* **Generates dev TLS Certificate** for local HTTPS
* **Seeds demo accounts & departments**
* **Opens securely on**: [https://127.0.0.1:5000](https://127.0.0.1:5000)

### Docker & Docker Compose:
```bash
docker-compose up --build
```

---

## 🔑 Demo Accounts (Pre-Seeded)

All accounts are pre-provisioned with encrypted private keys and signed X.509 certificates.

| Role | Username | Password | Purpose & Capabilities |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin` | `AdminPass123!` | Manages departments, access matrix, CRL revocations, audit exports |
| **Doctor** | `dr_alice` | `DoctorPass123!` | Composes signed reports, views inbox, executes break-glass emergency access |
| **Doctor** | `dr_carol` | `DoctorPass123!` | Attending clinician, receives referrals |
| **Technician** | `tech_bob` | `TechPass123!` | Pathology/Lab specialist, inspects and verifies blood panels |
| **Pharmacist**| `pharm_dave` | `PharmPass123!` | Fulfills verified digital prescriptions |
| **Auditor** | `auditor_eve` | `AuditorPass123!` | Read-only ledger auditor, verifies hash-chain integrity & anomaly alerts |
| **Patient** | `patient_john` | `PatientPass123!` | Patient portal, views personal reports, manages consent directives |

---

## 🛡️ Cryptographic Architecture

```
                       [ SENDER SIDE ]
1. Payload JSON --------> SHA-256 Digest --------> RSA-PSS Sign (Sender Private Key)
       |                                                         |
       +---------------> AES-256-GCM Encrypt (Session Key, 96-bit Nonce)
                                 |                               |
       Session Key ------------> RSA-OAEP Wrap (Per Recipient Public Key)
                                 |
           [ SERVER STORES ONLY ENVELOPE: CIPHERTEXT + WRAPPED KEYS + SIGNATURE ]
                                 |
                      [ RECIPIENT SIDE ]
1. Verify Sender Certificate against Root CA & CRL
2. Unwrap Session Key using Recipient's Private Key
3. Check 300s Timestamp Sliding Window & Unique Message Nonce (Anti-Replay)
4. Decrypt Ciphertext Payload & Verify AEAD Tag
5. Recompute SHA-256 Digest & Verify RSA-PSS Signature
```

---

## 🧪 Interactive Security Lab (`/demo/lab`)

Log in to any account and navigate to **Security Lab** (`https://127.0.0.1:5000/demo/lab`):
1. **Ciphertext Bit Flipping**: Modifies 1 byte of encrypted data. Watch AES-256-GCM reject decryption with an AEAD tag mismatch.
2. **Sender Impersonation / Forgery**: Simulates Eve generating a forged prescription. Watch RSA-PSS reject the invalid signature.
3. **Replay Attack**: Sniffs a legitimate transfer and retransmits it. Watch the anti-replay engine block the duplicate nonce and stale timestamp.

---

## 🔬 Wireshark Network Capture Guide

1. Start Wireshark and listen on interface `Loopback: adapter for loopback traffic` (`lo0` / `127.0.0.1`).
2. Set filter: `tcp.port == 5000`.
3. Open [https://127.0.0.1:5000](https://127.0.0.1:5000).
4. Observe that all HTTP traffic is encapsulated in TLS `Application Data` records.
5. In the database and disk storage, verify that payload contents in `instance/uploads/enc_report_*.bin` are encrypted AES-GCM binary blobs. Plaintext is never stored.

---

## 🧪 Running the Automated Test Suite

```bash
python -m pytest tests/ -v
```
**16 out of 16 tests passing**:
* `tests/test_phase1_foundation.py`: Argon2id, lockout, security headers, RBAC.
* `tests/test_phase2_crypto.py`: Hybrid AES-GCM, RSA-PSS, Root CA, CRL revocation, anti-replay.
* `tests/test_phase3_reports.py`: End-to-end report exchange, zero-knowledge storage, verification drawer.
* `tests/test_phase4_departments.py`: Dynamic runtime provisioning, access matrix permissions.
* `tests/test_phase5_audit.py`: Hash-chained audit ledger, tamper detection, anomaly alert heuristics.
* `tests/test_phase6_patients.py`: Patient portal & consent delegation directives.
