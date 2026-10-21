# Pimpri Chinchwad College of Engineering
### Department of Information Technology
**Course:** Cryptography and Network Security (BIT27PC01)  
**Final Year B.Tech | Academic Year : 2026 – 27 | Semester – VII**  
**Formative Assessment I & II — Submitted By A2**  

---

## Secure Hospital Patient Records System: A Hybrid Cryptographic Framework Using AES-256-GCM, RSA, SHA-256 and Role-Based Access Control

**Guide:** Dr. Jayashree V. Katti, Head of IT Department  

### Team Members
| Team Member | PRN |
| :--- | :---: |
| **Shivanjali Bhosale** | 123B1F009 |
| **Rutuja Bobade** | 123B1F012 |
| **Aditya Deore** | 123B1F019 |
| **Chaitanya Deore** | 123B1F020 |

---

## Executive Summary

Modern hospital networks rely on rapid electronic communication among multidisciplinary departments (Outpatient, Pathology, Radiology, Pharmacy, Surgery, Emergency/ICU, Cardiology, Billing, and Medical Records). However, standard Electronic Health Record (EHR) systems frequently maintain patient data in plaintext databases or depend solely on transport-layer encryption (TLS), leaving clinical records vulnerable to database exfiltration, insider threats, Man-In-The-Middle (MITM) diagnostic alteration, prescription forgery, and replay attacks.

**SecureMed** addresses these vulnerabilities by establishing a zero-knowledge hospital report exchange system. The central server functions strictly as an untrusted, zero-knowledge courier: plaintext medical reports and plaintext private keys are **never stored** on disk or in the database. 

End-to-end security is guaranteed through a rigorous cryptographic pipeline combining **SHA-256 digests**, **RSA-PSS 2048-bit digital signatures**, **AES-256-GCM authenticated envelope encryption**, **multi-recipient RSA-OAEP key encapsulation**, **X.509 v3 public key certificates with an internal Certificate Authority (CA) and Certificate Revocation List (CRL)**, **high-entropy anti-replay nonces**, and a **blockchain-style SHA-256 hash-chained audit ledger**.

All non-negotiable security requirements, role-based workflows, emergency break-glass protocols, patient consent directives, and real-time attack defenses have been implemented and verified with a 100% pass rate across automated test suites.

---

## 1. Problem Statement & Threat Model

### 1.1 Problem Definition
In clinical environments, interception or alteration of diagnostic reports presents catastrophic patient safety hazards:
1. **Confidentiality Breaches:** Unauthorized access to diagnostic findings (e.g., oncology biopsies, HIV status, genetic screening) exposes hospitals to legal liabilities and violates privacy standards (HIPAA / GDPR).
2. **Integrity Violations & Data Tampering:** Alteration of clinical parameters in transit (e.g., changing blood potassium from 4.2 mEq/L to 7.0 mEq/L or altering chemotherapy dosages) directly leads to lethal clinical actions.
3. **Impersonation & Forgery:** Rogue actors or malicious staff forging prescriptions or clinical orders claiming to be attending physicians.
4. **Replay & Freshness Attacks:** Intercepting a legitimate signed order and retransmitting it hours or days later to duplicate clinical procedures (e.g., re-administering controlled substances like morphine).

### 1.2 STRIDE Threat Model & Defenses

| Threat Category (STRIDE) | Attack Vector | SecureMed Defense Architecture |
| :--- | :--- | :--- |
| **Spoofing** | Attacker Eve sends forged orders claiming to be Dr. Alice. | **RSA-PSS 2048-bit signatures** verified against **X.509 certificates** issued exclusively by the internal Root CA. |
| **Tampering** | Man-In-The-Middle flips bits in transit or edits database rows. | **AES-256-GCM AEAD** 128-bit Poly1305/GHASH authentication tags halt decryption upon 1-bit alteration. |
| **Repudiation** | Doctor denies authoring an erroneous or lethal prescription. | **Asymmetric RSA-PSS signatures** signed with doctor's password-derived private key guarantee mathematical non-repudiation. |
| **Information Disclosure** | Database dumps or network sniffing reveal patient records. | **Zero-Knowledge Storage**: Payload stored as AES-256-GCM ciphertext files (`enc_report_*.bin`); keys wrapped via **RSA-OAEP**. |
| **Denial of Service** | Flooding authentication endpoints or disk storage. | **Flask-Limiter** rate limiting (`10/min` login), **5-attempt account lockout**, and **16MB upload ceiling**. |
| **Elevation of Privilege** | Billing staff attempting to inspect oncology surgical notes. | **Server-side RBAC decorators** (`@roles_required`) coupled with an inter-department **Access Control Matrix**. |

---

## 2. Technical Stack & Operational Prerequisites

To maintain strict compliance, zero external non-standard cryptography is used:

- **Programming Language:** Python 3.11+ / Python 3.13
- **Web Framework:** Flask 3.1, Jinja2 Templates, Werkzeug
- **Database & ORM:** SQLAlchemy 2.0+, SQLite (embedded, zero external service dependency)
- **Cryptography Engine:** `cryptography` library (PyCA/cryptography) exclusively (no custom crypto)
- **Password KDF:** Argon2id via `argon2-cffi`
- **Private Key Derivation:** Scrypt (`N=16384, r=8, p=1`)
- **Authentication & Security:** Flask-Login, Flask-WTF (CSRF), Flask-Limiter, PyOTP (TOTP 2FA)
- **Frontend & UI:** Jinja2 + Tailwind CSS (CDN) + Alpine.js (reactive state without heavy frontend bundles)
- **Testing:** `pytest`, `pytest-flask`
- **Transport:** Self-signed TLS 1.3/1.2 (`localhost.crt`, `localhost.key`) auto-generated on startup

---

## 3. Cryptographic Architecture & Engineering Design

SecureMed structures the cryptographic lifecycle into distinct phases for both Sender (Dispatch) and Receiver (Verification):

```
                       [ SENDER SIDE (Dr. Alice) ]
1. Clinical Payload JSON
       |
       +-------> Compute SHA-256 Digest -------> RSA-PSS 2048-bit Digital Signature (Alice's Private Key)
       |                                                         |
       +-------> AES-256-GCM Encrypt (Fresh 256-bit Session Key, 96-bit Nonce)
                         |                                       |
       Session Key ------> RSA-OAEP Wrap (Per-Recipient Public Key) |
                         |                                       |
       Metadata ---------> Anti-Replay Nonce + ISO-8601 Timestamp + Cert Serial
                         |                                       |
                         V                                       V
             [ UNTRUSTED DATABASE & DISK: ZERO-KNOWLEDGE ENVELOPE ]
                         |
                         V
                      [ RECEIVER SIDE (Tech Bob) ]
1. Validate Sender's X.509 Certificate against Internal Root CA (Signature, Dates, CRL Revocation)
2. Verify Freshness & Anti-Replay (Sliding 300s window check & database nonce lookup)
3. Unwrap Session Key using Bob's Scrypt-unlocked Private Key via RSA-OAEP
4. Decrypt Payload using AES-256-GCM & verify 128-bit AEAD tag
5. Recompute SHA-256 Digest of plaintext & verify RSA-PSS Digital Signature
                         |
         +---------------+---------------+
         |                               |
         V                               V
    ALL CHECKS PASS               ANY CHECK FAILS
   Status: [VERIFIED]           Status: [TAMPERED] / [REJECTED]
```

### 3.1 Key Management & Zero-Knowledge Private Key Storage
- **Asymmetric Keypairs:** Generated using standard RSA-2048 (`public_exponent=65537`).
- **Encrypted Key Storage:** Private keys are never stored in plaintext. When a user registers:
  $$\text{Derived Key} = \text{Scrypt}(\text{Password}, \text{Salt}, N=16384, r=8, p=1)$$
  The PKCS#8 private key bytes are encrypted using **AES-256-GCM** with this derived key. The resulting JSON envelope `{"salt": ..., "nonce": ..., "ciphertext": ...}` is stored in the database.
- **Session Unlocking:** When a user logs in, their password allows temporary decryption of the private key into memory during their active session, ensuring zero plaintext exposure when idle.

### 3.2 Internal Mini Certificate Authority (CA) & CRL
- **Root CA:** Automatically initialized on first launch in `instance/ca/root_ca.crt` (RSA-4096, 10-year validity, self-signed).
- **Issuance:** Every clinician, technician, and department is issued an **X.509 v3 Certificate** signed by this Root CA upon creation.
- **Revocation (CRL):** Administrators can revoke any certificate via the UI. When a report is opened, the verification engine checks the active CRL; any report signed by a revoked key is immediately flagged as **`REJECTED`**.

### 3.3 Hybrid Encryption & Envelope Dispatch
1. **Digest:** The payload JSON is serialized with sorted keys: $\text{Digest} = \text{SHA-256}(\text{Payload Bytes})$.
2. **Signature:** Signed via **RSA-PSS** using MGF1-SHA256 and maximum salt length.
3. **Payload Cipher:** Encrypted using **AES-256-GCM** with a fresh 256-bit symmetric session key $K$ and 96-bit nonce $N$ (`os.urandom`).
4. **Key Encapsulation:** For each recipient (individual user or department), $K$ is wrapped:
   $$\text{WrappedKey} = \text{RSA-OAEP}(K, \text{RecipientPublicKey}, \text{MGF1-SHA256})$$
5. **Freshness:** An ISO-8601 UTC timestamp and a high-entropy UUID message nonce are bound to the version record.

### 3.4 Multi-Stage Verification Pipeline
When a recipient opens a report, SecureMed executes a 5-point verification drawer:
1. **CA Trust:** Validates X.509 signature against Root CA and verifies non-revocation in CRL.
2. **Freshness:** Verifies $\Delta t \le 300\text{ seconds}$ and confirms the nonce has not been previously recorded in `replay_nonces`.
3. **Key Unwrap:** Recipient unwraps the AES session key using their private key.
4. **AEAD Authentication:** AES-256-GCM verifies the 128-bit authentication tag.
5. **Digest & Signature Verification:** Plaintext is hashed via SHA-256 and compared to the signed digest using RSA-PSS.

---

## 4. Multi-Department Architecture & Workflows

SecureMed replaces static hospital silos with a data-driven department model:

### 4.1 Seeded Clinical Specialties
1. **OPD (Outpatient Department):** Clinical consultation notes and general orders.
2. **PATH (Pathology/Lab):** Diagnostic blood panels, biopsies, urinalysis.
3. **RAD (Radiology):** CT, MRI, X-ray imaging reports and scan attachments.
4. **PHARM (Pharmacy):** Digital prescription fulfillment and dosage validation.
5. **SURG (Surgery):** Pre-operative clearances, operative notes, post-op instructions.
6. **EMERG (Emergency/ICU):** Acute trauma management, triage evaluations.
7. **CARD (Cardiology):** Echocardiograms, ECGs, catheterization summaries.
8. **BILL (Billing/Insurance):** CPT coding and insurance claims.
9. **HIM (Medical Records):** Long-term legal archiving.

### 4.2 Dynamic Runtime Provisioning
Administrators can create, edit, or disable departments from the UI with **zero code modifications**. The backend automatically provisions a dedicated RSA-2048 department keypair, issues a Root CA-signed X.509 certificate, and wraps the department private key for authorized staff via `DepartmentKeyWrap`.

### 4.3 Access Control Matrix
Administrators configure directional transfer permissions. Intra-department transfers are permitted by default, while inter-department pathways (e.g., Doctor $\rightarrow$ Lab $\rightarrow$ Doctor) are governed by editable policy records.

---

## 5. Audit Logging, Anomaly Heuristics & Emergency Protocol

### 5.1 Blockchain-Style Hash-Chained Audit Ledger
Every authentication, encryption, decryption, verification failure, or administrative change is appended to an immutable hash chain:

$$\text{Hash}_i = \text{SHA-256}\left(\text{Hash}_{i-1} \parallel \text{Seq}_i \parallel \text{Timestamp} \parallel \text{ActorID} \parallel \text{Action} \parallel \text{Target} \parallel \text{Details}\right)$$

- **Genesis Block:** $\text{Hash}_0 = \text{"0"}\times 64$.
- **Tamper Evident:** Modifying, deleting, or reordering any entry invalidates all downstream hashes.
- **Verification Engine:** The UI provides a **"Verify Chain Integrity"** button that recalculates all hashes from Genesis and pinpoints the exact tampered row.

### 5.2 Security Telemetry & Anomaly Detection
The telemetry engine automatically detects and flags:
- Repeated AEAD tag mismatches (ciphertext tampering).
- Brute-force account lockouts.
- Off-hours administrative logins.
- Emergency break-glass events.

### 5.3 Emergency Break-Glass Override
In life-critical circumstances (e.g., unconscious trauma patient in emergency resuscitation), patient consent checks can be bypassed:
- Requires mandatory clinical justification ($\ge 15$ characters).
- Logs an immutable high-priority `BREAK_GLASS_ACCESS` record.
- Alerts compliance officers and hospital administration on the security telemetry dashboard.

---

## 6. Patient Portal & Consent Management

SecureMed provides a dedicated patient-facing interface (`/patients/portal`):
- **Record Access:** Patients can log in to view finalized diagnostic reports issued to their Medical Record Number (MRN).
- **Consent Directives:** Patients can dynamically grant or revoke access to their health records per department or doctor.
- **"Who Viewed My Data":** An immutable transparency ledger listing every clinician or staff member who decrypted or accessed their records, complete with UTC timestamps.

---

## 7. Interactive Security Lab & Attack Demonstrations

Located at `/demo/lab`, the application features a live exploit demonstration environment that tests cryptographic defenses in real time:

1. **Ciphertext Bit-Flipping Attack (Integrity):**
   - *Attack:* Flips 1 bit in the AES-256-GCM ciphertext file in transit.
   - *Defense:* AES-256-GCM AEAD authentication tag calculation fails, halting decryption and blocking corrupted data.
2. **Sender Impersonation / Forgery Attack (Authenticity):**
   - *Attack:* Eve signs a prescription using her own key while claiming to be Dr. Alice.
   - *Defense:* The Root CA binds Alice's identity to Alice's public key; RSA-PSS verification fails mathematically.
3. **Replay Attack (Freshness):**
   - *Attack:* Retransmits a valid intercepted encrypted report.
   - *Defense:* Anti-replay engine detects the duplicate nonce in the database and enforces the 300-second freshness window.

---

## 8. Automated Test Suite & Verification Results

The entire platform is covered by an automated test suite (`pytest`) executing 16 test cases across all 8 development phases:

```text
============================= test session starts =============================
platform win32 -- Python 3.13.9, pytest-8.4.2, pluggy-1.5.0
rootdir: C:\Users\deore\Desktop\CNS FA
collected 16 items

tests\test_phase1_foundation.py ...                                      [ 18%]
tests\test_phase2_crypto.py .......                                      [ 62%]
tests\test_phase3_reports.py .                                           [ 68%]
tests\test_phase4_departments.py ..                                      [ 81%]
tests\test_phase5_audit.py ..                                            [ 93%]
tests\test_phase6_patients.py .                                          [100%]

============================== 16 passed in 18.62s ==============================
```

### Verified Test Scenarios:
- **Phase 1:** Argon2id hashing, 5-attempt lockout, CSP/HSTS headers, RBAC route gating.
- **Phase 2:** Scrypt private key encryption, hybrid AES-GCM + RSA-OAEP, RSA-PSS signatures, Root CA issuance, CRL revocation, tampered ciphertext rejection, forged sender rejection, replay attack rejection.
- **Phase 3:** Multi-recipient zero-knowledge envelope dispatch, decryption, and verification badge generation.
- **Phase 4:** Dynamic runtime department creation, key wrapping, and access matrix policy enforcement.
- **Phase 5:** Audit log hash chain verification, database row tampering detection, and anomaly heuristic alerting.
- **Phase 6:** Patient consent delegation and revocation rules.

---

## 9. Deployment & Execution Instructions

### Local Execution:
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run automated test suite
python -m pytest tests/ -v

# 3. Start SecureMed server
python run.py
```
- Auto-creates `instance/securemed.db`.
- Generates internal Root CA and dev TLS certificates.
- Seeds all demo accounts and departments.
- Serves securely at **`https://127.0.0.1:5000`**.

### Docker Deployment:
```bash
docker-compose up --build
```

### Pre-Configured Demo Accounts:
- **Admin:** `admin` / `AdminPass123!`
- **Doctor:** `dr_alice` / `DoctorPass123!`
- **Technician:** `tech_bob` / `TechPass123!`
- **Pharmacist:** `pharm_dave` / `PharmPass123!`
- **Auditor:** `auditor_eve` / `AuditorPass123!`
- **Patient:** `patient_john` / `PatientPass123!`

---

## 10. Conclusion

SecureMed successfully demonstrates a production-grade, zero-knowledge clinical report exchange architecture that meets the rigorous demands of modern healthcare information security. By replacing naive database storage with authenticated hybrid encryption (AES-256-GCM + RSA-OAEP), digital signatures (RSA-PSS), a dedicated Root Certificate Authority with CRL, anti-replay sliding windows, and a blockchain-style hash-chained audit ledger, the system provides mathematical guarantees of confidentiality, integrity, authenticity, non-repudiation, and availability.
