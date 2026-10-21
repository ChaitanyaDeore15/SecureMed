import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE

def create_deck():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # Professional Medical & Cyber Palette
    TEAL_DARK = RGBColor(15, 118, 110)    # #0f766e
    TEAL_LIGHT = RGBColor(240, 253, 250)  # #f0fdfa
    SLATE_DARK = RGBColor(15, 23, 42)     # #0f172a
    SLATE_MUTED = RGBColor(100, 116, 139) # #64748b
    CARD_BG = RGBColor(255, 255, 255)
    BORDER_COLOR = RGBColor(226, 232, 240)
    ACCENT_RED = RGBColor(225, 29, 72)
    ACCENT_GREEN = RGBColor(16, 185, 129)

    slides_data = [
        # Slide 1: Title
        {
            "title": "SecureMed",
            "subtitle": "Cryptographic Hospital Patient-Report Exchange System\nCryptography & Network Security (CNS) Final Project",
            "bullets": [
                "Zero-Knowledge Clinical Envelopes (AES-256-GCM + RSA-OAEP)",
                "Digital Signatures & Non-Repudiation (RSA-PSS 2048-bit)",
                "Mini Certificate Authority (X.509 v3 + CRL Revocation)",
                "Blockchain-Style Hash-Chained Audit Ledger"
            ],
            "is_title": True
        },
        # Slide 2: Problem Statement
        {
            "title": "The Problem in Modern Healthcare IT",
            "subtitle": "Vulnerabilities in Traditional Hospital Patient Record Exchange",
            "cards": [
                ("Plaintext Database Vulnerability", "Rogue DB administrators, cloud misconfigurations, or ransomware SQL dumps expose confidential diagnostic reports."),
                ("Man-In-The-Middle (MITM) Alteration", "Attackers intercepting transmission can modify diagnostic parameters (e.g., blood potassium levels, drug dosages)."),
                ("Sender Impersonation & Forgery", "Lack of non-repudiation allows unauthorized actors to forge prescriptions or falsify clinical orders."),
                ("Replay & Freshness Attacks", "Valid intercepted signed orders can be retransmitted to duplicate clinical actions (e.g., duplicate morphine administration).")
            ]
        },
        # Slide 3: System Architecture & Core Philosophy
        {
            "title": "Core Philosophy: Zero-Knowledge Courier",
            "subtitle": "The Server Never Stores Plaintext Medical Reports",
            "cards": [
                ("Confidential Storage", "Reports are stored exclusively as AES-256-GCM ciphertext blobs on disk (enc_report_*.bin). Plaintext never touches disk or DB."),
                ("Multi-Recipient Wrap", "A fresh 256-bit session key is generated per report and wrapped separately for each doctor/dept using RSA-OAEP."),
                ("Private Key Protection", "Clinicians' private keys are protected with Scrypt key derivation (N=16384) + AES-GCM; never held in plaintext."),
                ("Defense-in-Depth", "Strict HSTS, CSP headers, rate-limiting, and sliding 15-minute brute-force lockout after 5 failed logins.")
            ]
        },
        # Slide 4: Cryptographic Pipeline (Sender Side)
        {
            "title": "Cryptographic Pipeline: Sender Side (Dispatch)",
            "subtitle": "Step-by-Step Mathematical Flow on Report Composition",
            "cards": [
                ("1. Digest Computation", "The clinical payload JSON is serialized and digested using SHA-256 (32 bytes)."),
                ("2. Digital Signature", "Digest is signed with sender's unlocked private key using RSA-PSS with SHA-256 and MGF1 (Non-Repudiation)."),
                ("3. AES-256-GCM Encryption", "Payload is encrypted using a fresh 256-bit random session key and a 96-bit nonce, generating a 128-bit AEAD tag."),
                ("4. Key Encapsulation (OAEP)", "The symmetric session key is wrapped for each recipient's public key using RSA-OAEP with SHA-256."),
                ("5. Metadata Binding", "ISO-8601 UTC timestamp, unique UUID message nonce, and sender X.509 cert serial are bound to envelope.")
            ]
        },
        # Slide 5: Cryptographic Pipeline (Receiver Side)
        {
            "title": "Cryptographic Pipeline: Receiver Side (Verification)",
            "subtitle": "5-Point Automated Cryptographic Verification on Open",
            "cards": [
                ("1. Root CA Chain & CRL Check", "Validates sender's X.509 certificate against Root CA. Rejects if expired or present in CRL."),
                ("2. Freshness & Anti-Replay", "Enforces a 300-second sliding time window and verifies that the message nonce has never been seen."),
                ("3. Key Unwrap (RSA-OAEP)", "Recipient unlocks private key to decrypt the wrapped AES session key."),
                ("4. AEAD Decryption & Tag Match", "AES-256-GCM verifies 128-bit authentication tag. 1-bit alteration halts decryption immediately."),
                ("5. Signature & Hash Check", "Recomputes SHA-256 digest and verifies RSA-PSS digital signature against sender's certificate.")
            ]
        },
        # Slide 6: Mini Certificate Authority & PKI
        {
            "title": "Mini Certificate Authority (PKI)",
            "subtitle": "Automated X.509 Certificate Issuance and Revocation Lifecycle",
            "cards": [
                ("Internal Root CA", "Generates an internal RSA-4096 Root CA (10-year validity) on initial application bootstrap."),
                ("Automated Issuance", "Issues individual X.509 v3 certificates to doctors, technicians, pharmacists, and departments upon provisioning."),
                ("Interactive CRL", "Administrators can immediately revoke compromised certificates from the UI."),
                ("Fail-Closed Security", "Verification automatically rejects reports signed by revoked or expired certificates with audit alerts.")
            ]
        },
        # Slide 7: Multi-Department System & Access Matrix
        {
            "title": "Multi-Department Architecture & Routing",
            "subtitle": "Data-Driven Hospital Specialties with Granular Access Controls",
            "cards": [
                ("9 Seeded Departments", "OPD, Pathology/Lab, Radiology, Pharmacy, Surgery, Emergency/ICU, Cardiology, Billing, Medical Records."),
                ("Dynamic Provisioning", "Admins can add new hospital departments at runtime with auto-generated RSA keypairs and X.509 certs."),
                ("Department Keys", "Shared department inboxes where authorized clinicians unwrap department keys via member key-wraps."),
                ("Access Control Matrix", "Configurable inter-department routing rules controlling which specialties can exchange reports.")
            ]
        },
        # Slide 8: Audit Ledger & Emergency Access
        {
            "title": "Hash-Chained Audit Ledger & Break-Glass",
            "subtitle": "Immutable Blockchain-Style Ledger & Emergency Protocol",
            "cards": [
                ("Hash-Chained Ledger", "H_i = SHA-256(H_i-1 || Seq || Timestamp || Actor || Action || Details). Genesis starts at H_0 = 0*64."),
                ("Tamper Detection", "One-click 'Verify Chain Integrity' recalculates all hashes from Genesis to immediately catch any DB modifications."),
                ("Emergency Break-Glass", "Allows emergency doctors to override consent during trauma shock, requiring mandatory justification."),
                ("High-Priority Alerting", "Break-glass and verification failures immediately alert administrators on the Security Telemetry dashboard.")
            ]
        },
        # Slide 9: Patient Portal & Security Lab
        {
            "title": "Patient Portal & CNS Security Lab",
            "subtitle": "Patient Empowerment & Interactive Exploit Evaluation",
            "cards": [
                ("Patient Portal", "Patients view finalized reports, manage consent (grant/revoke per doctor/department), and inspect 'Who Viewed My Data'."),
                ("Lab: Bit-Flipping Attack", "Alters 1 byte of AES-GCM ciphertext to prove AEAD tag mismatch blocks corrupted data."),
                ("Lab: Forged Sender Attack", "Eve signs a prescription with her key claiming to be Dr. Alice; RSA-PSS blocks invalid signature."),
                ("Lab: Replay Attack", "Retransmits an intercepted legitimate encrypted message; anti-replay engine rejects duplicate nonce.")
            ]
        },
        # Slide 10: Conclusion & Verification Results
        {
            "title": "Verification Results & Definition of Done",
            "subtitle": "Rigorous Automated Testing & Standards Compliance",
            "cards": [
                ("16/16 Unit Tests Passed", "Full test coverage across foundation, crypto core, reports, departments, audit ledger, and patient consent."),
                ("One-Command Launch", "python run.py starts the server on HTTPS localhost:5000 with pre-seeded demo accounts and TLS cert."),
                ("Container Ready", "Complete Dockerfile and docker-compose.yml ready for cloud or disconnected offline field hospital deployments."),
                ("Production Compliance", "Strictly adheres to standard Python cryptography, Argon2id, pyotp TOTP, and zero custom crypto.")
            ]
        }
    ]

    for data in slides_data:
        slide = prs.slides.add_slide(blank_layout)

        # Header Box
        header_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.6), Inches(11.7), Inches(1.2))
        tf = header_box.text_frame
        tf.word_wrap = True
        
        p = tf.paragraphs[0]
        p.text = data["title"]
        p.font.size = Pt(28 if not data.get("is_title") else 38)
        p.font.bold = True
        p.font.color.rgb = SLATE_DARK

        p2 = tf.add_paragraph()
        p2.text = data["subtitle"]
        p2.font.size = Pt(14 if not data.get("is_title") else 18)
        p2.font.color.rgb = TEAL_DARK

        if data.get("is_title"):
            # Title slide bullets in prominent container
            container = slide.shapes.add_shape(
                MSO_SHAPE.ROUNDED_RECTANGLE,
                Inches(1.5), Inches(2.6), Inches(10.3), Inches(3.8)
            )
            container.fill.solid()
            container.fill.fore_color.rgb = TEAL_LIGHT
            container.line.color.rgb = TEAL_DARK
            container.line.width = Pt(1.5)

            c_tf = container.text_frame
            c_tf.word_wrap = True
            c_p = c_tf.paragraphs[0]
            c_p.text = "Key System Highlights:"
            c_p.font.size = Pt(20)
            c_p.font.bold = True
            c_p.font.color.rgb = TEAL_DARK
            c_p.space_after = Pt(14)

            for b in data["bullets"]:
                bp = c_tf.add_paragraph()
                bp.text = f"  •  {b}"
                bp.font.size = Pt(16)
                bp.font.color.rgb = SLATE_DARK
                bp.space_after = Pt(10)

        elif "cards" in data:
            cards = data["cards"]
            # Layout: 4 cards in 2x2 grid, or 5 cards in flexible layout
            if len(cards) == 4:
                positions = [
                    (Inches(0.8), Inches(2.1), Inches(5.6), Inches(2.2)),
                    (Inches(6.9), Inches(2.1), Inches(5.6), Inches(2.2)),
                    (Inches(0.8), Inches(4.7), Inches(5.6), Inches(2.2)),
                    (Inches(6.9), Inches(4.7), Inches(5.6), Inches(2.2)),
                ]
            else:
                positions = [
                    (Inches(0.8), Inches(2.1), Inches(3.6), Inches(4.8)),
                    (Inches(4.8), Inches(2.1), Inches(3.6), Inches(4.8)),
                    (Inches(8.8), Inches(2.1), Inches(3.6), Inches(4.8)),
                ]

            for idx, (head, body) in enumerate(cards[:len(positions)]):
                left, top, width, height = positions[idx]
                card = slide.shapes.add_shape(
                    MSO_SHAPE.ROUNDED_RECTANGLE,
                    left, top, width, height
                )
                card.fill.solid()
                card.fill.fore_color.rgb = CARD_BG
                card.line.color.rgb = BORDER_COLOR
                card.line.width = Pt(1)

                ctf = card.text_frame
                ctf.word_wrap = True
                
                cp1 = ctf.paragraphs[0]
                cp1.text = head
                cp1.font.size = Pt(15)
                cp1.font.bold = True
                cp1.font.color.rgb = TEAL_DARK
                cp1.space_after = Pt(6)

                cp2 = ctf.add_paragraph()
                cp2.text = body
                cp2.font.size = Pt(12)
                cp2.font.color.rgb = SLATE_DARK

    output_path = os.path.join(os.path.dirname(__file__), "SecureMed_Presentation.pptx")
    prs.save(output_path)
    print(f"Presentation saved to: {output_path}")

if __name__ == "__main__":
    create_deck()
