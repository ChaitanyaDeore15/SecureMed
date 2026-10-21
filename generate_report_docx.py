import os
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), fill_hex)
    tcPr.append(shd)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def set_table_borders(table, color="000000", sz="4", val="single"):
    tblPr = table._tbl.tblPr
    tblBorders = OxmlElement('w:tblBorders')
    for border_name in ['top', 'left', 'bottom', 'right', 'insideH', 'insideV']:
        border = OxmlElement(f'w:{border_name}')
        border.set(qn('w:val'), val)
        border.set(qn('w:sz'), sz)
        border.set(qn('w:space'), '0')
        border.set(qn('w:color'), color)
        tblBorders.append(border)
    tblPr.append(tblBorders)

def add_page_border(section):
    sectPr = section._sectPr
    pgBorders = OxmlElement('w:pgBorders')
    pgBorders.set(qn('w:offsetFrom'), 'page')
    for b_name in ['top', 'left', 'bottom', 'right']:
        border = OxmlElement(f'w:{b_name}')
        border.set(qn('w:val'), 'single')
        border.set(qn('w:sz'), '24') # thick border like sample
        border.set(qn('w:space'), '24')
        border.set(qn('w:color'), '000000')
        pgBorders.append(border)
    sectPr.append(pgBorders)

def build_cover_page(doc):
    # Paragraph helper
    def add_p(text="", size=12, bold=False, color=(0,0,0), align=WD_ALIGN_PARAGRAPH.CENTER, space_before=0, space_after=2, underline=False):
        p = doc.add_paragraph()
        p.alignment = align
        p.paragraph_format.space_before = Pt(space_before)
        p.paragraph_format.space_after = Pt(space_after)
        p.paragraph_format.line_spacing = 1.0
        if text:
            r = p.add_run(text)
            r.font.name = "Times New Roman"
            r.font.size = Pt(size)
            r.font.bold = bold
            r.font.underline = underline
            r.font.color.rgb = RGBColor(*color)
        return p

    # 1. Header: Trust & College
    add_p("Pimpri Chinchwad Education Trust's", size=11, bold=True, space_before=12, space_after=3)
    add_p("Pimpri Chinchwad College of Engineering", size=16, bold=True, space_before=0, space_after=3)
    add_p("Sector No. 26, Pradhikaran, Nigdi, Pune, 411044", size=10, bold=False, space_before=0, space_after=2)
    add_p("An Autonomous Institute Approved By AICTE and Affiliated To SPPU, Pune", size=10, bold=False, space_before=0, space_after=14)

    # 2. Department
    add_p("DEPARTMENT OF INFORMATION TECHNOLOGY", size=14, bold=True, space_before=4, space_after=14)

    # 3. Logo
    logo_path = os.path.join(os.path.dirname(__file__), "instance", "pccoe_logo_clean.png")
    if os.path.exists(logo_path):
        p_logo = doc.add_paragraph()
        p_logo.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_logo.paragraph_format.space_before = Pt(2)
        p_logo.paragraph_format.space_after = Pt(14)
        run_logo = p_logo.add_run()
        run_logo.add_picture(logo_path, width=Inches(1.5))

    # 4. Course Name
    add_p("Cryptography and Network Security (BIT27PC01)", size=13, bold=True, space_before=4, space_after=10)

    # 5. Class & Academic Year
    add_p("Final Year B.Tech", size=12, bold=True, space_before=0, space_after=2)
    add_p("Academic Year : 2026 – 27", size=11, bold=True, space_before=0, space_after=2)
    add_p("Semester – VII", size=11, bold=False, space_before=0, space_after=10)

    # 6. Assessment & Group
    add_p("Formative Assessment I & II", size=12, bold=True, space_before=0, space_after=2)
    add_p("Submitted By A2", size=13, bold=True, underline=True, space_before=0, space_after=14)

    # 7. Project Title (Exact title requested / matched)
    p_title = add_p("Secure Hospital Patient Records System: A Hybrid Cryptographic Framework", size=12, bold=True, space_before=4, space_after=1)
    p_title2 = add_p("Using AES-256-GCM, RSA, SHA-256 and Role-Based Access Control", size=12, bold=True, space_before=0, space_after=14)

    # 8. Guide
    add_p("Guide: Dr. Jayashree V. Katti, Head of IT Department", size=11, bold=True, space_before=2, space_after=10)

    # 9. Team Members Table (Exact names & PRNs specified by user)
    members = [
        ("Shivanjali Bhosale", "123B1F009"),
        ("Rutuja Bobade", "123B1F012"),
        ("Aditya Deore", "123B1F019"),
        ("Chaitanya Deore", "123B1F020"),
    ]

    table = doc.add_table(rows=1 + len(members), cols=2)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False

    # Widths
    col_widths = [Inches(3.2), Inches(2.2)]
    for row in table.rows:
        for idx, width in enumerate(col_widths):
            row.cells[idx].width = width

    # Header Row
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = "Team Member"
    hdr_cells[1].text = "PRN"
    for cell in hdr_cells:
        set_cell_background(cell, "E2E8F0") # soft gray
        set_cell_margins(cell, top=80, bottom=80, left=120, right=120)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        for r in p.runs:
            r.font.name = "Times New Roman"
            r.font.size = Pt(11)
            r.font.bold = True

    # Member Rows
    for idx, (name, prn) in enumerate(members):
        row_cells = table.rows[idx + 1].cells
        row_cells[0].text = name
        row_cells[1].text = prn
        for c_idx, cell in enumerate(row_cells):
            set_cell_margins(cell, top=60, bottom=60, left=120, right=120)
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            for r in p.runs:
                r.font.name = "Times New Roman"
                r.font.size = Pt(10.5)

    set_table_borders(table, color="000000", sz="4")

    # Page Break after Cover Page
    doc.add_page_break()

def generate_complete_academic_report():
    doc = docx.Document()

    # Section Margins & Page Border on Section 1
    sec1 = doc.sections[0]
    sec1.top_margin = Inches(0.7)
    sec1.bottom_margin = Inches(0.7)
    sec1.left_margin = Inches(0.8)
    sec1.right_margin = Inches(0.8)
    add_page_border(sec1)

    # 1. Build Cover Page
    build_cover_page(doc)

    # Formatting helpers for report body
    TEAL_HEX = "0F766E"
    GRAY_BG = "F8FAFC"

    def add_heading_1(text):
        h = doc.add_paragraph()
        h.paragraph_format.space_before = Pt(16)
        h.paragraph_format.space_after = Pt(4)
        r = h.add_run(text)
        r.font.name = "Times New Roman"
        r.font.size = Pt(15)
        r.font.bold = True
        r.font.color.rgb = RGBColor(15, 118, 110)
        return h

    def add_heading_2(text):
        h = doc.add_paragraph()
        h.paragraph_format.space_before = Pt(10)
        h.paragraph_format.space_after = Pt(3)
        r = h.add_run(text)
        r.font.name = "Times New Roman"
        r.font.size = Pt(12)
        r.font.bold = True
        r.font.color.rgb = RGBColor(15, 23, 42)
        return h

    def add_body(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(5)
        p.paragraph_format.line_spacing = 1.15
        r = p.add_run(text)
        r.font.name = "Times New Roman"
        r.font.size = Pt(11)
        r.font.color.rgb = RGBColor(30, 41, 59)
        return p

    def add_bullet(bold_prefix, text):
        p = doc.add_paragraph(style='List Bullet')
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.line_spacing = 1.15
        r1 = p.add_run(bold_prefix + ": ")
        r1.font.name = "Times New Roman"
        r1.font.size = Pt(11)
        r1.font.bold = True
        r1.font.color.rgb = RGBColor(15, 118, 110)
        r2 = p.add_run(text)
        r2.font.name = "Times New Roman"
        r2.font.size = Pt(11)
        return p

    # Report Body Content
    add_heading_1("1. Executive Summary")
    add_body("Modern healthcare facilities exchange confidential medical reports, surgical evaluations, lab panels, and radiological findings across interconnected clinical specialties. Standard Electronic Health Record (EHR) systems frequently maintain patient records in unencrypted database tables or rely exclusively on perimeter transport encryption (TLS). Consequently, databases remain vulnerable to insider tampering, SQL injection exfiltration, Man-In-The-Middle (MITM) diagnostic parameter alteration, and prescription forgery.")
    add_body("SecureMed is an end-to-end zero-knowledge clinical report exchange platform. The central application server acts strictly as an untrusted, zero-knowledge courier: plaintext medical reports and plaintext private keys are never stored on disk or in the database. Security is mathematically guaranteed through SHA-256 digests, RSA-PSS 2048-bit digital signatures, AES-256-GCM envelope encryption, multi-recipient RSA-OAEP key wrapping, an internal X.509 Root Certificate Authority (CA) with a live Certificate Revocation List (CRL), anti-replay nonces with sliding freshness windows, and a blockchain-style SHA-256 hash-chained audit ledger.")

    add_heading_1("2. Problem Statement & STRIDE Threat Model")
    add_body("In clinical environments, the compromise of medical information leads to direct patient harm. Intercepted reports violate HIPAA/GDPR privacy mandates, while unauthorized alteration of clinical diagnostic values (e.g., blood potassium levels, biopsy indications, chemotherapy dosages) can cause fatal clinical misdiagnoses.")
    add_body("To address these threats rigorously, SecureMed implements countermeasures aligned with the STRIDE security framework:")
    
    add_bullet("Spoofing Defense", "Sender identity is tied to an X.509 v3 certificate issued by the hospital's internal Root CA. Senders must generate an RSA-PSS digital signature over the report hash; recipients verify signatures strictly against the sender's public key certificate.")
    add_bullet("Tampering Defense", "Payloads are encrypted using AES-256-GCM, producing a 128-bit Poly1305/GHASH authentication tag. Any single-bit alteration halts decryption and triggers an immediate tampered status.")
    add_bullet("Repudiation Defense", "Reports are signed with the clinician's password-derived private key. Because private keys are held exclusively by the respective clinician, mathematical non-repudiation is enforced.")
    add_bullet("Information Disclosure Defense", "Plaintext reports are never written to disk or the database. Payloads exist solely as AES-256-GCM binary ciphertext files, with session keys encapsulated via RSA-OAEP.")
    add_bullet("Denial of Service Defense", "Flask-Limiter rate-limiting, 16MB file upload caps, and automatic 15-minute account lockout after 5 failed login attempts prevent resource exhaustion.")
    add_bullet("Elevation of Privilege Defense", "Strict server-side Role-Based Access Control (RBAC) decorators gate all routes, combined with a data-driven Access Control Matrix regulating inter-department communication.")

    add_heading_1("3. Cryptographic Algorithms & Mechanics")
    add_body("SecureMed exclusively employs industry-standard cryptographic primitives from the Python cryptography library:")

    table_data = [
        ("Algorithm", "Type / Standard", "Specific Purpose", "Execution Timing"),
        ("Argon2id", "Memory-Hard KDF", "Password hashing resisting GPU/ASIC attacks", "User registration & login verification"),
        ("Scrypt", "Memory-Hard KDF", "Derives 256-bit key from password to encrypt private key", "Account provisioning & session unlock"),
        ("AES-256-GCM", "Symmetric AEAD", "Payload encryption with 128-bit authentication tag", "Report dispatch & recipient decryption"),
        ("RSA-PSS", "Asymmetric Signature", "Digital signature with MGF1-SHA256 (Non-Repudiation)", "Sender signing & receiver verification"),
        ("RSA-OAEP", "Key Encapsulation", "Wraps AES session key separately for each recipient", "Multi-recipient envelope creation"),
        ("SHA-256", "Cryptographic Hash", "Payload digests & blockchain-style audit hashing", "Pre-signing, verification, audit events"),
        ("X.509 v3", "PKI Public Cert", "Binds user/department identity to public key", "CA issuance & receiver trust verification"),
        ("TOTP", "Time-Based OTP", "Two-Factor Authentication (RFC 6238)", "Account login with authenticator apps")
    ]

    t = doc.add_table(rows=len(table_data), cols=4)
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for r_idx, row in enumerate(table_data):
        for c_idx, cell_value in enumerate(row):
            cell = t.cell(r_idx, c_idx)
            cell.text = cell_value
            p = cell.paragraphs[0]
            p.paragraph_format.space_before = Pt(3)
            p.paragraph_format.space_after = Pt(3)
            r = p.runs[0]
            r.font.name = "Times New Roman"
            r.font.size = Pt(9.5)
            if r_idx == 0:
                r.font.bold = True
                r.font.color.rgb = RGBColor(255, 255, 255)
                set_cell_background(cell, TEAL_HEX)
            else:
                set_cell_background(cell, GRAY_BG if r_idx % 2 == 1 else "FFFFFF")

    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    add_heading_1("4. Multi-Department Architecture & Clinical Workflows")
    add_body("Hospital departments are dynamic database entities equipped with dedicated RSA-2048 keypairs, Root CA-signed X.509 certificates, and departmental member key-wrapping. The system seeds 9 foundational departments:")
    add_bullet("Clinical Specialties", "Outpatient (OPD), Pathology/Lab (PATH), Radiology (RAD), Pharmacy (PHARM), Surgery (SURG), Emergency/ICU (EMERG), Cardiology (CARD), Billing/Insurance (BILL), and Medical Records (HIM).")
    add_bullet("Runtime Provisioning", "Hospital administrators can add, update, or disable departments from the web interface without writing a single line of code. Dedicated asymmetric keypairs and certificates are issued automatically.")
    add_bullet("Department Key-Wrapping", "Reports addressed to an entire specialty (e.g., Pathology) are decrypted via an encapsulated department symmetric key wrapped for each authorized staff member.")
    add_bullet("Access Control Matrix", "Administrators define explicit inter-department exchange rules (e.g., Surgery can order from Pathology, but Billing cannot access raw surgical pathology notes).")

    add_heading_1("5. Blockchain-Style Hash-Chained Audit Ledger")
    add_body("To prevent malicious administrators or intruders from tampering with forensic records, all system activities are recorded in a cryptographic hash chain:")
    add_body("H_i = SHA-256(H_{i-1} || Sequence || Timestamp || ActorID || Action || Target || Details)")
    add_bullet("Genesis Block", "The first entry links to a constant Genesis Hash of 64 zeros (H_0 = 0*64).")
    add_bullet("Tamper Evident", "Altering, deleting, or reordering any audit row invalidates the cryptographic hash chain for all subsequent entries.")
    add_bullet("Verification Engine", "The audit dashboard includes a 'Verify Chain Integrity' tool that recalculates every hash from Genesis to verify ledger authenticity in milliseconds.")

    add_heading_1("6. Emergency Break-Glass Protocol & Patient Portal")
    add_body("In emergency trauma scenarios where patients are unconscious or unable to provide consent, clinical care cannot be halted. SecureMed incorporates an Emergency Break-Glass Override Protocol:")
    add_bullet("Break-Glass Workflow", "Attending physicians can bypass normal consent barriers by providing a mandatory clinical emergency justification (>= 15 characters).")
    add_bullet("Critical Alerting", "Break-glass events trigger high-priority alerts across the administrative security dashboard and append an immutable event to the audit ledger.")
    add_body("Patients access their own dedicated portal (/patients/portal) where they can view finalized reports, grant or revoke consent per doctor/department, and inspect the 'Who Viewed My Data' transparency ledger.")

    add_heading_1("7. Security Lab & Verification Results")
    add_body("The platform features an in-app Security Lab (/demo/lab) allowing users and evaluators to execute live cryptographic attacks and observe real-time defenses:")
    add_bullet("Ciphertext Bit-Flipping", "Altering 1 bit in transit fails AES-256-GCM AEAD authentication and halts decryption.")
    add_bullet("Sender Forgery", "Forged signatures claiming to be another clinician are rejected mathematically under RSA-PSS.")
    add_bullet("Replay Retransmission", "Duplicated message envelopes are blocked by database nonce checks and the 300s freshness window.")
    
    add_body("The complete architecture has been validated via an automated pytest test suite across all 16 distinct test cases with a 100% pass rate:")
    add_bullet("Test Suite Coverage", "16 passed in 18.62s covering password hashing, hybrid encryption, Root CA lifecycle, CRL revocation, department provisioning, hash-chained ledger, and patient consent.")

    add_heading_1("8. Deployment & Execution")
    add_body("SecureMed is runnable on a standard laptop with a single command:")
    add_bullet("One-Command Execution", "python run.py automatically provisions the SQLite database, generates Root CA and dev TLS certificates, seeds demo accounts, and launches at https://127.0.0.1:5000.")
    add_bullet("Containerization", "Production Dockerfile and docker-compose.yml files enable rapid containerized deployment.")

    doc_path = os.path.join(os.path.dirname(__file__), "SecureMed_Project_Report.docx")
    doc.save(doc_path)
    print(f"Academic Report document saved successfully at: {doc_path}")

if __name__ == "__main__":
    generate_complete_academic_report()
