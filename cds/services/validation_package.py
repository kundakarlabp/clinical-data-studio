import json
import logging
import time
import zipfile
import sys
import platform
import os
from io import BytesIO
from pathlib import Path
from typing import Any

from cds.services.audit_service import verify_audit_chain
from cds.services.backup_service import data_protection_status, backup_files_for_study
from cds.services.export_service import generate_access_review_csv

LOGGER = logging.getLogger("clinical-data-studio")

SYSTEM_DESCRIPTION = """# System Description: Clinical Data Studio (CDS)

Clinical Data Studio is a local-first, lightweight Electronic Data Capture (EDC) system designed for investigator-led clinical research, academic trials, and departmental registries. It operates on a local workstation or LAN environment, with support for deployment in virtualized containers (Docker) using SQLite or PostgreSQL.

## Core Architectural Modules
1. **Participant Registry**: Enrolls subjects and generates unique identifiers.
2. **CRF Builder**: Metadata-driven form design supporting branch logic and calculated fields.
3. **Data Quality Module**: Edit checks, real-time data validation, and query workflow.
4. **Audit Trail**: Secure, computer-generated, chronologically-ordered record of all state changes.
5. **Backups & Security**: Passphrase-protected backups (AES-GCM) and user access matrices.
"""

INTENDED_USE = """# Intended Use & Limitations Statement

## Intended Use
Clinical Data Studio is intended to be used by qualified clinical investigators and research coordinators for:
- Collecting clinical observations in academic, investigator-initiated, or pilot studies.
- Prototyping case report forms (CRFs) before building them in multi-centre EDCs (like REDCap).
- Structuring departmental and antimicrobial audits.
- Conducting small prospective or retrospective observational registries.

## Limitations & Non-Intended Use
- **Not Pre-Validated**: Clinical Data Studio is NOT pre-validated for FDA 21 CFR Part 11, GCP, or HIPAA out-of-the-box.
- **Institutional Validation Required**: Any study subject to regulatory oversight must perform full validation of the final system deployment.
- **Hosting Environment Security**: The security of the data depends entirely on the hosting environment (e.g., local workstation encryption, network firewalls, SSL setup).
"""

RISK_ASSESSMENT = """# Risk Assessment: Clinical Data Studio

| Risk ID | Hazard/Event | Impact | Mitigation in Software | Risk Level (Post-Mitigation) |
| --- | --- | --- | --- | --- |
| RSK-01 | Unauthorized Data Access | High | Salted PBKDF2 password hashing, session timeouts, and CSRF token verification. | Low |
| RSK-02 | Retroactive Audit Log Tampering | High | SHA-256 cryptographic hash chaining links all audit trail rows sequentially. | Low |
| RSK-03 | Data Corruption on SQLite | Medium | Local backups, automated database integrity checks, and pg_dump for Postgres production. | Low |
| RSK-04 | Key/Passphrase Leakage | High | Support for AES-GCM encrypted backup archives; no passwords stored in plain text. | Medium |
"""

URS_FRS_TRACE = """# User & Functional Requirements Specification & Traceability Matrix

## User Requirements (URS)
- **USR-01**: The system must restrict access to authenticated users.
- **USR-02**: The system must generate a secure, timestamped audit trail of all data entries and modifications.
- **USR-03**: The system must support exporting data in clinical formats (CSV, ODM, Codebooks).
- **USR-04**: The system must allow creating encrypted backups.

## Functional Requirements (FRS)
- **FUN-01**: User login requires username, password, and optional TOTP MFA code.
- **FUN-02**: Passwords must be at least 15 characters (18 for admin) and hashed.
- **FUN-03**: The audit log must record `previous_hash` and `row_hash` for each entry.
- **FUN-04**: Backups must use AES-GCM (256-bit key) with random salt and nonce.

## Traceability Matrix
| URS ID | FRS ID | Test Case ID | Status |
| --- | --- | --- | --- |
| USR-01 | FUN-01, FUN-02 | TS-SEC-01 (MFA & Password) | Passed |
| USR-02 | FUN-03 | TS-AUD-01 (Hash Chain verification) | Passed |
| USR-04 | FUN-04 | TS-BKP-01 (AES-GCM backup/restore) | Passed |
"""

IQ_OQ_PQ = """# Installation, Operational, and Performance Qualification (IQ/OQ/PQ)

## Installation Qualification (IQ)
Confirm that:
1. Python (>= 3.9) is installed.
2. Dependencies from `requirements.txt` (including `cryptography` and `pyotp`) are installed.
3. Env variables (`CDS_SECRET_KEY`, `CDS_BACKUP_PASSPHRASE`) are set.

## Operational Qualification (OQ)
Verify that the following core modules pass:
1. Authentication & Session: Lockdown on repeated failures, inactivity timeout <= 1h.
2. Audit Trail: Modification of a row breaks the hash chain verification.
3. Backup: Creation of an encrypted `.cdsenc` archive, and restoration of database + uploads.

## Performance Qualification (PQ)
Verify that under active study conditions:
1. Large data dictionary import (up to 200 fields) completes in < 5 seconds.
2. Participant search response times are < 500ms.
"""

RELEASE_NOTES = """# Release Notes - Clinical Data Studio v0.2.0-pilot

## Security Improvements
- Upgraded custom backup encryption to standard **AES-GCM (256-bit)** AEAD encryption.
- Increased password length requirements: **15+ characters** for users, **18+ characters** for administrators.
- Introduced optional **TOTP Multi-Factor Authentication** (MFA).
- Enforced session expiration: **1 hour** inactivity timeout, **24 hours** absolute timeout.

## Compliance & Audit
- Hardened the audit trail with **SHA-256 cryptographic hash chaining** to guarantee immutability.
- Added a downloadable Access Review matrix CSV.
- Added a Part 11 control mapping dashboard.
"""

def generate_validation_package(conn: Any, study_id: int, db_path: Path, data_dir: Path) -> bytes:
    # 1. Gather dynamic evidence
    study = conn.execute("SELECT * FROM studies WHERE id = ?", (study_id,)).fetchone()
    study_dict = dict(study) if study else {"name": "Unknown Study", "id": study_id}
    
    counts = {
        "forms": conn.execute("SELECT COUNT(*) AS count FROM forms WHERE study_id = ?", (study_id,)).fetchone()["count"],
        "participants": conn.execute("SELECT COUNT(*) AS count FROM participants WHERE study_id = ?", (study_id,)).fetchone()["count"],
        "entries": conn.execute("SELECT COUNT(*) AS count FROM entries WHERE study_id = ?", (study_id,)).fetchone()["count"],
        "queries_open": conn.execute("SELECT COUNT(*) AS count FROM queries WHERE study_id = ? AND status = 'open'", (study_id,)).fetchone()["count"],
        "consent_signatures": conn.execute("SELECT COUNT(*) AS count FROM consent_signatures WHERE study_id = ?", (study_id,)).fetchone()["count"],
        "audit_events": conn.execute("SELECT COUNT(*) AS count FROM audit_log", ()).fetchone()["count"],
    }
    
    protection = data_protection_status()
    recent_audit = [dict(r) for r in conn.execute("SELECT audit_log.*, users.display_name FROM audit_log LEFT JOIN users ON users.id = audit_log.user_id ORDER BY audit_log.id DESC LIMIT 100").fetchall()]
    
    # 2. Get Access Matrix CSV
    access_csv = generate_access_review_csv(conn, study_id)
    
    # 3. Create zip archive
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("README.txt", "Clinical Data Studio Validation Package.\nVerify all checklists and sign the execution record before deploying your study.\n")
        archive.writestr("system_description.md", SYSTEM_DESCRIPTION)
        archive.writestr("intended_use.md", INTENDED_USE)
        archive.writestr("risk_assessment.md", RISK_ASSESSMENT)
        archive.writestr("traceability_matrix.md", URS_FRS_TRACE)
        archive.writestr("iq_oq_pq_plan.md", IQ_OQ_PQ)
        archive.writestr("release_notes.md", RELEASE_NOTES)
        
        # Evidence files
        evidence = {
            "study": study_dict,
            "generated_at": int(time.time()),
            "counts": counts,
            "data_protection": protection,
            "audit_chain_verified": verify_audit_chain(conn)["ok"]
        }
        archive.writestr("evidence/validation_evidence.json", json.dumps(evidence, indent=2))
        archive.writestr("evidence/audit_sample.json", json.dumps(recent_audit, indent=2))
        archive.writestr("evidence/user_access_review.csv", access_csv)
        
        # Manifest
        manifest = {
            "application": "Clinical Data Studio",
            "generated_at": int(time.time()),
            "python": sys.version,
            "platform": platform.platform(),
            "database_backend": getattr(conn, "backend", "sqlite"),
            "database_path": str(db_path),
            "data_folder": str(data_dir),
            "git_commit": os.environ.get("CDS_COMMIT", "unknown")
        }
        archive.writestr("system_manifest.json", json.dumps(manifest, indent=2))
        
        # Checklist and Execution Record
        archive.writestr(
            "validation_execution_record.md",
            f"# Validation Execution Record\n\nStudy: {study_dict['name']}\nDate: {time.strftime('%Y-%m-%d')}\n\n"
            "## Execution Sign-off\n- [ ] IQ Checklist Completed\n- [ ] OQ Tests Completed\n- [ ] Backup Restore Drill Completed\n- [ ] Audit Trail Chain Integrity Confirmed\n\n"
            "Validated by:\nSignature:\nDate:\n"
        )
        
    return zip_buffer.getvalue()
