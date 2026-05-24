import unittest
import tempfile
import sqlite3
import time
import json
import base64
from pathlib import Path
from unittest.mock import patch

from cds.security.passwords import encode_password, verify_password, validate_password_strength
from cds.security.sessions import create_session, verify_session, delete_session, invalidate_user_sessions, session_token_digest
from cds.security.csrf import csrf_token, verify_csrf_token
from cds.services.backup_service import encrypted_archive_bytes, decrypted_archive_bytes
from cds.services.audit_service import audit, verify_audit_chain

class SecurityAndAuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test.db"
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        
        # Setup tables needed
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'admin',
                active INTEGER NOT NULL DEFAULT 1,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                failed_login_count INTEGER NOT NULL DEFAULT 0,
                locked_until INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                mfa_secret TEXT,
                mfa_enabled INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                last_action_at INTEGER,
                mfa_verified INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER REFERENCES users(id),
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id INTEGER,
                before_json TEXT,
                after_json TEXT,
                created_at INTEGER NOT NULL,
                study_id INTEGER,
                ip_address TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT '',
                request_id TEXT NOT NULL DEFAULT '',
                previous_hash TEXT,
                row_hash TEXT
            )
            """
        )
        self.conn.commit()

        # Seed admin
        self.conn.execute(
            "INSERT INTO users (username, password_hash, display_name, role, active, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            ("admin", encode_password("admin1234567890"), "Administrator", "super_admin", 1, int(time.time()))
        )
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        self.tmp_dir.cleanup()

    # 1. Password Strength tests
    def test_password_strength_enforcement(self):
        # Admin needs >= 18 characters
        with self.assertRaises(ValueError):
            validate_password_strength("ShortAdmin12", is_admin=True)
            
        # Regular user needs >= 15 characters
        with self.assertRaises(ValueError):
            validate_password_strength("ShortUser12", is_admin=False)
            
        # Valid passwords pass
        validate_password_strength("LongPassphraseForAdminIsOk", is_admin=True)
        validate_password_strength("ValidRegularUserPassphrase", is_admin=False)
        
        # Max limit 128
        with self.assertRaises(ValueError):
            validate_password_strength("a" * 129)

    # 2. AEAD Backup Encryption tests
    def test_aead_backup_encryption(self):
        plain_text = b"Confidential clinical research data"
        passphrase = "SecurePassphrase12345"
        
        # Encrypt
        encrypted = encrypted_archive_bytes(plain_text, passphrase)
        self.assertTrue(encrypted.startswith(b"CDSENC2\n"))
        
        # Decrypt
        decrypted = decrypted_archive_bytes(encrypted, passphrase)
        self.assertEqual(decrypted, plain_text)
        
        # Decrypt with wrong password fails
        with self.assertRaises(ValueError):
            decrypted_archive_bytes(encrypted, "WrongPassphrase12345")
            
        # Decrypt tampered payload fails
        tampered_archive = bytearray(encrypted)
        tampered_archive[40] = tampered_archive[40] ^ 0xFF  # Corrupt ciphertext byte
        with self.assertRaises(ValueError):
            decrypted_archive_bytes(bytes(tampered_archive), passphrase)

    # 3. Session Timeout and Invalidation tests
    def test_session_lifecycle(self):
        # Create session
        token = create_session(self.conn, 1)
        digest = session_token_digest(token)
        
        # Check active session
        session = verify_session(self.conn, digest)
        self.assertIsNotNone(session)
        self.assertEqual(session["user_id"], 1)
        
        # Test inactivity timeout (mock time 3601 seconds in future)
        with patch("cds.security.sessions.now", return_value=int(time.time()) + 3601):
            session_expired = verify_session(self.conn, digest)
            self.assertIsNone(session_expired)
            
        # Re-create session
        token = create_session(self.conn, 1)
        digest = session_token_digest(token)
        
        # Test absolute timeout (mock time 86401 seconds in future)
        with patch("cds.security.sessions.now", return_value=int(time.time()) + 86401):
            session_expired = verify_session(self.conn, digest)
            self.assertIsNone(session_expired)
            
        # Invalidate sessions on password change
        token1 = create_session(self.conn, 1)
        token2 = create_session(self.conn, 1)
        digest1 = session_token_digest(token1)
        digest2 = session_token_digest(token2)
        
        invalidate_user_sessions(self.conn, 1, keep_token=digest1)
        self.assertIsNotNone(verify_session(self.conn, digest1))
        self.assertIsNone(verify_session(self.conn, digest2))

    # 4. CSRF tests
    def test_csrf_token_verification(self):
        session_digest = "test_session_digest_1234"
        
        # Generate token
        token = csrf_token(session_digest)
        
        # Verify active token
        self.assertTrue(verify_csrf_token(session_digest, token))
        
        # Verify with wrong digest fails
        self.assertFalse(verify_csrf_token("wrong_digest", token))
        
        # Verify tampered token fails
        self.assertFalse(verify_csrf_token(session_digest, token + "tamper"))
        
        # Verify expired token fails (mock time 15 days in future)
        with patch("cds.security.csrf.now", return_value=int(time.time()) + (15 * 24 * 3600)):
            self.assertFalse(verify_csrf_token(session_digest, token))

    # 5. Cryptographic Audit Trail Hash Chain tests
    def test_audit_hash_chain(self):
        # Write first audit record
        audit(self.conn, 1, "test_action_1", "study", 101, before={"v": 1}, after={"v": 2})
        # Write second audit record
        audit(self.conn, 1, "test_action_2", "study", 101, before={"v": 2}, after={"v": 3})
        
        # Verify chain integrity
        verif = verify_audit_chain(self.conn)
        self.assertTrue(verif["ok"])
        self.assertEqual(verif["count"], 2)
        
        # Inspect rows
        rows = self.conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
        self.assertEqual(len(rows), 2)
        
        # Row 2 previous_hash must equal Row 1 row_hash
        self.assertEqual(rows[1]["previous_hash"], rows[0]["row_hash"])
        
        # Tamper with row content in database
        self.conn.execute("UPDATE audit_log SET after_json = ? WHERE id = ?", (json.dumps({"v": 999}), rows[0]["id"]))
        self.conn.commit()
        
        # Verification must now fail!
        verif_failed = verify_audit_chain(self.conn)
        self.assertFalse(verif_failed["ok"])
        self.assertEqual(verif_failed["break_at_id"], rows[0]["id"])

    # 6. Log Sanitizer and Request ID correlation tests
    def test_log_sanitizer_redaction(self):
        from cds.services.log_sanitizer import sanitize_log_message, set_request_id, get_request_id, SanitizingFormatter
        import logging
        
        # Test basic redactors
        raw_msg = 'Received login for user admin with password "secret123" and token cds_DYUQpQK0VaZPveAALz8jtRYY05W42K07ogtHNpyDvNo'
        sanitized = sanitize_log_message(raw_msg)
        self.assertNotIn("secret123", sanitized)
        self.assertNotIn("cds_DYUQpQK0VaZPveAALz8jtRYY05W42K07ogtHNpyDvNo", sanitized)
        self.assertIn('"password": "REDACTED"', sanitized)
        self.assertIn("cds_REDACTED", sanitized)
        
        # Test PHI redactors
        phi_msg = "Patient name is John Doe, email john.doe@example.com, phone +1-555-555-5555"
        sanitized_phi = sanitize_log_message(phi_msg)
        self.assertNotIn("John Doe", sanitized_phi)
        self.assertNotIn("john.doe@example.com", sanitized_phi)
        self.assertNotIn("555-555-5555", sanitized_phi)
        self.assertIn("[PHI REDACTED]", sanitized_phi)
        self.assertIn("[EMAIL REDACTED]", sanitized_phi)
        self.assertIn("[PHONE REDACTED]", sanitized_phi)
        
        # Test request_id correlation
        set_request_id("REQ-12345")
        self.assertEqual(get_request_id(), "REQ-12345")
        
        # Test formatter injection
        formatter = SanitizingFormatter("%(request_id)s - %(message)s")
        record = logging.LogRecord("test", logging.INFO, "path", 10, "Hello John Doe", (), None)
        formatted_log = formatter.format(record)
        self.assertEqual(formatted_log, "REQ-12345 - Hello [PHI REDACTED]")
