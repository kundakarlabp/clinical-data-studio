import json
import tempfile
import unittest
import zipfile
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

import config
import authz
import server


class CoreEdcTests(unittest.TestCase):
    def test_normalize_schema_rejects_duplicate_codes(self):
        with self.assertRaises(ValueError):
            server.normalize_schema(
                {
                    "fields": [
                        {"code": "age", "label": "Age", "type": "number"},
                        {"code": "age", "label": "Age duplicate", "type": "number"},
                    ]
                }
            )

    def test_calculated_field_evaluates_safely(self):
        schema = server.normalize_schema(
            {
                "fields": [
                    {"code": "weight", "label": "Weight", "type": "number"},
                    {"code": "double_weight", "label": "Double weight", "type": "calc", "calculation": "weight * 2"},
                ]
            }
        )
        cleaned, issues = server.validate_entry_data(schema, {"weight": "50"})
        self.assertEqual(issues, [])
        self.assertEqual(cleaned["double_weight"], 100)

    def test_redcap_style_choices_metadata_and_branching(self):
        schema = server.normalize_schema(
            {
                "fields": [
                    {"code": "age", "label": "Age", "type": "integer", "min": 0, "max": 120, "units": "years"},
                    {"code": "sex", "label": "Sex", "type": "radio", "choices": "1, Male | 2, Female | 3, Other"},
                    {"code": "pregnant", "label": "Pregnant", "type": "yesno", "branching_logic": "age >= 18 AND sex == 2"},
                    {"code": "note", "label": "Note", "type": "descriptive", "help_text": "Shown only as text"},
                ]
            }
        )
        self.assertEqual(schema["fields"][1]["choices"][1], {"value": "2", "label": "Female"})
        self.assertEqual(schema["fields"][2]["options"], ["1", "0"])
        cleaned, issues = server.validate_entry_data(schema, {"age": "21", "sex": "2", "pregnant": "1"})
        self.assertEqual(issues, [])
        self.assertEqual(cleaned["age"], 21)
        self.assertEqual(cleaned["sex"], "2")
        self.assertEqual(cleaned["pregnant"], "1")
        cleaned_hidden, issues = server.validate_entry_data(schema, {"age": "12", "sex": "2", "pregnant": "1"})
        self.assertEqual(issues, [])
        self.assertNotIn("pregnant", cleaned_hidden)
        self.assertEqual(server.choice_label(schema["fields"][1], "2"), "Female")

    def test_authz_denies_unknown_roles_and_actions(self):
        user = {"id": 10, "role": "data_entry"}
        membership = {"role": "data_entry", "data_group_id": 1}
        self.assertTrue(authz.can(user, "entries.create", membership, {"data_group_id": 1}))
        self.assertFalse(authz.can(user, "export.read", membership))
        self.assertFalse(authz.can({"id": 11, "role": "unknown"}, "entries.create", {"role": "unknown"}))
        self.assertFalse(authz.can(user, "unknown.action", membership))
        self.assertFalse(authz.can(user, "entries.create", membership, {"data_group_id": 2}))

    def test_local_crf_assistant_detects_types_and_choices(self):
        schema, warnings = server.draft_crf_schema_locally("Age\nVisit date\nSex (Female, Male, Unknown)\nAny adverse event?")
        self.assertEqual(warnings, [])
        fields = {field["code"]: field for field in schema["fields"]}
        self.assertEqual(fields["age"]["type"], "number")
        self.assertEqual(fields["visit_date"]["type"], "date")
        self.assertEqual(fields["sex"]["options"], ["Female", "Male", "Unknown"])
        self.assertEqual(fields["any_adverse_event"]["options"], ["No", "Yes"])

    def test_case_intelligence_extracts_publication_fields(self):
        extracted = server.extract_case_intelligence(
            "A 42 year old female presented with fever and cough. Diagnosis: severe influenza pneumonia. "
            "CT chest showed bilateral infiltrates. Treatment: oseltamivir and oxygen. Outcome: improved and discharged.",
            "Influenza pneumonia case",
        )
        self.assertEqual(extracted["demographics"]["age"], "42")
        self.assertEqual(extracted["demographics"]["sex"], "Female")
        self.assertIn("influenza", extracted["clinical"]["diagnosis"].lower())
        self.assertIn("oseltamivir", extracted["clinical"]["treatment"].lower())
        self.assertNotIn("outcome", extracted["missing_fields"])

    def test_local_academic_review_suggests_adaptive_fields(self):
        case = {
            "id": 1,
            "case_uid": "CASE-001",
            "files": [{"name": "note.txt"}],
            "extracted": server.extract_case_intelligence(
                "A 42 year old female. Diagnosis: influenza pneumonia. Treatment: oseltamivir. Outcome: improved.",
                "Influenza pneumonia",
            ),
        }
        review = server.local_academic_case_review(case, [case], "publication angle?")
        self.assertIn("publication_guidance", review)
        self.assertTrue(review["adaptive_crf_suggestions"])
        self.assertTrue(any(field["code"] == "diagnosis" for field in review["adaptive_crf_suggestions"]))

    def test_migration_creates_database(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            original_data = server.DATA
            original_db = server.DB_PATH
            original_backend = server.DATABASE_BACKEND
            try:
                server.DATA = Path(tmp)
                server.DB_PATH = Path(tmp) / "test.sqlite3"
                server.DATABASE_BACKEND = "sqlite"
                server.migrate()
                self.assertTrue(server.DB_PATH.exists())
            finally:
                server.DATA = original_data
                server.DB_PATH = original_db
                server.DATABASE_BACKEND = original_backend

    def test_development_settings_do_not_bind_publicly(self):
        with patch.dict("os.environ", {"CDS_ENV": "development", "CDS_HOST": "0.0.0.0"}, clear=False):
            settings = config.load_settings()
        self.assertEqual(settings.host, "127.0.0.1")

    def test_postgres_settings_derive_url_from_password(self):
        with patch.dict("os.environ", {"CDS_DATABASE_BACKEND": "postgres", "POSTGRES_PASSWORD": "StrongDbPassword123", "DATABASE_URL": ""}, clear=False):
            settings = config.load_settings()
        self.assertEqual(settings.database_url, "postgresql://clinical:StrongDbPassword123@db:5432/clinical_data_studio")

    def test_production_startup_requires_secret_key(self):
        original_settings = server.SETTINGS
        original_host = server.HOST
        try:
            server.SETTINGS = replace(original_settings, env="production", secret_key="", admin_password="StrongAdminPassword123")
            server.HOST = "127.0.0.1"
            with self.assertRaises(RuntimeError):
                server.validate_startup()
        finally:
            server.SETTINGS = original_settings
            server.HOST = original_host

    def test_production_startup_rejects_placeholder_postgres_url(self):
        original_settings = server.SETTINGS
        original_host = server.HOST
        original_backend = server.DATABASE_BACKEND
        original_url = server.DATABASE_URL
        try:
            server.SETTINGS = replace(
                original_settings,
                env="production",
                secret_key="x" * 40,
                admin_password="StrongAdminPassword123",
                public_base_url="https://example.org",
            )
            server.HOST = "127.0.0.1"
            server.DATABASE_BACKEND = "postgres"
            server.DATABASE_URL = "postgresql://clinical:change_me@db:5432/clinical_data_studio"
            with self.assertRaises(RuntimeError):
                server.validate_startup()
        finally:
            server.SETTINGS = original_settings
            server.HOST = original_host
            server.DATABASE_BACKEND = original_backend
            server.DATABASE_URL = original_url

    def test_production_startup_rejects_sqlite_without_explicit_override(self):
        original_settings = server.SETTINGS
        original_host = server.HOST
        original_backend = server.DATABASE_BACKEND
        try:
            server.SETTINGS = replace(
                original_settings,
                env="production",
                secret_key="x" * 40,
                admin_password="StrongAdminPassword123",
                public_base_url="https://example.org",
            )
            server.HOST = "127.0.0.1"
            server.DATABASE_BACKEND = "sqlite"
            with patch.dict("os.environ", {"CDS_ALLOW_SQLITE_PRODUCTION": ""}, clear=False):
                with self.assertRaises(RuntimeError):
                    server.validate_startup()
        finally:
            server.SETTINGS = original_settings
            server.HOST = original_host
            server.DATABASE_BACKEND = original_backend

    def test_external_ai_phi_gate_blocks_identifiers_by_default(self):
        original_settings = server.SETTINGS
        try:
            server.SETTINGS = replace(original_settings, ai_provider="openai", ai_enabled=True, ai_allow_phi=False)
            with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=False):
                with self.assertRaises(ValueError):
                    server.assert_external_ai_safe("Patient name: John Doe\nPhone: 9999999999\nDOB: 01/02/1960")
        finally:
            server.SETTINGS = original_settings

    def test_ai_safety_deidentifies_common_identifiers(self):
        text = "Patient name: John Doe\nPhone: 9999999999\nEmail: john@example.com\nDOB: 01/02/1960\nUHID: ABC123"
        cleaned = server.deidentify_for_ai(text, "CASE-001")
        self.assertIn("Patient name: CASE-001", cleaned)
        self.assertIn("[phone removed]", cleaned)
        self.assertIn("[email removed]", cleaned)
        self.assertIn("DOB: [removed]", cleaned)
        self.assertIn("UHID: [removed]", cleaned)

    def test_ai_status_defaults_to_local_without_key(self):
        original_settings = server.SETTINGS
        try:
            server.SETTINGS = replace(original_settings, ai_provider="openai", ai_enabled=True, ai_allow_phi=False, ai_multimodal=True)
            with patch.dict("os.environ", {"OPENAI_API_KEY": ""}, clear=False):
                status = server.ai_status()
        finally:
            server.SETTINGS = original_settings
        self.assertEqual(status["provider"], "local")
        self.assertFalse(status["external_ai_enabled"])
        self.assertFalse(status["multimodal_enabled"])

    def test_full_backup_includes_database_uploads_and_verifies(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            original_data = server.DATA
            original_backups = server.BACKUPS
            original_uploads = server.UPLOADS
            original_db = server.DB_PATH
            original_backend = server.DATABASE_BACKEND
            try:
                root = Path(tmp)
                server.DATA = root / "data"
                server.BACKUPS = root / "backups"
                server.UPLOADS = root / "uploads"
                server.DB_PATH = server.DATA / "test.sqlite3"
                server.DATABASE_BACKEND = "sqlite"
                server.migrate()
                upload_file = server.UPLOADS / "studies" / "1" / "cases" / "1" / "note.txt"
                upload_file.parent.mkdir(parents=True, exist_ok=True)
                upload_file.write_text("case evidence", encoding="utf-8")

                backup = server.create_full_backup("LongLocalPassphrase123")
                self.assertTrue(backup["name"].endswith(".full.cdsenc"))
                verification = server.verify_full_backup(server.BACKUPS / backup["name"], "LongLocalPassphrase123", record=True)

                self.assertTrue(verification["ok"], verification["errors"])
                self.assertIn("manifest.json", verification["contents"])
                self.assertIn("SHA256SUMS.txt", verification["contents"])
                self.assertIn("uploads.zip", verification["contents"])
                self.assertTrue(verification["database_dump"])
                self.assertTrue(verification["database_dump_nonempty"])
                self.assertTrue(verification["includes_manifest"])
                self.assertTrue(verification["includes_uploads"])
                self.assertTrue(verification["checksum_verified"])
                self.assertFalse(verification["manifest"]["encryption"]["passphrase_stored"])
                self.assertNotIn("LongLocalPassphrase123", json.dumps(verification["manifest"]))
                self.assertEqual(verification["upload_file_count"], 1)
                self.assertTrue(server.latest_full_backup_info()["verified"])
                health = server.health_payload()
                self.assertTrue(health["backup"]["latest_full_backup_verified"])
                self.assertEqual(health["backup"]["uploads"]["file_count"], 1)
            finally:
                server.DATA = original_data
                server.BACKUPS = original_backups
                server.UPLOADS = original_uploads
                server.DB_PATH = original_db
                server.DATABASE_BACKEND = original_backend

    def test_full_backup_verification_fails_without_upload_archive(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            original_backups = server.BACKUPS
            try:
                server.BACKUPS = Path(tmp)
                server.BACKUPS.mkdir(parents=True, exist_ok=True)
                payload = BytesIO()
                with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED) as archive:
                    archive.writestr("postgres.dump", b"dump")
                    archive.writestr("manifest.json", json.dumps({"backup_type": "full", "database_dump": "postgres.dump", "uploads_archive": "uploads.zip"}))
                    archive.writestr("SHA256SUMS.txt", f"{server.sha256_bytes(b'dump')}  postgres.dump\n")
                broken = server.BACKUPS / "full_broken.full.cdsenc"
                broken.write_bytes(server.encrypted_archive_bytes(payload.getvalue(), "LongLocalPassphrase123"))
                verification = server.verify_full_backup(broken, "LongLocalPassphrase123")
                self.assertFalse(verification["ok"])
                self.assertTrue(any("Uploads archive" in item or "uploads.zip" in item for item in verification["errors"]))
            finally:
                server.BACKUPS = original_backups

    def test_full_backup_verification_fails_on_checksum_mismatch(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            original_backups = server.BACKUPS
            try:
                server.BACKUPS = Path(tmp)
                server.BACKUPS.mkdir(parents=True, exist_ok=True)
                uploads = BytesIO()
                with zipfile.ZipFile(uploads, "w", zipfile.ZIP_DEFLATED) as upload_zip:
                    upload_zip.writestr("EMPTY_UPLOADS.txt", "empty")
                upload_bytes = uploads.getvalue()
                payload = BytesIO()
                with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED) as archive:
                    archive.writestr("postgres.dump", b"dump")
                    archive.writestr("uploads.zip", upload_bytes)
                    archive.writestr("manifest.json", json.dumps({"backup_type": "full", "database_dump": "postgres.dump", "uploads_archive": "uploads.zip"}))
                    archive.writestr("SHA256SUMS.txt", f"{'0' * 64}  postgres.dump\n{server.sha256_bytes(upload_bytes)}  uploads.zip\n")
                broken = server.BACKUPS / "full_checksum.full.cdsenc"
                broken.write_bytes(server.encrypted_archive_bytes(payload.getvalue(), "LongLocalPassphrase123"))
                verification = server.verify_full_backup(broken, "LongLocalPassphrase123")
                self.assertFalse(verification["ok"])
                self.assertFalse(verification["checksum_verified"])
                self.assertTrue(any("Checksum mismatch" in item for item in verification["errors"]))
            finally:
                server.BACKUPS = original_backups

    def test_public_base_url_warnings_detect_placeholder_and_mismatch(self):
        original_settings = server.SETTINGS
        try:
            server.SETTINGS = replace(original_settings, env="production", public_base_url="https://your-domain.example", require_https=True)
            warnings = server.public_base_url_warnings("real.example", "https")
            self.assertTrue(any("placeholder" in warning for warning in warnings))
            self.assertTrue(any("does not match" in warning for warning in warnings))
            server.SETTINGS = replace(original_settings, env="production", public_base_url="http://real.example", require_https=True)
            self.assertTrue(any("http://" in warning for warning in server.public_base_url_warnings("real.example", "https")))
        finally:
            server.SETTINGS = original_settings

    def test_env_example_quotes_display_name_with_spaces(self):
        env_text = (server.ROOT / ".env.example").read_text(encoding="utf-8")
        self.assertIn('CDS_ADMIN_DISPLAY_NAME="Study Administrator"', env_text)


if __name__ == "__main__":
    unittest.main()
