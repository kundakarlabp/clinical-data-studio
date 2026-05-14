import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import config
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
            try:
                server.DATA = Path(tmp)
                server.DB_PATH = Path(tmp) / "test.sqlite3"
                server.migrate()
                self.assertTrue(server.DB_PATH.exists())
            finally:
                server.DATA = original_data
                server.DB_PATH = original_db

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
                    server.assert_external_ai_safe("Patient name: John Doe\nPhone: 9999999999")
        finally:
            server.SETTINGS = original_settings


if __name__ == "__main__":
    unittest.main()
