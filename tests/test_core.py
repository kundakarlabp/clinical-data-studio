import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
