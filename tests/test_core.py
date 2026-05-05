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
