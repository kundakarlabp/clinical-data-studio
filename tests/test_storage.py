import unittest

import storage


class StorageAdapterTests(unittest.TestCase):
    def test_insert_or_ignore_form_events_translates_to_postgres_upsert(self):
        sql = "INSERT OR IGNORE INTO form_events(study_id, event_id, form_id, required) VALUES (?, ?, ?, 1)"
        translated = storage.translate_sql(sql)
        self.assertIn("INSERT INTO form_events", translated)
        self.assertIn("ON CONFLICT(event_id, form_id) DO NOTHING", translated)
        self.assertEqual(translated.count("%s"), 3)

    def test_insert_or_replace_field_states_translates_to_postgres_upsert(self):
        sql = "INSERT OR REPLACE INTO field_states(entry_id, field_code, state, reason, user_id, created_at) VALUES (?, ?, ?, ?, ?, ?)"
        translated = storage.translate_sql(sql)
        self.assertIn("INSERT INTO field_states", translated)
        self.assertIn("ON CONFLICT(entry_id, field_code, state) DO UPDATE", translated)
        self.assertIn("reason = EXCLUDED.reason", translated)
        self.assertEqual(translated.count("%s"), 6)

    def test_split_sql_script_preserves_semicolon_inside_string(self):
        script = "CREATE TABLE demo(value TEXT DEFAULT 'a;b'); CREATE INDEX demo_idx ON demo(value);"
        statements = storage.split_sql_script(script)
        self.assertEqual(len(statements), 2)
        self.assertIn("'a;b'", statements[0])
        self.assertIn("CREATE INDEX", statements[1])


if __name__ == "__main__":
    unittest.main()
