import unittest
import sqlite3
import tempfile
from pathlib import Path

from cds.db.migrations import run_migrations

class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "migration_test.db"
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row

    def tearDown(self):
        self.conn.close()
        self.tmp_dir.cleanup()

    def test_run_migrations_from_scratch(self):
        # Database starts completely empty
        # Run migrations
        run_migrations(self.conn)
        
        # Verify schema_migrations table exists and has versions
        rows = self.conn.execute("SELECT * FROM schema_migrations ORDER BY version").fetchall()
        versions = [r["version"] for r in rows]
        
        # We expect versions [1, 2, 3, 4] to be applied
        self.assertEqual(versions, [1, 2, 3, 4])
        
        # Verify some core tables exist
        tables_row = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('users', 'sessions', 'audit_log', 'studies')"
        ).fetchall()
        tables = {r["name"] for r in tables_row}
        self.assertTrue({"users", "sessions", "audit_log", "studies"}.issubset(tables))
        
        # Verify columns from migration v2 exist (MFA)
        user_cols = [c["name"] for c in self.conn.execute("PRAGMA table_info(users)").fetchall()]
        self.assertIn("mfa_secret", user_cols)
        self.assertIn("mfa_enabled", user_cols)
        
        # Verify columns from migration v3 exist (Audit hash chain)
        audit_cols = [c["name"] for c in self.conn.execute("PRAGMA table_info(audit_log)").fetchall()]
        self.assertIn("previous_hash", audit_cols)
        self.assertIn("row_hash", audit_cols)
        
        # Verify sessions column from migration v4 exists (last_action_at)
        session_cols = [c["name"] for c in self.conn.execute("PRAGMA table_info(sessions)").fetchall()]
        self.assertIn("last_action_at", session_cols)
        self.assertIn("mfa_verified", session_cols)

    def test_run_migrations_retroactive_baseline(self):
        # Scenario where 'users' table already exists (simulating old database),
        # but 'schema_migrations' does not exist.
        self.conn.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                display_name TEXT,
                role TEXT,
                active INTEGER,
                created_at INTEGER
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER,
                expires_at INTEGER,
                created_at INTEGER
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                action TEXT,
                entity_type TEXT,
                entity_id INTEGER,
                before_json TEXT,
                after_json TEXT,
                created_at INTEGER
            )
            """
        )
        self.conn.commit()
        
        # Run migrations. It should detect existing users table,
        # insert v1 retroactively, and apply v2, v3, v4.
        run_migrations(self.conn)
        
        rows = self.conn.execute("SELECT * FROM schema_migrations ORDER BY version").fetchall()
        versions = [r["version"] for r in rows]
        self.assertEqual(versions, [1, 2, 3, 4])
        
        # Check that new columns were added
        user_cols = [c["name"] for c in self.conn.execute("PRAGMA table_info(users)").fetchall()]
        self.assertIn("mfa_secret", user_cols)
        self.assertIn("mfa_enabled", user_cols)
