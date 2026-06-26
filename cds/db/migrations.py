import logging
import sqlite3
import time
from typing import Any
from contextlib import closing

import config
from cds.services.audit_service import backfill_audit_chain

LOGGER = logging.getLogger("clinical-data-studio")

def now() -> int:
    return int(time.time())

def add_column_if_not_exists(conn: Any, table: str, column: str, definition: str) -> None:
    backend = getattr(conn, "backend", "sqlite")
    if backend == "postgres":
        if column in conn.table_columns(table):
            return
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        return
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
    except Exception as exc:
        # SQLite does not support ADD COLUMN IF NOT EXISTS on all supported versions.
        LOGGER.debug(f"Could not add column {column} to table {table} (it might already exist): {exc}")

def migration_1_initial(conn: Any) -> None:
    # Baseline setup. If tables already exist, do nothing.
    backend = getattr(conn, "backend", "sqlite")
    
    # Check if 'users' table already exists. If so, baseline is already present.
    try:
        if backend == "postgres":
            res = conn.execute("SELECT 1 FROM information_schema.tables WHERE table_name = 'users'").fetchone()
            exists = bool(res)
        else:
            res = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
            exists = bool(res)
    except Exception:
        exists = False

    if exists:
        LOGGER.info("Baseline tables already exist. Skipping Migration 1.")
        return

    LOGGER.info("Creating baseline tables...")
    if backend == "postgres":
        from storage import POSTGRES_SCHEMA_SQL, PRODUCTION_INDEX_SQL
        conn.executescript(POSTGRES_SCHEMA_SQL)
        conn.executescript(PRODUCTION_INDEX_SQL)
    else:
        # We can run the SQL script for sqlite baseline
        # (This SQL is imported from server.py or written here)
        # We will write the full sqlite baseline tables schema
        sqlite_schema = """
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
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS studies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            protocol_id TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'draft',
            ai_policy_json TEXT NOT NULL DEFAULT '{}',
            eligibility_criteria_json TEXT NOT NULL DEFAULT '{}',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS data_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            code TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(study_id, code)
        );
        CREATE TABLE IF NOT EXISTS study_memberships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            role TEXT NOT NULL DEFAULT 'data_entry',
            data_group_id INTEGER REFERENCES data_groups(id) ON DELETE SET NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(study_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS forms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            code TEXT NOT NULL,
            schema_json TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            active INTEGER NOT NULL DEFAULT 1,
            lifecycle_state TEXT NOT NULL DEFAULT 'published',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(study_id, code)
        );
        CREATE TABLE IF NOT EXISTS study_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            code TEXT NOT NULL,
            arm_name TEXT NOT NULL DEFAULT 'Default',
            day_offset INTEGER NOT NULL DEFAULT 0,
            display_order INTEGER NOT NULL DEFAULT 1,
            active INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(study_id, code)
        );
        CREATE TABLE IF NOT EXISTS form_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            event_id INTEGER NOT NULL REFERENCES study_events(id) ON DELETE CASCADE,
            form_id INTEGER NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
            required INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(event_id, form_id)
        );
        CREATE TABLE IF NOT EXISTS survey_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            form_id INTEGER NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
            event_id INTEGER REFERENCES study_events(id) ON DELETE SET NULL,
            token TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            consent_required INTEGER NOT NULL DEFAULT 0,
            consent_text TEXT NOT NULL DEFAULT '',
            created_by INTEGER REFERENCES users(id),
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS form_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            form_id INTEGER NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            version INTEGER NOT NULL,
            name TEXT NOT NULL,
            code TEXT NOT NULL,
            schema_json TEXT NOT NULL,
            saved_by INTEGER REFERENCES users(id),
            saved_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS participants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            data_group_id INTEGER REFERENCES data_groups(id) ON DELETE SET NULL,
            study_uid TEXT NOT NULL,
            initials TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'screening',
            recruitment_source TEXT NOT NULL DEFAULT '',
            screening_date INTEGER,
            consent_date INTEGER,
            consent_status TEXT NOT NULL DEFAULT 'pending',
            consent_version TEXT NOT NULL DEFAULT '',
            eligibility_checklist_json TEXT NOT NULL DEFAULT '{}',
            screening_notes TEXT NOT NULL DEFAULT '',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(study_id, study_uid)
        );
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            participant_id INTEGER NOT NULL REFERENCES participants(id) ON DELETE CASCADE,
            form_id INTEGER NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
            event_id INTEGER REFERENCES study_events(id) ON DELETE SET NULL,
            event_name TEXT NOT NULL DEFAULT 'Baseline',
            repeat_instance INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'draft',
            data_json TEXT NOT NULL DEFAULT '{}',
            form_version INTEGER NOT NULL DEFAULT 1,
            schema_snapshot_json TEXT NOT NULL DEFAULT '{}',
            entry_hash TEXT NOT NULL DEFAULT '',
            created_by INTEGER REFERENCES users(id),
            updated_by INTEGER REFERENCES users(id),
            locked_at INTEGER,
            locked_by INTEGER REFERENCES users(id),
            lock_reason TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(participant_id, form_id, event_name, repeat_instance)
        );
        CREATE TABLE IF NOT EXISTS queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            participant_id INTEGER REFERENCES participants(id) ON DELETE CASCADE,
            form_id INTEGER REFERENCES forms(id) ON DELETE CASCADE,
            entry_id INTEGER REFERENCES entries(id) ON DELETE SET NULL,
            field_code TEXT NOT NULL DEFAULT '',
            message TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            created_by INTEGER REFERENCES users(id),
            assigned_to INTEGER REFERENCES users(id),
            due_at INTEGER,
            closed_at INTEGER,
            closed_by INTEGER REFERENCES users(id),
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS query_responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query_id INTEGER NOT NULL REFERENCES queries(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id),
            message TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS field_states (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
            field_code TEXT NOT NULL,
            state TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            user_id INTEGER REFERENCES users(id),
            created_at INTEGER NOT NULL,
            UNIQUE(entry_id, field_code, state)
        );
        CREATE TABLE IF NOT EXISTS consent_signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            participant_id INTEGER NOT NULL REFERENCES participants(id) ON DELETE CASCADE,
            entry_id INTEGER REFERENCES entries(id) ON DELETE SET NULL,
            signer_name TEXT NOT NULL,
            signature_text TEXT NOT NULL,
            consent_text TEXT NOT NULL,
            ip_address TEXT NOT NULL DEFAULT '',
            user_agent TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS survey_invitations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            survey_link_id INTEGER NOT NULL REFERENCES survey_links(id) ON DELETE CASCADE,
            participant_id INTEGER REFERENCES participants(id) ON DELETE SET NULL,
            contact TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            invite_token TEXT UNIQUE NOT NULL,
            last_sent_at INTEGER,
            reminder_count INTEGER NOT NULL DEFAULT 0,
            completed_at INTEGER,
            created_by INTEGER REFERENCES users(id),
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id INTEGER,
            before_json TEXT,
            after_json TEXT,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            filters_json TEXT NOT NULL DEFAULT '{}',
            created_by INTEGER REFERENCES users(id),
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS case_intakes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            participant_id INTEGER REFERENCES participants(id) ON DELETE SET NULL,
            case_uid TEXT NOT NULL,
            title TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft',
            source_text TEXT NOT NULL DEFAULT '',
            extracted_json TEXT NOT NULL DEFAULT '{}',
            tags_json TEXT NOT NULL DEFAULT '[]',
            created_by INTEGER REFERENCES users(id),
            updated_by INTEGER REFERENCES users(id),
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(study_id, case_uid)
        );
        CREATE TABLE IF NOT EXISTS case_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL REFERENCES case_intakes(id) ON DELETE CASCADE,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            original_filename TEXT NOT NULL DEFAULT '',
            stored_filename TEXT NOT NULL DEFAULT '',
            content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
            size INTEGER NOT NULL DEFAULT 0,
            sha256 TEXT NOT NULL DEFAULT '',
            data_base64 TEXT NOT NULL DEFAULT '',
            created_by INTEGER REFERENCES users(id),
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS case_ai_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL REFERENCES case_intakes(id) ON DELETE CASCADE,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            user_prompt TEXT NOT NULL DEFAULT '',
            mode TEXT NOT NULL DEFAULT 'local',
            response_json TEXT NOT NULL DEFAULT '{}',
            file_count INTEGER NOT NULL DEFAULT 0,
            created_by INTEGER REFERENCES users(id),
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ai_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            study_id INTEGER REFERENCES studies(id) ON DELETE CASCADE,
            case_id INTEGER REFERENCES case_intakes(id) ON DELETE SET NULL,
            provider TEXT NOT NULL DEFAULT 'local',
            model TEXT NOT NULL DEFAULT 'local-rules',
            mode TEXT NOT NULL DEFAULT 'local',
            purpose TEXT NOT NULL DEFAULT '',
            input_type TEXT NOT NULL DEFAULT 'text',
            phi_detected INTEGER NOT NULL DEFAULT 0,
            phi_allowed INTEGER NOT NULL DEFAULT 0,
            deidentified INTEGER NOT NULL DEFAULT 0,
            file_count INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'ok',
            error TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS academic_cv_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            item_type TEXT NOT NULL DEFAULT 'publication',
            title TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'planned',
            item_date TEXT NOT NULL DEFAULT '',
            citation TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            linked_case_id INTEGER REFERENCES case_intakes(id) ON DELETE SET NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            active INTEGER NOT NULL DEFAULT 1,
            created_by INTEGER REFERENCES users(id),
            updated_by INTEGER REFERENCES users(id),
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS academic_outputs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            output_type TEXT NOT NULL DEFAULT 'publication_idea',
            title TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'idea',
            linked_case_id INTEGER REFERENCES case_intakes(id) ON DELETE SET NULL,
            participant_ids_json TEXT NOT NULL DEFAULT '[]',
            evidence_file_ids_json TEXT NOT NULL DEFAULT '[]',
            dataset_ref TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            active INTEGER NOT NULL DEFAULT 1,
            created_by INTEGER REFERENCES users(id),
            updated_by INTEGER REFERENCES users(id),
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT UNIQUE NOT NULL,
            label TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            last_used_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS randomization_lists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            arms_json TEXT NOT NULL,
            next_index INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1,
            created_by INTEGER REFERENCES users(id),
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS randomization_allocations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            list_id INTEGER NOT NULL REFERENCES randomization_lists(id) ON DELETE CASCADE,
            participant_id INTEGER NOT NULL REFERENCES participants(id) ON DELETE CASCADE,
            arm TEXT NOT NULL,
            allocated_by INTEGER REFERENCES users(id),
            created_at INTEGER NOT NULL,
            UNIQUE(list_id, participant_id)
        );
        CREATE TABLE IF NOT EXISTS ai_drafts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            entity_type TEXT NOT NULL,
            entity_id INTEGER NOT NULL,
            draft_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending_review',
            draft_json TEXT NOT NULL DEFAULT '{}',
            rule_metadata_json TEXT NOT NULL DEFAULT '{}',
            created_by INTEGER REFERENCES users(id),
            updated_by INTEGER REFERENCES users(id),
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ai_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id),
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id INTEGER,
            payload_json TEXT NOT NULL DEFAULT '{}',
            created_at INTEGER NOT NULL
        );
        """
        conn.executescript(sqlite_schema)
    ensure_legacy_columns(conn)

def migration_2_mfa(conn: Any) -> None:
    LOGGER.info("Running Migration 2: Adding MFA columns to users table...")
    add_column_if_not_exists(conn, "users", "mfa_secret", "TEXT")
    add_column_if_not_exists(conn, "users", "mfa_enabled", "INTEGER NOT NULL DEFAULT 0")
    add_column_if_not_exists(conn, "sessions", "mfa_verified", "INTEGER NOT NULL DEFAULT 1")

def migration_3_hash_chain(conn: Any) -> None:
    LOGGER.info("Running Migration 3: Adding hash chaining to audit_log...")
    # Add columns to audit_log table
    add_column_if_not_exists(conn, "audit_log", "previous_hash", "TEXT")
    add_column_if_not_exists(conn, "audit_log", "row_hash", "TEXT")
    
    # Backfill hashes for existing rows so we have a solid retrospective chain!
    backfill_audit_chain(conn)

def migration_4_sessions_inactivity(conn: Any) -> None:
    LOGGER.info("Running Migration 4: Adding inactivity tracking to sessions...")
    add_column_if_not_exists(conn, "sessions", "last_action_at", "INTEGER")
    # Backfill existing sessions: last_action_at = created_at
    conn.execute("UPDATE sessions SET last_action_at = created_at WHERE last_action_at IS NULL")

# List of migrations
MIGRATIONS = [
    {"version": 1, "description": "Initial setup of schema tables", "up": migration_1_initial},
    {"version": 2, "description": "Add optional TOTP MFA columns to users", "up": migration_2_mfa},
    {"version": 3, "description": "Add cryptographic hash chaining to audit_log", "up": migration_3_hash_chain},
    {"version": 4, "description": "Add session inactivity tracking column", "up": migration_4_sessions_inactivity},
]


                
def ensure_legacy_columns(conn: Any) -> None:
    # Support old ad hoc column migrations from server.py, keeping it resilient
    # We will ensure columns added by late ad-hoc migrations exist:
    add_column_if_not_exists(conn, "entries", "repeat_instance", "INTEGER NOT NULL DEFAULT 1")
    add_column_if_not_exists(conn, "entries", "locked_at", "INTEGER")
    add_column_if_not_exists(conn, "entries", "locked_by", "INTEGER REFERENCES users(id)")
    add_column_if_not_exists(conn, "entries", "lock_reason", "TEXT NOT NULL DEFAULT ''")
    add_column_if_not_exists(conn, "entries", "event_id", "INTEGER REFERENCES study_events(id) ON DELETE SET NULL")
    add_column_if_not_exists(conn, "entries", "form_version", "INTEGER NOT NULL DEFAULT 1")
    add_column_if_not_exists(conn, "entries", "schema_snapshot_json", "TEXT NOT NULL DEFAULT '{}'")
    add_column_if_not_exists(conn, "entries", "entry_hash", "TEXT NOT NULL DEFAULT ''")
    add_column_if_not_exists(conn, "queries", "entry_id", "INTEGER REFERENCES entries(id) ON DELETE SET NULL")
    add_column_if_not_exists(conn, "queries", "due_at", "INTEGER")
    add_column_if_not_exists(conn, "queries", "closed_at", "INTEGER")
    add_column_if_not_exists(conn, "queries", "closed_by", "INTEGER REFERENCES users(id)")
    add_column_if_not_exists(conn, "participants", "data_group_id", "INTEGER REFERENCES data_groups(id) ON DELETE SET NULL")
    add_column_if_not_exists(conn, "participants", "recruitment_source", "TEXT NOT NULL DEFAULT ''")
    add_column_if_not_exists(conn, "participants", "screening_date", "INTEGER")
    add_column_if_not_exists(conn, "participants", "consent_date", "INTEGER")
    add_column_if_not_exists(conn, "participants", "consent_status", "TEXT NOT NULL DEFAULT 'pending'")
    add_column_if_not_exists(conn, "participants", "consent_version", "TEXT NOT NULL DEFAULT ''")
    add_column_if_not_exists(conn, "participants", "eligibility_checklist_json", "TEXT NOT NULL DEFAULT '{}'")
    add_column_if_not_exists(conn, "participants", "screening_notes", "TEXT NOT NULL DEFAULT ''")
    add_column_if_not_exists(conn, "users", "must_change_password", "INTEGER NOT NULL DEFAULT 0")
    add_column_if_not_exists(conn, "users", "failed_login_count", "INTEGER NOT NULL DEFAULT 0")
    add_column_if_not_exists(conn, "users", "locked_until", "INTEGER NOT NULL DEFAULT 0")
    add_column_if_not_exists(conn, "api_tokens", "scopes_json", "TEXT NOT NULL DEFAULT '[]'")
    add_column_if_not_exists(conn, "audit_log", "study_id", "INTEGER")
    add_column_if_not_exists(conn, "audit_log", "ip_address", "TEXT NOT NULL DEFAULT ''")
    add_column_if_not_exists(conn, "audit_log", "user_agent", "TEXT NOT NULL DEFAULT ''")
    add_column_if_not_exists(conn, "audit_log", "request_id", "TEXT NOT NULL DEFAULT ''")
    add_column_if_not_exists(conn, "forms", "active", "INTEGER NOT NULL DEFAULT 1")
    add_column_if_not_exists(conn, "forms", "lifecycle_state", "TEXT NOT NULL DEFAULT 'published'")
    add_column_if_not_exists(conn, "studies", "ai_policy_json", "TEXT NOT NULL DEFAULT '{}'")
    add_column_if_not_exists(conn, "studies", "eligibility_criteria_json", "TEXT NOT NULL DEFAULT '{}'")
    add_column_if_not_exists(conn, "survey_links", "expires_at", "INTEGER")
    add_column_if_not_exists(conn, "survey_links", "one_time", "INTEGER NOT NULL DEFAULT 0")
    add_column_if_not_exists(conn, "academic_cv_items", "active", "INTEGER NOT NULL DEFAULT 1")
    add_column_if_not_exists(conn, "case_files", "original_filename", "TEXT NOT NULL DEFAULT ''")
    add_column_if_not_exists(conn, "case_files", "stored_filename", "TEXT NOT NULL DEFAULT ''")
    add_column_if_not_exists(conn, "case_files", "sha256", "TEXT NOT NULL DEFAULT ''")
    add_column_if_not_exists(conn, "academic_outputs", "active", "INTEGER NOT NULL DEFAULT 1")
    conn.commit()

def run_migrations(conn: Any) -> None:
    backend = getattr(conn, "backend", "sqlite")
    # Create schema migrations tracking table if not exists
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            description TEXT NOT NULL,
            applied_at INTEGER NOT NULL
        )
        """
    )

    # Determine whether this is a legacy/existing database before altering tables.
    if backend == "postgres":
        users_exists = bool(conn.execute("SELECT 1 FROM information_schema.tables WHERE table_name = 'users'").fetchone())
    else:
        users_exists = bool(conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").fetchone())

    # Existing databases may need columns that predate versioned migrations. A fresh
    # database must run the baseline migration first, otherwise PostgreSQL enters an
    # aborted transaction when ALTER TABLE targets tables that do not exist yet.
    if users_exists:
        ensure_legacy_columns(conn)

    # To support backward compatibility for existing SQLite/Postgres databases that were
    # created by old server.py, retroactively mark Migration 1 when appropriate.
    res = conn.execute("SELECT count(*) as cnt FROM schema_migrations").fetchone()
    if res["cnt"] == 0 and users_exists:
        LOGGER.info("Retroactively marking Migration 1 (baseline) as applied.")
        conn.execute(
            "INSERT INTO schema_migrations (version, description, applied_at) VALUES (?, ?, ?)",
            (1, "Retroactive baseline setup mark", now())
        )
        conn.commit()

    # Get applied migrations
    applied = {row["version"] for row in conn.execute("SELECT version FROM schema_migrations").fetchall()}
    
    for mig in MIGRATIONS:
        v = mig["version"]
        if v not in applied:
            LOGGER.info(f"Applying migration v{v}: {mig['description']}...")
            try:
                mig["up"](conn)
                conn.execute(
                    "INSERT INTO schema_migrations (version, description, applied_at) VALUES (?, ?, ?)",
                    (v, mig["description"], now())
                )
                conn.commit()
                LOGGER.info(f"Migration v{v} applied successfully.")
            except Exception as exc:
                conn.rollback()
                LOGGER.error(f"Migration v{v} failed: {exc}")
                raise RuntimeError(f"Database migration failure at version {v}: {exc}") from exc
                
    # Re-run after to ensure everything is locked down
    ensure_legacy_columns(conn)
