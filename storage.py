from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any


INSERT_ID_TABLES = {
    "users",
    "data_groups",
    "study_memberships",
    "studies",
    "forms",
    "study_events",
    "form_events",
    "survey_links",
    "form_versions",
    "participants",
    "entries",
    "queries",
    "query_responses",
    "field_states",
    "consent_signatures",
    "survey_invitations",
    "audit_log",
    "reports",
    "academic_cv_items",
    "academic_outputs",
    "case_intakes",
    "case_files",
    "case_ai_reviews",
    "ai_audit",
    "api_tokens",
    "randomization_lists",
    "randomization_allocations",
}


def sqlite_connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def postgres_available() -> bool:
    try:
        import psycopg  # noqa: F401
    except ImportError:
        return False
    return True


class PostgresCursor:
    def __init__(self, cursor, lastrowid=None):
        self.cursor = cursor
        self.lastrowid = lastrowid

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()


class PostgresConnection:
    backend = "postgres"

    def __init__(self, database_url: str):
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError("PostgreSQL backend requires psycopg[binary]. Install requirements.txt or use the Docker image.") from exc
        self._conn = psycopg.connect(database_url, row_factory=dict_row)

    def close(self) -> None:
        self._conn.close()

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def __enter__(self):
        self._conn.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        return self._conn.__exit__(exc_type, exc, tb)

    def execute(self, sql: str, params: tuple | list = ()):
        translated = translate_sql(sql)
        table = insert_table(translated)
        returning_id = bool(table and table in INSERT_ID_TABLES and " returning " not in translated.lower())
        if returning_id:
            translated = translated.rstrip().rstrip(";") + " RETURNING id"
        cursor = self._conn.execute(translated, tuple(params or ()))
        lastrowid = None
        if returning_id:
            result = cursor.fetchone()
            if result:
                lastrowid = result.get("id") if isinstance(result, dict) else result[0]
        return PostgresCursor(cursor, lastrowid)

    def executescript(self, script: str) -> None:
        for statement in split_sql_script(script):
            if statement.strip():
                self.execute(statement)

    def table_columns(self, table: str) -> set[str]:
        cursor = self.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = %s
            """.replace("%s", "?"),
            (table,),
        )
        return {item["column_name"] for item in cursor.fetchall()}


def insert_table(sql: str) -> str | None:
    match = re.match(r"\s*INSERT\s+INTO\s+([A-Za-z_][A-Za-z0-9_]*)", sql, flags=re.IGNORECASE)
    return match.group(1).lower() if match else None


def translate_sql(sql: str) -> str:
    translated = sql
    translated = re.sub(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", "INSERT INTO", translated, flags=re.IGNORECASE)
    if re.search(r"\bINSERT\s+OR\s+REPLACE\s+INTO\s+field_states\b", translated, flags=re.IGNORECASE):
        translated = re.sub(r"\bINSERT\s+OR\s+REPLACE\s+INTO\b", "INSERT INTO", translated, flags=re.IGNORECASE)
        translated = translated.rstrip().rstrip(";") + " ON CONFLICT(entry_id, field_code, state) DO UPDATE SET reason = EXCLUDED.reason, user_id = EXCLUDED.user_id, created_at = EXCLUDED.created_at"
    elif re.search(r"\bINSERT\s+INTO\s+form_events\b", translated, flags=re.IGNORECASE) and "OR IGNORE" in sql.upper():
        translated = translated.rstrip().rstrip(";") + " ON CONFLICT(event_id, form_id) DO NOTHING"
    return translated.replace("?", "%s")


def split_sql_script(script: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    in_single = False
    for char in script:
        if char == "'":
            in_single = not in_single
        if char == ";" and not in_single:
            statements.append("".join(current))
            current = []
        else:
            current.append(char)
    if current:
        statements.append("".join(current))
    return statements


def connect_database(backend: str, sqlite_path: Path, database_url: str):
    if backend == "postgres":
        return PostgresConnection(database_url)
    return sqlite_connect(sqlite_path)


POSTGRES_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    active INTEGER NOT NULL DEFAULT 1,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    locked_until BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS data_groups (
    id BIGSERIAL PRIMARY KEY,
    study_id BIGINT NOT NULL,
    name TEXT NOT NULL,
    code TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE(study_id, code)
);
CREATE TABLE IF NOT EXISTS studies (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    protocol_id TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS study_memberships (
    id BIGSERIAL PRIMARY KEY,
    study_id BIGINT NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'data_entry',
    data_group_id BIGINT REFERENCES data_groups(id) ON DELETE SET NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE(study_id, user_id)
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS forms (
    id BIGSERIAL PRIMARY KEY,
    study_id BIGINT NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    code TEXT NOT NULL,
    schema_json TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    active INTEGER NOT NULL DEFAULT 1,
    lifecycle_state TEXT NOT NULL DEFAULT 'published',
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE(study_id, code)
);
CREATE TABLE IF NOT EXISTS study_events (
    id BIGSERIAL PRIMARY KEY,
    study_id BIGINT NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    code TEXT NOT NULL,
    arm_name TEXT NOT NULL DEFAULT 'Default',
    day_offset INTEGER NOT NULL DEFAULT 0,
    display_order INTEGER NOT NULL DEFAULT 1,
    active INTEGER NOT NULL DEFAULT 1,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE(study_id, code)
);
CREATE TABLE IF NOT EXISTS form_events (
    id BIGSERIAL PRIMARY KEY,
    study_id BIGINT NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
    event_id BIGINT NOT NULL REFERENCES study_events(id) ON DELETE CASCADE,
    form_id BIGINT NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
    required INTEGER NOT NULL DEFAULT 1,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE(event_id, form_id)
);
CREATE TABLE IF NOT EXISTS survey_links (
    id BIGSERIAL PRIMARY KEY,
    study_id BIGINT NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
    form_id BIGINT NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
    event_id BIGINT REFERENCES study_events(id) ON DELETE SET NULL,
    token TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    expires_at BIGINT,
    one_time INTEGER NOT NULL DEFAULT 0,
    consent_required INTEGER NOT NULL DEFAULT 0,
    consent_text TEXT NOT NULL DEFAULT '',
    created_by BIGINT REFERENCES users(id),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS form_versions (
    id BIGSERIAL PRIMARY KEY,
    form_id BIGINT NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
    study_id BIGINT NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    name TEXT NOT NULL,
    code TEXT NOT NULL,
    schema_json TEXT NOT NULL,
    saved_by BIGINT REFERENCES users(id),
    saved_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS participants (
    id BIGSERIAL PRIMARY KEY,
    study_id BIGINT NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
    data_group_id BIGINT REFERENCES data_groups(id) ON DELETE SET NULL,
    study_uid TEXT NOT NULL,
    initials TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'screening',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE(study_id, study_uid)
);
CREATE TABLE IF NOT EXISTS entries (
    id BIGSERIAL PRIMARY KEY,
    study_id BIGINT NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
    participant_id BIGINT NOT NULL REFERENCES participants(id) ON DELETE CASCADE,
    form_id BIGINT NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
    event_id BIGINT REFERENCES study_events(id) ON DELETE SET NULL,
    event_name TEXT NOT NULL DEFAULT 'Baseline',
    repeat_instance INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'draft',
    data_json TEXT NOT NULL DEFAULT '{}',
    form_version INTEGER NOT NULL DEFAULT 1,
    schema_snapshot_json TEXT NOT NULL DEFAULT '{}',
    entry_hash TEXT NOT NULL DEFAULT '',
    created_by BIGINT REFERENCES users(id),
    updated_by BIGINT REFERENCES users(id),
    locked_at BIGINT,
    locked_by BIGINT REFERENCES users(id),
    lock_reason TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE(participant_id, form_id, event_name, repeat_instance)
);
CREATE TABLE IF NOT EXISTS queries (
    id BIGSERIAL PRIMARY KEY,
    study_id BIGINT NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
    participant_id BIGINT REFERENCES participants(id) ON DELETE CASCADE,
    form_id BIGINT REFERENCES forms(id) ON DELETE SET NULL,
    field_code TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_by BIGINT REFERENCES users(id),
    assigned_to BIGINT REFERENCES users(id),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS query_responses (
    id BIGSERIAL PRIMARY KEY,
    query_id BIGINT NOT NULL REFERENCES queries(id) ON DELETE CASCADE,
    user_id BIGINT REFERENCES users(id),
    message TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS field_states (
    id BIGSERIAL PRIMARY KEY,
    entry_id BIGINT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    field_code TEXT NOT NULL,
    state TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    user_id BIGINT REFERENCES users(id),
    created_at BIGINT NOT NULL,
    UNIQUE(entry_id, field_code, state)
);
CREATE TABLE IF NOT EXISTS consent_signatures (
    id BIGSERIAL PRIMARY KEY,
    study_id BIGINT NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
    participant_id BIGINT NOT NULL REFERENCES participants(id) ON DELETE CASCADE,
    entry_id BIGINT REFERENCES entries(id) ON DELETE SET NULL,
    signer_name TEXT NOT NULL,
    signature_text TEXT NOT NULL,
    consent_text TEXT NOT NULL,
    ip_address TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS survey_invitations (
    id BIGSERIAL PRIMARY KEY,
    study_id BIGINT NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
    survey_link_id BIGINT NOT NULL REFERENCES survey_links(id) ON DELETE CASCADE,
    participant_id BIGINT REFERENCES participants(id) ON DELETE SET NULL,
    contact TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    invite_token TEXT UNIQUE NOT NULL,
    last_sent_at BIGINT,
    reminder_count INTEGER NOT NULL DEFAULT 0,
    completed_at BIGINT,
    created_by BIGINT REFERENCES users(id),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(id),
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id BIGINT,
    before_json TEXT,
    after_json TEXT,
    created_at BIGINT NOT NULL,
    study_id BIGINT,
    ip_address TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS reports (
    id BIGSERIAL PRIMARY KEY,
    study_id BIGINT NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    filters_json TEXT NOT NULL DEFAULT '{}',
    created_by BIGINT REFERENCES users(id),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS case_intakes (
    id BIGSERIAL PRIMARY KEY,
    study_id BIGINT NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
    participant_id BIGINT REFERENCES participants(id) ON DELETE SET NULL,
    case_uid TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    source_text TEXT NOT NULL DEFAULT '',
    extracted_json TEXT NOT NULL DEFAULT '{}',
    tags_json TEXT NOT NULL DEFAULT '[]',
    created_by BIGINT REFERENCES users(id),
    updated_by BIGINT REFERENCES users(id),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE(study_id, case_uid)
);
CREATE TABLE IF NOT EXISTS case_files (
    id BIGSERIAL PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES case_intakes(id) ON DELETE CASCADE,
    study_id BIGINT NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    original_filename TEXT NOT NULL DEFAULT '',
    stored_filename TEXT NOT NULL DEFAULT '',
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    size BIGINT NOT NULL DEFAULT 0,
    sha256 TEXT NOT NULL DEFAULT '',
    data_base64 TEXT NOT NULL DEFAULT '',
    created_by BIGINT REFERENCES users(id),
    created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS case_ai_reviews (
    id BIGSERIAL PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES case_intakes(id) ON DELETE CASCADE,
    study_id BIGINT NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
    user_prompt TEXT NOT NULL DEFAULT '',
    mode TEXT NOT NULL DEFAULT 'local',
    response_json TEXT NOT NULL DEFAULT '{}',
    file_count INTEGER NOT NULL DEFAULT 0,
    created_by BIGINT REFERENCES users(id),
    created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_audit (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    study_id BIGINT REFERENCES studies(id) ON DELETE CASCADE,
    case_id BIGINT REFERENCES case_intakes(id) ON DELETE SET NULL,
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
    created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS academic_cv_items (
    id BIGSERIAL PRIMARY KEY,
    study_id BIGINT NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
    item_type TEXT NOT NULL DEFAULT 'publication',
    title TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'planned',
    item_date TEXT NOT NULL DEFAULT '',
    citation TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    linked_case_id BIGINT REFERENCES case_intakes(id) ON DELETE SET NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    active INTEGER NOT NULL DEFAULT 1,
    created_by BIGINT REFERENCES users(id),
    updated_by BIGINT REFERENCES users(id),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS academic_outputs (
    id BIGSERIAL PRIMARY KEY,
    study_id BIGINT NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
    output_type TEXT NOT NULL DEFAULT 'publication_idea',
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'idea',
    linked_case_id BIGINT REFERENCES case_intakes(id) ON DELETE SET NULL,
    participant_ids_json TEXT NOT NULL DEFAULT '[]',
    evidence_file_ids_json TEXT NOT NULL DEFAULT '[]',
    dataset_ref TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    active INTEGER NOT NULL DEFAULT 1,
    created_by BIGINT REFERENCES users(id),
    updated_by BIGINT REFERENCES users(id),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_tokens (
    id BIGSERIAL PRIMARY KEY,
    study_id BIGINT NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT UNIQUE NOT NULL,
    label TEXT NOT NULL,
    scopes_json TEXT NOT NULL DEFAULT '[]',
    active INTEGER NOT NULL DEFAULT 1,
    created_at BIGINT NOT NULL,
    last_used_at BIGINT
);
CREATE TABLE IF NOT EXISTS randomization_lists (
    id BIGSERIAL PRIMARY KEY,
    study_id BIGINT NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    arms_json TEXT NOT NULL,
    next_index INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1,
    created_by BIGINT REFERENCES users(id),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS randomization_allocations (
    id BIGSERIAL PRIMARY KEY,
    study_id BIGINT NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
    list_id BIGINT NOT NULL REFERENCES randomization_lists(id) ON DELETE CASCADE,
    participant_id BIGINT NOT NULL REFERENCES participants(id) ON DELETE CASCADE,
    arm TEXT NOT NULL,
    allocated_by BIGINT REFERENCES users(id),
    created_at BIGINT NOT NULL,
    UNIQUE(list_id, participant_id)
);
"""


PRODUCTION_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_study_memberships_study_id ON study_memberships(study_id);
CREATE INDEX IF NOT EXISTS idx_study_memberships_user_id ON study_memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_participants_study_id ON participants(study_id);
CREATE INDEX IF NOT EXISTS idx_entries_study_id ON entries(study_id);
CREATE INDEX IF NOT EXISTS idx_entries_participant_id ON entries(participant_id);
CREATE INDEX IF NOT EXISTS idx_entries_form_id ON entries(form_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_entity ON audit_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_academic_cv_items_study_id ON academic_cv_items(study_id);
CREATE INDEX IF NOT EXISTS idx_academic_outputs_study_id ON academic_outputs(study_id);
CREATE INDEX IF NOT EXISTS idx_ai_audit_study_id ON ai_audit(study_id);
CREATE INDEX IF NOT EXISTS idx_ai_audit_user_id ON ai_audit(user_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_study_id ON api_tokens(study_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_token_hash ON api_tokens(token_hash);
"""


def migrate_postgres(conn: PostgresConnection) -> None:
    conn.executescript(POSTGRES_SCHEMA_SQL)
    conn.executescript(PRODUCTION_INDEX_SQL)
