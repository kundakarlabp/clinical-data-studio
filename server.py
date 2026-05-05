from __future__ import annotations

import ast
import base64
import csv
import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import sqlite3
import tempfile
import time
from io import StringIO
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
DATA = ROOT / "data"
BACKUPS = DATA / "backups"
DB_PATH = DATA / "clinical_data_studio.sqlite3"
HOST = "0.0.0.0"
PORT = int(os.environ.get("CDS_PORT", "8765"))
PBKDF2_ROUNDS = 260_000
CALC_OPERATORS = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.Div: lambda a, b: a / b,
    ast.USub: lambda a: -a,
    ast.UAdd: lambda a: a,
}

ROLE_PERMISSIONS = {
    "admin": {
        "manage_users",
        "manage_study",
        "manage_forms",
        "enter_data",
        "review_data",
        "export_data",
        "view_analysis",
    },
    "owner": {
        "manage_users",
        "manage_study",
        "manage_forms",
        "enter_data",
        "review_data",
        "export_data",
        "view_analysis",
    },
    "data_entry": {"enter_data"},
    "reviewer": {"review_data", "view_analysis"},
    "analyst": {"export_data", "view_analysis"},
    "read_only": {"view_analysis"},
}


def now() -> int:
    return int(time.time())


def db() -> sqlite3.Connection:
    DATA.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def encode_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, rounds, salt_b64, digest_b64 = encoded.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(rounds))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def archive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, PBKDF2_ROUNDS)


def hmac_stream(key: bytes, nonce: bytes, length: int) -> bytes:
    blocks = []
    counter = 0
    while sum(len(block) for block in blocks) < length:
        counter += 1
        blocks.append(hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest())
    return b"".join(blocks)[:length]


def xor_bytes(data: bytes, stream: bytes) -> bytes:
    return bytes(left ^ right for left, right in zip(data, stream))


def encrypted_archive_bytes(plain: bytes, passphrase: str) -> bytes:
    if len(passphrase) < 12:
        raise ValueError("Encrypted archive passphrase must be at least 12 characters")
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    key = archive_key(passphrase, salt)
    cipher = xor_bytes(plain, hmac_stream(key, nonce, len(plain)))
    header = {
        "format": "CDSENC1",
        "kdf": "pbkdf2_hmac_sha256",
        "rounds": PBKDF2_ROUNDS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "note": "Passphrase-protected local archive. Keep the passphrase separately.",
    }
    header_bytes = json.dumps(header, sort_keys=True).encode("utf-8")
    tag = hmac.new(key, header_bytes + cipher, hashlib.sha256).digest()
    return b"CDSENC1\n" + len(header_bytes).to_bytes(4, "big") + header_bytes + cipher + tag


def decrypted_archive_bytes(archive: bytes, passphrase: str) -> bytes:
    if not archive.startswith(b"CDSENC1\n") or len(archive) < 44:
        raise ValueError("Unsupported encrypted archive format")
    header_length = int.from_bytes(archive[8:12], "big")
    header_start = 12
    header_end = header_start + header_length
    header_bytes = archive[header_start:header_end]
    header = json.loads(header_bytes.decode("utf-8"))
    if header.get("format") != "CDSENC1" or int(header.get("rounds", 0)) != PBKDF2_ROUNDS:
        raise ValueError("Unsupported encrypted archive format")
    salt = base64.b64decode(header["salt"])
    nonce = base64.b64decode(header["nonce"])
    key = archive_key(passphrase, salt)
    cipher = archive[header_end:-32]
    tag = archive[-32:]
    expected = hmac.new(key, header_bytes + cipher, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("Encrypted archive passphrase is incorrect or the file is damaged")
    return xor_bytes(cipher, hmac_stream(key, nonce, len(cipher)))


def write_sqlite_backup(conn: sqlite3.Connection, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    destination = sqlite3.connect(target)
    try:
        conn.backup(destination)
    finally:
        destination.close()


def setup_required(conn: sqlite3.Connection) -> bool:
    default_admin = row(conn, "SELECT password_hash FROM users WHERE username = 'admin' AND active = 1")
    return bool(default_admin and verify_password("admin123", default_admin["password_hash"]))


def rows(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[dict]:
    return [dict(row) for row in conn.execute(sql, params).fetchall()]


def row(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> dict | None:
    result = conn.execute(sql, params).fetchone()
    return dict(result) if result else None


def load_json(value: str | None, fallback):
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {dict(row)["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def add_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    if column not in table_columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def migrate_entries_unique_key(conn: sqlite3.Connection) -> None:
    schema = row(conn, "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'entries'")
    if not schema or "UNIQUE(participant_id, form_id, event_name)" not in schema["sql"]:
        return
    conn.executescript(
        """
        ALTER TABLE entries RENAME TO entries_old;
        CREATE TABLE entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
            participant_id INTEGER NOT NULL REFERENCES participants(id) ON DELETE CASCADE,
            form_id INTEGER NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
            event_id INTEGER REFERENCES study_events(id) ON DELETE SET NULL,
            event_name TEXT NOT NULL DEFAULT 'Baseline',
            repeat_instance INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'draft',
            data_json TEXT NOT NULL DEFAULT '{}',
            created_by INTEGER REFERENCES users(id),
            updated_by INTEGER REFERENCES users(id),
            locked_at INTEGER,
            locked_by INTEGER REFERENCES users(id),
            lock_reason TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(participant_id, form_id, event_name, repeat_instance)
        );
        INSERT INTO entries(
            id, study_id, participant_id, form_id, event_id, event_name, repeat_instance, status,
            data_json, created_by, updated_by, locked_at, locked_by, lock_reason, created_at, updated_at
        )
        SELECT
            id, study_id, participant_id, form_id, event_id, event_name,
            COALESCE(repeat_instance, 1), status, data_json, created_by, updated_by,
            locked_at, locked_by, COALESCE(lock_reason, ''), created_at, updated_at
        FROM entries_old;
        DROP TABLE entries_old;
        """
    )


def audit(conn: sqlite3.Connection, user_id: int | None, action: str, entity_type: str, entity_id: int | None, before=None, after=None) -> None:
    conn.execute(
        """
        INSERT INTO audit_log(user_id, action, entity_type, entity_id, before_json, after_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            action,
            entity_type,
            entity_id,
            json.dumps(before, sort_keys=True) if before is not None else None,
            json.dumps(after, sort_keys=True) if after is not None else None,
            now(),
        ),
    )


def migrate() -> None:
    with db() as conn:
        conn.executescript(
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
                created_at INTEGER NOT NULL
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

            CREATE TABLE IF NOT EXISTS studies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                protocol_id TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'draft',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS forms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                study_id INTEGER NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                code TEXT NOT NULL,
                schema_json TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                active INTEGER NOT NULL DEFAULT 1,
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
                field_code TEXT NOT NULL DEFAULT '',
                message TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                created_by INTEGER REFERENCES users(id),
                assigned_to INTEGER REFERENCES users(id),
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
            """
        )
        add_column(conn, "entries", "repeat_instance", "INTEGER NOT NULL DEFAULT 1")
        add_column(conn, "entries", "locked_at", "INTEGER")
        add_column(conn, "entries", "locked_by", "INTEGER REFERENCES users(id)")
        add_column(conn, "entries", "lock_reason", "TEXT NOT NULL DEFAULT ''")
        add_column(conn, "entries", "event_id", "INTEGER REFERENCES study_events(id) ON DELETE SET NULL")
        add_column(conn, "participants", "data_group_id", "INTEGER REFERENCES data_groups(id) ON DELETE SET NULL")
        add_column(conn, "users", "must_change_password", "INTEGER NOT NULL DEFAULT 0")
        add_column(conn, "users", "failed_login_count", "INTEGER NOT NULL DEFAULT 0")
        add_column(conn, "users", "locked_until", "INTEGER NOT NULL DEFAULT 0")
        migrate_entries_unique_key(conn)
        if not row(conn, "SELECT id FROM users WHERE username = ?", ("admin",)):
            user = {
                "username": "admin",
                "display_name": "Administrator",
                "role": "admin",
                "created_at": now(),
            }
            conn.execute(
                "INSERT INTO users(username, password_hash, display_name, role, must_change_password, created_at) VALUES (?, ?, ?, ?, 1, ?)",
                ("admin", encode_password("admin123"), user["display_name"], user["role"], user["created_at"]),
            )
            audit(conn, None, "seed", "user", 1, None, user)
        default_admin = row(conn, "SELECT id, password_hash FROM users WHERE username = 'admin'")
        if default_admin and verify_password("admin123", default_admin["password_hash"]):
            conn.execute("UPDATE users SET must_change_password = 1 WHERE id = ?", (default_admin["id"],))
        if not row(conn, "SELECT id FROM studies LIMIT 1"):
            seed_study(conn)
        seed_admin_memberships(conn)
        seed_baseline_events(conn)


def seed_study(conn: sqlite3.Connection) -> None:
    timestamp = now()
    cur = conn.execute(
        "INSERT INTO studies(name, protocol_id, description, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("Demo Clinical Registry", "DEMO-001", "Starter study with demographics and visit forms.", "active", timestamp, timestamp),
    )
    study_id = cur.lastrowid
    forms = [
        (
            "Demographics",
            "demographics",
            [
                {"code": "age", "label": "Age", "type": "number", "required": True, "min": 0, "max": 120},
                {"code": "sex", "label": "Sex", "type": "select", "required": True, "options": ["Female", "Male", "Other"]},
                {"code": "consent_date", "label": "Consent date", "type": "date", "required": True},
                {"code": "diagnosis", "label": "Primary diagnosis", "type": "text", "required": True},
            ],
        ),
        (
            "Clinical Visit",
            "clinical_visit",
            [
                {"code": "visit_date", "label": "Visit date", "type": "date", "required": True},
                {"code": "weight", "label": "Weight kg", "type": "number", "min": 1, "max": 300},
                {"code": "systolic_bp", "label": "Systolic BP", "type": "number", "min": 50, "max": 260},
                {"code": "diastolic_bp", "label": "Diastolic BP", "type": "number", "min": 30, "max": 160},
                {"code": "adverse_event", "label": "Any adverse event?", "type": "select", "required": True, "options": ["No", "Yes"]},
                {"code": "ae_details", "label": "Adverse event details", "type": "textarea", "show_if": {"field": "adverse_event", "equals": "Yes"}},
            ],
        ),
    ]
    for name, code, fields in forms:
        conn.execute(
            "INSERT INTO forms(study_id, name, code, schema_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (study_id, name, code, json.dumps({"fields": fields}), timestamp, timestamp),
        )
    audit(conn, None, "seed", "study", study_id, None, {"study_id": study_id})


def seed_admin_memberships(conn: sqlite3.Connection) -> None:
    admin_users = rows(conn, "SELECT id FROM users WHERE role = 'admin' AND active = 1")
    studies = rows(conn, "SELECT id FROM studies")
    timestamp = now()
    for study in studies:
        for user in admin_users:
            if not row(conn, "SELECT id FROM study_memberships WHERE study_id = ? AND user_id = ?", (study["id"], user["id"])):
                conn.execute(
                    """
                    INSERT INTO study_memberships(study_id, user_id, role, active, created_at, updated_at)
                    VALUES (?, ?, 'owner', 1, ?, ?)
                    """,
                    (study["id"], user["id"], timestamp, timestamp),
                )


def seed_baseline_events(conn: sqlite3.Connection) -> None:
    timestamp = now()
    for study in rows(conn, "SELECT id FROM studies"):
        event = row(conn, "SELECT id FROM study_events WHERE study_id = ? AND code = 'baseline'", (study["id"],))
        if not event:
            cur = conn.execute(
                """
                INSERT INTO study_events(study_id, name, code, arm_name, day_offset, display_order, active, created_at, updated_at)
                VALUES (?, 'Baseline', 'baseline', 'Default', 0, 1, 1, ?, ?)
                """,
                (study["id"], timestamp, timestamp),
            )
            event_id = cur.lastrowid
        else:
            event_id = event["id"]
        for form in rows(conn, "SELECT id FROM forms WHERE study_id = ?", (study["id"],)):
            if not row(conn, "SELECT id FROM form_events WHERE event_id = ? AND form_id = ?", (event_id, form["id"])):
                conn.execute(
                    """
                    INSERT INTO form_events(study_id, event_id, form_id, required, created_at, updated_at)
                    VALUES (?, ?, ?, 1, ?, ?)
                    """,
                    (study["id"], event_id, form["id"], timestamp, timestamp),
                )
        conn.execute("UPDATE entries SET event_id = ? WHERE study_id = ? AND event_id IS NULL AND event_name = 'Baseline'", (event_id, study["id"]))


def normalize_code(value: str, fallback: str = "") -> str:
    normalized = "".join(ch.lower() if ch.isalnum() else "_" for ch in value.strip())
    normalized = "_".join(part for part in normalized.split("_") if part)
    return normalized or fallback


def normalize_schema(schema: dict) -> dict:
    fields = []
    seen = set()
    for index, source in enumerate(schema.get("fields", []), start=1):
        label = str(source.get("label", "")).strip() or f"Field {index}"
        code = normalize_code(str(source.get("code", "")), f"field_{index}")
        if code in seen:
            raise ValueError(f"Duplicate field code: {code}")
        seen.add(code)
        field_type = str(source.get("type", "text")).strip() or "text"
        if field_type not in {"text", "textarea", "number", "date", "select", "checkbox", "calc", "file"}:
            raise ValueError(f"Unsupported field type: {field_type}")
        field = {
            "code": code,
            "label": label,
            "type": field_type,
            "required": bool(source.get("required", False)),
        }
        for key in ("min", "max"):
            if source.get(key) not in (None, ""):
                field[key] = float(source[key])
        if field_type in {"select", "checkbox"}:
            options = source.get("options") or []
            if isinstance(options, str):
                options = [item.strip() for item in options.split(",")]
            field["options"] = [str(item).strip() for item in options if str(item).strip()]
        if source.get("show_if"):
            show_if = source["show_if"]
            field["show_if"] = {"field": normalize_code(str(show_if.get("field", ""))), "equals": str(show_if.get("equals", ""))}
        if source.get("calculation"):
            field["calculation"] = str(source["calculation"])
        fields.append(field)
    if not fields:
        raise ValueError("A CRF must contain at least one field")
    return {"fields": fields, "repeatable": bool(schema.get("repeatable", False))}


def validate_entry_data(schema: dict, data: dict) -> tuple[dict, list[dict]]:
    cleaned = {}
    issues = []
    for field in schema.get("fields", []):
        code = field["code"]
        value = data.get(code)
        visible = True
        if field.get("show_if"):
            condition = field["show_if"]
            visible = str(data.get(condition["field"], "")) == str(condition["equals"])
        if not visible:
            continue
        if isinstance(value, str):
            value = value.strip()
        if value in (None, "", []):
            if field.get("required"):
                issues.append({"field_code": code, "severity": "error", "message": f"{field['label']} is required"})
            cleaned[code] = "" if field["type"] != "checkbox" else []
            continue
        if field["type"] == "calc":
            continue
        if field["type"] == "number":
            try:
                number = float(value)
            except (TypeError, ValueError):
                issues.append({"field_code": code, "severity": "error", "message": f"{field['label']} must be numeric"})
                cleaned[code] = value
                continue
            if "min" in field and number < field["min"]:
                issues.append({"field_code": code, "severity": "error", "message": f"{field['label']} is below minimum {field['min']}"})
            if "max" in field and number > field["max"]:
                issues.append({"field_code": code, "severity": "error", "message": f"{field['label']} is above maximum {field['max']}"})
            cleaned[code] = number
            continue
        if field["type"] == "select":
            if field.get("options") and str(value) not in field["options"]:
                issues.append({"field_code": code, "severity": "error", "message": f"{field['label']} must be one of the coded options"})
            cleaned[code] = str(value)
            continue
        if field["type"] == "checkbox":
            selected = value if isinstance(value, list) else [value]
            selected = [str(item) for item in selected if str(item)]
            invalid = [item for item in selected if field.get("options") and item not in field["options"]]
            if invalid:
                issues.append({"field_code": code, "severity": "error", "message": f"{field['label']} has invalid checkbox options"})
            cleaned[code] = selected
            continue
        if field["type"] == "file":
            if not isinstance(value, dict):
                issues.append({"field_code": code, "severity": "error", "message": f"{field['label']} must be an uploaded file"})
                cleaned[code] = {}
                continue
            filename = str(value.get("name", "")).strip()
            data_b64 = str(value.get("data", "")).strip()
            content_type = str(value.get("type", "application/octet-stream")).strip() or "application/octet-stream"
            try:
                raw = base64.b64decode(data_b64, validate=True)
            except Exception:
                issues.append({"field_code": code, "severity": "error", "message": f"{field['label']} upload is not valid base64"})
                raw = b""
            if raw and len(raw) > 5 * 1024 * 1024:
                issues.append({"field_code": code, "severity": "error", "message": f"{field['label']} exceeds 5 MB"})
            cleaned[code] = {"name": filename, "type": content_type, "size": len(raw), "data": data_b64}
            continue
        cleaned[code] = str(value)
    for field in schema.get("fields", []):
        if field["type"] != "calc":
            continue
        code = field["code"]
        calculation = field.get("calculation", "")
        if not calculation:
            cleaned[code] = ""
            continue
        try:
            cleaned[code] = round(float(evaluate_calculation(calculation, cleaned)), 6)
        except Exception:
            issues.append({"field_code": code, "severity": "error", "message": f"{field['label']} calculation could not be evaluated"})
    return cleaned, issues


def evaluate_calculation(expression: str, values: dict) -> float:
    def eval_node(node):
        if isinstance(node, ast.Expression):
            return eval_node(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return float(node.value)
        if isinstance(node, ast.Name):
            value = values.get(node.id, 0)
            return float(value or 0)
        if isinstance(node, ast.BinOp) and type(node.op) in CALC_OPERATORS:
            right = eval_node(node.right)
            if isinstance(node.op, ast.Div) and right == 0:
                raise ZeroDivisionError
            return CALC_OPERATORS[type(node.op)](eval_node(node.left), right)
        if isinstance(node, ast.UnaryOp) and type(node.op) in CALC_OPERATORS:
            return CALC_OPERATORS[type(node.op)](eval_node(node.operand))
        raise ValueError("Unsupported calculation")

    parsed = ast.parse(expression, mode="eval")
    return eval_node(parsed)


def user_membership(conn: sqlite3.Connection, user: dict, study_id: int) -> dict | None:
    if user.get("role") == "admin":
        membership = row(
            conn,
            """
            SELECT study_memberships.*, data_groups.name AS data_group_name, data_groups.code AS data_group_code
            FROM study_memberships
            LEFT JOIN data_groups ON data_groups.id = study_memberships.data_group_id
            WHERE study_memberships.study_id = ? AND study_memberships.user_id = ? AND study_memberships.active = 1
            """,
            (study_id, user["id"]),
        )
        if membership:
            return membership
        return {"study_id": study_id, "user_id": user["id"], "role": "owner", "data_group_id": None, "data_group_name": None, "data_group_code": None, "active": 1}
    return row(
        conn,
        """
        SELECT study_memberships.*, data_groups.name AS data_group_name, data_groups.code AS data_group_code
        FROM study_memberships
        LEFT JOIN data_groups ON data_groups.id = study_memberships.data_group_id
        WHERE study_memberships.study_id = ? AND study_memberships.user_id = ? AND study_memberships.active = 1
        """,
        (study_id, user["id"]),
    )


def role_has(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())


def membership_has(membership: dict | None, permission: str) -> bool:
    return bool(membership and role_has(membership["role"], permission))


class App(BaseHTTPRequestHandler):
    server_version = "ClinicalDataStudio/0.1"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            self.handle_api("GET", parsed.path, parse_qs(parsed.query))
        else:
            self.serve_static(parsed.path)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        self.handle_api("POST", parsed.path, parse_qs(parsed.query))

    def do_PATCH(self) -> None:
        parsed = urlparse(self.path)
        self.handle_api("PATCH", parsed.path, parse_qs(parsed.query))

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        self.handle_api("DELETE", parsed.path, parse_qs(parsed.query))

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.address_string()} - {fmt % args}")

    def body(self) -> dict:
        length = int(self.headers.get("content-length", "0"))
        if length == 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        return json.loads(raw or "{}")

    def send_json(self, payload, status: int = 200) -> None:
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def send_error_json(self, message: str, status: int = 400) -> None:
        self.send_json({"error": message}, status)

    def serve_static(self, path: str) -> None:
        if path in ("", "/"):
            path = "/index.html"
        target = (STATIC / path.lstrip("/")).resolve()
        if not str(target).startswith(str(STATIC.resolve())) or not target.exists() or not target.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content = target.read_bytes()
        mime = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("content-type", mime)
        self.send_header("content-length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def current_user(self, conn: sqlite3.Connection) -> dict | None:
        header = self.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            return None
        token = header.removeprefix("Bearer ").strip()
        user = row(
            conn,
            """
            SELECT users.id, users.username, users.display_name, users.role, users.active, users.must_change_password
            FROM sessions JOIN users ON users.id = sessions.user_id
            WHERE sessions.token = ? AND sessions.expires_at > ? AND users.active = 1
            """,
            (token, now()),
        )
        return user

    def require_user(self, conn: sqlite3.Connection) -> dict | None:
        user = self.current_user(conn)
        if not user:
            self.send_error_json("Login required", 401)
            return None
        return user

    def handle_api(self, method: str, path: str, query: dict[str, list[str]]) -> None:
        try:
            with db() as conn:
                if path == "/api/login" and method == "POST":
                    return self.login(conn)
                if path == "/api/logout" and method == "POST":
                    return self.logout(conn)
                if path.startswith("/api/public/surveys/"):
                    return self.public_survey(conn, method, path)
                if path == "/api/setup" and method == "GET":
                    return self.send_json({"required": setup_required(conn)})
                if path == "/api/setup" and method == "POST":
                    return self.first_run_setup(conn)
                if path == "/api/health" and method == "GET":
                    return self.send_json({"ok": True, "app": "Clinical Data Studio", "database": DB_PATH.exists()})

                user = self.require_user(conn)
                if not user:
                    return

                if path == "/api/me":
                    memberships = rows(
                        conn,
                        """
                        SELECT study_memberships.*, studies.name AS study_name, data_groups.name AS data_group_name
                        FROM study_memberships
                        JOIN studies ON studies.id = study_memberships.study_id
                        LEFT JOIN data_groups ON data_groups.id = study_memberships.data_group_id
                        WHERE study_memberships.user_id = ? AND study_memberships.active = 1
                        ORDER BY studies.name
                        """,
                        (user["id"],),
                    )
                    return self.send_json({"user": user, "memberships": memberships})
                if path == "/api/password" and method == "POST":
                    return self.change_password(conn, user)
                if path == "/api/assist/crf" and method == "POST":
                    return self.assist_crf(conn, user)
                if path == "/api/studies" and method == "GET":
                    return self.send_json({"studies": self.visible_studies(conn, user)})
                if path == "/api/studies" and method == "POST":
                    return self.create_study(conn, user)
                if path == "/api/users":
                    return self.users(conn, user, method)
                if path.startswith("/api/studies/"):
                    return self.study_routes(conn, user, method, path, query)
                if path == "/api/audit" and method == "GET":
                    if user.get("role") != "admin":
                        self.send_error_json("Admin permission required", 403)
                        return
                    return self.send_json({"audit": rows(conn, "SELECT audit_log.*, users.display_name FROM audit_log LEFT JOIN users ON users.id = audit_log.user_id ORDER BY audit_log.id DESC LIMIT 250")})
                self.send_error_json("Unknown endpoint", 404)
        except ValueError as exc:
            self.send_error_json(str(exc), 400)
        except sqlite3.IntegrityError as exc:
            self.send_error_json(f"Data conflict: {exc}", 409)
        except json.JSONDecodeError:
            self.send_error_json("Invalid JSON body", 400)
        except Exception as exc:
            self.send_error_json(f"Server error: {exc}", 500)

    def login(self, conn: sqlite3.Connection) -> None:
        payload = self.body()
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        user = row(conn, "SELECT * FROM users WHERE username = ? AND active = 1", (username,))
        if user and user.get("locked_until", 0) and user["locked_until"] > now():
            self.send_error_json("Account is temporarily locked after repeated failed logins", 423)
            return
        if not user or not verify_password(password, user["password_hash"]):
            if user:
                failed = int(user.get("failed_login_count") or 0) + 1
                locked_until = now() + 15 * 60 if failed >= 5 else 0
                conn.execute("UPDATE users SET failed_login_count = ?, locked_until = ? WHERE id = ?", (failed, locked_until, user["id"]))
                audit(conn, user["id"], "failed_login", "user", user["id"], None, {"failed_login_count": failed, "locked": bool(locked_until)})
                conn.commit()
            self.send_error_json("Invalid username or password", 401)
            return
        token = secrets.token_urlsafe(32)
        conn.execute("UPDATE users SET failed_login_count = 0, locked_until = 0 WHERE id = ?", (user["id"],))
        conn.execute("INSERT INTO sessions(token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)", (token, user["id"], now() + 60 * 60 * 24 * 14, now()))
        audit(conn, user["id"], "login", "session", None, None, {"username": username})
        conn.commit()
        self.send_json({"token": token, "user": {"id": user["id"], "username": user["username"], "display_name": user["display_name"], "role": user["role"], "must_change_password": user.get("must_change_password", 0)}})

    def first_run_setup(self, conn: sqlite3.Connection) -> None:
        if not setup_required(conn):
            self.send_error_json("First-run setup is already complete", 409)
            return
        payload = self.body()
        username = normalize_code(str(payload.get("username", "admin")).strip()).replace("_", ".") or "admin"
        display_name = str(payload.get("display_name", "Administrator")).strip() or "Administrator"
        password = str(payload.get("password", ""))
        confirm = str(payload.get("confirm_password", ""))
        if len(password) < 12:
            self.send_error_json("Admin password must be at least 12 characters", 400)
            return
        if password != confirm:
            self.send_error_json("Password confirmation does not match", 400)
            return
        before = row(conn, "SELECT id, username, display_name, role, active, must_change_password FROM users WHERE username = 'admin'")
        conn.execute(
            """
            UPDATE users
            SET username = ?, display_name = ?, password_hash = ?, must_change_password = 0,
                failed_login_count = 0, locked_until = 0
            WHERE username = 'admin'
            """,
            (username, display_name, encode_password(password)),
        )
        after = row(conn, "SELECT id, username, display_name, role, active, must_change_password FROM users WHERE username = ?", (username,))
        audit(conn, after["id"] if after else None, "first_run_setup", "user", after["id"] if after else None, before, after)
        conn.commit()
        self.send_json({"ok": True})

    def logout(self, conn: sqlite3.Connection) -> None:
        header = self.headers.get("authorization", "")
        token = header.removeprefix("Bearer ").strip() if header.startswith("Bearer ") else ""
        if token:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        self.send_json({"ok": True})

    def visible_studies(self, conn: sqlite3.Connection, user: dict) -> list[dict]:
        if user.get("role") == "admin":
            return rows(conn, "SELECT * FROM studies ORDER BY updated_at DESC")
        return rows(
            conn,
            """
            SELECT studies.*
            FROM studies
            JOIN study_memberships ON study_memberships.study_id = studies.id
            WHERE study_memberships.user_id = ? AND study_memberships.active = 1
            ORDER BY studies.updated_at DESC
            """,
            (user["id"],),
        )

    def users(self, conn: sqlite3.Connection, user: dict, method: str) -> None:
        if user.get("role") != "admin":
            self.send_error_json("Admin permission required", 403)
            return
        if method == "GET":
            users = rows(conn, "SELECT id, username, display_name, role, active, must_change_password, created_at FROM users ORDER BY username")
            self.send_json({"users": users})
            return
        if method == "POST":
            payload = self.body()
            username = normalize_code(str(payload.get("username", ""))).replace("_", ".")
            display_name = str(payload.get("display_name", "")).strip() or username
            password = str(payload.get("password", "")).strip()
            role_name = str(payload.get("role", "data_entry")).strip()
            if not username or len(password) < 8:
                self.send_error_json("Username and password with at least 8 characters are required", 400)
                return
            if role_name not in ROLE_PERMISSIONS:
                self.send_error_json("Unsupported role", 400)
                return
            timestamp = now()
            cur = conn.execute(
                "INSERT INTO users(username, password_hash, display_name, role, active, created_at) VALUES (?, ?, ?, ?, 1, ?)",
                (username, encode_password(password), display_name, role_name, timestamp),
            )
            after = row(conn, "SELECT id, username, display_name, role, active, must_change_password, created_at FROM users WHERE id = ?", (cur.lastrowid,))
            audit(conn, user["id"], "create", "user", cur.lastrowid, None, after)
            self.send_json({"user": after}, 201)
            return
        self.send_error_json("Unsupported user operation", 405)

    def change_password(self, conn: sqlite3.Connection, user: dict) -> None:
        payload = self.body()
        current_password = str(payload.get("current_password", ""))
        new_password = str(payload.get("new_password", ""))
        stored = row(conn, "SELECT password_hash FROM users WHERE id = ?", (user["id"],))
        if not stored or not verify_password(current_password, stored["password_hash"]):
            self.send_error_json("Current password is incorrect", 403)
            return
        if len(new_password) < 8:
            self.send_error_json("New password must be at least 8 characters", 400)
            return
        conn.execute("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?", (encode_password(new_password), user["id"]))
        audit(conn, user["id"], "change_password", "user", user["id"], None, {"user_id": user["id"]})
        self.send_json({"ok": True})

    def assist_crf(self, conn: sqlite3.Connection, user: dict) -> None:
        payload = self.body()
        text = str(payload.get("text", "")).strip()
        if not text:
            self.send_error_json("CRF text is required", 400)
            return
        fields = []
        for line in text.splitlines():
            label = line.strip(" -:\t")
            if not label:
                continue
            lower = label.lower()
            field_type = "text"
            if any(word in lower for word in ("date", "day")):
                field_type = "date"
            elif any(word in lower for word in ("age", "weight", "height", "score", "bp", "pressure", "dose")):
                field_type = "number"
            elif lower.startswith("any ") or lower.endswith("?"):
                field_type = "select"
            field = {"code": normalize_code(label), "label": label, "type": field_type, "required": False}
            if field_type == "select":
                field["options"] = ["No", "Yes"]
            fields.append(field)
            if len(fields) >= 40:
                break
        self.send_json({"schema": normalize_schema({"fields": fields or [{"code": "notes", "label": "Notes", "type": "textarea"}]})})

    def create_study(self, conn: sqlite3.Connection, user: dict) -> None:
        payload = self.body()
        timestamp = now()
        cur = conn.execute(
            "INSERT INTO studies(name, protocol_id, description, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                str(payload.get("name", "")).strip() or "Untitled Study",
                str(payload.get("protocol_id", "")).strip(),
                str(payload.get("description", "")).strip(),
                str(payload.get("status", "draft")),
                timestamp,
                timestamp,
            ),
        )
        study = row(conn, "SELECT * FROM studies WHERE id = ?", (cur.lastrowid,))
        conn.execute(
            """
            INSERT INTO study_memberships(study_id, user_id, role, active, created_at, updated_at)
            VALUES (?, ?, 'owner', 1, ?, ?)
            """,
            (cur.lastrowid, user["id"], timestamp, timestamp),
        )
        audit(conn, user["id"], "create", "study", cur.lastrowid, None, study)
        self.send_json({"study": study}, 201)

    def public_survey(self, conn: sqlite3.Connection, method: str, path: str) -> None:
        parts = path.strip("/").split("/")
        if len(parts) != 4:
            self.send_error_json("Survey link not found", 404)
            return
        token = parts[3]
        survey = row(
            conn,
            """
            SELECT survey_links.*, studies.name AS study_name, studies.protocol_id,
                   forms.name AS form_name, forms.code AS form_code, forms.schema_json,
                   study_events.name AS event_name, study_events.code AS event_code
            FROM survey_links
            JOIN studies ON studies.id = survey_links.study_id
            JOIN forms ON forms.id = survey_links.form_id
            LEFT JOIN study_events ON study_events.id = survey_links.event_id
            WHERE survey_links.token = ? AND survey_links.enabled = 1
            """,
            (token,),
        )
        if not survey:
            self.send_error_json("Survey link not found", 404)
            return
        schema = load_json(survey["schema_json"], {"fields": []})
        if method == "GET":
            self.send_json(
                {
                    "survey": {
                        "title": survey["title"],
                        "study_name": survey["study_name"],
                        "protocol_id": survey["protocol_id"],
                        "form_name": survey["form_name"],
                        "event_name": survey.get("event_name") or "Baseline",
                        "consent_required": bool(survey["consent_required"]),
                        "consent_text": survey["consent_text"],
                        "schema": schema,
                    }
                }
            )
            return
        if method != "POST":
            self.send_error_json("Unsupported survey operation", 405)
            return
        payload = self.body()
        participant_payload = payload.get("participant") or {}
        study_uid = str(participant_payload.get("study_uid", "")).strip()
        if not study_uid:
            self.send_error_json("Participant study ID is required", 400)
            return
        cleaned, issues = validate_entry_data(schema, payload.get("data") or {})
        if issues:
            self.send_json({"errors": issues}, 422)
            return
        consent_payload = payload.get("consent") or {}
        if survey["consent_required"]:
            signer_name = str(consent_payload.get("signer_name", "")).strip()
            signature_text = str(consent_payload.get("signature_text", "")).strip()
            if not signer_name or not signature_text:
                self.send_error_json("Consent name and signature are required", 400)
                return
        timestamp = now()
        participant = row(conn, "SELECT * FROM participants WHERE study_id = ? AND study_uid = ?", (survey["study_id"], study_uid))
        if not participant:
            cur = conn.execute(
                "INSERT INTO participants(study_id, study_uid, initials, status, metadata_json, created_at, updated_at) VALUES (?, ?, ?, 'screening', '{}', ?, ?)",
                (survey["study_id"], study_uid, str(participant_payload.get("initials", "")).strip().upper(), timestamp, timestamp),
            )
            participant = row(conn, "SELECT * FROM participants WHERE id = ?", (cur.lastrowid,))
            audit(conn, None, "public_create", "participant", cur.lastrowid, None, participant)
        event_id = survey.get("event_id")
        event_name = survey.get("event_code") or "Baseline"
        existing = row(conn, "SELECT * FROM entries WHERE participant_id = ? AND form_id = ? AND event_name = ? AND repeat_instance = 1", (participant["id"], survey["form_id"], event_name))
        if existing:
            if existing.get("locked_at"):
                self.send_error_json("This submitted CRF is locked and cannot be updated from the public link", 423)
                return
            conn.execute(
                "UPDATE entries SET event_id = ?, data_json = ?, status = 'complete', updated_at = ? WHERE id = ?",
                (event_id, json.dumps(cleaned), timestamp, existing["id"]),
            )
            entry_id = existing["id"]
            after = row(conn, "SELECT * FROM entries WHERE id = ?", (entry_id,))
            audit(conn, None, "public_update", "entry", entry_id, existing, after)
        else:
            cur = conn.execute(
                "INSERT INTO entries(study_id, participant_id, form_id, event_id, event_name, repeat_instance, status, data_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, 'complete', ?, ?, ?)",
                (survey["study_id"], participant["id"], survey["form_id"], event_id, event_name, json.dumps(cleaned), timestamp, timestamp),
            )
            entry_id = cur.lastrowid
            after = row(conn, "SELECT * FROM entries WHERE id = ?", (entry_id,))
            audit(conn, None, "public_create", "entry", entry_id, None, after)
        if survey["consent_required"]:
            conn.execute(
                """
                INSERT INTO consent_signatures(study_id, participant_id, entry_id, signer_name, signature_text, consent_text, ip_address, user_agent, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    survey["study_id"],
                    participant["id"],
                    entry_id,
                    str(consent_payload.get("signer_name", "")).strip(),
                    str(consent_payload.get("signature_text", "")).strip(),
                    survey["consent_text"],
                    self.client_address[0] if self.client_address else "",
                    self.headers.get("user-agent", ""),
                    timestamp,
                ),
            )
            audit(conn, None, "sign", "consent", entry_id, None, {"participant_id": participant["id"], "entry_id": entry_id})
        invitation_token = str(payload.get("invitation_token", "")).strip()
        if invitation_token:
            invitation = row(conn, "SELECT * FROM survey_invitations WHERE invite_token = ? AND survey_link_id = ?", (invitation_token, survey["id"]))
            if invitation:
                conn.execute(
                    "UPDATE survey_invitations SET participant_id = ?, status = 'completed', completed_at = ?, updated_at = ? WHERE id = ?",
                    (participant["id"], timestamp, timestamp, invitation["id"]),
                )
                audit(conn, None, "complete", "survey_invitation", invitation["id"], invitation, {"participant_id": participant["id"], "entry_id": entry_id})
        conn.commit()
        self.send_json({"ok": True, "participant_id": participant["id"], "entry_id": entry_id}, 201)

    def study_routes(self, conn: sqlite3.Connection, user: dict, method: str, path: str, query: dict[str, list[str]]) -> None:
        parts = path.strip("/").split("/")
        if len(parts) < 3:
            self.send_error_json("Study route missing id", 404)
            return
        study_id = int(parts[2])
        if not row(conn, "SELECT id FROM studies WHERE id = ?", (study_id,)):
            self.send_error_json("Study not found", 404)
            return
        membership = user_membership(conn, user, study_id)
        if not membership:
            self.send_error_json("Study access denied", 403)
            return
        resource = parts[3] if len(parts) > 3 else ""
        if resource == "forms":
            if method != "GET" and not membership_has(membership, "manage_forms"):
                self.send_error_json("Form management permission required", 403)
                return
            return self.forms(conn, user, method, study_id, parts)
        if resource == "dictionary":
            if not membership_has(membership, "manage_forms"):
                self.send_error_json("Form management permission required", 403)
                return
            return self.dictionary(conn, user, method, study_id)
        if resource == "records" and len(parts) == 5 and parts[4] == "import":
            if method != "POST":
                self.send_error_json("Unsupported records operation", 405)
                return
            if not membership_has(membership, "enter_data"):
                self.send_error_json("Data entry permission required", 403)
                return
            return self.import_records(conn, user, study_id, membership)
        if resource == "events":
            if method != "GET" and not membership_has(membership, "manage_study"):
                self.send_error_json("Study management permission required", 403)
                return
            return self.events(conn, user, method, study_id, parts)
        if resource == "form-events":
            if method != "GET" and not membership_has(membership, "manage_forms"):
                self.send_error_json("Form management permission required", 403)
                return
            return self.form_events(conn, user, method, study_id, parts)
        if resource == "surveys":
            if method != "GET" and not membership_has(membership, "manage_forms"):
                self.send_error_json("Form management permission required", 403)
                return
            return self.surveys(conn, user, method, study_id, parts)
        if resource == "invitations":
            if method != "GET" and not membership_has(membership, "manage_forms"):
                self.send_error_json("Form management permission required", 403)
                return
            return self.invitations(conn, user, method, study_id, parts)
        if resource == "participants":
            if method != "GET" and not membership_has(membership, "enter_data"):
                self.send_error_json("Data entry permission required", 403)
                return
            return self.participants(conn, user, method, study_id, parts, membership)
        if resource == "entries":
            if method == "GET":
                return self.entries(conn, user, method, study_id, parts, query, membership)
            if method == "POST" and not membership_has(membership, "enter_data"):
                self.send_error_json("Data entry permission required", 403)
                return
            if method == "PATCH" and not membership_has(membership, "review_data"):
                self.send_error_json("Review permission required", 403)
                return
            return self.entries(conn, user, method, study_id, parts, query, membership)
        if resource == "queries":
            if method != "GET" and not membership_has(membership, "review_data"):
                self.send_error_json("Review permission required", 403)
                return
            return self.queries(conn, user, method, study_id, parts, membership)
        if resource == "groups":
            if method != "GET" and not membership_has(membership, "manage_users"):
                self.send_error_json("User management permission required", 403)
                return
            return self.data_groups(conn, user, method, study_id, parts)
        if resource == "memberships":
            if not membership_has(membership, "manage_users"):
                self.send_error_json("User management permission required", 403)
                return
            return self.memberships(conn, user, method, study_id, parts)
        if resource == "metadata" and method == "GET":
            return self.metadata(conn, study_id)
        if resource == "validation" and method == "GET":
            if not membership_has(membership, "review_data") and not membership_has(membership, "manage_study"):
                self.send_error_json("Validation evidence permission required", 403)
                return
            return self.validation_evidence(conn, study_id)
        if resource == "quality" and method == "GET":
            return self.quality(conn, study_id, membership)
        if resource == "analysis" and method == "GET":
            if not membership_has(membership, "view_analysis") and not membership_has(membership, "review_data"):
                self.send_error_json("Analysis permission required", 403)
                return
            return self.analysis(conn, study_id, membership)
        if resource == "assist" and method == "GET" and len(parts) == 5 and parts[4] == "summary":
            if not membership_has(membership, "view_analysis") and not membership_has(membership, "review_data"):
                self.send_error_json("Analysis permission required", 403)
                return
            return self.assist_summary(conn, study_id, membership)
        if resource == "reports":
            if not membership_has(membership, "view_analysis") and not membership_has(membership, "export_data"):
                self.send_error_json("Report permission required", 403)
                return
            return self.reports(conn, user, method, study_id, parts, membership)
        if resource == "backups":
            if not membership_has(membership, "manage_study"):
                self.send_error_json("Study management permission required", 403)
                return
            return self.backups(conn, user, method, study_id, parts)
        if resource == "export" and method == "GET":
            if not membership_has(membership, "export_data"):
                self.send_error_json("Export permission required", 403)
                return
            return self.export_csv(conn, study_id, membership)
        if resource == "codebook" and method == "GET":
            if not membership_has(membership, "export_data"):
                self.send_error_json("Export permission required", 403)
                return
            return self.export_codebook(conn, study_id)
        if resource == "audit" and method == "GET":
            if not membership_has(membership, "review_data"):
                self.send_error_json("Review permission required", 403)
                return
            return self.send_json({"audit": rows(conn, "SELECT audit_log.*, users.display_name FROM audit_log LEFT JOIN users ON users.id = audit_log.user_id WHERE entity_id IN (SELECT id FROM participants WHERE study_id = ?) OR entity_type = 'study' ORDER BY audit_log.id DESC LIMIT 250", (study_id,))})
        self.send_error_json("Unknown study route", 404)

    def forms(self, conn, user, method, study_id, parts) -> None:
        if method == "GET" and len(parts) == 6 and parts[5] == "versions":
            form_id = int(parts[4])
            versions = rows(conn, "SELECT id, form_id, study_id, version, name, code, saved_by, saved_at FROM form_versions WHERE form_id = ? AND study_id = ? ORDER BY version DESC", (form_id, study_id))
            self.send_json({"versions": versions})
            return
        if method == "GET":
            forms = rows(conn, "SELECT * FROM forms WHERE study_id = ? ORDER BY id", (study_id,))
            for form in forms:
                form["schema"] = load_json(form.pop("schema_json"), {"fields": []})
            self.send_json({"forms": forms})
            return
        if method == "POST" and len(parts) == 4:
            payload = self.body()
            timestamp = now()
            schema = normalize_schema(payload.get("schema") or {"fields": []})
            cur = conn.execute(
                "INSERT INTO forms(study_id, name, code, schema_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (study_id, str(payload.get("name", "")).strip() or "Untitled Form", normalize_code(str(payload.get("code", "")), f"form_{timestamp}"), json.dumps(schema), timestamp, timestamp),
            )
            event_ids = payload.get("event_ids") or []
            if not event_ids:
                baseline = row(conn, "SELECT id FROM study_events WHERE study_id = ? AND code = 'baseline'", (study_id,))
                event_ids = [baseline["id"]] if baseline else []
            for event_id in event_ids:
                if row(conn, "SELECT id FROM study_events WHERE id = ? AND study_id = ?", (event_id, study_id)):
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO form_events(study_id, event_id, form_id, required, created_at, updated_at)
                        VALUES (?, ?, ?, 1, ?, ?)
                        """,
                        (study_id, event_id, cur.lastrowid, timestamp, timestamp),
                    )
            after = row(conn, "SELECT * FROM forms WHERE id = ?", (cur.lastrowid,))
            audit(conn, user["id"], "create", "form", cur.lastrowid, None, after)
            self.send_json({"form": after}, 201)
            return
        if method == "PATCH" and len(parts) == 5:
            form_id = int(parts[4])
            before = row(conn, "SELECT * FROM forms WHERE id = ? AND study_id = ?", (form_id, study_id))
            if not before:
                self.send_error_json("Form not found", 404)
                return
            payload = self.body()
            schema = normalize_schema(payload.get("schema", load_json(before["schema_json"], {})))
            conn.execute(
                "INSERT INTO form_versions(form_id, study_id, version, name, code, schema_json, saved_by, saved_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (form_id, study_id, before["version"], before["name"], before["code"], before["schema_json"], user["id"], now()),
            )
            conn.execute(
                "UPDATE forms SET name = ?, code = ?, schema_json = ?, version = version + 1, updated_at = ? WHERE id = ? AND study_id = ?",
                (str(payload.get("name", before["name"])).strip(), normalize_code(str(payload.get("code", before["code"])), before["code"]), json.dumps(schema), now(), form_id, study_id),
            )
            after = row(conn, "SELECT * FROM forms WHERE id = ?", (form_id,))
            audit(conn, user["id"], "update", "form", form_id, before, after)
            conn.commit()
            self.send_json({"form": after})
            return
        self.send_error_json("Unsupported forms operation", 405)

    def events(self, conn, user, method, study_id, parts) -> None:
        if method == "GET":
            self.send_json({"events": rows(conn, "SELECT * FROM study_events WHERE study_id = ? ORDER BY display_order, id", (study_id,))})
            return
        if method == "POST":
            payload = self.body()
            timestamp = now()
            name = str(payload.get("name", "")).strip()
            code = normalize_code(str(payload.get("code", "")), normalize_code(name))
            if not name or not code:
                self.send_error_json("Event name is required", 400)
                return
            display_order = int(payload.get("display_order") or row(conn, "SELECT COALESCE(MAX(display_order), 0) + 1 AS next_order FROM study_events WHERE study_id = ?", (study_id,))["next_order"])
            cur = conn.execute(
                """
                INSERT INTO study_events(study_id, name, code, arm_name, day_offset, display_order, active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (study_id, name, code, str(payload.get("arm_name", "Default")).strip() or "Default", int(payload.get("day_offset") or 0), display_order, timestamp, timestamp),
            )
            after = row(conn, "SELECT * FROM study_events WHERE id = ?", (cur.lastrowid,))
            audit(conn, user["id"], "create", "event", cur.lastrowid, None, after)
            self.send_json({"event": after}, 201)
            return
        self.send_error_json("Unsupported events operation", 405)

    def form_events(self, conn, user, method, study_id, parts) -> None:
        if method == "GET":
            self.send_json({"form_events": rows(conn, "SELECT form_events.*, study_events.name AS event_name, forms.name AS form_name FROM form_events JOIN study_events ON study_events.id = form_events.event_id JOIN forms ON forms.id = form_events.form_id WHERE form_events.study_id = ? ORDER BY study_events.display_order, forms.id", (study_id,))})
            return
        if method == "POST":
            payload = self.body()
            timestamp = now()
            event_id = int(payload.get("event_id"))
            form_id = int(payload.get("form_id"))
            required = 1 if payload.get("required", True) else 0
            if not row(conn, "SELECT id FROM study_events WHERE id = ? AND study_id = ?", (event_id, study_id)) or not row(conn, "SELECT id FROM forms WHERE id = ? AND study_id = ?", (form_id, study_id)):
                self.send_error_json("Event or form not found", 404)
                return
            existing = row(conn, "SELECT id FROM form_events WHERE event_id = ? AND form_id = ?", (event_id, form_id))
            if existing:
                conn.execute("UPDATE form_events SET required = ?, updated_at = ? WHERE id = ?", (required, timestamp, existing["id"]))
                after = row(conn, "SELECT * FROM form_events WHERE id = ?", (existing["id"],))
                audit(conn, user["id"], "update", "form_event", existing["id"], None, after)
                self.send_json({"form_event": after})
                return
            cur = conn.execute(
                "INSERT INTO form_events(study_id, event_id, form_id, required, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (study_id, event_id, form_id, required, timestamp, timestamp),
            )
            after = row(conn, "SELECT * FROM form_events WHERE id = ?", (cur.lastrowid,))
            audit(conn, user["id"], "create", "form_event", cur.lastrowid, None, after)
            self.send_json({"form_event": after}, 201)
            return
        self.send_error_json("Unsupported form-event operation", 405)

    def surveys(self, conn, user, method, study_id, parts) -> None:
        if method == "GET" and len(parts) == 4:
            survey_rows = rows(
                conn,
                """
                SELECT survey_links.*, forms.name AS form_name, study_events.name AS event_name
                FROM survey_links
                JOIN forms ON forms.id = survey_links.form_id
                LEFT JOIN study_events ON study_events.id = survey_links.event_id
                WHERE survey_links.study_id = ?
                ORDER BY survey_links.updated_at DESC
                """,
                (study_id,),
            )
            self.send_json({"surveys": survey_rows})
            return
        if method == "POST" and len(parts) == 4:
            payload = self.body()
            form_id = int(payload.get("form_id") or 0)
            event_id = payload.get("event_id")
            form = row(conn, "SELECT * FROM forms WHERE id = ? AND study_id = ?", (form_id, study_id))
            if not form:
                self.send_error_json("Form not found", 404)
                return
            if event_id:
                event = row(conn, "SELECT * FROM study_events WHERE id = ? AND study_id = ?", (int(event_id), study_id))
                if not event:
                    self.send_error_json("Event not found", 404)
                    return
                event_id = event["id"]
            else:
                event_id = None
            timestamp = now()
            cur = conn.execute(
                """
                INSERT INTO survey_links(study_id, form_id, event_id, token, title, enabled, consent_required, consent_text, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    study_id,
                    form_id,
                    event_id,
                    secrets.token_urlsafe(24),
                    str(payload.get("title", form["name"])).strip() or form["name"],
                    1,
                    1 if payload.get("consent_required") else 0,
                    str(payload.get("consent_text", "")).strip(),
                    user["id"],
                    timestamp,
                    timestamp,
                ),
            )
            after = row(conn, "SELECT * FROM survey_links WHERE id = ?", (cur.lastrowid,))
            audit(conn, user["id"], "create", "survey_link", cur.lastrowid, None, after)
            conn.commit()
            self.send_json({"survey": after}, 201)
            return
        if method == "PATCH" and len(parts) == 5:
            survey_id = int(parts[4])
            before = row(conn, "SELECT * FROM survey_links WHERE id = ? AND study_id = ?", (survey_id, study_id))
            if not before:
                self.send_error_json("Survey link not found", 404)
                return
            payload = self.body()
            conn.execute(
                "UPDATE survey_links SET title = ?, enabled = ?, consent_required = ?, consent_text = ?, updated_at = ? WHERE id = ?",
                (
                    str(payload.get("title", before["title"])).strip() or before["title"],
                    1 if payload.get("enabled", bool(before["enabled"])) else 0,
                    1 if payload.get("consent_required", bool(before["consent_required"])) else 0,
                    str(payload.get("consent_text", before["consent_text"])).strip(),
                    now(),
                    survey_id,
                ),
            )
            after = row(conn, "SELECT * FROM survey_links WHERE id = ?", (survey_id,))
            audit(conn, user["id"], "update", "survey_link", survey_id, before, after)
            conn.commit()
            self.send_json({"survey": after})
            return
        self.send_error_json("Unsupported survey operation", 405)

    def invitations(self, conn, user, method, study_id, parts) -> None:
        if method == "GET" and len(parts) == 4:
            invitation_rows = rows(
                conn,
                """
                SELECT survey_invitations.*, survey_links.title AS survey_title, participants.study_uid
                FROM survey_invitations
                JOIN survey_links ON survey_links.id = survey_invitations.survey_link_id
                LEFT JOIN participants ON participants.id = survey_invitations.participant_id
                WHERE survey_invitations.study_id = ?
                ORDER BY survey_invitations.updated_at DESC
                """,
                (study_id,),
            )
            self.send_json({"invitations": invitation_rows})
            return
        if method == "POST" and len(parts) == 4:
            payload = self.body()
            survey_link_id = int(payload.get("survey_link_id") or 0)
            survey = row(conn, "SELECT * FROM survey_links WHERE id = ? AND study_id = ?", (survey_link_id, study_id))
            if not survey:
                self.send_error_json("Survey link not found", 404)
                return
            contact = str(payload.get("contact", "")).strip()
            if not contact:
                self.send_error_json("Invitation contact is required", 400)
                return
            participant_id = payload.get("participant_id") or None
            if participant_id and not row(conn, "SELECT id FROM participants WHERE id = ? AND study_id = ?", (participant_id, study_id)):
                self.send_error_json("Participant not found", 404)
                return
            timestamp = now()
            cur = conn.execute(
                """
                INSERT INTO survey_invitations(study_id, survey_link_id, participant_id, contact, status, invite_token, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?)
                """,
                (study_id, survey_link_id, participant_id, contact, secrets.token_urlsafe(20), user["id"], timestamp, timestamp),
            )
            after = row(conn, "SELECT * FROM survey_invitations WHERE id = ?", (cur.lastrowid,))
            audit(conn, user["id"], "create", "survey_invitation", cur.lastrowid, None, after)
            conn.commit()
            self.send_json({"invitation": after}, 201)
            return
        if method == "PATCH" and len(parts) == 5:
            invitation_id = int(parts[4])
            before = row(conn, "SELECT * FROM survey_invitations WHERE id = ? AND study_id = ?", (invitation_id, study_id))
            if not before:
                self.send_error_json("Invitation not found", 404)
                return
            payload = self.body()
            action = str(payload.get("action", "")).strip()
            timestamp = now()
            if action == "mark_sent":
                conn.execute(
                    "UPDATE survey_invitations SET status = 'sent', last_sent_at = ?, reminder_count = reminder_count + 1, updated_at = ? WHERE id = ?",
                    (timestamp, timestamp, invitation_id),
                )
            elif action == "mark_completed":
                conn.execute(
                    "UPDATE survey_invitations SET status = 'completed', completed_at = ?, updated_at = ? WHERE id = ?",
                    (timestamp, timestamp, invitation_id),
                )
            elif action == "cancel":
                conn.execute("UPDATE survey_invitations SET status = 'cancelled', updated_at = ? WHERE id = ?", (timestamp, invitation_id))
            else:
                self.send_error_json("Unsupported invitation action", 405)
                return
            after = row(conn, "SELECT * FROM survey_invitations WHERE id = ?", (invitation_id,))
            audit(conn, user["id"], action, "survey_invitation", invitation_id, before, after)
            conn.commit()
            self.send_json({"invitation": after})
            return
        self.send_error_json("Unsupported invitation operation", 405)

    def dictionary(self, conn, user, method, study_id) -> None:
        if method != "POST":
            self.send_error_json("Unsupported dictionary operation", 405)
            return
        payload = self.body()
        csv_text = str(payload.get("csv", "")).strip()
        if not csv_text:
            self.send_error_json("CSV content is required", 400)
            return
        reader = csv.DictReader(StringIO(csv_text))
        required = {"instrument_name", "instrument_label", "field_name", "field_label", "field_type"}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            self.send_error_json("Dictionary CSV is missing required columns", 400)
            return
        grouped: dict[str, dict] = {}
        for raw in reader:
            instrument = normalize_code(raw.get("instrument_name", ""))
            if not instrument:
                continue
            grouped.setdefault(
                instrument,
                {
                    "name": raw.get("instrument_label") or instrument,
                    "code": instrument,
                    "events": raw.get("events", ""),
                    "repeatable": str(raw.get("repeatable", "")).strip().lower() in {"yes", "true", "1"},
                    "fields": [],
                },
            )
            field_type = str(raw.get("field_type", "text")).strip() or "text"
            choices = [item.strip() for item in str(raw.get("choices", "")).replace("|", ",").split(",") if item.strip()]
            field = {
                "code": raw.get("field_name", ""),
                "label": raw.get("field_label", ""),
                "type": field_type,
                "required": str(raw.get("required", "")).strip().lower() in {"yes", "true", "1"},
            }
            if choices:
                field["options"] = choices
            if raw.get("validation_min") not in (None, ""):
                field["min"] = raw.get("validation_min")
            if raw.get("validation_max") not in (None, ""):
                field["max"] = raw.get("validation_max")
            if raw.get("calculation"):
                field["calculation"] = raw.get("calculation")
                field["type"] = "calc"
            grouped[instrument]["fields"].append(field)
        imported = []
        timestamp = now()
        for item in grouped.values():
            schema = normalize_schema({"fields": item["fields"], "repeatable": item["repeatable"]})
            existing = row(conn, "SELECT * FROM forms WHERE study_id = ? AND code = ?", (study_id, item["code"]))
            if existing:
                conn.execute(
                    "INSERT INTO form_versions(form_id, study_id, version, name, code, schema_json, saved_by, saved_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (existing["id"], study_id, existing["version"], existing["name"], existing["code"], existing["schema_json"], user["id"], timestamp),
                )
                conn.execute(
                    "UPDATE forms SET name = ?, schema_json = ?, version = version + 1, updated_at = ? WHERE id = ?",
                    (item["name"], json.dumps(schema), timestamp, existing["id"]),
                )
                form_id = existing["id"]
                action = "update"
            else:
                cur = conn.execute(
                    "INSERT INTO forms(study_id, name, code, schema_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (study_id, item["name"], item["code"], json.dumps(schema), timestamp, timestamp),
                )
                form_id = cur.lastrowid
                action = "create"
            event_codes = [normalize_code(part.strip()) for part in str(item.get("events", "")).replace("|", ",").split(",") if part.strip()]
            if not event_codes:
                event_codes = ["baseline"]
            for event_code in event_codes:
                event = row(conn, "SELECT id FROM study_events WHERE study_id = ? AND code = ?", (study_id, event_code))
                if event:
                    conn.execute(
                        "INSERT OR IGNORE INTO form_events(study_id, event_id, form_id, required, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)",
                        (study_id, event["id"], form_id, timestamp, timestamp),
                    )
            imported.append({"form_id": form_id, "code": item["code"], "action": action})
        audit(conn, user["id"], "import", "dictionary", study_id, None, {"forms": imported})
        self.send_json({"imported": imported})

    def import_records(self, conn, user, study_id: int, membership) -> None:
        payload = self.body()
        csv_text = str(payload.get("csv", "")).strip()
        if not csv_text:
            self.send_error_json("Record CSV content is required", 400)
            return
        reader = csv.DictReader(StringIO(csv_text))
        if not reader.fieldnames or "study_uid" not in reader.fieldnames:
            self.send_error_json("Record CSV must include study_uid", 400)
            return
        forms = rows(conn, "SELECT * FROM forms WHERE study_id = ?", (study_id,))
        forms_by_code = {item["code"]: item for item in forms}
        forms_by_name = {item["name"]: item for item in forms}
        events_by_code = {item["code"]: item for item in rows(conn, "SELECT * FROM study_events WHERE study_id = ?", (study_id,))}
        imported = {"participants_created": 0, "entries_created": 0, "entries_updated": 0, "errors": []}
        timestamp = now()
        for row_index, raw in enumerate(reader, start=2):
            study_uid = str(raw.get("study_uid", "")).strip()
            if not study_uid:
                imported["errors"].append({"row": row_index, "message": "study_uid is required"})
                continue
            participant = row(conn, "SELECT * FROM participants WHERE study_id = ? AND study_uid = ?", (study_id, study_uid))
            if not participant:
                data_group_id = membership.get("data_group_id")
                cur = conn.execute(
                    "INSERT INTO participants(study_id, data_group_id, study_uid, initials, status, metadata_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, '{}', ?, ?)",
                    (study_id, data_group_id, study_uid, str(raw.get("initials", "")).strip().upper(), str(raw.get("participant_status", "enrolled") or "enrolled"), timestamp, timestamp),
                )
                participant = row(conn, "SELECT * FROM participants WHERE id = ?", (cur.lastrowid,))
                audit(conn, user["id"], "create", "participant", cur.lastrowid, None, participant)
                imported["participants_created"] += 1
            if membership.get("data_group_id") and participant.get("data_group_id") != membership["data_group_id"]:
                imported["errors"].append({"row": row_index, "message": "Participant is outside your data access group"})
                continue
            form = forms_by_code.get(str(raw.get("form_code", "")).strip()) or forms_by_code.get(str(raw.get("instrument_name", "")).strip()) or forms_by_name.get(str(raw.get("form_name", "")).strip())
            if not form:
                for key, value in raw.items():
                    if "__" in key and value not in (None, ""):
                        form = forms_by_code.get(key.split("__", 1)[0])
                        if form:
                            break
            if not form:
                imported["errors"].append({"row": row_index, "message": "Could not identify CRF/form"})
                continue
            schema = load_json(form["schema_json"], {"fields": []})
            data = {}
            for field in schema.get("fields", []):
                field_code = field.get("code", "")
                scoped = f"{form['code']}__{field_code}"
                if scoped in raw:
                    data[field_code] = raw.get(scoped, "")
                elif field_code in raw:
                    data[field_code] = raw.get(field_code, "")
            cleaned, issues = validate_entry_data(schema, data)
            if issues:
                imported["errors"].append({"row": row_index, "message": "Validation failed", "issues": issues})
                continue
            event_code = normalize_code(str(raw.get("event_code") or raw.get("event_name") or "baseline"))
            event = events_by_code.get(event_code) or events_by_code.get("baseline")
            event_id = event["id"] if event else None
            event_name = event["code"] if event else "Baseline"
            repeat_instance = max(int(raw.get("repeat_instance") or 1), 1)
            status = str(raw.get("entry_status") or raw.get("status") or "draft")
            existing = row(conn, "SELECT * FROM entries WHERE participant_id = ? AND form_id = ? AND event_name = ? AND repeat_instance = ?", (participant["id"], form["id"], event_name, repeat_instance))
            if existing:
                if existing.get("locked_at"):
                    imported["errors"].append({"row": row_index, "message": "Existing CRF is locked"})
                    continue
                conn.execute("UPDATE entries SET event_id = ?, data_json = ?, status = ?, updated_by = ?, updated_at = ? WHERE id = ?", (event_id, json.dumps(cleaned), status, user["id"], timestamp, existing["id"]))
                after = row(conn, "SELECT * FROM entries WHERE id = ?", (existing["id"],))
                audit(conn, user["id"], "import_update", "entry", existing["id"], existing, after)
                imported["entries_updated"] += 1
            else:
                cur = conn.execute(
                    "INSERT INTO entries(study_id, participant_id, form_id, event_id, event_name, repeat_instance, status, data_json, created_by, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (study_id, participant["id"], form["id"], event_id, event_name, repeat_instance, status, json.dumps(cleaned), user["id"], user["id"], timestamp, timestamp),
                )
                after = row(conn, "SELECT * FROM entries WHERE id = ?", (cur.lastrowid,))
                audit(conn, user["id"], "import_create", "entry", cur.lastrowid, None, after)
                imported["entries_created"] += 1
        audit(conn, user["id"], "import", "records", study_id, None, imported)
        conn.commit()
        status = 207 if imported["errors"] else 201
        self.send_json({"imported": imported}, status)

    def participants(self, conn, user, method, study_id, parts, membership) -> None:
        if method == "GET":
            if membership.get("data_group_id"):
                participants = rows(conn, "SELECT * FROM participants WHERE study_id = ? AND data_group_id = ? ORDER BY id DESC", (study_id, membership["data_group_id"]))
            else:
                participants = rows(conn, "SELECT * FROM participants WHERE study_id = ? ORDER BY id DESC", (study_id,))
            for participant in participants:
                participant["metadata"] = load_json(participant.pop("metadata_json"), {})
            self.send_json({"participants": participants})
            return
        if method == "POST":
            payload = self.body()
            timestamp = now()
            data_group_id = payload.get("data_group_id") or membership.get("data_group_id")
            cur = conn.execute(
                "INSERT INTO participants(study_id, data_group_id, study_uid, initials, status, metadata_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (study_id, data_group_id, str(payload.get("study_uid", "")).strip(), str(payload.get("initials", "")).strip().upper(), str(payload.get("status", "screening")), json.dumps(payload.get("metadata", {})), timestamp, timestamp),
            )
            after = row(conn, "SELECT * FROM participants WHERE id = ?", (cur.lastrowid,))
            audit(conn, user["id"], "create", "participant", cur.lastrowid, None, after)
            self.send_json({"participant": after}, 201)
            return
        if method == "PATCH" and len(parts) == 5:
            participant_id = int(parts[4])
            before = row(conn, "SELECT * FROM participants WHERE id = ? AND study_id = ?", (participant_id, study_id))
            if not before:
                self.send_error_json("Participant not found", 404)
                return
            if membership.get("data_group_id") and before.get("data_group_id") != membership["data_group_id"]:
                self.send_error_json("Participant is outside your data access group", 403)
                return
            payload = self.body()
            data_group_id = payload.get("data_group_id", before.get("data_group_id"))
            if membership.get("data_group_id"):
                data_group_id = membership["data_group_id"]
            conn.execute(
                "UPDATE participants SET data_group_id = ?, study_uid = ?, initials = ?, status = ?, metadata_json = ?, updated_at = ? WHERE id = ? AND study_id = ?",
                (data_group_id, str(payload.get("study_uid", before["study_uid"])).strip(), str(payload.get("initials", before["initials"])).strip().upper(), str(payload.get("status", before["status"])), json.dumps(payload.get("metadata", load_json(before["metadata_json"], {}))), now(), participant_id, study_id),
            )
            after = row(conn, "SELECT * FROM participants WHERE id = ?", (participant_id,))
            audit(conn, user["id"], "update", "participant", participant_id, before, after)
            self.send_json({"participant": after})
            return
        self.send_error_json("Unsupported participant operation", 405)

    def entries(self, conn, user, method, study_id, parts, query, membership) -> None:
        if method == "GET" and len(parts) == 6 and parts[5] == "history":
            entry_id = int(parts[4])
            entry = row(conn, "SELECT * FROM entries WHERE id = ? AND study_id = ?", (entry_id, study_id))
            if not entry:
                self.send_error_json("Entry not found", 404)
                return
            participant = row(conn, "SELECT * FROM participants WHERE id = ?", (entry["participant_id"],))
            if membership.get("data_group_id") and participant and participant.get("data_group_id") != membership["data_group_id"]:
                self.send_error_json("Entry is outside your data access group", 403)
                return
            history = rows(
                conn,
                """
                SELECT audit_log.*, users.display_name
                FROM audit_log
                LEFT JOIN users ON users.id = audit_log.user_id
                WHERE audit_log.entity_type = 'entry' AND audit_log.entity_id = ?
                ORDER BY audit_log.created_at DESC, audit_log.id DESC
                """,
                (entry_id,),
            )
            for item in history:
                item["before"] = load_json(item.pop("before_json"), None)
                item["after"] = load_json(item.pop("after_json"), None)
            states = rows(conn, "SELECT field_states.*, users.display_name FROM field_states LEFT JOIN users ON users.id = field_states.user_id WHERE entry_id = ? ORDER BY created_at DESC", (entry_id,))
            self.send_json({"history": history, "field_states": states})
            return
        if method == "GET":
            participant_id = int((query.get("participant_id") or ["0"])[0])
            params: tuple = (study_id,)
            sql = "SELECT entries.*, forms.name AS form_name, forms.code AS form_code, participants.study_uid, study_events.name AS mapped_event_name, study_events.code AS event_code FROM entries JOIN forms ON forms.id = entries.form_id JOIN participants ON participants.id = entries.participant_id LEFT JOIN study_events ON study_events.id = entries.event_id WHERE entries.study_id = ?"
            if membership.get("data_group_id"):
                sql += " AND participants.data_group_id = ?"
                params = (study_id, membership["data_group_id"])
            if participant_id:
                sql += " AND participant_id = ?"
                params = (*params, participant_id)
            entries = rows(conn, sql + " ORDER BY entries.updated_at DESC", params)
            for entry in entries:
                entry["data"] = load_json(entry.pop("data_json"), {})
            self.send_json({"entries": entries})
            return
        if method == "POST":
            payload = self.body()
            timestamp = now()
            participant_id = int(payload["participant_id"])
            form_id = int(payload["form_id"])
            event_id = payload.get("event_id")
            event = None
            if event_id:
                event = row(conn, "SELECT * FROM study_events WHERE id = ? AND study_id = ?", (int(event_id), study_id))
                if not event:
                    self.send_error_json("Event not found", 404)
                    return
                event_id = event["id"]
            event_name = str(payload.get("event_name", "")).strip()
            if event:
                event_name = event["code"]
            if not event_name:
                event_name = "Baseline"
            repeat_instance = max(int(payload.get("repeat_instance", 1) or 1), 1)
            data = payload.get("data", {})
            status = str(payload.get("status", "draft"))
            form = row(conn, "SELECT * FROM forms WHERE id = ? AND study_id = ?", (form_id, study_id))
            participant = row(conn, "SELECT * FROM participants WHERE id = ? AND study_id = ?", (participant_id, study_id))
            if not form or not participant:
                self.send_error_json("Participant or form not found", 404)
                return
            if event_id and not row(conn, "SELECT id FROM form_events WHERE study_id = ? AND event_id = ? AND form_id = ?", (study_id, event_id, form_id)):
                self.send_error_json("This CRF is not assigned to the selected event", 400)
                return
            if membership.get("data_group_id") and participant.get("data_group_id") != membership["data_group_id"]:
                self.send_error_json("Participant is outside your data access group", 403)
                return
            schema = load_json(form["schema_json"], {"fields": []})
            if repeat_instance > 1 and not schema.get("repeatable"):
                self.send_error_json("This CRF is not configured as repeatable", 400)
                return
            cleaned, issues = validate_entry_data(schema, data)
            if issues:
                self.send_json({"errors": issues}, 422)
                return
            existing = row(conn, "SELECT * FROM entries WHERE participant_id = ? AND form_id = ? AND event_name = ? AND repeat_instance = ?", (participant_id, form_id, event_name, repeat_instance))
            if existing:
                if existing.get("locked_at"):
                    reason = str(payload.get("change_reason", "")).strip()
                    if not reason:
                        self.send_error_json("Change reason is required before editing a locked CRF", 423)
                        return
                before = existing
                conn.execute(
                    "UPDATE entries SET event_id = ?, data_json = ?, status = ?, updated_by = ?, updated_at = ?, locked_at = NULL, locked_by = NULL, lock_reason = '' WHERE id = ?",
                    (event_id, json.dumps(cleaned), status, user["id"], timestamp, existing["id"]),
                )
                after = row(conn, "SELECT * FROM entries WHERE id = ?", (existing["id"],))
                audit(conn, user["id"], "update", "entry", existing["id"], before, {"entry": after, "change_reason": payload.get("change_reason", "")})
                self.send_json({"entry": after})
                return
            cur = conn.execute(
                "INSERT INTO entries(study_id, participant_id, form_id, event_id, event_name, repeat_instance, status, data_json, created_by, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (study_id, participant_id, form_id, event_id, event_name, repeat_instance, status, json.dumps(cleaned), user["id"], user["id"], timestamp, timestamp),
            )
            after = row(conn, "SELECT * FROM entries WHERE id = ?", (cur.lastrowid,))
            audit(conn, user["id"], "create", "entry", cur.lastrowid, None, after)
            self.send_json({"entry": after}, 201)
            return
        if method == "PATCH" and len(parts) == 5:
            entry_id = int(parts[4])
            before = row(conn, "SELECT * FROM entries WHERE id = ? AND study_id = ?", (entry_id, study_id))
            if not before:
                self.send_error_json("Entry not found", 404)
                return
            participant = row(conn, "SELECT * FROM participants WHERE id = ?", (before["participant_id"],))
            if membership.get("data_group_id") and participant and participant.get("data_group_id") != membership["data_group_id"]:
                self.send_error_json("Entry is outside your data access group", 403)
                return
            payload = self.body()
            action = str(payload.get("action", "")).strip()
            if action == "lock":
                reason = str(payload.get("reason", "")).strip() or "Reviewed and locked"
                conn.execute("UPDATE entries SET locked_at = ?, locked_by = ?, lock_reason = ?, status = 'complete', updated_by = ?, updated_at = ? WHERE id = ?", (now(), user["id"], reason, user["id"], now(), entry_id))
                after = row(conn, "SELECT * FROM entries WHERE id = ?", (entry_id,))
                audit(conn, user["id"], "lock", "entry", entry_id, before, after)
                self.send_json({"entry": after})
                return
            if action == "unlock":
                reason = str(payload.get("reason", "")).strip()
                if not reason:
                    self.send_error_json("Unlock reason is required", 400)
                    return
                conn.execute("UPDATE entries SET locked_at = NULL, locked_by = NULL, lock_reason = '', updated_by = ?, updated_at = ? WHERE id = ?", (user["id"], now(), entry_id))
                after = row(conn, "SELECT * FROM entries WHERE id = ?", (entry_id,))
                audit(conn, user["id"], "unlock", "entry", entry_id, before, {"entry": after, "reason": reason})
                self.send_json({"entry": after})
                return
            if action in {"verify_field", "freeze_field"}:
                field_code = normalize_code(str(payload.get("field_code", "")))
                if not field_code:
                    self.send_error_json("Field code is required", 400)
                    return
                state = "verified" if action == "verify_field" else "frozen"
                reason = str(payload.get("reason", "")).strip()
                conn.execute(
                    """
                    INSERT OR REPLACE INTO field_states(entry_id, field_code, state, reason, user_id, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (entry_id, field_code, state, reason, user["id"], now()),
                )
                audit(conn, user["id"], action, "entry", entry_id, before, {"field_code": field_code, "state": state, "reason": reason})
                self.send_json({"field_state": {"entry_id": entry_id, "field_code": field_code, "state": state}})
                return
            self.send_error_json("Unsupported entry action", 405)
            return
        self.send_error_json("Unsupported entries operation", 405)

    def queries(self, conn, user, method, study_id, parts, membership) -> None:
        if method == "GET":
            if membership.get("data_group_id"):
                data = rows(
                    conn,
                    """
                    SELECT queries.*, participants.study_uid, forms.name AS form_name
                    FROM queries
                    LEFT JOIN participants ON participants.id = queries.participant_id
                    LEFT JOIN forms ON forms.id = queries.form_id
                    WHERE queries.study_id = ? AND (participants.data_group_id = ? OR queries.participant_id IS NULL)
                    ORDER BY queries.status, queries.updated_at DESC
                    """,
                    (study_id, membership["data_group_id"]),
                )
            else:
                data = rows(conn, "SELECT queries.*, participants.study_uid, forms.name AS form_name FROM queries LEFT JOIN participants ON participants.id = queries.participant_id LEFT JOIN forms ON forms.id = queries.form_id WHERE queries.study_id = ? ORDER BY queries.status, queries.updated_at DESC", (study_id,))
            responses = rows(conn, "SELECT query_responses.*, users.display_name FROM query_responses LEFT JOIN users ON users.id = query_responses.user_id WHERE query_id IN (SELECT id FROM queries WHERE study_id = ?) ORDER BY created_at", (study_id,))
            by_query: dict[int, list[dict]] = {}
            for response in responses:
                by_query.setdefault(response["query_id"], []).append(response)
            for query_item in data:
                query_item["responses"] = by_query.get(query_item["id"], [])
            self.send_json({"queries": data})
            return
        if method == "POST" and len(parts) == 4:
            payload = self.body()
            timestamp = now()
            participant_id = payload.get("participant_id")
            if participant_id and membership.get("data_group_id"):
                participant = row(conn, "SELECT data_group_id FROM participants WHERE id = ? AND study_id = ?", (participant_id, study_id))
                if not participant or participant.get("data_group_id") != membership["data_group_id"]:
                    self.send_error_json("Participant is outside your data access group", 403)
                    return
            cur = conn.execute(
                "INSERT INTO queries(study_id, participant_id, form_id, field_code, message, status, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (study_id, participant_id, payload.get("form_id"), str(payload.get("field_code", "")), str(payload.get("message", "")).strip(), "open", user["id"], timestamp, timestamp),
            )
            after = row(conn, "SELECT * FROM queries WHERE id = ?", (cur.lastrowid,))
            audit(conn, user["id"], "create", "query", cur.lastrowid, None, after)
            self.send_json({"query": after}, 201)
            return
        if method == "PATCH" and len(parts) == 5:
            query_id = int(parts[4])
            before = row(conn, "SELECT * FROM queries WHERE id = ? AND study_id = ?", (query_id, study_id))
            payload = self.body()
            conn.execute("UPDATE queries SET status = ?, updated_at = ? WHERE id = ? AND study_id = ?", (str(payload.get("status", before["status"])), now(), query_id, study_id))
            after = row(conn, "SELECT * FROM queries WHERE id = ?", (query_id,))
            audit(conn, user["id"], "update", "query", query_id, before, after)
            self.send_json({"query": after})
            return
        if method == "POST" and len(parts) == 6 and parts[5] == "responses":
            query_id = int(parts[4])
            if not row(conn, "SELECT id FROM queries WHERE id = ? AND study_id = ?", (query_id, study_id)):
                self.send_error_json("Query not found", 404)
                return
            payload = self.body()
            message = str(payload.get("message", "")).strip()
            if not message:
                self.send_error_json("Response message is required", 400)
                return
            cur = conn.execute(
                "INSERT INTO query_responses(query_id, user_id, message, created_at) VALUES (?, ?, ?, ?)",
                (query_id, user["id"], message, now()),
            )
            after = row(conn, "SELECT * FROM query_responses WHERE id = ?", (cur.lastrowid,))
            audit(conn, user["id"], "respond", "query", query_id, None, after)
            self.send_json({"response": after}, 201)
            return
        self.send_error_json("Unsupported queries operation", 405)

    def data_groups(self, conn, user, method, study_id, parts) -> None:
        if method == "GET":
            self.send_json({"groups": rows(conn, "SELECT * FROM data_groups WHERE study_id = ? ORDER BY name", (study_id,))})
            return
        if method == "POST":
            payload = self.body()
            timestamp = now()
            name = str(payload.get("name", "")).strip()
            code = normalize_code(str(payload.get("code", "")), normalize_code(name))
            if not name or not code:
                self.send_error_json("Group name is required", 400)
                return
            cur = conn.execute(
                "INSERT INTO data_groups(study_id, name, code, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                (study_id, name, code, timestamp, timestamp),
            )
            after = row(conn, "SELECT * FROM data_groups WHERE id = ?", (cur.lastrowid,))
            audit(conn, user["id"], "create", "data_group", cur.lastrowid, None, after)
            self.send_json({"group": after}, 201)
            return
        self.send_error_json("Unsupported group operation", 405)

    def memberships(self, conn, user, method, study_id, parts) -> None:
        if method == "GET":
            memberships = rows(
                conn,
                """
                SELECT study_memberships.*, users.username, users.display_name, data_groups.name AS data_group_name
                FROM study_memberships
                JOIN users ON users.id = study_memberships.user_id
                LEFT JOIN data_groups ON data_groups.id = study_memberships.data_group_id
                WHERE study_memberships.study_id = ?
                ORDER BY users.username
                """,
                (study_id,),
            )
            self.send_json({"memberships": memberships})
            return
        if method == "POST":
            payload = self.body()
            timestamp = now()
            user_id = int(payload.get("user_id"))
            role_name = str(payload.get("role", "data_entry")).strip()
            data_group_id = payload.get("data_group_id") or None
            active = 1 if payload.get("active", True) else 0
            if role_name not in ROLE_PERMISSIONS:
                self.send_error_json("Unsupported role", 400)
                return
            if data_group_id and not row(conn, "SELECT id FROM data_groups WHERE id = ? AND study_id = ?", (data_group_id, study_id)):
                self.send_error_json("Data access group not found", 404)
                return
            existing = row(conn, "SELECT * FROM study_memberships WHERE study_id = ? AND user_id = ?", (study_id, user_id))
            if existing:
                before = existing
                conn.execute(
                    "UPDATE study_memberships SET role = ?, data_group_id = ?, active = ?, updated_at = ? WHERE id = ?",
                    (role_name, data_group_id, active, timestamp, existing["id"]),
                )
                after = row(conn, "SELECT * FROM study_memberships WHERE id = ?", (existing["id"],))
                audit(conn, user["id"], "update", "membership", existing["id"], before, after)
                self.send_json({"membership": after})
                return
            cur = conn.execute(
                """
                INSERT INTO study_memberships(study_id, user_id, role, data_group_id, active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (study_id, user_id, role_name, data_group_id, active, timestamp, timestamp),
            )
            after = row(conn, "SELECT * FROM study_memberships WHERE id = ?", (cur.lastrowid,))
            audit(conn, user["id"], "create", "membership", cur.lastrowid, None, after)
            self.send_json({"membership": after}, 201)
            return
        self.send_error_json("Unsupported membership operation", 405)

    def metadata(self, conn, study_id: int) -> None:
        study = row(conn, "SELECT * FROM studies WHERE id = ?", (study_id,))
        forms = rows(conn, "SELECT * FROM forms WHERE study_id = ? ORDER BY id", (study_id,))
        mappings = rows(conn, "SELECT form_events.*, study_events.name AS event_name, study_events.code AS event_code FROM form_events JOIN study_events ON study_events.id = form_events.event_id WHERE form_events.study_id = ? AND form_events.required = 1", (study_id,))
        instruments = []
        data_dictionary = []
        for form in forms:
            schema = load_json(form["schema_json"], {"fields": []})
            instruments.append(
                {
                    "instrument_name": form["code"],
                    "instrument_label": form["name"],
                    "version": form["version"],
                    "repeatable": bool(schema.get("repeatable")),
                }
            )
            for order, field in enumerate(schema.get("fields", []), start=1):
                data_dictionary.append(
                    {
                        "instrument_name": form["code"],
                        "field_order": order,
                        "field_name": field["code"],
                        "field_label": field["label"],
                        "field_type": field["type"],
                        "required": bool(field.get("required")),
                        "choices": field.get("options", []),
                        "validation_min": field.get("min", ""),
                        "validation_max": field.get("max", ""),
                        "branching_logic": field.get("show_if", ""),
                        "calculation": field.get("calculation", ""),
                    }
                )
        self.send_json({"project": study, "instruments": instruments, "data_dictionary": data_dictionary})

    def validation_evidence(self, conn, study_id: int) -> None:
        study = row(conn, "SELECT * FROM studies WHERE id = ?", (study_id,))
        counts = {
            "forms": row(conn, "SELECT COUNT(*) AS count FROM forms WHERE study_id = ?", (study_id,))["count"],
            "participants": row(conn, "SELECT COUNT(*) AS count FROM participants WHERE study_id = ?", (study_id,))["count"],
            "entries": row(conn, "SELECT COUNT(*) AS count FROM entries WHERE study_id = ?", (study_id,))["count"],
            "queries_open": row(conn, "SELECT COUNT(*) AS count FROM queries WHERE study_id = ? AND status = 'open'", (study_id,))["count"],
            "survey_links": row(conn, "SELECT COUNT(*) AS count FROM survey_links WHERE study_id = ?", (study_id,))["count"],
            "survey_invitations": row(conn, "SELECT COUNT(*) AS count FROM survey_invitations WHERE study_id = ?", (study_id,))["count"],
            "consent_signatures": row(conn, "SELECT COUNT(*) AS count FROM consent_signatures WHERE study_id = ?", (study_id,))["count"],
            "audit_events": row(conn, "SELECT COUNT(*) AS count FROM audit_log", ())["count"],
        }
        recent_audit = rows(conn, "SELECT audit_log.*, users.display_name FROM audit_log LEFT JOIN users ON users.id = audit_log.user_id ORDER BY audit_log.id DESC LIMIT 50")
        checks = [
            {"name": "first_run_setup", "status": "document", "evidence": "Confirm permanent admin account setup in access review."},
            {"name": "crf_versioning", "status": "available", "evidence": f"{counts['forms']} CRF(s) configured."},
            {"name": "public_surveys", "status": "available" if counts["survey_links"] else "not_used", "evidence": f"{counts['survey_links']} survey link(s)."},
            {"name": "econsent", "status": "available" if counts["consent_signatures"] else "not_used", "evidence": f"{counts['consent_signatures']} consent signature(s)."},
            {"name": "backup_restore", "status": "document", "evidence": "Run backup restore drill and attach result."},
            {"name": "audit_review", "status": "available", "evidence": f"{counts['audit_events']} audit event(s)."},
        ]
        self.send_json({"study": study, "generated_at": now(), "counts": counts, "checks": checks, "recent_audit": recent_audit})

    def quality(self, conn, study_id: int, membership) -> None:
        forms = rows(conn, "SELECT * FROM forms WHERE study_id = ? ORDER BY id", (study_id,))
        mappings = rows(conn, "SELECT form_events.*, study_events.name AS event_name, study_events.code AS event_code FROM form_events JOIN study_events ON study_events.id = form_events.event_id WHERE form_events.study_id = ? AND form_events.required = 1", (study_id,))
        group_filter = ""
        params: tuple = (study_id,)
        if membership.get("data_group_id"):
            group_filter = " AND participants.data_group_id = ?"
            params = (study_id, membership["data_group_id"])
        entries = rows(
            conn,
            f"""
            SELECT entries.*, forms.name AS form_name, forms.schema_json, participants.study_uid
            FROM entries
            JOIN forms ON forms.id = entries.form_id
            JOIN participants ON participants.id = entries.participant_id
            WHERE entries.study_id = ?
            {group_filter}
            ORDER BY participants.study_uid, forms.id
            """,
            params,
        )
        issues = []
        for entry in entries:
            schema = load_json(entry["schema_json"], {"fields": []})
            data = load_json(entry["data_json"], {})
            _, entry_issues = validate_entry_data(schema, data)
            for issue in entry_issues:
                issues.append(
                    {
                        "participant_id": entry["participant_id"],
                        "study_uid": entry["study_uid"],
                        "form_id": entry["form_id"],
                        "form_name": entry["form_name"],
                        "event_name": entry["event_name"],
                        "repeat_instance": entry["repeat_instance"],
                        **issue,
                    }
                )
        if membership.get("data_group_id"):
            participants = rows(conn, "SELECT id, study_uid FROM participants WHERE study_id = ? AND data_group_id = ?", (study_id, membership["data_group_id"]))
        else:
            participants = rows(conn, "SELECT id, study_uid FROM participants WHERE study_id = ?", (study_id,))
        existing_pairs = {(entry["participant_id"], entry["form_id"], entry["event_id"] or entry["event_name"]) for entry in entries}
        for participant in participants:
            expected = mappings or [{"form_id": form["id"], "event_id": None, "event_name": "Baseline", "event_code": "Baseline"} for form in forms]
            for mapping in expected:
                event_key = mapping.get("event_id") or mapping.get("event_code") or mapping.get("event_name") or "Baseline"
                if (participant["id"], mapping["form_id"], event_key) not in existing_pairs:
                    form = next((item for item in forms if item["id"] == mapping["form_id"]), {"name": "CRF"})
                    issues.append(
                        {
                            "participant_id": participant["id"],
                            "study_uid": participant["study_uid"],
                            "form_id": mapping["form_id"],
                            "form_name": form["name"],
                            "event_name": mapping.get("event_name") or "Baseline",
                            "repeat_instance": 1,
                            "field_code": "",
                            "severity": "warning",
                            "message": "Expected baseline CRF has not been started",
                        }
                    )
        self.send_json({"issues": issues})

    def analysis(self, conn, study_id: int, membership) -> None:
        if membership.get("data_group_id"):
            participants = rows(conn, "SELECT * FROM participants WHERE study_id = ? AND data_group_id = ?", (study_id, membership["data_group_id"]))
            entries = rows(conn, "SELECT entries.*, forms.name AS form_name, forms.schema_json FROM entries JOIN forms ON forms.id = entries.form_id JOIN participants ON participants.id = entries.participant_id WHERE entries.study_id = ? AND participants.data_group_id = ?", (study_id, membership["data_group_id"]))
        else:
            participants = rows(conn, "SELECT * FROM participants WHERE study_id = ?", (study_id,))
            entries = rows(conn, "SELECT entries.*, forms.name AS form_name, forms.schema_json FROM entries JOIN forms ON forms.id = entries.form_id WHERE entries.study_id = ?", (study_id,))
        fields: dict[str, dict] = {}
        values: dict[str, list] = {}
        completed = 0
        for entry in entries:
            if entry["status"] == "complete":
                completed += 1
            schema = load_json(entry["schema_json"], {"fields": []})
            data = load_json(entry["data_json"], {})
            for field in schema.get("fields", []):
                code = field.get("code")
                if not code:
                    continue
                scoped_code = f"{entry['form_id']}__{code}"
                label = f"{entry['form_name']}: {field.get('label', code)}"
                fields[scoped_code] = {"label": label, "type": field.get("type", "text")}
                value = data.get(code)
                if value not in (None, ""):
                    values.setdefault(scoped_code, []).append(value)
        summaries = []
        for code, meta in fields.items():
            series = values.get(code, [])
            numeric = []
            for value in series:
                try:
                    numeric.append(float(value))
                except (TypeError, ValueError):
                    pass
            summary = {"code": code, "label": meta["label"], "count": len(series), "missing": max(len(entries) - len(series), 0)}
            if numeric and len(numeric) == len(series):
                summary.update({"type": "numeric", "mean": round(sum(numeric) / len(numeric), 2), "min": min(numeric), "max": max(numeric)})
            else:
                counts: dict[str, int] = {}
                for value in series:
                    counts[str(value)] = counts.get(str(value), 0) + 1
                summary.update({"type": "categorical", "counts": counts})
            summaries.append(summary)
        open_queries = row(conn, "SELECT COUNT(*) AS count FROM queries WHERE study_id = ? AND status = 'open'", (study_id,))["count"]
        self.send_json({"participant_count": len(participants), "entry_count": len(entries), "completed_entry_count": completed, "open_query_count": open_queries, "field_summaries": summaries})

    def assist_summary(self, conn, study_id: int, membership) -> None:
        group_join = ""
        group_where = ""
        params: list = [study_id]
        if membership.get("data_group_id"):
            group_join = "JOIN participants ON participants.id = entries.participant_id"
            group_where = " AND participants.data_group_id = ?"
            params.append(membership["data_group_id"])
        participant_sql = "SELECT COUNT(*) AS count FROM participants WHERE study_id = ?"
        participant_params: tuple = (study_id,)
        if membership.get("data_group_id"):
            participant_sql += " AND data_group_id = ?"
            participant_params = (study_id, membership["data_group_id"])
        participant_count = row(conn, participant_sql, participant_params)["count"]
        entry_count = row(conn, f"SELECT COUNT(*) AS count FROM entries {group_join} WHERE entries.study_id = ?{group_where}", tuple(params))["count"]
        complete_count = row(conn, f"SELECT COUNT(*) AS count FROM entries {group_join} WHERE entries.study_id = ? AND entries.status = 'complete'{group_where}", tuple(params))["count"]
        open_queries = row(conn, "SELECT COUNT(*) AS count FROM queries WHERE study_id = ? AND status = 'open'", (study_id,))["count"]
        issue_count = 0
        quality_rows = rows(
            conn,
            f"""
            SELECT entries.data_json, forms.schema_json
            FROM entries
            JOIN forms ON forms.id = entries.form_id
            {group_join}
            WHERE entries.study_id = ?{group_where}
            """,
            tuple(params),
        )
        for entry in quality_rows:
            _, issues = validate_entry_data(load_json(entry["schema_json"], {"fields": []}), load_json(entry["data_json"], {}))
            issue_count += len(issues)
        warnings = []
        if open_queries:
            warnings.append(f"{open_queries} open review querie(s) should be resolved or documented before analysis export.")
        if issue_count:
            warnings.append(f"{issue_count} quality issue(s) are currently visible.")
        if entry_count and complete_count < entry_count:
            warnings.append(f"{entry_count - complete_count} CRF entrie(s) are still draft.")
        if not participant_count:
            warnings.append("No participants are enrolled yet.")
        if not warnings:
            warnings.append("No immediate query, completion, or edit-check blockers were detected.")
        self.send_json(
            {
                "summary": {
                    "participant_count": participant_count,
                    "entry_count": entry_count,
                    "completed_entry_count": complete_count,
                    "open_query_count": open_queries,
                    "quality_issue_count": issue_count,
                    "warnings": warnings,
                    "next_steps": [
                        "Review open queries and field verification states.",
                        "Export the codebook with every analysis dataset.",
                        "Create a local backup before major CRF edits or data imports.",
                    ],
                }
            }
        )

    def export_csv(self, conn, study_id: int, membership) -> None:
        return self.export_entries_csv(conn, study_id, membership, {}, "clinical_data_export.csv")

    def export_entries_csv(self, conn, study_id: int, membership, filters: dict, filename: str) -> None:
        forms = rows(conn, "SELECT * FROM forms WHERE study_id = ? ORDER BY id", (study_id,))
        field_codes = []
        labels = {}
        for form in forms:
            for field in load_json(form["schema_json"], {"fields": []}).get("fields", []):
                code = f"{form['code']}__{field.get('code')}"
                field_codes.append(code)
                labels[code] = field.get("label", code)
        output = []
        header = ["study_uid", "initials", "participant_status", "event_name", "event_code", "repeat_instance", "form_name", "entry_status", "locked"] + field_codes
        output.append(header)
        where = ["entries.study_id = ?"]
        params: list = [study_id]
        if filters.get("participant_status"):
            where.append("participants.status = ?")
            params.append(filters["participant_status"])
        if filters.get("entry_status"):
            where.append("entries.status = ?")
            params.append(filters["entry_status"])
        if filters.get("event_id"):
            where.append("entries.event_id = ?")
            params.append(int(filters["event_id"]))
        if filters.get("form_id"):
            where.append("entries.form_id = ?")
            params.append(int(filters["form_id"]))
        if membership.get("data_group_id"):
            where.append("participants.data_group_id = ?")
            params.append(membership["data_group_id"])
        sql = f"""
            SELECT entries.*, participants.study_uid, participants.initials, participants.status AS participant_status,
                   forms.name AS form_name, forms.code AS form_code,
                   study_events.name AS mapped_event_name, study_events.code AS event_code
            FROM entries
            JOIN participants ON participants.id = entries.participant_id
            JOIN forms ON forms.id = entries.form_id
            LEFT JOIN study_events ON study_events.id = entries.event_id
            WHERE {" AND ".join(where)}
            ORDER BY participants.study_uid, study_events.display_order, forms.id
        """
        entries = rows(conn, sql, tuple(params))
        for entry in entries:
            data = load_json(entry["data_json"], {})
            line = [entry["study_uid"], entry["initials"], entry["participant_status"], entry.get("mapped_event_name") or entry["event_name"], entry.get("event_code") or entry["event_name"], entry["repeat_instance"], entry["form_name"], entry["status"], "yes" if entry["locked_at"] else "no"]
            for code in field_codes:
                prefix, field_code = code.split("__", 1)
                line.append(data.get(field_code, "") if prefix == entry["form_code"] else "")
            output.append(line)
        text_lines = []
        class Sink:
            def write(self, value):
                text_lines.append(value)
        writer = csv.writer(Sink())
        writer.writerows(output)
        content = "".join(text_lines).encode("utf-8-sig")
        self.send_response(200)
        self.send_header("content-type", "text/csv; charset=utf-8")
        self.send_header("content-disposition", f"attachment; filename={filename}")
        self.send_header("content-length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def reports(self, conn, user, method, study_id, parts, membership) -> None:
        if method == "GET" and len(parts) == 4:
            data = rows(conn, "SELECT reports.*, users.display_name AS created_by_name FROM reports LEFT JOIN users ON users.id = reports.created_by WHERE reports.study_id = ? ORDER BY reports.updated_at DESC", (study_id,))
            for report in data:
                report["filters"] = load_json(report.pop("filters_json"), {})
            self.send_json({"reports": data})
            return
        if method == "POST" and len(parts) == 4:
            if not membership_has(membership, "export_data"):
                self.send_error_json("Export permission required", 403)
                return
            payload = self.body()
            timestamp = now()
            filters = payload.get("filters") or {}
            cur = conn.execute(
                "INSERT INTO reports(study_id, name, description, filters_json, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (study_id, str(payload.get("name", "")).strip() or "Untitled Report", str(payload.get("description", "")).strip(), json.dumps(filters), user["id"], timestamp, timestamp),
            )
            after = row(conn, "SELECT * FROM reports WHERE id = ?", (cur.lastrowid,))
            audit(conn, user["id"], "create", "report", cur.lastrowid, None, after)
            self.send_json({"report": after}, 201)
            return
        if method == "GET" and len(parts) == 6 and parts[5] == "export":
            if not membership_has(membership, "export_data"):
                self.send_error_json("Export permission required", 403)
                return
            report_id = int(parts[4])
            report = row(conn, "SELECT * FROM reports WHERE id = ? AND study_id = ?", (report_id, study_id))
            if not report:
                self.send_error_json("Report not found", 404)
                return
            filename = f"clinical_report_{normalize_code(report['name'], 'report')}.csv"
            return self.export_entries_csv(conn, study_id, membership, load_json(report["filters_json"], {}), filename)
        self.send_error_json("Unsupported reports operation", 405)

    def backups(self, conn, user, method, study_id, parts) -> None:
        BACKUPS.mkdir(parents=True, exist_ok=True)
        if method == "GET" and len(parts) == 4:
            files = []
            for item in sorted(BACKUPS.iterdir(), key=lambda path: path.stat().st_mtime, reverse=True):
                if item.is_file() and item.name.startswith(f"study_{study_id}_") and item.suffix in (".sqlite3", ".cdsenc"):
                    files.append({"name": item.name, "size": item.stat().st_size, "created_at": int(item.stat().st_mtime), "encrypted": item.suffix == ".cdsenc"})
            self.send_json({"backups": files})
            return
        if method == "POST" and len(parts) == 4:
            payload = self.body()
            timestamp = time.strftime("%Y%m%d_%H%M%S", time.localtime())
            conn.commit()
            passphrase = str(payload.get("passphrase", ""))
            if passphrase:
                target = BACKUPS / f"study_{study_id}_{timestamp}.cdsenc"
                with tempfile.NamedTemporaryFile(delete=False, dir=BACKUPS, suffix=".sqlite3") as temporary:
                    plain_target = Path(temporary.name)
                try:
                    write_sqlite_backup(conn, plain_target)
                    target.write_bytes(encrypted_archive_bytes(plain_target.read_bytes(), passphrase))
                finally:
                    if plain_target.exists():
                        plain_target.unlink()
                audit(conn, user["id"], "create_encrypted", "backup", study_id, None, {"filename": target.name})
                self.send_json({"backup": {"name": target.name, "size": target.stat().st_size, "created_at": int(target.stat().st_mtime), "encrypted": True}}, 201)
                return
            target = BACKUPS / f"study_{study_id}_{timestamp}.sqlite3"
            write_sqlite_backup(conn, target)
            audit(conn, user["id"], "create", "backup", study_id, None, {"filename": target.name})
            self.send_json({"backup": {"name": target.name, "size": target.stat().st_size, "created_at": int(target.stat().st_mtime), "encrypted": False}}, 201)
            return
        if method == "GET" and len(parts) == 5:
            filename = Path(parts[4]).name
            if not filename.startswith(f"study_{study_id}_") or not (filename.endswith(".sqlite3") or filename.endswith(".cdsenc")):
                self.send_error_json("Backup not found", 404)
                return
            target = (BACKUPS / filename).resolve()
            if not str(target).startswith(str(BACKUPS.resolve())) or not target.exists():
                self.send_error_json("Backup not found", 404)
                return
            content = target.read_bytes()
            self.send_response(200)
            self.send_header("content-type", "application/octet-stream")
            self.send_header("content-disposition", f"attachment; filename={target.name}")
            self.send_header("content-length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return
        if method == "POST" and len(parts) == 6 and parts[5] == "restore":
            payload = self.body()
            filename = Path(parts[4]).name
            if not filename.startswith(f"study_{study_id}_") or not (filename.endswith(".sqlite3") or filename.endswith(".cdsenc")):
                self.send_error_json("Backup not found", 404)
                return
            target = (BACKUPS / filename).resolve()
            if not str(target).startswith(str(BACKUPS.resolve())) or not target.exists():
                self.send_error_json("Backup not found", 404)
                return
            restore_target = target
            cleanup_target = None
            if filename.endswith(".cdsenc"):
                passphrase = str(payload.get("passphrase", ""))
                if not passphrase:
                    self.send_error_json("Encrypted backup passphrase is required", 400)
                    return
                with tempfile.NamedTemporaryFile(delete=False, dir=BACKUPS, suffix=".sqlite3") as temporary:
                    temporary.write(decrypted_archive_bytes(target.read_bytes(), passphrase))
                    cleanup_target = Path(temporary.name)
                    restore_target = cleanup_target
            try:
                source = sqlite3.connect(restore_target)
                try:
                    source.backup(conn)
                finally:
                    source.close()
            finally:
                if cleanup_target and cleanup_target.exists():
                    cleanup_target.unlink()
            audit(conn, user["id"], "restore", "backup", study_id, None, {"filename": filename})
            self.send_json({"restored": filename})
            return
        self.send_error_json("Unsupported backup operation", 405)

    def export_codebook(self, conn, study_id: int) -> None:
        forms = rows(conn, "SELECT * FROM forms WHERE study_id = ? ORDER BY id", (study_id,))
        form_event_rows = rows(conn, "SELECT form_events.form_id, study_events.code AS event_code FROM form_events JOIN study_events ON study_events.id = form_events.event_id WHERE form_events.study_id = ? ORDER BY study_events.display_order", (study_id,))
        events_by_form: dict[int, list[str]] = {}
        for item in form_event_rows:
            events_by_form.setdefault(item["form_id"], []).append(item["event_code"])
        output = [["instrument_name", "instrument_label", "events", "field_order", "field_name", "field_label", "field_type", "required", "choices", "validation_min", "validation_max", "branching_logic", "calculation", "repeatable"]]
        for form in forms:
            schema = load_json(form["schema_json"], {"fields": []})
            for order, field in enumerate(schema.get("fields", []), start=1):
                choices = " | ".join(field.get("options", []))
                branching = ""
                if field.get("show_if"):
                    branching = f"[{field['show_if']['field']}] = '{field['show_if']['equals']}'"
                output.append(
                    [
                        form["code"],
                        form["name"],
                        " | ".join(events_by_form.get(form["id"], [])),
                        order,
                        field["code"],
                        field["label"],
                        field["type"],
                        "yes" if field.get("required") else "no",
                        choices,
                        field.get("min", ""),
                        field.get("max", ""),
                        branching,
                        field.get("calculation", ""),
                        "yes" if schema.get("repeatable") else "no",
                    ]
                )
        text_lines = []

        class Sink:
            def write(self, value):
                text_lines.append(value)

        writer = csv.writer(Sink())
        writer.writerows(output)
        content = "".join(text_lines).encode("utf-8-sig")
        self.send_response(200)
        self.send_header("content-type", "text/csv; charset=utf-8")
        self.send_header("content-disposition", "attachment; filename=clinical_data_codebook.csv")
        self.send_header("content-length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def main() -> None:
    migrate()
    server = ThreadingHTTPServer((HOST, PORT), App)
    print(f"Clinical Data Studio running at http://127.0.0.1:{PORT}")
    print("Use this computer's Wi-Fi IP address from phones on the same network.")
    server.serve_forever()


if __name__ == "__main__":
    main()
