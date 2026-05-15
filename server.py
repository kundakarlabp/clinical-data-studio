from __future__ import annotations

import ast
import base64
from contextlib import closing
import csv
import hashlib
import hmac
import json
import logging
import mimetypes
import os
import platform
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import ctypes
import zipfile
from io import BytesIO, StringIO
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request as UrlRequest, urlopen as urlopen_request
from xml.etree import ElementTree

from ai.safety import ai_status_payload, assert_external_ai_safe as assert_ai_text_safe, deidentify_for_ai as deidentify_text_for_ai, phi_findings as detect_phi_findings
from config import load_settings
from storage import connect_database, migrate_postgres

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
SETTINGS = load_settings()
DATA = SETTINGS.data_dir
BACKUPS = SETTINGS.backup_dir
UPLOADS = SETTINGS.upload_dir
DB_PATH = SETTINGS.sqlite_path
DATABASE_BACKEND = SETTINGS.database_backend
DATABASE_URL = SETTINGS.database_url
HOST = SETTINGS.host
PORT = SETTINGS.port
PBKDF2_ROUNDS = 260_000
SESSION_TTL_SECONDS = 60 * 60 * 24 * 14
MIN_PRODUCTION_SECRET_LENGTH = 32
SESSION_COOKIE_NAME = "cds_session"
CSRF_HEADER_NAME = "X-CSRF-Token"
DEFAULT_OPENAI_MODEL = "gpt-5.2"
DEFAULT_TRANSCRIBE_MODEL = "gpt-4o-transcribe"
CALC_OPERATORS = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.Div: lambda a, b: a / b,
    ast.USub: lambda a: -a,
    ast.UAdd: lambda a: a,
}
FILE_ATTRIBUTE_ENCRYPTED = 0x4000

ROLE_PERMISSIONS = {
    "super_admin": {
        "system_admin",
        "manage_users",
        "manage_study",
        "manage_forms",
        "enter_data",
        "review_data",
        "export_data",
        "view_analysis",
    },
    "admin": {
        "system_admin",
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
    "project_admin": {
        "manage_users",
        "manage_study",
        "manage_forms",
        "enter_data",
        "review_data",
        "export_data",
        "view_analysis",
    },
    "pi": {
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
    "viewer": {"view_analysis"},
    "read_only": {"view_analysis"},
}
SUPERUSER_ROLES = {"admin", "super_admin"}
PROJECT_ADMIN_ROLES = {"owner", "project_admin", "pi"}
PASSWORD_MIN_LENGTH = 10
PRODUCTION_ADMIN_PASSWORD_MIN_LENGTH = 12
API_TOKEN_SCOPES = {
    "metadata:read",
    "records:read",
    "records:write",
    "export:read",
    "randomization:write",
    "ai:use",
}
DEFAULT_API_TOKEN_SCOPES = sorted(API_TOKEN_SCOPES)
SETTINGS.log_dir.mkdir(parents=True, exist_ok=True)
LOG_FILE = SETTINGS.log_dir / "clinical-data-studio.log"
logging.basicConfig(
    level=getattr(logging, SETTINGS.log_level, logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler()],
)
LOGGER = logging.getLogger("clinical-data-studio")


def now() -> int:
    return int(time.time())


def db() -> sqlite3.Connection:
    DATA.mkdir(parents=True, exist_ok=True)
    BACKUPS.mkdir(parents=True, exist_ok=True)
    UPLOADS.mkdir(parents=True, exist_ok=True)
    return connect_database(DATABASE_BACKEND, DB_PATH, DATABASE_URL)


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


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def session_token_digest(token: str) -> str:
    secret = SETTINGS.secret_key or "clinical-data-studio-development-session-key"
    return hmac.new(secret.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()


def csrf_token(session_digest: str, timestamp: int | None = None) -> str:
    issued_at = timestamp or now()
    secret = SETTINGS.secret_key or "clinical-data-studio-development-session-key"
    signature = hmac.new(secret.encode("utf-8"), f"{session_digest}:{issued_at}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{issued_at}.{signature}"


def verify_csrf_token(session_digest: str, token: str) -> bool:
    try:
        issued_raw, signature = token.split(".", 1)
        issued_at = int(issued_raw)
    except Exception:
        return False
    if issued_at <= 0 or now() - issued_at > SESSION_TTL_SECONDS:
        return False
    return hmac.compare_digest(csrf_token(session_digest, issued_at), token)


def prune_expired_sessions(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now(),))


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


def path_encrypted(path: Path) -> bool:
    if os.name != "nt":
        return False
    target = str(path.resolve())
    attributes = ctypes.windll.kernel32.GetFileAttributesW(target)
    if attributes == -1:
        return False
    return bool(attributes & FILE_ATTRIBUTE_ENCRYPTED)


def data_protection_status() -> dict:
    DATA.mkdir(exist_ok=True)
    return {
        "platform": os.name,
        "data_path": str(DATA),
        "database_path": str(DB_PATH),
        "efs_supported": os.name == "nt",
        "data_folder_encrypted": path_encrypted(DATA),
        "database_file_encrypted": path_encrypted(DB_PATH) if DB_PATH.exists() else False,
        "archive_encryption_available": True,
        "note": "Windows EFS protects the local data folder at rest for the current Windows account. Encrypted archive export protects backup copies.",
    }


def ai_status() -> dict:
    return ai_status_payload(SETTINGS, os.environ, DEFAULT_OPENAI_MODEL, DEFAULT_TRANSCRIBE_MODEL)


def is_super_admin(user: dict | None) -> bool:
    return bool(user and user.get("role") in SUPERUSER_ROLES)


def safe_role(role: str) -> str:
    return (role or "").strip().lower()


def parse_token_scopes(value: str | None) -> set[str]:
    scopes = set(load_json(value, []))
    return {scope for scope in scopes if scope in API_TOKEN_SCOPES}


def token_has_scope(token_row: dict, scope: str) -> bool:
    return scope in parse_token_scopes(token_row.get("scopes_json"))


def phi_findings(text: str) -> list[str]:
    return detect_phi_findings(text)


def deidentify_for_ai(text: str, replacement: str = "Study participant") -> str:
    return deidentify_text_for_ai(text, replacement)


def assert_external_ai_safe(text: str) -> None:
    assert_ai_text_safe(text, ai_status())


def git_commit() -> str:
    configured = os.environ.get("CDS_COMMIT", "").strip()
    if configured:
        return configured
    try:
        result = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True, timeout=5, check=True)
        return result.stdout.strip()
    except Exception:
        return "unknown"


def database_status() -> dict:
    try:
        with closing(db()) as conn:
            user_count = row(conn, "SELECT COUNT(*) AS count FROM users")
            return {"ok": True, "backend": DATABASE_BACKEND, "user_count": user_count["count"] if user_count else 0}
    except Exception as exc:
        return {"ok": False, "backend": DATABASE_BACKEND, "error": str(exc)}


def latest_backup_time() -> int | None:
    if not BACKUPS.exists():
        return None
    files = [item for item in BACKUPS.iterdir() if item.is_file()]
    if not files:
        return None
    return int(max(item.stat().st_mtime for item in files))


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def backup_file_info(path: Path, backup_type: str | None = None) -> dict:
    info = {
        "name": path.name,
        "size": path.stat().st_size,
        "created_at": int(path.stat().st_mtime),
        "encrypted": path.suffix == ".cdsenc",
    }
    if backup_type:
        info["backup_type"] = backup_type
    return info


def latest_matching_backup(predicate) -> dict | None:
    if not BACKUPS.exists():
        return None
    matches = [item for item in BACKUPS.iterdir() if item.is_file() and predicate(item)]
    if not matches:
        return None
    target = max(matches, key=lambda item: item.stat().st_mtime)
    if ".full." in target.name or target.name.startswith("full_"):
        return latest_full_backup_info(target)
    backup_type = "postgres" if target.name.startswith("postgres_") or target.name.endswith(".dump") else "database"
    return backup_file_info(target, backup_type)


def backup_name(prefix: str = "system") -> str:
    return f"{prefix}_{time.strftime('%Y%m%d_%H%M%S', time.localtime())}"


def create_database_backup(passphrase: str = "", study_id: int | None = None) -> dict:
    BACKUPS.mkdir(parents=True, exist_ok=True)
    prefix = f"study_{study_id}" if study_id else "system"
    stem = backup_name(prefix)
    if DATABASE_BACKEND == "postgres":
        dump_target = BACKUPS / f"{stem}.dump"
        command = ["pg_dump", "--format=custom", "--file", str(dump_target), DATABASE_URL]
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=300)
        if passphrase:
            encrypted = BACKUPS / f"{stem}.cdsenc"
            encrypted.write_bytes(encrypted_archive_bytes(dump_target.read_bytes(), passphrase))
            dump_target.unlink(missing_ok=True)
            target = encrypted
        else:
            target = dump_target
        return {"name": target.name, "size": target.stat().st_size, "created_at": int(target.stat().st_mtime), "encrypted": target.suffix == ".cdsenc", "backend": "postgres"}
    with closing(db()) as conn:
        plain_target = BACKUPS / f"{stem}.sqlite3"
        write_sqlite_backup(conn, plain_target)
    if passphrase:
        encrypted = BACKUPS / f"{stem}.cdsenc"
        encrypted.write_bytes(encrypted_archive_bytes(plain_target.read_bytes(), passphrase))
        plain_target.unlink(missing_ok=True)
        target = encrypted
    else:
        target = plain_target
    return {"name": target.name, "size": target.stat().st_size, "created_at": int(target.stat().st_mtime), "encrypted": target.suffix == ".cdsenc", "backend": "sqlite"}


def write_uploads_archive(target: Path) -> int:
    target.parent.mkdir(parents=True, exist_ok=True)
    upload_count = 0
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        if UPLOADS.exists():
            for item in sorted(UPLOADS.rglob("*")):
                if item.is_file():
                    archive.write(item, item.relative_to(UPLOADS).as_posix())
                    upload_count += 1
        if upload_count == 0:
            archive.writestr("EMPTY_UPLOADS.txt", "No upload files were present when this backup was created.\n")
    return upload_count


def write_database_dump(target: Path) -> str:
    target.parent.mkdir(parents=True, exist_ok=True)
    if DATABASE_BACKEND == "postgres":
        subprocess.run(["pg_dump", "--format=custom", "--file", str(target), DATABASE_URL], check=True, capture_output=True, text=True, timeout=300)
        return "postgres.dump"
    with closing(db()) as conn:
        write_sqlite_backup(conn, target)
    return "sqlite.sqlite3"


def create_full_backup(passphrase: str = "") -> dict:
    passphrase = passphrase or SETTINGS.backup_passphrase
    if not passphrase:
        raise ValueError("Full backup passphrase is required")
    BACKUPS.mkdir(parents=True, exist_ok=True)
    UPLOADS.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S", time.localtime())
    target = BACKUPS / f"full_{timestamp}.full.cdsenc"
    with tempfile.TemporaryDirectory(dir=BACKUPS) as tmp_name:
        tmp = Path(tmp_name)
        db_name = "postgres.dump" if DATABASE_BACKEND == "postgres" else "sqlite.sqlite3"
        db_path = tmp / db_name
        db_name = write_database_dump(db_path)
        uploads_path = tmp / "uploads.zip"
        upload_count = write_uploads_archive(uploads_path)
        manifest = {
            "backup_type": "full",
            "created_at": int(time.time()),
            "created_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "app": "Clinical Data Studio",
            "version": os.environ.get("CDS_VERSION", "0.1"),
            "git_commit": git_commit(),
            "database_backend": DATABASE_BACKEND,
            "database_dump": db_name,
            "uploads_archive": uploads_path.name,
            "upload_file_count": upload_count,
            "encryption": {
                "format": "CDSENC1",
                "kdf": "pbkdf2_hmac_sha256",
                "passphrase_stored": False,
            },
        }
        manifest_path = tmp / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
        checksum_targets = [db_path, uploads_path, manifest_path]
        sums_path = tmp / "SHA256SUMS.txt"
        sums_path.write_text("".join(f"{file_sha256(item)}  {item.name}\n" for item in checksum_targets), encoding="utf-8")
        payload_path = tmp / "full_backup_payload.zip"
        with zipfile.ZipFile(payload_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for item in [db_path, uploads_path, manifest_path, sums_path]:
                archive.write(item, item.name)
        target.write_bytes(encrypted_archive_bytes(payload_path.read_bytes(), passphrase))
    info = backup_file_info(target, "full")
    info.update({"backend": DATABASE_BACKEND, "uploads_included": True, "verified": False})
    return info


def verification_sidecar_path(backup_path: Path) -> Path:
    return backup_path.with_name(f"{backup_path.name}.verify.json")


def full_backup_candidates() -> list[Path]:
    if not BACKUPS.exists():
        return []
    return sorted(
        [item for item in BACKUPS.iterdir() if item.is_file() and not item.name.endswith(".verify.json") and (item.name.startswith("full_") or ".full." in item.name)],
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )


def latest_full_backup_info(path: Path | None = None) -> dict | None:
    target = path or (full_backup_candidates()[0] if full_backup_candidates() else None)
    if not target:
        return None
    info = backup_file_info(target, "full")
    info["uploads_included"] = True
    sidecar = verification_sidecar_path(target)
    if sidecar.exists():
        try:
            verification = json.loads(sidecar.read_text(encoding="utf-8"))
            info["verification"] = verification
            info["verified"] = bool(verification.get("ok"))
            info["verified_at"] = verification.get("checked_at")
        except Exception:
            info["verified"] = False
    else:
        info["verified"] = False
    return info


def latest_postgres_backup_info() -> dict | None:
    return latest_matching_backup(lambda item: item.name.startswith("postgres_") or item.name.endswith(".dump"))


def verify_full_backup(backup_file: Path, passphrase: str = "", record: bool = False) -> dict:
    passphrase = passphrase or SETTINGS.backup_passphrase
    if not passphrase:
        raise ValueError("Full backup passphrase is required for verification")
    target = backup_file.resolve()
    backup_root = BACKUPS.resolve()
    if not str(target).startswith(str(backup_root)) or not target.exists() or not target.is_file():
        raise ValueError("Full backup file not found inside configured backup directory")
    archive_bytes = decrypted_archive_bytes(target.read_bytes(), passphrase) if target.suffix == ".cdsenc" else target.read_bytes()
    result = {
        "ok": False,
        "name": target.name,
        "checked_at": int(time.time()),
        "contents": [],
        "database_dump": "",
        "uploads_archive": "",
        "upload_file_count": 0,
        "errors": [],
    }
    try:
        with zipfile.ZipFile(BytesIO(archive_bytes), "r") as archive:
            names = archive.namelist()
            result["contents"] = names
            required = {"manifest.json", "SHA256SUMS.txt", "uploads.zip"}
            missing = sorted(required - set(names))
            if missing:
                result["errors"].append(f"Missing required file(s): {', '.join(missing)}")
            manifest = json.loads(archive.read("manifest.json").decode("utf-8")) if "manifest.json" in names else {}
            result["manifest"] = manifest
            result["database_dump"] = str(manifest.get("database_dump") or "")
            result["uploads_archive"] = str(manifest.get("uploads_archive") or "")
            if result["database_dump"] not in names:
                result["errors"].append("Database dump is missing")
            if result["uploads_archive"] not in names:
                result["errors"].append("Uploads archive is missing")
            if manifest.get("backup_type") != "full":
                result["errors"].append("Manifest backup_type is not full")
            if "SHA256SUMS.txt" in names:
                checksum_lines = archive.read("SHA256SUMS.txt").decode("utf-8").splitlines()
                for line in checksum_lines:
                    if not line.strip():
                        continue
                    expected, filename = line.split(None, 1)
                    filename = filename.strip()
                    if filename not in names:
                        result["errors"].append(f"Checksum target missing: {filename}")
                        continue
                    actual = sha256_bytes(archive.read(filename))
                    if actual != expected:
                        result["errors"].append(f"Checksum mismatch: {filename}")
            if result["uploads_archive"] in names:
                with zipfile.ZipFile(BytesIO(archive.read(result["uploads_archive"])), "r") as uploads:
                    result["upload_file_count"] = len([name for name in uploads.namelist() if not name.endswith("/") and name != "EMPTY_UPLOADS.txt"])
        result["ok"] = not result["errors"]
    except Exception as exc:
        result["errors"].append(str(exc))
        result["ok"] = False
    if record:
        verification_sidecar_path(target).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    return result


def restore_database_backup(backup_file: Path, passphrase: str = "") -> dict:
    target = backup_file.resolve()
    backup_root = BACKUPS.resolve()
    if not str(target).startswith(str(backup_root)) or not target.exists() or not target.is_file():
        raise ValueError("Backup file not found inside configured backup directory")
    cleanup_target = None
    restore_target = target
    if target.suffix == ".cdsenc":
        if not passphrase:
            raise ValueError("Encrypted backup passphrase is required")
        with tempfile.NamedTemporaryFile(delete=False, dir=BACKUPS, suffix=".dump" if DATABASE_BACKEND == "postgres" else ".sqlite3") as temporary:
            temporary.write(decrypted_archive_bytes(target.read_bytes(), passphrase))
            cleanup_target = Path(temporary.name)
            restore_target = cleanup_target
    try:
        if DATABASE_BACKEND == "postgres":
            subprocess.run(["pg_restore", "--clean", "--if-exists", "--no-owner", "--dbname", DATABASE_URL, str(restore_target)], check=True, capture_output=True, text=True, timeout=300)
        else:
            source = sqlite3.connect(restore_target)
            try:
                with closing(db()) as conn:
                    source.backup(conn)
            finally:
                source.close()
    finally:
        if cleanup_target:
            cleanup_target.unlink(missing_ok=True)
    return {"restored": target.name, "backend": DATABASE_BACKEND}


def health_payload() -> dict:
    db_status = database_status()
    latest_full = latest_full_backup_info()
    return {
        "ok": db_status["ok"],
        "app": "Clinical Data Studio",
        "version": os.environ.get("CDS_VERSION", "0.1"),
        "commit": git_commit(),
        "environment": SETTINGS.env,
        "database": db_status,
        "database_backend": DATABASE_BACKEND,
        "migration_status": "ok" if db_status["ok"] else "error",
        "public_base_url": SETTINGS.public_base_url,
        "host": HOST,
        "port": PORT,
        "require_https": SETTINGS.require_https,
        "https_detected": SETTINGS.public_base_url.startswith("https://"),
        "data_protection": data_protection_status(),
        "ai": ai_status(),
        "backup": {
            "directory": str(BACKUPS),
            "latest_backup_at": latest_backup_time(),
            "latest_postgres_backup": latest_postgres_backup_info(),
            "latest_full_backup": latest_full,
            "latest_full_backup_verified": bool(latest_full and latest_full.get("verified")),
            "uploads": {
                "directory": str(UPLOADS),
                "exists": UPLOADS.exists(),
                "file_count": sum(1 for item in UPLOADS.rglob("*") if item.is_file()) if UPLOADS.exists() else 0,
            },
        },
    }


def backup_files_for_study(study_id: int) -> list[dict]:
    BACKUPS.mkdir(parents=True, exist_ok=True)
    files = []
    for item in sorted(BACKUPS.iterdir(), key=lambda path: path.stat().st_mtime, reverse=True):
        if item.is_file() and item.name.startswith(f"study_{study_id}_") and item.suffix in (".sqlite3", ".cdsenc", ".dump"):
            files.append(backup_file_info(item, "database"))
    return files


def allowed_evidence_content_type(content_type: str, filename: str) -> bool:
    suffix = Path(filename).suffix.lower()
    return (
        content_type.startswith("image/")
        or content_type.startswith("audio/")
        or content_type in {"application/pdf", "text/plain", "text/csv", "application/csv"}
        or suffix in {".pdf", ".txt", ".csv"}
    )


def case_upload_dir(study_id: int, case_id: int) -> Path:
    target = UPLOADS / "studies" / str(study_id) / "cases" / str(case_id)
    target.mkdir(parents=True, exist_ok=True)
    return target


def stored_case_file_path(study_id: int, case_id: int, stored_filename: str) -> Path:
    target = (UPLOADS / "studies" / str(study_id) / "cases" / str(case_id) / stored_filename).resolve()
    root = (UPLOADS / "studies" / str(study_id) / "cases" / str(case_id)).resolve()
    if not str(target).startswith(str(root)) or not target.exists():
        raise FileNotFoundError("Case evidence file not found on disk")
    return target


def case_file_content(file_row: dict) -> bytes:
    if file_row.get("data_base64"):
        return base64.b64decode(file_row["data_base64"], validate=True)
    stored_filename = file_row.get("stored_filename", "")
    if not stored_filename:
        raise FileNotFoundError("Case evidence file is missing stored filename")
    return stored_case_file_path(file_row["study_id"], file_row["case_id"], stored_filename).read_bytes()


def stored_case_filename(original_name: str) -> str:
    suffix = Path(original_name).suffix.lower()
    if suffix and not re.match(r"^\.[a-z0-9]{1,12}$", suffix):
        suffix = ""
    return f"{now()}_{secrets.token_hex(12)}{suffix}"


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


def postgres_column_definition(definition: str) -> str:
    cleaned = definition.replace("INTEGER", "BIGINT").replace("REFERENCES", "REFERENCES")
    cleaned = re.sub(r"\s+ON\s+DELETE\s+SET\s+NULL", "", cleaned, flags=re.IGNORECASE)
    return cleaned


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    if getattr(conn, "backend", "sqlite") == "postgres":
        return conn.table_columns(table)
    return {dict(row)["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def add_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    if getattr(conn, "backend", "sqlite") == "postgres":
        conn.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {postgres_column_definition(definition)}")
    elif column not in table_columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def migrate_entries_unique_key(conn: sqlite3.Connection) -> None:
    if getattr(conn, "backend", "sqlite") == "postgres":
        return
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
        INSERT INTO entries(
            id, study_id, participant_id, form_id, event_id, event_name, repeat_instance, status,
            data_json, form_version, schema_snapshot_json, entry_hash, created_by, updated_by, locked_at, locked_by, lock_reason, created_at, updated_at
        )
        SELECT
            id, study_id, participant_id, form_id, event_id, event_name,
            COALESCE(repeat_instance, 1), status, data_json, COALESCE(form_version, 1), COALESCE(schema_snapshot_json, '{}'), COALESCE(entry_hash, ''), created_by, updated_by,
            locked_at, locked_by, COALESCE(lock_reason, ''), created_at, updated_at
        FROM entries_old;
        DROP TABLE entries_old;
        """
    )


def audit(
    conn: sqlite3.Connection,
    user_id: int | None,
    action: str,
    entity_type: str,
    entity_id: int | None,
    before=None,
    after=None,
    study_id: int | None = None,
    ip_address: str = "",
    user_agent: str = "",
    request_id: str = "",
) -> None:
    conn.execute(
        """
        INSERT INTO audit_log(user_id, action, entity_type, entity_id, before_json, after_json, created_at, study_id, ip_address, user_agent, request_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            action,
            entity_type,
            entity_id,
            json.dumps(before, sort_keys=True) if before is not None else None,
            json.dumps(after, sort_keys=True) if after is not None else None,
            now(),
            study_id,
            ip_address[:120],
            user_agent[:240],
            request_id[:80],
        ),
    )


STUDY_AUDIT_FILTER = """
(
    audit_log.study_id = ?
    OR
    (audit_log.entity_type = 'study' AND audit_log.entity_id = ?)
    OR (audit_log.entity_type IN ('backup', 'dictionary', 'records') AND audit_log.entity_id = ?)
    OR (audit_log.entity_type = 'participant' AND audit_log.entity_id IN (SELECT id FROM participants WHERE study_id = ?))
    OR (audit_log.entity_type IN ('entry', 'field_state', 'consent') AND audit_log.entity_id IN (SELECT id FROM entries WHERE study_id = ?))
    OR (audit_log.entity_type = 'form' AND audit_log.entity_id IN (SELECT id FROM forms WHERE study_id = ?))
    OR (audit_log.entity_type = 'event' AND audit_log.entity_id IN (SELECT id FROM study_events WHERE study_id = ?))
    OR (audit_log.entity_type = 'form_event' AND audit_log.entity_id IN (SELECT id FROM form_events WHERE study_id = ?))
    OR (audit_log.entity_type = 'query' AND audit_log.entity_id IN (SELECT id FROM queries WHERE study_id = ?))
    OR (audit_log.entity_type = 'data_group' AND audit_log.entity_id IN (SELECT id FROM data_groups WHERE study_id = ?))
    OR (audit_log.entity_type = 'membership' AND audit_log.entity_id IN (SELECT id FROM study_memberships WHERE study_id = ?))
    OR (audit_log.entity_type = 'api_token' AND audit_log.entity_id IN (SELECT id FROM api_tokens WHERE study_id = ?))
    OR (audit_log.entity_type = 'randomization_list' AND audit_log.entity_id IN (SELECT id FROM randomization_lists WHERE study_id = ?))
    OR (audit_log.entity_type = 'randomization' AND audit_log.entity_id IN (SELECT id FROM randomization_allocations WHERE study_id = ?))
    OR (audit_log.entity_type = 'survey_link' AND audit_log.entity_id IN (SELECT id FROM survey_links WHERE study_id = ?))
    OR (audit_log.entity_type = 'survey_invitation' AND audit_log.entity_id IN (SELECT id FROM survey_invitations WHERE study_id = ?))
    OR (audit_log.entity_type = 'report' AND audit_log.entity_id IN (SELECT id FROM reports WHERE study_id = ?))
    OR (audit_log.entity_type = 'academic_cv_item' AND audit_log.entity_id IN (SELECT id FROM academic_cv_items WHERE study_id = ?))
    OR (audit_log.entity_type = 'case_intake' AND audit_log.entity_id IN (SELECT id FROM case_intakes WHERE study_id = ?))
    OR (audit_log.entity_type = 'case_ai_review' AND audit_log.entity_id IN (SELECT id FROM case_ai_reviews WHERE study_id = ?))
)
"""


def study_audit_params(study_id: int) -> tuple[int, ...]:
    return (study_id,) * STUDY_AUDIT_FILTER.count("?")


def migrate() -> None:
    with closing(db()) as conn, conn:
        if getattr(conn, "backend", "sqlite") == "postgres":
            migrate_postgres(conn)
            add_column(conn, "api_tokens", "scopes_json", "TEXT NOT NULL DEFAULT '[]'")
            add_column(conn, "audit_log", "study_id", "BIGINT")
            add_column(conn, "audit_log", "ip_address", "TEXT NOT NULL DEFAULT ''")
            add_column(conn, "audit_log", "user_agent", "TEXT NOT NULL DEFAULT ''")
            add_column(conn, "audit_log", "request_id", "TEXT NOT NULL DEFAULT ''")
            add_column(conn, "forms", "active", "INTEGER NOT NULL DEFAULT 1")
            add_column(conn, "survey_links", "expires_at", "BIGINT")
            add_column(conn, "survey_links", "one_time", "INTEGER NOT NULL DEFAULT 0")
            add_column(conn, "academic_cv_items", "active", "INTEGER NOT NULL DEFAULT 1")
            add_column(conn, "case_files", "original_filename", "TEXT NOT NULL DEFAULT ''")
            add_column(conn, "case_files", "stored_filename", "TEXT NOT NULL DEFAULT ''")
            add_column(conn, "case_files", "sha256", "TEXT NOT NULL DEFAULT ''")
            seed_initial_data(conn)
            return
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
            """
        )
        add_column(conn, "entries", "repeat_instance", "INTEGER NOT NULL DEFAULT 1")
        add_column(conn, "entries", "locked_at", "INTEGER")
        add_column(conn, "entries", "locked_by", "INTEGER REFERENCES users(id)")
        add_column(conn, "entries", "lock_reason", "TEXT NOT NULL DEFAULT ''")
        add_column(conn, "entries", "event_id", "INTEGER REFERENCES study_events(id) ON DELETE SET NULL")
        add_column(conn, "entries", "form_version", "INTEGER NOT NULL DEFAULT 1")
        add_column(conn, "entries", "schema_snapshot_json", "TEXT NOT NULL DEFAULT '{}'")
        add_column(conn, "entries", "entry_hash", "TEXT NOT NULL DEFAULT ''")
        add_column(conn, "participants", "data_group_id", "INTEGER REFERENCES data_groups(id) ON DELETE SET NULL")
        add_column(conn, "users", "must_change_password", "INTEGER NOT NULL DEFAULT 0")
        add_column(conn, "users", "failed_login_count", "INTEGER NOT NULL DEFAULT 0")
        add_column(conn, "users", "locked_until", "INTEGER NOT NULL DEFAULT 0")
        add_column(conn, "api_tokens", "scopes_json", "TEXT NOT NULL DEFAULT '[]'")
        add_column(conn, "audit_log", "study_id", "INTEGER")
        add_column(conn, "audit_log", "ip_address", "TEXT NOT NULL DEFAULT ''")
        add_column(conn, "audit_log", "user_agent", "TEXT NOT NULL DEFAULT ''")
        add_column(conn, "audit_log", "request_id", "TEXT NOT NULL DEFAULT ''")
        add_column(conn, "forms", "active", "INTEGER NOT NULL DEFAULT 1")
        add_column(conn, "survey_links", "expires_at", "INTEGER")
        add_column(conn, "survey_links", "one_time", "INTEGER NOT NULL DEFAULT 0")
        add_column(conn, "academic_cv_items", "active", "INTEGER NOT NULL DEFAULT 1")
        add_column(conn, "case_files", "original_filename", "TEXT NOT NULL DEFAULT ''")
        add_column(conn, "case_files", "stored_filename", "TEXT NOT NULL DEFAULT ''")
        add_column(conn, "case_files", "sha256", "TEXT NOT NULL DEFAULT ''")
        migrate_entries_unique_key(conn)
        seed_initial_data(conn)
        add_production_indexes(conn)


def seed_initial_data(conn) -> None:
    if not row(conn, "SELECT id FROM users LIMIT 1"):
        production = SETTINGS.production
        admin_password = SETTINGS.admin_password if production else (SETTINGS.admin_password or "admin123")
        if production and (not admin_password or len(admin_password) < PRODUCTION_ADMIN_PASSWORD_MIN_LENGTH or admin_password == "admin123"):
            raise RuntimeError("Production startup requires CDS_ADMIN_PASSWORD with at least 12 characters and not the default password.")
        user = {
            "username": SETTINGS.admin_username if production else "admin",
            "display_name": SETTINGS.admin_display_name if production else "Administrator",
            "role": "super_admin" if production else "admin",
            "created_at": now(),
        }
        conn.execute(
            "INSERT INTO users(username, password_hash, display_name, role, must_change_password, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (user["username"], encode_password(admin_password), user["display_name"], user["role"], 0 if production else 1, user["created_at"]),
        )
        audit(conn, None, "seed", "user", 1, None, user)
    default_admin = row(conn, "SELECT id, password_hash FROM users WHERE username = 'admin'")
    if default_admin and verify_password("admin123", default_admin["password_hash"]):
        conn.execute("UPDATE users SET must_change_password = 1 WHERE id = ?", (default_admin["id"],))
    if not row(conn, "SELECT id FROM studies LIMIT 1"):
        seed_study(conn)
    seed_admin_memberships(conn)
    seed_baseline_events(conn)


def add_production_indexes(conn) -> None:
    statements = [
        "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)",
        "CREATE INDEX IF NOT EXISTS idx_study_memberships_study_id ON study_memberships(study_id)",
        "CREATE INDEX IF NOT EXISTS idx_study_memberships_user_id ON study_memberships(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_participants_study_id ON participants(study_id)",
        "CREATE INDEX IF NOT EXISTS idx_entries_study_id ON entries(study_id)",
        "CREATE INDEX IF NOT EXISTS idx_entries_participant_id ON entries(participant_id)",
        "CREATE INDEX IF NOT EXISTS idx_entries_form_id ON entries(form_id)",
        "CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_audit_log_entity ON audit_log(entity_type, entity_id)",
        "CREATE INDEX IF NOT EXISTS idx_academic_cv_items_study_id ON academic_cv_items(study_id)",
        "CREATE INDEX IF NOT EXISTS idx_api_tokens_study_id ON api_tokens(study_id)",
        "CREATE INDEX IF NOT EXISTS idx_api_tokens_token_hash ON api_tokens(token_hash)",
    ]
    for statement in statements:
        conn.execute(statement)


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
    admin_users = rows(conn, "SELECT id FROM users WHERE role IN ('admin', 'super_admin') AND active = 1")
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


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def form_schema_snapshot(form: dict, schema: dict | None = None) -> dict:
    schema = schema or load_json(form.get("schema_json", "{}"), {"fields": []})
    return {
        "form_id": form.get("id"),
        "form_name": form.get("name", ""),
        "form_code": form.get("code", ""),
        "form_version": int(form.get("version") or 1),
        "repeatable": bool(schema.get("repeatable", False)),
        "fields": schema.get("fields", []),
    }


def schema_for_entry(entry: dict, fallback_schema: dict | None = None) -> dict:
    snapshot = load_json(entry.get("schema_snapshot_json", ""), {})
    if snapshot.get("fields"):
        return {"fields": snapshot.get("fields", []), "repeatable": bool(snapshot.get("repeatable", False))}
    return fallback_schema or {"fields": []}


def entry_hash(data: dict, form_version: int, schema_snapshot: dict) -> str:
    payload = {"data": data, "form_version": int(form_version or 1), "schema_snapshot": schema_snapshot}
    return sha256_bytes(canonical_json(payload).encode("utf-8"))


def form_schema_diff(old_schema: dict, new_schema: dict) -> dict:
    old_fields = {field.get("code"): field for field in old_schema.get("fields", []) if field.get("code")}
    new_fields = {field.get("code"): field for field in new_schema.get("fields", []) if field.get("code")}
    added = sorted(set(new_fields) - set(old_fields))
    removed = sorted(set(old_fields) - set(new_fields))
    changed = []
    for code in sorted(set(old_fields) & set(new_fields)):
        before = old_fields[code]
        after = new_fields[code]
        changes = {}
        for key in ("label", "type", "options", "min", "max", "required", "show_if", "calculation", "units", "validation", "regex"):
            if before.get(key) != after.get(key):
                changes[key] = {"before": before.get(key), "after": after.get(key)}
        if changes:
            changed.append({"field": code, "changes": changes})
    return {"fields_added": added, "fields_removed": removed, "fields_changed": changed}


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


def field_options_from_label(label: str) -> tuple[str, list[str]]:
    choices_match = re.search(r"\(([^()]{3,160})\)\s*$", label)
    if not choices_match:
        choices_match = re.search(r"\[([^\[\]]{3,160})\]\s*$", label)
    if not choices_match:
        return label, []
    raw_choices = choices_match.group(1)
    if not any(separator in raw_choices for separator in (",", "/", "|", ";")):
        return label, []
    clean_label = label[: choices_match.start()].strip(" -:\t") or label
    choices = [part.strip() for part in re.split(r"[,/|;]", raw_choices) if part.strip()]
    return clean_label, choices[:12]


def draft_crf_schema_locally(text: str) -> tuple[dict, list[str]]:
    warnings = []
    fields = []
    seen = set()
    for line in text.splitlines():
        label = re.sub(r"^\s*(?:[-*]|\d+[.)])\s*", "", line).strip(" -:\t")
        if not label:
            continue
        required = "*" in label or " required" in label.lower()
        label = label.replace("*", "").strip()
        label, parsed_options = field_options_from_label(label)
        lower = label.lower()
        field_type = "text"
        options = parsed_options
        if any(word in lower for word in ("note", "comment", "description", "details", "history", "narrative")):
            field_type = "textarea"
        if any(word in lower for word in ("date", "day of", "visit day", "dob")):
            field_type = "date"
        if any(word in lower for word in ("age", "weight", "height", "score", "bp", "pressure", "dose", "rate", "count", "number", "value")):
            field_type = "number"
        if any(word in lower for word in ("upload", "attachment", "file", "image", "scan")):
            field_type = "file"
        if parsed_options:
            field_type = "select"
        elif lower.startswith(("any ", "was ", "were ", "is ", "are ", "has ", "have ", "did ")) or lower.endswith("?"):
            field_type = "select"
            options = ["No", "Yes"]
        elif "sex" in lower or "gender" in lower:
            field_type = "select"
            options = ["Female", "Male", "Other", "Unknown"]
        code = normalize_code(label)
        if not code or code in seen:
            continue
        seen.add(code)
        field = {"code": code, "label": label, "type": field_type, "required": required}
        if field_type in {"select", "checkbox"}:
            field["options"] = options or ["No", "Yes"]
        fields.append(field)
        if len(fields) >= 80:
            warnings.append("Draft limited to the first 80 detected fields.")
            break
    if not fields:
        fields = [{"code": "notes", "label": "Notes", "type": "textarea", "required": False}]
        warnings.append("No discrete field labels were detected; created a notes field.")
    return normalize_schema({"fields": fields}), warnings


def extract_openai_text(payload: dict) -> str:
    if payload.get("output_text"):
        return str(payload["output_text"])
    parts = []
    for item in payload.get("output", []):
        for content in item.get("content", []):
            if content.get("type") in {"output_text", "text"} and content.get("text"):
                parts.append(str(content["text"]))
    return "\n".join(parts)


def draft_crf_schema_with_openai(text: str) -> dict:
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise ValueError("OPENAI_API_KEY is not configured")
    model = SETTINGS.ai_model or DEFAULT_OPENAI_MODEL
    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "fields": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "code": {"type": "string"},
                        "label": {"type": "string"},
                        "type": {"type": "string", "enum": ["text", "textarea", "number", "date", "select", "checkbox", "file"]},
                        "required": {"type": "boolean"},
                        "options": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["code", "label", "type", "required", "options"],
                },
            }
        },
        "required": ["fields"],
    }
    request_payload = {
        "model": model,
        "input": [
            {
                "role": "system",
                "content": (
                    "Draft a clinical CRF schema from the user's de-identified field list. "
                    "Do not invent diagnosis-specific conclusions. Use short stable variable codes. "
                    "Use select options only when choices are explicit or clearly yes/no."
                ),
            },
            {"role": "user", "content": text[:12000]},
        ],
        "text": {"format": {"type": "json_schema", "name": "crf_schema", "strict": True, "schema": schema}},
    }
    request = UrlRequest(
        "https://api.openai.com/v1/responses",
        data=json.dumps(request_payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    with urlopen_request(request, timeout=45) as response:
        result = json.loads(response.read().decode("utf-8"))
    output_text = extract_openai_text(result)
    if not output_text:
        raise ValueError("AI response did not contain text output")
    parsed = json.loads(output_text)
    return normalize_schema(parsed)


def openai_error_message(exc: HTTPError) -> str:
    try:
        detail = exc.read().decode("utf-8", errors="replace")
    except Exception:
        detail = exc.reason
    return f"OpenAI API error {exc.code}: {str(detail)[:600]}"


def openai_response_json(system_prompt: str, content_parts: list[dict], schema_name: str, schema: dict, timeout: int = 90) -> dict:
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise ValueError("OPENAI_API_KEY is not configured")
    model = SETTINGS.ai_model or DEFAULT_OPENAI_MODEL
    request_payload = {
        "model": model,
        "input": [
            {"role": "system", "content": [{"type": "input_text", "text": system_prompt}]},
            {"role": "user", "content": content_parts},
        ],
        "text": {"format": {"type": "json_schema", "name": schema_name, "strict": True, "schema": schema}},
    }
    request = UrlRequest(
        "https://api.openai.com/v1/responses",
        data=json.dumps(request_payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen_request(request, timeout=timeout) as response:
            result = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise ValueError(openai_error_message(exc)) from exc
    output_text = extract_openai_text(result)
    if not output_text:
        raise ValueError("AI response did not contain text output")
    return json.loads(output_text)


def openai_transcribe_audio(filename: str, content_type: str, content: bytes) -> str:
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise ValueError("OPENAI_API_KEY is not configured")
    model = SETTINGS.ai_transcribe_model or DEFAULT_TRANSCRIBE_MODEL
    boundary = f"----cds{secrets.token_hex(16)}"
    chunks: list[bytes] = []

    def add_field(name: str, value: str) -> None:
        chunks.append(f"--{boundary}\r\n".encode("utf-8"))
        chunks.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"))
        chunks.append(value.encode("utf-8"))
        chunks.append(b"\r\n")

    def add_file(name: str, file_name: str, file_type: str, value: bytes) -> None:
        safe_name = Path(file_name).name or "audio"
        chunks.append(f"--{boundary}\r\n".encode("utf-8"))
        chunks.append(f'Content-Disposition: form-data; name="{name}"; filename="{safe_name}"\r\n'.encode("utf-8"))
        chunks.append(f"Content-Type: {file_type or 'application/octet-stream'}\r\n\r\n".encode("utf-8"))
        chunks.append(value)
        chunks.append(b"\r\n")

    add_field("model", model)
    add_field("response_format", "json")
    add_file("file", filename, content_type, content)
    chunks.append(f"--{boundary}--\r\n".encode("utf-8"))
    request = UrlRequest(
        "https://api.openai.com/v1/audio/transcriptions",
        data=b"".join(chunks),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    try:
        with urlopen_request(request, timeout=120) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise ValueError(openai_error_message(exc)) from exc
    return str(payload.get("text", "")).strip()


def first_matching_line(text: str, labels: tuple[str, ...]) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        for label in labels:
            if lower.startswith(label):
                return stripped.split(":", 1)[-1].strip() if ":" in stripped else stripped
    return ""


def matching_sentence(text: str, words: tuple[str, ...]) -> str:
    parts = re.split(r"(?<=[.!?])\s+|\n+", text)
    for part in parts:
        clean = part.strip()
        lower = clean.lower()
        if clean and any(word in lower for word in words):
            return clean[:600]
    return ""


def extract_age(text: str) -> str:
    patterns = [
        r"\bage\s*[:=]?\s*(\d{1,3})\b",
        r"\b(\d{1,3})\s*(?:year|years|yr|yrs|y/o|yo)\s*(?:old)?\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def extract_sex(text: str) -> str:
    lower = text.lower()
    if re.search(r"\b(female|woman|girl|lady)\b", lower):
        return "Female"
    if re.search(r"\b(male|man|boy|gentleman)\b", lower):
        return "Male"
    return ""


def extract_case_intelligence(text: str, title: str = "") -> dict:
    clean = re.sub(r"\s+", " ", text).strip()
    diagnosis = first_matching_line(text, ("diagnosis", "dx", "impression", "final diagnosis"))
    if not diagnosis:
        diagnosis = matching_sentence(text, ("diagnosed with", "diagnosis", "impression", "case of"))
    presentation = first_matching_line(text, ("presentation", "presenting complaint", "chief complaint", "complaint"))
    if not presentation:
        presentation = matching_sentence(text, ("presented", "complaint", "symptom", "history of"))
    investigations = first_matching_line(text, ("investigation", "investigations", "lab", "labs", "imaging", "ct", "mri"))
    if not investigations:
        investigations = matching_sentence(text, ("investigation", "laboratory", "imaging", "ct", "mri", "ultrasound", "x-ray", "biopsy"))
    treatment = first_matching_line(text, ("treatment", "management", "intervention", "procedure", "surgery"))
    if not treatment:
        treatment = matching_sentence(text, ("treatment", "management", "intervention", "procedure", "treated", "started", "given", "surgery", "managed"))
    outcome = first_matching_line(text, ("outcome", "follow up", "follow-up", "discharge", "result"))
    if not outcome:
        outcome = matching_sentence(text, ("outcome", "improved", "recovered", "died", "death", "discharged", "follow", "complication"))
    dates = re.findall(r"\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{1,2}-\d{1,2})\b", text)
    group_source = diagnosis or title or "Ungrouped case"
    group_label = re.sub(r"\b\d{1,3}\b", "", group_source).strip(" .,:;-")[:80] or "Ungrouped case"
    tags = []
    for value in (diagnosis, treatment, outcome):
        for token in re.findall(r"[A-Za-z][A-Za-z0-9+-]{3,}", value):
            normalized = token.lower()
            if normalized not in tags and normalized not in {"with", "from", "treated", "patient", "case"}:
                tags.append(normalized)
    missing = []
    for key, value in {
        "age": extract_age(text),
        "sex": extract_sex(text),
        "diagnosis": diagnosis,
        "presentation": presentation,
        "investigations": investigations,
        "treatment": treatment,
        "outcome": outcome,
    }.items():
        if not value:
            missing.append(key)
    warnings = []
    if re.search(r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b", text):
        warnings.append("Possible patient/person name detected; de-identify before publication or external AI use.")
    if re.search(r"\b\d{10,}\b", text):
        warnings.append("Long number detected; check for phone, MRN, or identifier.")
    return {
        "demographics": {"age": extract_age(text), "sex": extract_sex(text)},
        "clinical": {
            "diagnosis": diagnosis,
            "presentation": presentation,
            "investigations": investigations,
            "treatment": treatment,
            "outcome": outcome,
        },
        "timeline": dates[:12],
        "group_label": group_label,
        "tags": tags[:12],
        "missing_fields": missing,
        "publication_notes": [
            "Map the case against CARE case-report items.",
            "For a case series, keep denominator, inclusion criteria, and follow-up consistent across cases.",
            "Use source files only as internal evidence; publish de-identified summaries.",
        ],
        "warnings": warnings,
        "source_excerpt": clean[:900],
    }


def adaptive_case_fields(case_items: list[dict]) -> list[dict]:
    fields = [
        {"code": "case_uid", "label": "Case ID", "type": "text", "required": True, "reason": "Stable case tracking"},
        {"code": "age", "label": "Age", "type": "number", "required": False, "reason": "Core case-report demographic item"},
        {"code": "sex", "label": "Sex", "type": "select", "required": False, "options": ["Female", "Male", "Other", "Unknown"], "reason": "Core case-report demographic item"},
        {"code": "diagnosis", "label": "Diagnosis", "type": "textarea", "required": True, "reason": "Main grouping and publication variable"},
        {"code": "presentation", "label": "Presentation", "type": "textarea", "required": False, "reason": "Symptoms and clinical context"},
        {"code": "investigations", "label": "Investigations", "type": "textarea", "required": False, "reason": "Diagnostic evidence"},
        {"code": "treatment", "label": "Treatment / Management", "type": "textarea", "required": False, "reason": "Intervention or exposure"},
        {"code": "outcome", "label": "Outcome", "type": "textarea", "required": False, "reason": "Clinical course and publication relevance"},
        {"code": "follow_up", "label": "Follow-up Duration", "type": "text", "required": False, "reason": "Case-series comparability"},
    ]
    tag_counts: dict[str, int] = {}
    for item in case_items:
        for tag in (item.get("extracted") or {}).get("tags", []):
            if len(tag) >= 4:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
    for tag, count in sorted(tag_counts.items(), key=lambda pair: (-pair[1], pair[0]))[:8]:
        if count < 2 and len(case_items) > 1:
            continue
        fields.append(
            {
                "code": normalize_code(f"has_{tag}")[:40],
                "label": f"{tag.title()} present",
                "type": "select",
                "required": False,
                "options": ["No", "Yes", "Unknown"],
                "reason": f"Detected in {count} case(s); consider a structured field if clinically meaningful.",
            }
        )
    normalized = []
    seen = set()
    for field in fields:
        code = normalize_code(field["code"])[:60]
        if code in seen:
            continue
        seen.add(code)
        normalized.append({**field, "code": code, "options": field.get("options", [])})
    return normalized


def case_series_summary(case_items: list[dict]) -> dict:
    groups: dict[str, dict] = {}
    missing_total = 0
    warnings = 0
    for item in case_items:
        extracted = item.get("extracted") or {}
        group = extracted.get("group_label") or "Ungrouped case"
        bucket = groups.setdefault(group, {"group": group, "count": 0, "case_uids": [], "tags": []})
        bucket["count"] += 1
        bucket["case_uids"].append(item["case_uid"])
        for tag in extracted.get("tags", []):
            if tag not in bucket["tags"]:
                bucket["tags"].append(tag)
        missing_total += len(extracted.get("missing_fields", []))
        warnings += len(extracted.get("warnings", []))
    group_list = sorted(groups.values(), key=lambda value: (-value["count"], value["group"]))
    return {
        "case_count": len(case_items),
        "group_count": len(group_list),
        "groups": group_list,
        "missing_field_count": missing_total,
        "warning_count": warnings,
        "adaptive_fields": adaptive_case_fields(case_items),
        "draft_outline": [
            "Title: concise diagnosis/intervention/outcome signal.",
            "Background: why these cases are clinically useful.",
            "Methods: retrospective source, inclusion criteria, dates, and de-identification process.",
            "Results: demographics, presentation, investigations, treatment, outcome, follow-up.",
            "Discussion: patterns, novelty, limitations, and lessons.",
        ],
    }


def publication_opportunities(case_items: list[dict]) -> list[dict]:
    groups: dict[str, dict] = {}
    for item in case_items:
        extracted = item.get("extracted") or {}
        clinical = extracted.get("clinical") or {}
        group = extracted.get("group_label") or clinical.get("diagnosis") or "Ungrouped case"
        bucket = groups.setdefault(
            group,
            {
                "group": group,
                "case_count": 0,
                "case_ids": [],
                "case_uids": [],
                "diagnoses": set(),
                "treatments": set(),
                "outcomes": set(),
                "missing_items": set(),
                "warnings": set(),
                "search_terms": set(),
            },
        )
        bucket["case_count"] += 1
        bucket["case_ids"].append(item["id"])
        bucket["case_uids"].append(item["case_uid"])
        for key, target in (("diagnosis", "diagnoses"), ("treatment", "treatments"), ("outcome", "outcomes")):
            value = str(clinical.get(key, "")).strip()
            if value:
                bucket[target].add(value)
        for value in extracted.get("missing_fields", []):
            bucket["missing_items"].add(str(value))
        for value in extracted.get("warnings", []):
            bucket["warnings"].add(str(value))
        for value in extracted.get("tags", []):
            bucket["search_terms"].add(str(value))
    opportunities = []
    for bucket in groups.values():
        case_count = bucket["case_count"]
        missing_count = len(bucket["missing_items"])
        warning_count = len(bucket["warnings"])
        if case_count >= 5 and missing_count <= case_count:
            potential = "high"
        elif case_count >= 2 or missing_count <= 3:
            potential = "moderate"
        else:
            potential = "early"
        article_type = "case report" if case_count == 1 else "case series"
        if case_count >= 10:
            article_type = "retrospective cohort / case series"
        rationale_parts = [f"{case_count} case(s) grouped under {bucket['group']}"]
        if missing_count:
            rationale_parts.append(f"{missing_count} missing publication data item(s)")
        if warning_count:
            rationale_parts.append(f"{warning_count} de-identification/data warning(s)")
        opportunities.append(
            {
                "group": bucket["group"],
                "case_count": case_count,
                "case_ids": bucket["case_ids"],
                "case_uids": bucket["case_uids"],
                "suggested_article_type": article_type,
                "publication_potential": potential,
                "rationale": "; ".join(rationale_parts) + ".",
                "diagnoses": sorted(bucket["diagnoses"]),
                "treatments": sorted(bucket["treatments"]),
                "outcomes": sorted(bucket["outcomes"]),
                "missing_items": sorted(bucket["missing_items"]),
                "warnings": sorted(bucket["warnings"]),
                "literature_search_terms": sorted(bucket["search_terms"] | set(bucket["diagnoses"]) | set(bucket["treatments"]))[:12],
                "next_actions": [
                    "Complete missing case variables and de-identify source material.",
                    "Run Academic AI review on representative cases.",
                    "Confirm ethics/consent requirements before manuscript preparation.",
                    "Export case CSV and prepare a reproducible analysis table.",
                ],
            }
        )
    return sorted(opportunities, key=lambda item: (-item["case_count"], item["group"]))


def academic_cv_markdown(study: dict, cv_items: list[dict], opportunities: list[dict]) -> str:
    lines = [
        f"# Academic Portfolio - {study['name']}",
        "",
        "## Publication Pipeline",
        "",
    ]
    if opportunities:
        for item in opportunities:
            lines.extend(
                [
                    f"- **{item['group']}**: {item['suggested_article_type']} ({item['publication_potential']} potential)",
                    f"  - Cases: {', '.join(item['case_uids'])}",
                    f"  - Rationale: {item['rationale']}",
                    f"  - Next: {item['next_actions'][0]}",
                ]
            )
    else:
        lines.append("- No case-based publication opportunities have been generated yet.")
    lines.extend(["", "## CV Items", ""])
    if cv_items:
        for item in cv_items:
            date = f" ({item['item_date']})" if item.get("item_date") else ""
            citation = f" - {item['citation']}" if item.get("citation") else ""
            notes = f" Notes: {item['notes']}" if item.get("notes") else ""
            lines.append(f"- **{item['title']}**{date}. {item['item_type']} / {item['status']}. Role: {item.get('role') or 'not specified'}{citation}.{notes}")
    else:
        lines.append("- Add abstracts, posters, manuscripts, presentations, audits, protocols, datasets, and awards here.")
    lines.extend(["", "## Safety Notes", "", "- Verify every AI-generated suggestion against source records.", "- Keep patient identifiers out of publication exports unless approved and necessary."])
    return "\n".join(lines) + "\n"


def academic_review_schema() -> dict:
    field_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "code": {"type": "string"},
            "label": {"type": "string"},
            "type": {"type": "string", "enum": ["text", "textarea", "number", "date", "select", "checkbox", "file"]},
            "required": {"type": "boolean"},
            "options": {"type": "array", "items": {"type": "string"}},
            "reason": {"type": "string"},
        },
        "required": ["code", "label", "type", "required", "options", "reason"],
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "case_summary": {"type": "string"},
            "structured_case_data": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "demographics": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {"age": {"type": "string"}, "sex": {"type": "string"}},
                        "required": ["age", "sex"],
                    },
                    "clinical": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "diagnosis": {"type": "string"},
                            "presentation": {"type": "string"},
                            "investigations": {"type": "string"},
                            "treatment": {"type": "string"},
                            "outcome": {"type": "string"},
                            "follow_up": {"type": "string"},
                        },
                        "required": ["diagnosis", "presentation", "investigations", "treatment", "outcome", "follow_up"],
                    },
                },
                "required": ["demographics", "clinical"],
            },
            "evidence_notes": {"type": "array", "items": {"type": "string"}},
            "adaptive_crf_suggestions": {"type": "array", "items": field_schema},
            "publication_guidance": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "case_report_potential": {"type": "string", "enum": ["low", "moderate", "high", "unclear"]},
                    "case_series_potential": {"type": "string", "enum": ["low", "moderate", "high", "unclear"]},
                    "suggested_article_type": {"type": "string"},
                    "rationale": {"type": "string"},
                    "manuscript_outline": {"type": "array", "items": {"type": "string"}},
                    "missing_items": {"type": "array", "items": {"type": "string"}},
                    "follow_up_questions": {"type": "array", "items": {"type": "string"}},
                    "literature_search_terms": {"type": "array", "items": {"type": "string"}},
                    "ethics_and_privacy_notes": {"type": "array", "items": {"type": "string"}},
                },
                "required": [
                    "case_report_potential",
                    "case_series_potential",
                    "suggested_article_type",
                    "rationale",
                    "manuscript_outline",
                    "missing_items",
                    "follow_up_questions",
                    "literature_search_terms",
                    "ethics_and_privacy_notes",
                ],
            },
            "response_to_question": {"type": "string"},
            "safety_notes": {"type": "array", "items": {"type": "string"}},
        },
        "required": [
            "case_summary",
            "structured_case_data",
            "evidence_notes",
            "adaptive_crf_suggestions",
            "publication_guidance",
            "response_to_question",
            "safety_notes",
        ],
    }


def local_academic_case_review(case_item: dict, all_cases: list[dict], question: str = "") -> dict:
    extracted = case_item.get("extracted") or {}
    clinical = extracted.get("clinical") or {}
    demographics = extracted.get("demographics") or {}
    missing = list(extracted.get("missing_fields", []))
    case_count = len(all_cases)
    has_outcome = bool(clinical.get("outcome"))
    potential = "moderate" if clinical.get("diagnosis") and has_outcome else "unclear"
    if len(missing) > 3:
        potential = "low"
    return {
        "case_summary": " ".join(part for part in [clinical.get("diagnosis", ""), clinical.get("presentation", ""), clinical.get("outcome", "")] if part)[:1200] or "Insufficient structured case text for a reliable summary.",
        "structured_case_data": {
            "demographics": {"age": demographics.get("age", ""), "sex": demographics.get("sex", "")},
            "clinical": {
                "diagnosis": clinical.get("diagnosis", ""),
                "presentation": clinical.get("presentation", ""),
                "investigations": clinical.get("investigations", ""),
                "treatment": clinical.get("treatment", ""),
                "outcome": clinical.get("outcome", ""),
                "follow_up": "",
            },
        },
        "evidence_notes": [
            f"{len(case_item.get('files', []))} evidence file(s) are stored locally.",
            "Local review uses typed/dictated/OCR text only; enable OpenAI multimodal review for image/audio interpretation.",
        ],
        "adaptive_crf_suggestions": adaptive_case_fields(all_cases),
        "publication_guidance": {
            "case_report_potential": potential,
            "case_series_potential": "moderate" if case_count >= 3 else "low",
            "suggested_article_type": "case report" if case_count < 3 else "case series",
            "rationale": "Publication potential depends on novelty, complete timeline, diagnostic evidence, intervention details, outcome/follow-up, consent/ethics, and a focused literature gap.",
            "manuscript_outline": [
                "Background and clinical rationale",
                "Case presentation with de-identified timeline",
                "Investigations and differential diagnosis",
                "Treatment or intervention",
                "Outcome and follow-up",
                "Discussion against existing literature",
            ],
            "missing_items": missing,
            "follow_up_questions": [
                "What makes this case uncommon, educational, or practice-changing?",
                "Are inclusion criteria consistent across similar cases?",
                "Is follow-up duration available for every publishable case?",
            ],
            "literature_search_terms": [value for value in [clinical.get("diagnosis", ""), clinical.get("treatment", ""), clinical.get("outcome", "")] if value][:8],
            "ethics_and_privacy_notes": [
                "Confirm consent/ethics requirements for case reports or retrospective case series.",
                "Remove names, MRNs, phone numbers, exact DOB, and unnecessary dates before external AI or publication.",
            ],
        },
        "response_to_question": question[:1200] if question else "Use the missing-item list and adaptive CRF suggestions to decide which fields to standardize next.",
        "safety_notes": list(extracted.get("warnings", [])) + ["AI/local suggestions are review aids, not final clinical interpretation."],
    }


def build_openai_case_content(conn: sqlite3.Connection, study_id: int, case_item: dict, all_cases: list[dict], question: str) -> tuple[list[dict], list[str], int]:
    status = ai_status()
    evidence_notes = []
    source_text = str(case_item.get("source_text", ""))
    assert_external_ai_safe(source_text + "\n" + question)
    ai_source_text = deidentify_for_ai(source_text, str(case_item.get("case_uid") or "Study participant")) if not status["phi_allowed"] else source_text
    case_context = {
        "case": {
            "case_uid": case_item.get("case_uid"),
            "title": case_item.get("title"),
            "status": case_item.get("status"),
            "source_text": ai_source_text[:18000],
            "local_extraction": case_item.get("extracted", {}),
        },
        "series_summary": case_series_summary(all_cases),
        "user_question": question[:3000],
    }
    content_parts = [{"type": "input_text", "text": "Review this de-identified clinical case intake JSON:\n" + json.dumps(case_context, ensure_ascii=False)}]
    file_rows = rows(conn, "SELECT * FROM case_files WHERE case_id = ? AND study_id = ? ORDER BY id", (case_item["id"], study_id))
    for file_row in file_rows:
        name = file_row["name"]
        content_type = file_row["content_type"] or mimetypes.guess_type(name)[0] or "application/octet-stream"
        try:
            decoded = case_file_content(file_row)
        except Exception:
            evidence_notes.append(f"{name}: could not read stored evidence.")
            continue
        if (content_type.startswith("text/") or Path(name).suffix.lower() in {".txt", ".csv"}) and status["multimodal_enabled"]:
            text = decoded.decode("utf-8", errors="replace")[:10000]
            assert_external_ai_safe(text)
            safe_text = deidentify_for_ai(text, str(case_item.get("case_uid") or "Study participant")) if not status["phi_allowed"] else text
            content_parts.append({"type": "input_text", "text": f"Evidence text file {name}:\n{safe_text}"})
            evidence_notes.append(f"{name}: text evidence included after identifier safety check.")
        elif content_type.startswith("image/") and status["multimodal_enabled"] and len(decoded) <= status["max_file_mb"] * 1024 * 1024:
            image_base64 = base64.b64encode(decoded).decode("ascii")
            content_parts.append({"type": "input_image", "image_url": f"data:{content_type};base64,{image_base64}"})
            evidence_notes.append(f"{name}: image sent for AI vision review.")
        elif content_type.startswith("audio/") and status["multimodal_enabled"] and len(decoded) <= status["max_file_mb"] * 1024 * 1024:
            transcript = openai_transcribe_audio(name, content_type, decoded)
            assert_external_ai_safe(transcript)
            safe_transcript = deidentify_for_ai(transcript, str(case_item.get("case_uid") or "Study participant")) if not status["phi_allowed"] else transcript
            content_parts.append({"type": "input_text", "text": f"Audio transcript from {name}:\n{safe_transcript[:12000]}"})
            evidence_notes.append(f"{name}: audio transcribed and included.")
        elif not status["multimodal_enabled"] and (content_type.startswith(("image/", "audio/", "text/")) or Path(name).suffix.lower() in {".txt", ".csv"}):
            evidence_notes.append(f"{name}: stored locally but not sent because CDS_AI_MULTIMODAL is not enabled.")
        else:
            evidence_notes.append(f"{name}: stored locally; unsupported for AI interpretation in this version.")
    content_parts.append({"type": "input_text", "text": "Evidence handling notes:\n" + "\n".join(evidence_notes)})
    return content_parts, evidence_notes, len(file_rows)


def openai_academic_case_review(conn: sqlite3.Connection, study_id: int, case_item: dict, all_cases: list[dict], question: str) -> dict:
    content_parts, evidence_notes, _ = build_openai_case_content(conn, study_id, case_item, all_cases, question)
    system_prompt = (
        "You are an academic clinical research assistant inside a local EDC app. "
        "Extract only what is supported by the supplied material. Do not invent facts. "
        "Suggest adaptive CRF fields for repeated retrospective cases. "
        "Assess publication possibilities using case report/case series thinking, but never claim novelty without a literature search. "
        "Prioritize de-identification, consent/ethics, missing data, and reviewer-verifiable outputs."
    )
    result = openai_response_json(system_prompt, content_parts, "academic_case_review", academic_review_schema(), timeout=120)
    if evidence_notes:
        result["evidence_notes"] = list(dict.fromkeys([*result.get("evidence_notes", []), *evidence_notes]))
    return result


def user_membership(conn: sqlite3.Connection, user: dict, study_id: int) -> dict | None:
    if is_super_admin(user):
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
        if parsed.path == "/healthz":
            payload = health_payload()
            self.send_json(payload, 200 if payload["ok"] else 503)
        elif parsed.path.startswith("/api/"):
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

    def request_values(self) -> dict:
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        content_type = self.headers.get("content-type", "")
        if "application/json" in content_type:
            return json.loads(raw or "{}")
        parsed = parse_qs(raw, keep_blank_values=True)
        return {key: values[-1] if values else "" for key, values in parsed.items()}

    def send_json(self, payload, status: int = 200) -> None:
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def queue_header(self, name: str, value: str) -> None:
        headers = getattr(self, "_extra_headers", [])
        headers.append((name, value))
        self._extra_headers = headers

    def end_headers(self) -> None:
        for name, value in getattr(self, "_extra_headers", []):
            self.send_header(name, value)
        self._extra_headers = []
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(self), microphone=(self), geolocation=()")
        if SETTINGS.require_https or self.headers.get("x-forwarded-proto", "").lower() == "https":
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        super().end_headers()

    def cookies(self) -> dict:
        parsed = {}
        for part in self.headers.get("cookie", "").split(";"):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            parsed[key.strip()] = value.strip()
        return parsed

    def request_is_https(self) -> bool:
        return SETTINGS.require_https or SETTINGS.production or self.headers.get("x-forwarded-proto", "").lower() == "https"

    def session_cookie_header(self, token: str, max_age: int = SESSION_TTL_SECONDS) -> str:
        parts = [f"{SESSION_COOKIE_NAME}={token}", "HttpOnly", "Path=/", "SameSite=Lax", f"Max-Age={max_age}"]
        if self.request_is_https():
            parts.append("Secure")
        return "; ".join(parts)

    def clear_session_cookie(self) -> None:
        parts = [f"{SESSION_COOKIE_NAME}=", "HttpOnly", "Path=/", "SameSite=Lax", "Max-Age=0"]
        if self.request_is_https():
            parts.append("Secure")
        self.queue_header("Set-Cookie", "; ".join(parts))

    def expected_origins(self) -> set[str]:
        host = self.headers.get("host", "")
        scheme = self.headers.get("x-forwarded-proto", "https" if self.request_is_https() else "http")
        origins = {f"{scheme}://{host}"} if host else set()
        if SETTINGS.public_base_url:
            parsed = urlparse(SETTINGS.public_base_url)
            if parsed.scheme and parsed.netloc:
                origins.add(f"{parsed.scheme}://{parsed.netloc}")
        return origins

    def origin_is_allowed(self) -> bool:
        supplied = self.headers.get("origin") or self.headers.get("referer")
        if not supplied:
            return True
        parsed = urlparse(supplied)
        if not parsed.scheme or not parsed.netloc:
            return False
        return f"{parsed.scheme}://{parsed.netloc}" in self.expected_origins()

    def require_csrf_for_cookie_auth(self) -> bool:
        if getattr(self, "auth_source", "") != "cookie" or self.command not in {"POST", "PATCH", "DELETE"}:
            return True
        if not self.origin_is_allowed():
            self.send_error_json("CSRF origin check failed", 403)
            return False
        token = self.headers.get(CSRF_HEADER_NAME, "")
        session_digest = getattr(self, "session_digest", "")
        if not session_digest or not verify_csrf_token(session_digest, token):
            self.send_error_json("CSRF token required", 403)
            return False
        return True

    def send_error_json(self, message: str, status: int = 400) -> None:
        self.send_json({"error": message}, status)

    def audit_context(self) -> dict:
        return {
            "ip_address": self.client_address[0] if self.client_address else "",
            "user_agent": self.headers.get("user-agent", ""),
            "request_id": self.headers.get("x-request-id", ""),
        }

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
        self.auth_source = ""
        self.session_digest = ""
        header = self.headers.get("authorization", "")
        token = ""
        if header.startswith("Bearer "):
            token = header.removeprefix("Bearer ").strip()
            self.auth_source = "bearer"
        else:
            token = self.cookies().get(SESSION_COOKIE_NAME, "")
            if token:
                self.auth_source = "cookie"
        if not token:
            return None
        digest = session_token_digest(token)
        self.session_digest = digest
        user = row(
            conn,
            """
            SELECT users.id, users.username, users.display_name, users.role, users.active, users.must_change_password
            FROM sessions JOIN users ON users.id = sessions.user_id
            WHERE sessions.token = ? AND sessions.expires_at > ? AND users.active = 1
            """,
            (digest, now()),
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
            with closing(db()) as conn, conn:
                if path == "/api/login" and method == "POST":
                    return self.login(conn)
                if path == "/api/logout" and method == "POST":
                    return self.logout(conn)
                if path.startswith("/api/public/surveys/"):
                    return self.public_survey(conn, method, path)
                if path == "/api/redcap":
                    return self.redcap_api(conn, method, query)
                if path == "/api/setup" and method == "GET":
                    return self.send_json({"required": setup_required(conn)})
                if path == "/api/setup" and method == "POST":
                    return self.first_run_setup(conn)
                if path == "/api/health" and method == "GET":
                    payload = health_payload()
                    return self.send_json(payload, 200 if payload["ok"] else 503)

                user = self.require_user(conn)
                if not user:
                    return
                if path == "/api/csrf" and method == "GET":
                    return self.send_json({"csrf_token": csrf_token(getattr(self, "session_digest", ""))})
                if not self.require_csrf_for_cookie_auth():
                    return
                if user.get("must_change_password") and path not in {"/api/me", "/api/password", "/api/logout"}:
                    self.send_error_json("Password change required before continuing.", 403)
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
                if path.startswith("/api/admin"):
                    return self.admin_routes(conn, user, method, path)
                if path.startswith("/api/studies/"):
                    return self.study_routes(conn, user, method, path, query)
                if path == "/api/audit" and method == "GET":
                    if not is_super_admin(user):
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
                audit(conn, user["id"], "failed_login", "user", user["id"], None, {"failed_login_count": failed, "locked": bool(locked_until)}, **self.audit_context())
                conn.commit()
            self.send_error_json("Invalid username or password", 401)
            return
        token = secrets.token_urlsafe(32)
        prune_expired_sessions(conn)
        conn.execute("UPDATE users SET failed_login_count = 0, locked_until = 0 WHERE id = ?", (user["id"],))
        conn.execute("INSERT INTO sessions(token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)", (session_token_digest(token), user["id"], now() + SESSION_TTL_SECONDS, now()))
        audit(conn, user["id"], "login", "session", None, None, {"username": username}, **self.audit_context())
        conn.commit()
        self.queue_header("Set-Cookie", self.session_cookie_header(token))
        self.send_json({"token": token, "session": "cookie", "user": {"id": user["id"], "username": user["username"], "display_name": user["display_name"], "role": user["role"], "must_change_password": user.get("must_change_password", 0)}})

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
        if not token:
            token = self.cookies().get(SESSION_COOKIE_NAME, "")
        if token:
            digest = session_token_digest(token)
            session = row(conn, "SELECT user_id FROM sessions WHERE token = ?", (digest,))
            conn.execute("DELETE FROM sessions WHERE token = ?", (digest,))
            audit(conn, session["user_id"] if session else None, "logout", "session", None, None, {"logged_out": bool(session)}, **self.audit_context())
            conn.commit()
        self.clear_session_cookie()
        self.send_json({"ok": True})

    def user_from_api_token(self, conn: sqlite3.Connection, raw_token: str) -> tuple[dict, dict] | tuple[None, None]:
        if not raw_token:
            return None, None
        token_row = row(conn, "SELECT * FROM api_tokens WHERE token_hash = ? AND active = 1", (token_digest(raw_token),))
        if not token_row:
            return None, None
        user = row(conn, "SELECT id, username, display_name, role, active, must_change_password FROM users WHERE id = ? AND active = 1", (token_row["user_id"],))
        if not user:
            return None, None
        conn.execute("UPDATE api_tokens SET last_used_at = ? WHERE id = ?", (now(), token_row["id"]))
        return user, token_row

    def require_token_scope(self, token_row: dict, scope: str) -> bool:
        if token_has_scope(token_row, scope):
            return True
        self.send_error_json(f"API token scope required: {scope}", 403)
        return False

    def redcap_api(self, conn: sqlite3.Connection, method: str, query: dict[str, list[str]]) -> None:
        if method not in {"GET", "POST"}:
            self.send_error_json("Unsupported REDCap-style API method", 405)
            return
        values = {key: value[-1] for key, value in query.items() if value}
        if method == "POST":
            values.update(self.request_values())
        raw_token = str(values.get("token") or self.headers.get("x-cds-api-token", "")).strip()
        user, token_row = self.user_from_api_token(conn, raw_token)
        if not user:
            self.send_error_json("Invalid API token", 401)
            return
        study_id = token_row["study_id"]
        membership = user_membership(conn, user, study_id)
        if not membership:
            self.send_error_json("Study access denied", 403)
            return
        content = str(values.get("content", "project")).strip().lower()
        action = str(values.get("action", "export")).strip().lower()
        output_format = str(values.get("format", "json")).strip().lower()
        audit(conn, user["id"], "api_request", "api_token", token_row["id"], None, {"content": content, "action": action, "format": output_format})
        if content in {"version", "api_version"}:
            return self.send_redcap_payload({"api_version": "local-redcap-style-v1", "application": "Clinical Data Studio"}, output_format)
        if content in {"project", "project_info"}:
            if not self.require_token_scope(token_row, "metadata:read"):
                return
            payload = row(conn, "SELECT * FROM studies WHERE id = ?", (study_id,))
            return self.send_redcap_payload(payload, output_format)
        if content in {"metadata", "data_dictionary"}:
            if not self.require_token_scope(token_row, "metadata:read"):
                return
            payload = self.metadata_payload(conn, study_id)["data_dictionary"]
            return self.send_redcap_payload(payload, output_format)
        if content in {"instrument", "instruments"}:
            if not self.require_token_scope(token_row, "metadata:read"):
                return
            payload = self.metadata_payload(conn, study_id)["instruments"]
            return self.send_redcap_payload(payload, output_format)
        if content in {"event", "events"}:
            if not self.require_token_scope(token_row, "metadata:read"):
                return
            payload = rows(conn, "SELECT name AS event_name, code AS unique_event_name, arm_name, day_offset FROM study_events WHERE study_id = ? ORDER BY display_order", (study_id,))
            return self.send_redcap_payload(payload, output_format)
        if content in {"arm", "arms"}:
            if not self.require_token_scope(token_row, "metadata:read"):
                return
            payload = self.arm_payload(conn, study_id)
            return self.send_redcap_payload(payload, output_format)
        if content in {"dag", "dags", "data_access_group", "data_access_groups"}:
            if not self.require_token_scope(token_row, "metadata:read"):
                return
            if not membership_has(membership, "manage_users"):
                self.send_error_json("User management permission required", 403)
                return
            payload = rows(conn, "SELECT code AS unique_group_name, name AS data_access_group_name FROM data_groups WHERE study_id = ? ORDER BY name", (study_id,))
            return self.send_redcap_payload(payload, output_format)
        if content in {"user", "users", "user_rights"}:
            if not self.require_token_scope(token_row, "metadata:read"):
                return
            if not membership_has(membership, "manage_users"):
                self.send_error_json("User management permission required", 403)
                return
            payload = self.user_rights_payload(conn, study_id)
            return self.send_redcap_payload(payload, output_format)
        if content in {"record", "records"}:
            if action == "import":
                if not self.require_token_scope(token_row, "records:write"):
                    return
                if not membership_has(membership, "enter_data"):
                    self.send_error_json("Data entry permission required", 403)
                    return
                csv_text = str(values.get("data", ""))
                if not csv_text and output_format == "json":
                    records = json.loads(str(values.get("records", "[]")))
                    csv_text = self.records_json_to_csv(records)
                return self.import_records_from_csv(conn, user, study_id, membership, csv_text)
            if not self.require_token_scope(token_row, "records:read"):
                return
            if not membership_has(membership, "export_data") and not membership_has(membership, "view_analysis"):
                self.send_error_json("Export permission required", 403)
                return
            payload = self.record_payload(conn, study_id, membership, {})
            return self.send_redcap_payload(payload, output_format, self.record_fieldnames(conn, study_id))
        if content == "randomization":
            if action != "allocate":
                if not self.require_token_scope(token_row, "metadata:read"):
                    return
                payload = rows(conn, "SELECT * FROM randomization_lists WHERE study_id = ? AND active = 1", (study_id,))
                return self.send_redcap_payload(payload, output_format)
            if not self.require_token_scope(token_row, "randomization:write"):
                return
            participant_uid = str(values.get("study_uid", "")).strip()
            list_id = int(values.get("list_id") or 0)
            participant = row(conn, "SELECT id FROM participants WHERE study_id = ? AND study_uid = ?", (study_id, participant_uid))
            if not participant:
                self.send_error_json("Participant not found", 404)
                return
            allocation = self.allocate_randomization(conn, user, study_id, list_id, participant["id"])
            conn.commit()
            return self.send_redcap_payload(allocation, output_format)
        self.send_error_json("Unsupported REDCap-style content", 400)

    def send_redcap_payload(self, payload, output_format: str, fieldnames: list[str] | None = None) -> None:
        if output_format == "csv":
            data = payload if isinstance(payload, list) else [payload]
            fields = fieldnames or (sorted({key for item in data for key in item.keys()}) if data else [])
            text_lines = []
            class Sink:
                def write(self, value):
                    text_lines.append(value)
            writer = csv.DictWriter(Sink(), fieldnames=fields)
            writer.writeheader()
            writer.writerows(data)
            content = "".join(text_lines).encode("utf-8-sig")
            self.send_response(200)
            self.send_header("content-type", "text/csv; charset=utf-8")
            self.send_header("content-length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return
        self.send_json(payload)

    def record_fieldnames(self, conn, study_id: int) -> list[str]:
        fields = ["study_uid", "initials", "participant_status", "event_name", "event_code", "repeat_instance", "form_name", "entry_status", "locked"]
        for form in rows(conn, "SELECT * FROM forms WHERE study_id = ? ORDER BY id", (study_id,)):
            for field in load_json(form["schema_json"], {"fields": []}).get("fields", []):
                fields.append(f"{form['code']}__{field.get('code')}")
        return fields

    def metadata_payload(self, conn, study_id: int) -> dict:
        study = row(conn, "SELECT * FROM studies WHERE id = ?", (study_id,))
        forms = rows(conn, "SELECT * FROM forms WHERE study_id = ? ORDER BY id", (study_id,))
        mappings = rows(conn, "SELECT form_events.*, study_events.name AS event_name, study_events.code AS event_code FROM form_events JOIN study_events ON study_events.id = form_events.event_id WHERE form_events.study_id = ? AND form_events.required = 1", (study_id,))
        events_by_form: dict[int, list[str]] = {}
        for mapping in mappings:
            events_by_form.setdefault(mapping["form_id"], []).append(mapping["event_code"])
        instruments = []
        data_dictionary = []
        for form in forms:
            schema = load_json(form["schema_json"], {"fields": []})
            instruments.append({"instrument_name": form["code"], "instrument_label": form["name"], "version": form["version"], "repeatable": bool(schema.get("repeatable"))})
            for order, field in enumerate(schema.get("fields", []), start=1):
                data_dictionary.append(
                    {
                        "field_name": field["code"],
                        "form_name": form["code"],
                        "section_header": "",
                        "field_type": field["type"],
                        "field_label": field["label"],
                        "select_choices_or_calculations": " | ".join(field.get("options", [])) or field.get("calculation", ""),
                        "field_note": "",
                        "text_validation_type_or_show_slider_number": "",
                        "text_validation_min": field.get("min", ""),
                        "text_validation_max": field.get("max", ""),
                        "identifier": "",
                        "branching_logic": f"[{field['show_if']['field']}] = '{field['show_if']['equals']}'" if field.get("show_if") else "",
                        "required_field": "y" if field.get("required") else "",
                        "custom_alignment": "",
                        "question_number": order,
                        "matrix_group_name": "",
                        "matrix_ranking": "",
                        "field_annotation": "",
                    }
                )
        return {"project": study, "instruments": instruments, "data_dictionary": data_dictionary, "events_by_form": events_by_form}

    def arm_payload(self, conn, study_id: int) -> list[dict]:
        arms = []
        seen = set()
        for event in rows(conn, "SELECT arm_name FROM study_events WHERE study_id = ? ORDER BY display_order, id", (study_id,)):
            arm_name = event.get("arm_name") or "Arm 1"
            if arm_name in seen:
                continue
            seen.add(arm_name)
            arms.append({"arm_num": len(arms) + 1, "name": arm_name})
        return arms or [{"arm_num": 1, "name": "Arm 1"}]

    def user_rights_payload(self, conn, study_id: int) -> list[dict]:
        memberships = rows(
            conn,
            """
            SELECT study_memberships.*, users.username, users.display_name, data_groups.code AS data_access_group
            FROM study_memberships
            JOIN users ON users.id = study_memberships.user_id
            LEFT JOIN data_groups ON data_groups.id = study_memberships.data_group_id
            WHERE study_memberships.study_id = ?
            ORDER BY users.username
            """,
            (study_id,),
        )
        permissions = ["manage_users", "manage_study", "manage_forms", "enter_data", "review_data", "export_data", "view_analysis"]
        payload = []
        for member in memberships:
            granted = ROLE_PERMISSIONS.get(member["role"], set()) if member["active"] else set()
            item = {
                "username": member["username"],
                "display_name": member["display_name"],
                "role": member["role"],
                "data_access_group": member.get("data_access_group") or "",
                "active": "1" if member["active"] else "0",
            }
            for permission in permissions:
                item[permission] = "1" if permission in granted else "0"
            payload.append(item)
        return payload

    def visible_studies(self, conn: sqlite3.Connection, user: dict) -> list[dict]:
        if is_super_admin(user):
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
        if not is_super_admin(user):
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
            if not username or len(password) < PASSWORD_MIN_LENGTH:
                self.send_error_json(f"Username and password with at least {PASSWORD_MIN_LENGTH} characters are required", 400)
                return
            if role_name not in ROLE_PERMISSIONS:
                self.send_error_json("Unsupported role", 400)
                return
            timestamp = now()
            cur = conn.execute(
                "INSERT INTO users(username, password_hash, display_name, role, active, must_change_password, created_at) VALUES (?, ?, ?, ?, 1, 1, ?)",
                (username, encode_password(password), display_name, role_name, timestamp),
            )
            after = row(conn, "SELECT id, username, display_name, role, active, must_change_password, created_at FROM users WHERE id = ?", (cur.lastrowid,))
            audit(conn, user["id"], "create", "user", cur.lastrowid, None, after)
            self.send_json({"user": after}, 201)
            return
        self.send_error_json("Unsupported user operation", 405)

    def admin_routes(self, conn: sqlite3.Connection, user: dict, method: str, path: str) -> None:
        if not is_super_admin(user):
            self.send_error_json("System admin permission required", 403)
            return
        parts = path.strip("/").split("/")
        if path == "/api/admin/status" and method == "GET":
            disk = shutil.disk_usage(ROOT)
            self.send_json(
                {
                    "health": health_payload(),
                    "disk": {"total": disk.total, "used": disk.used, "free": disk.free},
                    "logs": {"path": str(LOG_FILE), "exists": LOG_FILE.exists()},
                    "backups": {"directory": str(BACKUPS), "latest_backup_at": latest_backup_time()},
                    "settings": {
                        "environment": SETTINGS.env,
                        "database_backend": DATABASE_BACKEND,
                        "require_https": SETTINGS.require_https,
                        "public_base_url": SETTINGS.public_base_url,
                        "ai": ai_status(),
                    },
                }
            )
            return
        if path == "/api/admin/logs" and method == "GET":
            lines = []
            if LOG_FILE.exists():
                lines = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()[-500:]
            self.send_json({"lines": [self.sanitize_log_line(item) for item in lines]})
            return
        if path == "/api/admin/backups" and method == "GET":
            BACKUPS.mkdir(parents=True, exist_ok=True)
            files = []
            for item in sorted(BACKUPS.iterdir(), key=lambda path: path.stat().st_mtime, reverse=True):
                if item.is_file() and not item.name.endswith(".verify.json") and item.suffix in {".sqlite3", ".cdsenc", ".dump", ".gz"}:
                    backup_type = "full" if item.name.startswith("full_") or ".full." in item.name else ("postgres" if item.name.startswith("postgres_") or item.name.endswith(".dump") else "database")
                    files.append(latest_full_backup_info(item) if backup_type == "full" else backup_file_info(item, backup_type))
            self.send_json({"backups": files, "summary": health_payload()["backup"]})
            return
        if path == "/api/admin/backup" and method == "POST":
            payload = self.body()
            conn.commit()
            backup = create_database_backup(str(payload.get("passphrase", "")) or SETTINGS.backup_passphrase)
            audit(conn, user["id"], "create_encrypted" if backup["encrypted"] else "create", "backup", None, None, backup, **self.audit_context())
            self.send_json({"backup": backup}, 201)
            return
        if path == "/api/admin/backup/full" and method == "POST":
            payload = self.body()
            conn.commit()
            backup = create_full_backup(str(payload.get("passphrase", "")) or SETTINGS.backup_passphrase)
            audit(conn, user["id"], "create_full", "backup", None, None, backup, **self.audit_context())
            self.send_json({"backup": backup}, 201)
            return
        if path == "/api/admin/backups/verify" and method == "POST":
            payload = self.body()
            filename = Path(str(payload.get("filename", ""))).name
            target = (BACKUPS / filename).resolve() if filename else (full_backup_candidates()[0] if full_backup_candidates() else None)
            if not target or not str(target).startswith(str(BACKUPS.resolve())) or not target.exists():
                self.send_error_json("Full backup not found", 404)
                return
            verification = verify_full_backup(target, str(payload.get("passphrase", "")) or SETTINGS.backup_passphrase, record=True)
            audit(conn, user["id"], "verify", "backup", None, None, {"filename": target.name, "ok": verification["ok"]}, **self.audit_context())
            self.send_json({"verification": verification})
            return
        if len(parts) == 4 and parts[:3] == ["api", "admin", "backups"] and method == "GET":
            filename = Path(parts[3]).name
            target = (BACKUPS / filename).resolve()
            if not str(target).startswith(str(BACKUPS.resolve())) or not target.exists() or target.name.endswith(".verify.json"):
                self.send_error_json("Backup not found", 404)
                return
            content = target.read_bytes()
            audit(conn, user["id"], "download", "backup", None, None, {"filename": target.name, "size": target.stat().st_size}, **self.audit_context())
            conn.commit()
            self.send_response(200)
            self.send_header("content-type", "application/octet-stream")
            self.send_header("content-disposition", f"attachment; filename={target.name}")
            self.send_header("content-length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return
        if len(parts) == 5 and parts[:3] == ["api", "admin", "users"] and parts[4] == "reset-password" and method == "POST":
            target_user_id = int(parts[3])
            payload = self.body()
            password = str(payload.get("password", ""))
            if len(password) < PASSWORD_MIN_LENGTH:
                self.send_error_json(f"Temporary password must be at least {PASSWORD_MIN_LENGTH} characters", 400)
                return
            before = row(conn, "SELECT id, username, display_name, role, active, must_change_password FROM users WHERE id = ?", (target_user_id,))
            if not before:
                self.send_error_json("User not found", 404)
                return
            conn.execute("UPDATE users SET password_hash = ?, must_change_password = 1, failed_login_count = 0, locked_until = 0 WHERE id = ?", (encode_password(password), target_user_id))
            after = row(conn, "SELECT id, username, display_name, role, active, must_change_password FROM users WHERE id = ?", (target_user_id,))
            audit(conn, user["id"], "admin_reset_password", "user", target_user_id, before, after, **self.audit_context())
            self.send_json({"user": after})
            return
        if len(parts) == 4 and parts[:3] == ["api", "admin", "users"] and method == "PATCH":
            target_user_id = int(parts[3])
            before = row(conn, "SELECT id, username, display_name, role, active, must_change_password FROM users WHERE id = ?", (target_user_id,))
            if not before:
                self.send_error_json("User not found", 404)
                return
            payload = self.body()
            role_name = safe_role(str(payload.get("role", before["role"])))
            if role_name not in ROLE_PERMISSIONS:
                self.send_error_json("Unsupported role", 400)
                return
            active = 1 if payload.get("active", bool(before["active"])) else 0
            must_change = 1 if payload.get("must_change_password", bool(before["must_change_password"])) else 0
            display_name = str(payload.get("display_name", before["display_name"])).strip() or before["display_name"]
            conn.execute("UPDATE users SET display_name = ?, role = ?, active = ?, must_change_password = ? WHERE id = ?", (display_name, role_name, active, must_change, target_user_id))
            after = row(conn, "SELECT id, username, display_name, role, active, must_change_password FROM users WHERE id = ?", (target_user_id,))
            audit(conn, user["id"], "update", "user", target_user_id, before, after, **self.audit_context())
            self.send_json({"user": after})
            return
        self.send_error_json("Unknown admin route", 404)

    def sanitize_log_line(self, line: str) -> str:
        cleaned = re.sub(r"(password|passphrase|token|api[_-]?key|secret)=\S+", r"\1=[redacted]", line, flags=re.IGNORECASE)
        cleaned = re.sub(r"Bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [redacted]", cleaned)
        return cleaned[:1000]

    def change_password(self, conn: sqlite3.Connection, user: dict) -> None:
        payload = self.body()
        current_password = str(payload.get("current_password", ""))
        new_password = str(payload.get("new_password", ""))
        stored = row(conn, "SELECT password_hash FROM users WHERE id = ?", (user["id"],))
        if not stored or not verify_password(current_password, stored["password_hash"]):
            self.send_error_json("Current password is incorrect", 403)
            return
        if len(new_password) < PASSWORD_MIN_LENGTH:
            self.send_error_json(f"New password must be at least {PASSWORD_MIN_LENGTH} characters", 400)
            return
        conn.execute("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?", (encode_password(new_password), user["id"]))
        audit(conn, user["id"], "change_password", "user", user["id"], None, {"user_id": user["id"]})
        conn.commit()
        self.send_json({"ok": True})

    def assist_crf(self, conn: sqlite3.Connection, user: dict) -> None:
        payload = self.body()
        text = str(payload.get("text", "")).strip()
        if not text:
            self.send_error_json("CRF text is required", 400)
            return
        status = ai_status()
        warnings = []
        mode = "local"
        if status["external_ai_enabled"]:
            assert_external_ai_safe(text)
            try:
                schema = draft_crf_schema_with_openai(text)
                mode = "openai"
            except Exception as exc:
                schema, warnings = draft_crf_schema_locally(text)
                warnings.append(f"External AI drafting failed; local fallback used: {exc}")
        else:
            schema, warnings = draft_crf_schema_locally(text)
        audit(conn, user["id"], "assist_crf", "ai", None, None, {"mode": mode, "field_count": len(schema["fields"]), "warning_count": len(warnings)})
        self.send_json(
            {
                "schema": schema,
                "assistant": {
                    "mode": mode,
                    "field_count": len(schema["fields"]),
                    "warnings": warnings,
                    "safety_note": "Review every AI/local draft field before using it for real study data. Do not paste identifiers or PHI into external AI unless your study policy permits it.",
                },
            }
        )

    def create_study(self, conn: sqlite3.Connection, user: dict) -> None:
        if not is_super_admin(user):
            self.send_error_json("System admin permission required", 403)
            return
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
                   forms.name AS form_name, forms.code AS form_code, forms.schema_json, forms.version AS form_version,
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
        if survey.get("expires_at") and int(survey["expires_at"]) < now():
            self.send_error_json("Survey link has expired", 410)
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
        form_snapshot = form_schema_snapshot(
            {"id": survey["form_id"], "name": survey["form_name"], "code": survey["form_code"], "version": survey.get("form_version") or 1},
            schema,
        )
        form_version = int(survey.get("form_version") or 1)
        digest = entry_hash(cleaned, form_version, form_snapshot)
        snapshot_json = json.dumps(form_snapshot, sort_keys=True)
        existing = row(conn, "SELECT * FROM entries WHERE participant_id = ? AND form_id = ? AND event_name = ? AND repeat_instance = 1", (participant["id"], survey["form_id"], event_name))
        if existing:
            if existing.get("locked_at"):
                self.send_error_json("This submitted CRF is locked and cannot be updated from the public link", 423)
                return
            conn.execute(
                "UPDATE entries SET event_id = ?, data_json = ?, status = 'complete', form_version = ?, schema_snapshot_json = ?, entry_hash = ?, updated_at = ? WHERE id = ?",
                (event_id, json.dumps(cleaned), form_version, snapshot_json, digest, timestamp, existing["id"]),
            )
            entry_id = existing["id"]
            after = row(conn, "SELECT * FROM entries WHERE id = ?", (entry_id,))
            audit(conn, None, "public_update", "entry", entry_id, existing, after)
        else:
            cur = conn.execute(
                "INSERT INTO entries(study_id, participant_id, form_id, event_id, event_name, repeat_instance, status, data_json, form_version, schema_snapshot_json, entry_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, 'complete', ?, ?, ?, ?, ?, ?)",
                (survey["study_id"], participant["id"], survey["form_id"], event_id, event_name, json.dumps(cleaned), form_version, snapshot_json, digest, timestamp, timestamp),
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
        if survey.get("one_time"):
            conn.execute("UPDATE survey_links SET enabled = 0, updated_at = ? WHERE id = ?", (timestamp, survey["id"]))
            audit(conn, None, "disable_after_use", "survey_link", survey["id"], survey, {"entry_id": entry_id})
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
        if resource == "case-intake":
            if method == "GET":
                if not (membership_has(membership, "enter_data") or membership_has(membership, "view_analysis") or membership_has(membership, "review_data")):
                    self.send_error_json("Case intake permission required", 403)
                    return
            elif method == "POST":
                ai_review = len(parts) == 6 and parts[5] == "ai-review"
                if ai_review and not (membership_has(membership, "view_analysis") or membership_has(membership, "review_data")):
                    self.send_error_json("Analysis or review permission required", 403)
                    return
                if not ai_review and not membership_has(membership, "enter_data"):
                    self.send_error_json("Data entry permission required", 403)
                    return
            elif method == "PATCH":
                if not (membership_has(membership, "enter_data") or membership_has(membership, "review_data")):
                    self.send_error_json("Case update permission required", 403)
                    return
            else:
                self.send_error_json("Unsupported case intake operation", 405)
                return
            return self.case_intake(conn, user, method, study_id, parts, membership)
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
        if resource == "api-tokens":
            if not membership_has(membership, "manage_users"):
                self.send_error_json("User management permission required", 403)
                return
            return self.api_tokens(conn, user, method, study_id, parts)
        if resource == "randomization":
            if method != "GET" and not membership_has(membership, "manage_study") and not membership_has(membership, "review_data"):
                self.send_error_json("Study management or review permission required", 403)
                return
            return self.randomization(conn, user, method, study_id, parts)
        if resource == "metadata" and method == "GET":
            return self.metadata(conn, study_id)
        if resource == "validation" and method == "GET":
            if not membership_has(membership, "review_data") and not membership_has(membership, "manage_study"):
                self.send_error_json("Validation evidence permission required", 403)
                return
            return self.validation_evidence(conn, study_id)
        if resource == "validation-package" and method == "GET":
            if not membership_has(membership, "review_data") and not membership_has(membership, "manage_study"):
                self.send_error_json("Validation evidence permission required", 403)
                return
            return self.export_validation_package(conn, study_id)
        if resource == "readiness" and method == "GET":
            if not membership_has(membership, "review_data") and not membership_has(membership, "manage_study") and not membership_has(membership, "view_analysis"):
                self.send_error_json("Readiness permission required", 403)
                return
            return self.send_json({"readiness": self.readiness_payload(conn, study_id, membership)})
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
        if resource == "academic":
            if not (membership_has(membership, "view_analysis") or membership_has(membership, "review_data") or membership_has(membership, "export_data")):
                self.send_error_json("Academic workbench permission required", 403)
                return
            return self.academic_workbench(conn, user, method, study_id, parts, query, membership)
        if resource == "backups":
            if not membership_has(membership, "manage_study"):
                self.send_error_json("Study management permission required", 403)
                return
            return self.backups(conn, user, method, study_id, parts)
        if resource == "export" and method == "GET":
            if not membership_has(membership, "export_data"):
                self.send_error_json("Export permission required", 403)
                return
            audit(conn, user["id"], "export", "records", study_id, None, {"deidentified": membership.get("role") == "analyst"}, study_id=study_id, **self.audit_context())
            return self.export_csv(conn, study_id, membership, query)
        if resource == "odm" and method == "GET":
            if not membership_has(membership, "export_data"):
                self.send_error_json("Export permission required", 403)
                return
            audit(conn, user["id"], "export", "odm", study_id, None, {"format": "odm"}, study_id=study_id, **self.audit_context())
            return self.export_odm(conn, study_id)
        if resource == "stats-package" and method == "GET":
            if not membership_has(membership, "export_data"):
                self.send_error_json("Export permission required", 403)
                return
            package = (query.get("type") or ["r"])[0].lower()
            audit(conn, user["id"], "export", "stats_package", study_id, None, {"type": package, "deidentified": membership.get("role") == "analyst"}, study_id=study_id, **self.audit_context())
            return self.export_stats_package(conn, study_id, membership, package)
        if resource == "codebook" and method == "GET":
            if not membership_has(membership, "export_data"):
                self.send_error_json("Export permission required", 403)
                return
            audit(conn, user["id"], "export", "codebook", study_id, None, {"format": "csv"}, study_id=study_id, **self.audit_context())
            return self.export_codebook(conn, study_id)
        if resource == "audit" and method == "GET":
            if not membership_has(membership, "review_data"):
                self.send_error_json("Review permission required", 403)
                return
            audit_rows = rows(
                conn,
                f"""
                SELECT audit_log.*, users.display_name
                FROM audit_log
                LEFT JOIN users ON users.id = audit_log.user_id
                WHERE {STUDY_AUDIT_FILTER}
                ORDER BY audit_log.id DESC
                LIMIT 250
                """,
                study_audit_params(study_id),
            )
            return self.send_json({"audit": audit_rows})
        if resource == "audit-export" and method == "GET":
            if not membership_has(membership, "review_data"):
                self.send_error_json("Review permission required", 403)
                return
            audit(conn, user["id"], "export", "audit", study_id, None, {"format": "csv"}, study_id=study_id, **self.audit_context())
            return self.export_audit_csv(conn, study_id)
        self.send_error_json("Unknown study route", 404)

    def forms(self, conn, user, method, study_id, parts) -> None:
        if method == "GET" and len(parts) == 6 and parts[5] == "versions":
            form_id = int(parts[4])
            current = row(conn, "SELECT * FROM forms WHERE id = ? AND study_id = ?", (form_id, study_id))
            if not current:
                self.send_error_json("Form not found", 404)
                return
            versions = rows(conn, "SELECT id, form_id, study_id, version, name, code, schema_json, saved_by, saved_at FROM form_versions WHERE form_id = ? AND study_id = ? ORDER BY version DESC", (form_id, study_id))
            current_schema = load_json(current["schema_json"], {"fields": []})
            for version in versions:
                prior_schema = load_json(version.pop("schema_json"), {"fields": []})
                version["diff_to_current"] = form_schema_diff(prior_schema, current_schema)
            current_payload = {
                "id": current["id"],
                "form_id": current["id"],
                "study_id": study_id,
                "version": current["version"],
                "name": current["name"],
                "code": current["code"],
                "saved_by": None,
                "saved_at": current["updated_at"],
                "diff_to_current": {"fields_added": [], "fields_removed": [], "fields_changed": []},
                "current": True,
            }
            versions.insert(0, current_payload)
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
                INSERT INTO survey_links(study_id, form_id, event_id, token, title, enabled, expires_at, one_time, consent_required, consent_text, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    study_id,
                    form_id,
                    event_id,
                    secrets.token_urlsafe(24),
                    str(payload.get("title", form["name"])).strip() or form["name"],
                    1,
                    int(payload["expires_at"]) if payload.get("expires_at") else None,
                    1 if payload.get("one_time") else 0,
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
                "UPDATE survey_links SET title = ?, enabled = ?, expires_at = ?, one_time = ?, consent_required = ?, consent_text = ?, updated_at = ? WHERE id = ?",
                (
                    str(payload.get("title", before["title"])).strip() or before["title"],
                    1 if payload.get("enabled", bool(before["enabled"])) else 0,
                    int(payload["expires_at"]) if payload.get("expires_at") else None,
                    1 if payload.get("one_time", bool(before.get("one_time", 0))) else 0,
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
        return self.import_records_from_csv(conn, user, study_id, membership, csv_text)

    def records_json_to_csv(self, records: list[dict]) -> str:
        fields = sorted({key for item in records for key in item.keys()})
        text_lines = []
        class Sink:
            def write(self, value):
                text_lines.append(value)
        writer = csv.DictWriter(Sink(), fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)
        return "".join(text_lines)

    def import_records_from_csv(self, conn, user, study_id: int, membership, csv_text: str) -> None:
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
            form_snapshot = form_schema_snapshot(form, schema)
            form_version = int(form.get("version") or 1)
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
            digest = entry_hash(cleaned, form_version, form_snapshot)
            snapshot_json = json.dumps(form_snapshot, sort_keys=True)
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
                conn.execute(
                    "UPDATE entries SET event_id = ?, data_json = ?, status = ?, form_version = ?, schema_snapshot_json = ?, entry_hash = ?, updated_by = ?, updated_at = ? WHERE id = ?",
                    (event_id, json.dumps(cleaned), status, form_version, snapshot_json, digest, user["id"], timestamp, existing["id"]),
                )
                after = row(conn, "SELECT * FROM entries WHERE id = ?", (existing["id"],))
                audit(conn, user["id"], "import_update", "entry", existing["id"], existing, after)
                imported["entries_updated"] += 1
            else:
                cur = conn.execute(
                    "INSERT INTO entries(study_id, participant_id, form_id, event_id, event_name, repeat_instance, status, data_json, form_version, schema_snapshot_json, entry_hash, created_by, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (study_id, participant["id"], form["id"], event_id, event_name, repeat_instance, status, json.dumps(cleaned), form_version, snapshot_json, digest, user["id"], user["id"], timestamp, timestamp),
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
            conn.commit()
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
            conn.commit()
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
                entry["schema_snapshot"] = load_json(entry.pop("schema_snapshot_json"), {})
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
            snapshot = form_schema_snapshot(form, schema)
            form_version = int(form.get("version") or 1)
            if repeat_instance > 1 and not schema.get("repeatable"):
                self.send_error_json("This CRF is not configured as repeatable", 400)
                return
            cleaned, issues = validate_entry_data(schema, data)
            if issues:
                self.send_json({"errors": issues}, 422)
                return
            digest = entry_hash(cleaned, form_version, snapshot)
            snapshot_json = json.dumps(snapshot, sort_keys=True)
            existing = row(conn, "SELECT * FROM entries WHERE participant_id = ? AND form_id = ? AND event_name = ? AND repeat_instance = ?", (participant_id, form_id, event_name, repeat_instance))
            if existing:
                if existing.get("locked_at"):
                    reason = str(payload.get("change_reason", "")).strip()
                    if not reason:
                        self.send_error_json("Change reason is required before editing a locked CRF", 423)
                        return
                before = existing
                conn.execute(
                    "UPDATE entries SET event_id = ?, data_json = ?, status = ?, form_version = ?, schema_snapshot_json = ?, entry_hash = ?, updated_by = ?, updated_at = ?, locked_at = NULL, locked_by = NULL, lock_reason = '' WHERE id = ?",
                    (event_id, json.dumps(cleaned), status, form_version, snapshot_json, digest, user["id"], timestamp, existing["id"]),
                )
                after = row(conn, "SELECT * FROM entries WHERE id = ?", (existing["id"],))
                audit(conn, user["id"], "update", "entry", existing["id"], before, {"entry": after, "change_reason": payload.get("change_reason", "")})
                conn.commit()
                self.send_json({"entry": after})
                return
            cur = conn.execute(
                "INSERT INTO entries(study_id, participant_id, form_id, event_id, event_name, repeat_instance, status, data_json, form_version, schema_snapshot_json, entry_hash, created_by, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (study_id, participant_id, form_id, event_id, event_name, repeat_instance, status, json.dumps(cleaned), form_version, snapshot_json, digest, user["id"], user["id"], timestamp, timestamp),
            )
            after = row(conn, "SELECT * FROM entries WHERE id = ?", (cur.lastrowid,))
            audit(conn, user["id"], "create", "entry", cur.lastrowid, None, after)
            conn.commit()
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

    def case_payload(self, conn: sqlite3.Connection, case: dict) -> dict:
        payload = dict(case)
        payload["extracted"] = load_json(payload.pop("extracted_json", "{}"), {})
        payload["tags"] = load_json(payload.pop("tags_json", "[]"), [])
        payload["files"] = rows(
            conn,
            """
            SELECT id, name, original_filename, content_type, size, sha256, created_at
            FROM case_files
            WHERE case_id = ?
            ORDER BY id
            """,
            (case["id"],),
        )
        reviews = rows(
            conn,
            "SELECT id, user_prompt, mode, response_json, file_count, created_by, created_at FROM case_ai_reviews WHERE case_id = ? ORDER BY id DESC LIMIT 5",
            (case["id"],),
        )
        for review in reviews:
            review["response"] = load_json(review.pop("response_json"), {})
        payload["ai_reviews"] = reviews
        payload["latest_ai_review"] = reviews[0] if reviews else None
        return payload

    def case_rows(self, conn: sqlite3.Connection, study_id: int, membership: dict | None = None, user: dict | None = None) -> list[dict]:
        if membership and membership.get("data_group_id"):
            cases = rows(
                conn,
                """
                SELECT case_intakes.*
                FROM case_intakes
                LEFT JOIN participants ON participants.id = case_intakes.participant_id
                WHERE case_intakes.study_id = ?
                  AND (
                    participants.data_group_id = ?
                    OR (case_intakes.participant_id IS NULL AND case_intakes.created_by = ?)
                  )
                ORDER BY case_intakes.updated_at DESC, case_intakes.id DESC
                """,
                (study_id, membership["data_group_id"], user["id"] if user else 0),
            )
        else:
            cases = rows(conn, "SELECT * FROM case_intakes WHERE study_id = ? ORDER BY updated_at DESC, id DESC", (study_id,))
        return [self.case_payload(conn, item) for item in cases]

    def case_for_member(self, conn: sqlite3.Connection, study_id: int, case_id: int, membership: dict | None, user: dict) -> dict | None:
        case_row = row(conn, "SELECT * FROM case_intakes WHERE id = ? AND study_id = ?", (case_id, study_id))
        if not case_row:
            return None
        if membership and membership.get("data_group_id"):
            if case_row.get("participant_id"):
                participant = row(conn, "SELECT data_group_id FROM participants WHERE id = ? AND study_id = ?", (case_row["participant_id"], study_id))
                if not participant or participant.get("data_group_id") != membership["data_group_id"]:
                    return None
            elif case_row.get("created_by") != user["id"]:
                return None
        return case_row

    def save_case_files(self, conn: sqlite3.Connection, user_id: int, study_id: int, case_id: int, files: list) -> None:
        if len(files) > 8:
            raise ValueError("Upload at most 8 evidence files for one case")
        total_size = 0
        max_file_bytes = SETTINGS.max_upload_mb * 1024 * 1024
        max_total_bytes = max_file_bytes * 3
        for item in files:
            name = Path(str(item.get("name", "case_evidence"))).name[:160] or "case_evidence"
            content_type = str(item.get("type") or item.get("content_type") or mimetypes.guess_type(name)[0] or "application/octet-stream")[:120]
            data_base64 = str(item.get("data", ""))
            if not data_base64:
                continue
            if not allowed_evidence_content_type(content_type, name):
                raise ValueError(f"Evidence file {name} type is not allowed")
            try:
                decoded = base64.b64decode(data_base64, validate=True)
            except Exception as exc:
                raise ValueError(f"Evidence file {name} is not valid base64") from exc
            size = len(decoded)
            if len(decoded) > max_file_bytes:
                raise ValueError(f"Evidence file {name} is larger than {SETTINGS.max_upload_mb} MB")
            total_size += len(decoded)
            if total_size > max_total_bytes:
                raise ValueError(f"Total evidence upload for one case must stay under {SETTINGS.max_upload_mb * 3} MB")
            sha256 = hashlib.sha256(decoded).hexdigest()
            stored_filename = stored_case_filename(name)
            stored_path = case_upload_dir(study_id, case_id) / stored_filename
            stored_path.write_bytes(decoded)
            cur = conn.execute(
                """
                INSERT INTO case_files(
                    case_id, study_id, name, original_filename, stored_filename,
                    content_type, size, sha256, data_base64, created_by, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?)
                """,
                (case_id, study_id, name, name, stored_filename, content_type, size, sha256, user_id, now()),
            )
            audit(
                conn,
                user_id,
                "upload",
                "case_file",
                cur.lastrowid,
                None,
                {"case_id": case_id, "name": name, "content_type": content_type, "size": size, "sha256": sha256},
                study_id=study_id,
            )

    def case_intake(self, conn, user, method, study_id, parts, membership) -> None:
        if method == "GET" and len(parts) == 4:
            cases = self.case_rows(conn, study_id, membership, user)
            self.send_json({"cases": cases, "series": case_series_summary(cases), "ai": ai_status()})
            return
        if method == "GET" and len(parts) == 5 and parts[4] == "export":
            if not membership_has(membership, "export_data") and not membership_has(membership, "view_analysis"):
                self.send_error_json("Export permission required", 403)
                return
            return self.export_case_intake_csv(conn, study_id, membership, user)
        if method == "GET" and len(parts) == 7 and parts[5] == "files":
            case_id = int(parts[4])
            file_id = int(parts[6])
            if not self.case_for_member(conn, study_id, case_id, membership, user):
                self.send_error_json("Case evidence file not found", 404)
                return
            file_row = row(conn, "SELECT * FROM case_files WHERE id = ? AND case_id = ? AND study_id = ?", (file_id, case_id, study_id))
            if not file_row:
                self.send_error_json("Case evidence file not found", 404)
                return
            try:
                content = case_file_content(file_row)
            except Exception:
                self.send_error_json("Case evidence file content is unavailable", 404)
                return
            audit(conn, user["id"], "download", "case_file", file_id, None, {"case_id": case_id, "name": file_row["name"]}, study_id=study_id, **self.audit_context())
            conn.commit()
            self.send_response(200)
            self.send_header("content-type", file_row["content_type"] or "application/octet-stream")
            self.send_header("content-disposition", f"attachment; filename={Path(file_row['name']).name}")
            self.send_header("content-length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return
        if method == "POST" and len(parts) == 6 and parts[5] == "ai-review":
            case_id = int(parts[4])
            case_row = self.case_for_member(conn, study_id, case_id, membership, user)
            if not case_row:
                self.send_error_json("Case not found", 404)
                return
            payload = self.body()
            question = str(payload.get("question", "")).strip()
            all_cases = self.case_rows(conn, study_id, membership, user)
            case_item = self.case_payload(conn, case_row)
            status = ai_status()
            mode = "local"
            try:
                if status["external_ai_enabled"]:
                    response = openai_academic_case_review(conn, study_id, case_item, all_cases, question)
                    mode = "openai"
                else:
                    response = local_academic_case_review(case_item, all_cases, question)
            except Exception as exc:
                response = local_academic_case_review(case_item, all_cases, question)
                response["safety_notes"].append(f"External AI review failed; local fallback used: {exc}")
            file_count = len(case_item.get("files", []))
            timestamp = now()
            cur = conn.execute(
                """
                INSERT INTO case_ai_reviews(case_id, study_id, user_prompt, mode, response_json, file_count, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (case_id, study_id, question, mode, json.dumps(response), file_count, user["id"], timestamp),
            )
            review = row(conn, "SELECT id, user_prompt, mode, response_json, file_count, created_by, created_at FROM case_ai_reviews WHERE id = ?", (cur.lastrowid,))
            audit(conn, user["id"], "academic_ai_review", "case_ai_review", cur.lastrowid, None, {"case_id": case_id, "mode": mode, "file_count": file_count})
            conn.commit()
            review["response"] = load_json(review.pop("response_json"), {})
            self.send_json({"review": review, "ai": status}, 201)
            return
        if method == "POST" and len(parts) == 4:
            payload = self.body()
            timestamp = now()
            title = str(payload.get("title", "")).strip() or "Untitled Case"
            source_text = str(payload.get("source_text") or payload.get("text") or "").strip()
            files = payload.get("files") or []
            if not source_text and not files:
                self.send_error_json("Add typed/dictated text or at least one evidence file", 400)
                return
            case_uid_raw = str(payload.get("case_uid", "")).strip() or f"CASE-{timestamp}"
            case_uid = re.sub(r"[^A-Za-z0-9_.-]+", "-", case_uid_raw).strip("-")[:60] or f"CASE-{timestamp}"
            participant_id = int(payload.get("participant_id") or 0) or None
            if participant_id and not row(conn, "SELECT id FROM participants WHERE id = ? AND study_id = ?", (participant_id, study_id)):
                self.send_error_json("Linked participant not found", 404)
                return
            if participant_id and membership.get("data_group_id"):
                participant = row(conn, "SELECT data_group_id FROM participants WHERE id = ? AND study_id = ?", (participant_id, study_id))
                if not participant or participant.get("data_group_id") != membership["data_group_id"]:
                    self.send_error_json("Linked participant is outside your data access group", 403)
                    return
            extracted = extract_case_intelligence(source_text, title)
            status = str(payload.get("status", "draft")).strip().lower()
            if status not in {"draft", "triaged", "ready", "excluded"}:
                status = "draft"
            cur = conn.execute(
                """
                INSERT INTO case_intakes(study_id, participant_id, case_uid, title, status, source_text, extracted_json, tags_json, created_by, updated_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (study_id, participant_id, case_uid, title, status, source_text, json.dumps(extracted), json.dumps(extracted["tags"]), user["id"], user["id"], timestamp, timestamp),
            )
            self.save_case_files(conn, user["id"], study_id, cur.lastrowid, files)
            after = row(conn, "SELECT * FROM case_intakes WHERE id = ?", (cur.lastrowid,))
            audit(conn, user["id"], "create", "case_intake", cur.lastrowid, None, {"case": after, "file_count": len(files), "group": extracted["group_label"]})
            conn.commit()
            self.send_json({"case": self.case_payload(conn, after)}, 201)
            return
        if method == "PATCH" and len(parts) == 5:
            case_id = int(parts[4])
            before = self.case_for_member(conn, study_id, case_id, membership, user)
            if not before:
                self.send_error_json("Case not found", 404)
                return
            payload = self.body()
            title = str(payload.get("title", before["title"])).strip() or before["title"]
            source_text = str(payload.get("source_text", before["source_text"])).strip()
            status = str(payload.get("status", before["status"])).strip().lower()
            if status not in {"draft", "triaged", "ready", "excluded"}:
                status = before["status"]
            extracted = extract_case_intelligence(source_text, title)
            conn.execute(
                "UPDATE case_intakes SET title = ?, status = ?, source_text = ?, extracted_json = ?, tags_json = ?, updated_by = ?, updated_at = ? WHERE id = ? AND study_id = ?",
                (title, status, source_text, json.dumps(extracted), json.dumps(extracted["tags"]), user["id"], now(), case_id, study_id),
            )
            self.save_case_files(conn, user["id"], study_id, case_id, payload.get("files") or [])
            after = row(conn, "SELECT * FROM case_intakes WHERE id = ?", (case_id,))
            audit(conn, user["id"], "update", "case_intake", case_id, before, {"case": after, "group": extracted["group_label"]})
            conn.commit()
            self.send_json({"case": self.case_payload(conn, after)})
            return
        self.send_error_json("Unsupported case intake operation", 405)

    def export_case_intake_csv(self, conn, study_id: int, membership: dict | None, user: dict) -> None:
        cases = self.case_rows(conn, study_id, membership, user)
        fieldnames = ["case_uid", "title", "status", "group", "age", "sex", "diagnosis", "presentation", "investigations", "treatment", "outcome", "missing_fields", "warnings", "file_count", "updated_at"]
        text_lines = []
        class Sink:
            def write(self, value):
                text_lines.append(value)
        writer = csv.DictWriter(Sink(), fieldnames=fieldnames)
        writer.writeheader()
        for item in cases:
            extracted = item.get("extracted", {})
            clinical = extracted.get("clinical", {})
            demographics = extracted.get("demographics", {})
            writer.writerow(
                {
                    "case_uid": item["case_uid"],
                    "title": item["title"],
                    "status": item["status"],
                    "group": extracted.get("group_label", ""),
                    "age": demographics.get("age", ""),
                    "sex": demographics.get("sex", ""),
                    "diagnosis": clinical.get("diagnosis", ""),
                    "presentation": clinical.get("presentation", ""),
                    "investigations": clinical.get("investigations", ""),
                    "treatment": clinical.get("treatment", ""),
                    "outcome": clinical.get("outcome", ""),
                    "missing_fields": "; ".join(extracted.get("missing_fields", [])),
                    "warnings": "; ".join(extracted.get("warnings", [])),
                    "file_count": len(item.get("files", [])),
                    "updated_at": item["updated_at"],
                }
            )
        content = "".join(text_lines).encode("utf-8-sig")
        self.send_response(200)
        self.send_header("content-type", "text/csv; charset=utf-8")
        self.send_header("content-disposition", "attachment; filename=case_intake_export.csv")
        self.send_header("content-length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

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

    def api_tokens(self, conn, user, method, study_id, parts) -> None:
        if method == "GET":
            token_rows = rows(
                conn,
                """
                SELECT api_tokens.id, api_tokens.study_id, api_tokens.user_id, api_tokens.label, api_tokens.active,
                       api_tokens.scopes_json, api_tokens.created_at, api_tokens.last_used_at, users.username, users.display_name
                FROM api_tokens
                JOIN users ON users.id = api_tokens.user_id
                WHERE api_tokens.study_id = ?
                ORDER BY api_tokens.created_at DESC
                """,
                (study_id,),
            )
            for token_row in token_rows:
                token_row["scopes"] = sorted(parse_token_scopes(token_row.pop("scopes_json", "[]")))
            self.send_json({"tokens": token_rows})
            return
        if method == "POST":
            payload = self.body()
            user_id = int(payload.get("user_id") or user["id"])
            if not row(conn, "SELECT id FROM users WHERE id = ? AND active = 1", (user_id,)):
                self.send_error_json("User not found", 404)
                return
            label = str(payload.get("label", "API token")).strip() or "API token"
            scopes = payload.get("scopes") or DEFAULT_API_TOKEN_SCOPES
            if isinstance(scopes, str):
                scopes = [part.strip() for part in scopes.replace(",", " ").split() if part.strip()]
            scopes = sorted({scope for scope in scopes if scope in API_TOKEN_SCOPES})
            if not scopes:
                self.send_error_json("At least one valid API token scope is required", 400)
                return
            raw_token = f"cds_{secrets.token_urlsafe(32)}"
            timestamp = now()
            cur = conn.execute(
                "INSERT INTO api_tokens(study_id, user_id, token_hash, label, scopes_json, active, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)",
                (study_id, user_id, token_digest(raw_token), label, json.dumps(scopes), timestamp),
            )
            after = row(conn, "SELECT id, study_id, user_id, label, scopes_json, active, created_at, last_used_at FROM api_tokens WHERE id = ?", (cur.lastrowid,))
            after["scopes"] = sorted(parse_token_scopes(after.pop("scopes_json", "[]")))
            audit(conn, user["id"], "create", "api_token", cur.lastrowid, None, after)
            conn.commit()
            self.send_json({"token": raw_token, "record": after}, 201)
            return
        if method == "PATCH" and len(parts) == 5:
            token_id = int(parts[4])
            before = row(conn, "SELECT id, study_id, user_id, label, scopes_json, active, created_at, last_used_at FROM api_tokens WHERE id = ? AND study_id = ?", (token_id, study_id))
            if not before:
                self.send_error_json("API token not found", 404)
                return
            payload = self.body()
            active = 1 if payload.get("active", bool(before["active"])) else 0
            scopes = before["scopes_json"]
            if "scopes" in payload:
                requested = payload.get("scopes") or []
                if isinstance(requested, str):
                    requested = [part.strip() for part in requested.replace(",", " ").split() if part.strip()]
                normalized = sorted({scope for scope in requested if scope in API_TOKEN_SCOPES})
                if not normalized:
                    self.send_error_json("At least one valid API token scope is required", 400)
                    return
                scopes = json.dumps(normalized)
            conn.execute("UPDATE api_tokens SET active = ?, scopes_json = ? WHERE id = ?", (active, scopes, token_id))
            after = row(conn, "SELECT id, study_id, user_id, label, scopes_json, active, created_at, last_used_at FROM api_tokens WHERE id = ?", (token_id,))
            before["scopes"] = sorted(parse_token_scopes(before.pop("scopes_json", "[]")))
            after["scopes"] = sorted(parse_token_scopes(after.pop("scopes_json", "[]")))
            audit(conn, user["id"], "update", "api_token", token_id, before, after)
            conn.commit()
            self.send_json({"token": after})
            return
        self.send_error_json("Unsupported API token operation", 405)

    def randomization(self, conn, user, method, study_id, parts) -> None:
        if method == "GET" and len(parts) == 4:
            lists = rows(conn, "SELECT * FROM randomization_lists WHERE study_id = ? ORDER BY created_at DESC", (study_id,))
            allocations = rows(
                conn,
                """
                SELECT randomization_allocations.*, participants.study_uid, randomization_lists.name AS list_name
                FROM randomization_allocations
                JOIN participants ON participants.id = randomization_allocations.participant_id
                JOIN randomization_lists ON randomization_lists.id = randomization_allocations.list_id
                WHERE randomization_allocations.study_id = ?
                ORDER BY randomization_allocations.created_at DESC
                """,
                (study_id,),
            )
            for item in lists:
                item["arms"] = load_json(item.pop("arms_json"), [])
            self.send_json({"lists": lists, "allocations": allocations})
            return
        if method == "POST" and len(parts) == 4:
            payload = self.body()
            arms = payload.get("arms") or []
            if isinstance(arms, str):
                arms = [part.strip() for part in arms.replace("|", ",").split(",") if part.strip()]
            arms = [str(arm).strip() for arm in arms if str(arm).strip()]
            if len(arms) < 2:
                self.send_error_json("At least two randomization arms are required", 400)
                return
            timestamp = now()
            cur = conn.execute(
                "INSERT INTO randomization_lists(study_id, name, arms_json, active, created_by, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?, ?)",
                (study_id, str(payload.get("name", "Randomization List")).strip() or "Randomization List", json.dumps(arms), user["id"], timestamp, timestamp),
            )
            after = row(conn, "SELECT * FROM randomization_lists WHERE id = ?", (cur.lastrowid,))
            audit(conn, user["id"], "create", "randomization_list", cur.lastrowid, None, after)
            conn.commit()
            self.send_json({"list": after}, 201)
            return
        if method == "POST" and len(parts) == 6 and parts[5] == "allocate":
            list_id = int(parts[4])
            payload = self.body()
            participant_id = int(payload.get("participant_id") or 0)
            after = self.allocate_randomization(conn, user, study_id, list_id, participant_id)
            conn.commit()
            self.send_json({"allocation": after}, 201)
            return
        self.send_error_json("Unsupported randomization operation", 405)

    def allocate_randomization(self, conn, user, study_id: int, list_id: int, participant_id: int) -> dict:
        random_list = row(conn, "SELECT * FROM randomization_lists WHERE id = ? AND study_id = ? AND active = 1", (list_id, study_id))
        if not random_list:
            raise ValueError("Randomization list not found")
        if not row(conn, "SELECT id FROM participants WHERE id = ? AND study_id = ?", (participant_id, study_id)):
            raise ValueError("Participant not found")
        existing = row(conn, "SELECT * FROM randomization_allocations WHERE list_id = ? AND participant_id = ?", (list_id, participant_id))
        if existing:
            return existing
        arms = load_json(random_list["arms_json"], [])
        if not arms:
            raise ValueError("Randomization list has no arms")
        index = int(random_list["next_index"] or 0)
        arm = arms[index % len(arms)]
        timestamp = now()
        cur = conn.execute(
            "INSERT INTO randomization_allocations(study_id, list_id, participant_id, arm, allocated_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (study_id, list_id, participant_id, arm, user["id"], timestamp),
        )
        conn.execute("UPDATE randomization_lists SET next_index = ?, updated_at = ? WHERE id = ?", (index + 1, timestamp, list_id))
        after = row(conn, "SELECT * FROM randomization_allocations WHERE id = ?", (cur.lastrowid,))
        audit(conn, user["id"], "allocate", "randomization", cur.lastrowid, None, after)
        return after

    def metadata(self, conn, study_id: int) -> None:
        payload = self.metadata_payload(conn, study_id)
        self.send_json({"project": payload["project"], "instruments": payload["instruments"], "data_dictionary": payload["data_dictionary"]})

    def validation_evidence(self, conn, study_id: int) -> None:
        self.send_json(self.validation_payload(conn, study_id))

    def validation_payload(self, conn, study_id: int) -> dict:
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
        protection = data_protection_status()
        recent_audit = rows(conn, "SELECT audit_log.*, users.display_name FROM audit_log LEFT JOIN users ON users.id = audit_log.user_id ORDER BY audit_log.id DESC LIMIT 50")
        checks = [
            {"name": "first_run_setup", "status": "document", "evidence": "Confirm permanent admin account setup in access review."},
            {"name": "crf_versioning", "status": "available", "evidence": f"{counts['forms']} CRF(s) configured."},
            {"name": "public_surveys", "status": "available" if counts["survey_links"] else "not_used", "evidence": f"{counts['survey_links']} survey link(s)."},
            {"name": "econsent", "status": "available" if counts["consent_signatures"] else "not_used", "evidence": f"{counts['consent_signatures']} consent signature(s)."},
            {"name": "backup_restore", "status": "document", "evidence": "Run backup restore drill and attach result."},
            {"name": "data_folder_encryption", "status": "available" if protection["data_folder_encrypted"] else "not_enabled", "evidence": protection["note"]},
            {"name": "audit_review", "status": "available", "evidence": f"{counts['audit_events']} audit event(s)."},
        ]
        return {"study": study, "generated_at": now(), "counts": counts, "data_protection": protection, "checks": checks, "recent_audit": recent_audit}

    def export_validation_package(self, conn, study_id: int) -> None:
        study = row(conn, "SELECT * FROM studies WHERE id = ?", (study_id,))
        evidence = self.validation_payload(conn, study_id)
        metadata = self.metadata_payload(conn, study_id)
        audit_sample = rows(conn, "SELECT audit_log.*, users.display_name FROM audit_log LEFT JOIN users ON users.id = audit_log.user_id ORDER BY audit_log.id DESC LIMIT 250")
        manifest = {
            "application": "Clinical Data Studio",
            "generated_at": now(),
            "study_id": study["id"],
            "study_name": study["name"],
            "python": sys.version,
            "platform": platform.platform(),
            "database": str(DB_PATH),
            "data_folder": str(DATA),
            "ai": ai_status(),
            "commit": os.environ.get("CDS_COMMIT", "record-current-git-commit-manually"),
        }
        checklist = (ROOT / "docs" / "SOP_VALIDATION_CHECKLIST.md").read_text(encoding="utf-8")
        execution_record = (ROOT / "docs" / "VALIDATION_EXECUTION_RECORD.md").read_text(encoding="utf-8")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
            archive_path = Path(tmp.name)
        try:
            with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("validation_evidence.json", json.dumps(evidence, indent=2))
                archive.writestr("metadata_codebook.json", json.dumps(metadata, indent=2))
                archive.writestr("audit_sample.json", json.dumps(audit_sample, indent=2))
                archive.writestr("system_manifest.json", json.dumps(manifest, indent=2))
                archive.writestr("SOP_VALIDATION_CHECKLIST.md", checklist)
                archive.writestr("VALIDATION_EXECUTION_RECORD.md", execution_record)
                archive.writestr(
                    "README.txt",
                    "Clinical Data Studio validation package.\nReview every file, complete the execution record, attach screenshots, and sign off before real study use.\n",
                )
            content = archive_path.read_bytes()
        finally:
            archive_path.unlink(missing_ok=True)
        safe_name = normalize_code(study["name"], "study")
        self.send_response(200)
        self.send_header("content-type", "application/zip")
        self.send_header("content-disposition", f"attachment; filename={safe_name}_validation_package.zip")
        self.send_header("content-length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def readiness_payload(self, conn, study_id: int, membership) -> dict:
        forms = rows(conn, "SELECT * FROM forms WHERE study_id = ?", (study_id,))
        field_count = sum(len(load_json(form["schema_json"], {"fields": []}).get("fields", [])) for form in forms)
        participants = row(conn, "SELECT COUNT(*) AS count FROM participants WHERE study_id = ?", (study_id,))["count"]
        entries = row(conn, "SELECT COUNT(*) AS count FROM entries WHERE study_id = ?", (study_id,))["count"]
        completed = row(conn, "SELECT COUNT(*) AS count FROM entries WHERE study_id = ? AND status = 'complete'", (study_id,))["count"]
        locked = row(conn, "SELECT COUNT(*) AS count FROM entries WHERE study_id = ? AND locked_at IS NOT NULL", (study_id,))["count"]
        open_queries = row(conn, "SELECT COUNT(*) AS count FROM queries WHERE study_id = ? AND status = 'open'", (study_id,))["count"]
        memberships = row(conn, "SELECT COUNT(*) AS count FROM study_memberships WHERE study_id = ? AND active = 1", (study_id,))["count"]
        non_admin_users = row(
            conn,
            """
            SELECT COUNT(*) AS count
            FROM study_memberships
            JOIN users ON users.id = study_memberships.user_id
            WHERE study_memberships.study_id = ? AND study_memberships.active = 1 AND users.username <> 'admin'
            """,
            (study_id,),
        )["count"]
        field_states = rows(conn, "SELECT state, COUNT(*) AS count FROM field_states JOIN entries ON entries.id = field_states.entry_id WHERE entries.study_id = ? GROUP BY state", (study_id,))
        state_counts = {item["state"]: item["count"] for item in field_states}
        audit_events = row(conn, f"SELECT COUNT(*) AS count FROM audit_log WHERE {STUDY_AUDIT_FILTER}", study_audit_params(study_id))["count"]
        quality_count = len(self.quality_issues(conn, study_id, membership))
        backups = backup_files_for_study(study_id)
        encrypted_backups = [item for item in backups if item["encrypted"]]
        latest_backup_at = backups[0]["created_at"] if backups else None
        protection = data_protection_status()
        ai = ai_status()

        items = []

        def add_item(key, label, status, detail, action, weight=1):
            items.append({"key": key, "label": label, "status": status, "detail": detail, "action": action, "weight": weight})

        add_item(
            "admin_setup",
            "Administrator setup",
            "pass" if not setup_required(conn) else "fail",
            "Default administrator password has been changed." if not setup_required(conn) else "Default admin password is still active.",
            "Complete first-run setup or change the admin password.",
            2,
        )
        add_item(
            "crf_design",
            "CRF design",
            "pass" if forms and field_count else "fail",
            f"{len(forms)} form(s), {field_count} field(s).",
            "Build or import the study data dictionary before collecting data.",
            2,
        )
        add_item(
            "access_review",
            "Access review",
            "pass" if non_admin_users else ("warn" if memberships else "fail"),
            f"{memberships} active membership(s), {non_admin_users} named non-admin user(s).",
            "Create named users and avoid shared admin use for study work.",
            2,
        )
        add_item(
            "data_capture",
            "Data capture",
            "pass" if participants and entries else ("warn" if participants else "warn"),
            f"{participants} participant(s), {entries} CRF entrie(s), {completed} complete.",
            "Enter pilot records and verify the workflow on desktop and mobile.",
        )
        add_item(
            "data_quality",
            "Data quality",
            "pass" if quality_count == 0 else "warn",
            f"{quality_count} edit-check or missing-CRF issue(s).",
            "Resolve quality issues or document acceptable deviations before export.",
            2,
        )
        add_item(
            "query_review",
            "Query review",
            "pass" if open_queries == 0 else "warn",
            f"{open_queries} open querie(s).",
            "Close or document open queries before analysis lock.",
            2,
        )
        add_item(
            "review_lock",
            "Review controls",
            "pass" if locked or state_counts.get("verified") or state_counts.get("frozen") else "warn",
            f"{locked} locked CRF(s), {state_counts.get('verified', 0)} verified field(s), {state_counts.get('frozen', 0)} frozen field(s).",
            "Use field verification/freeze and CRF locks for reviewed data.",
        )
        add_item(
            "backup",
            "Backups",
            "pass" if encrypted_backups else ("warn" if backups else "fail"),
            f"{len(backups)} backup(s), {len(encrypted_backups)} encrypted archive(s).",
            "Create an encrypted backup and perform a restore drill.",
            2,
        )
        add_item(
            "at_rest_protection",
            "At-rest protection",
            "pass" if protection["data_folder_encrypted"] or encrypted_backups else "warn",
            protection["note"],
            "Enable Windows EFS for the data folder or rely on encrypted archives for backup copies.",
        )
        add_item(
            "audit_trail",
            "Audit trail",
            "pass" if audit_events else "warn",
            f"{audit_events} audit event(s) available for review.",
            "Export and sign off audit review at study milestones.",
        )
        add_item(
            "ai_policy",
            "AI policy",
            "warn" if ai["external_ai_enabled"] else "pass",
            f"AI mode: {ai['provider']} / {ai['model']}.",
            "Keep external AI disabled unless de-identification policy and approvals are in place.",
        )

        possible = sum(item["weight"] for item in items)
        earned = sum(item["weight"] if item["status"] == "pass" else item["weight"] * 0.5 if item["status"] == "warn" else 0 for item in items)
        score = round((earned / possible) * 100) if possible else 0
        status = "ready" if score >= 85 and not any(item["status"] == "fail" for item in items) else "needs_review" if score >= 65 else "blocked"
        blockers = [item for item in items if item["status"] == "fail"]
        warnings = [item for item in items if item["status"] == "warn"]
        next_actions = [item["action"] for item in blockers[:3]] or [item["action"] for item in warnings[:3]] or ["Continue routine backup, audit, and access review."]
        return {
            "score": score,
            "status": status,
            "generated_at": now(),
            "items": items,
            "blockers": blockers,
            "warnings": warnings,
            "next_actions": next_actions,
            "metrics": {
                "participants": participants,
                "entries": entries,
                "completed_entries": completed,
                "completion_percent": round((completed / entries) * 100) if entries else 0,
                "open_queries": open_queries,
                "quality_issues": quality_count,
                "latest_backup_at": latest_backup_at,
            },
        }

    def quality_issues(self, conn, study_id: int, membership) -> list[dict]:
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
            schema = schema_for_entry(entry, load_json(entry["schema_json"], {"fields": []}))
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
        return issues

    def quality(self, conn, study_id: int, membership) -> None:
        self.send_json({"issues": self.quality_issues(conn, study_id, membership)})

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
            schema = schema_for_entry(entry, load_json(entry["schema_json"], {"fields": []}))
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
            SELECT entries.data_json, entries.schema_snapshot_json, forms.schema_json
            FROM entries
            JOIN forms ON forms.id = entries.form_id
            {group_join}
            WHERE entries.study_id = ?{group_where}
            """,
            tuple(params),
        )
        for entry in quality_rows:
            _, issues = validate_entry_data(schema_for_entry(entry, load_json(entry["schema_json"], {"fields": []})), load_json(entry["data_json"], {}))
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

    def export_csv(self, conn, study_id: int, membership, query: dict[str, list[str]] | None = None) -> None:
        deidentified = membership.get("role") == "analyst"
        if query:
            value = (query.get("deidentified") or query.get("deidentified_export") or [""])[0].strip().lower()
            deidentified = deidentified or value in {"1", "true", "yes", "on"}
        filename = "clinical_data_deidentified_export.csv" if deidentified else "clinical_data_export.csv"
        return self.export_entries_csv(conn, study_id, membership, {"deidentified": deidentified}, filename)

    def record_payload(self, conn, study_id: int, membership, filters: dict) -> list[dict]:
        deidentified = bool(filters.get("deidentified")) or membership.get("role") == "analyst"
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
                   forms.name AS form_name, forms.code AS form_code, forms.schema_json, forms.version AS current_form_version,
                   study_events.name AS mapped_event_name, study_events.code AS event_code
            FROM entries
            JOIN participants ON participants.id = entries.participant_id
            JOIN forms ON forms.id = entries.form_id
            LEFT JOIN study_events ON study_events.id = entries.event_id
            WHERE {" AND ".join(where)}
            ORDER BY participants.study_uid, study_events.display_order, forms.id
        """
        payload = []
        export_ids: dict[int, str] = {}
        for entry in rows(conn, sql, tuple(params)):
            data = load_json(entry["data_json"], {})
            snapshot = load_json(entry.get("schema_snapshot_json"), {})
            schema = schema_for_entry(entry, load_json(entry["schema_json"], {"fields": []}))
            form_code = snapshot.get("form_code") or entry["form_code"]
            captured_version = int(entry.get("form_version") or snapshot.get("form_version") or 1)
            current_version = int(entry.get("current_form_version") or captured_version)
            export_ids.setdefault(entry["participant_id"], f"EXP{len(export_ids) + 1:05d}")
            record = {
                "study_uid": export_ids[entry["participant_id"]] if deidentified else entry["study_uid"],
                "initials": "" if deidentified else entry["initials"],
                "participant_status": entry["participant_status"],
                "event_name": entry.get("mapped_event_name") or entry["event_name"],
                "event_code": entry.get("event_code") or entry["event_name"],
                "repeat_instance": entry["repeat_instance"],
                "form_name": entry["form_name"],
                "form_version": captured_version,
                "form_version_warning": "older_form_version" if captured_version < current_version else "",
                "entry_status": entry["status"],
                "locked": "yes" if entry["locked_at"] else "no",
            }
            for field in schema.get("fields", []):
                field_code = field.get("code", "")
                if not field_code:
                    continue
                code = f"{form_code}__{field_code}"
                value = data.get(field_code, "")
                record[code] = deidentify_for_ai(str(value), record["study_uid"]) if deidentified and isinstance(value, str) else value
            payload.append(record)
        return payload

    def export_entries_csv(self, conn, study_id: int, membership, filters: dict, filename: str) -> None:
        records = self.record_payload(conn, study_id, membership, filters)
        fieldnames = list(dict.fromkeys(key for record in records for key in record.keys())) if records else ["study_uid", "initials", "participant_status", "event_name", "event_code", "repeat_instance", "form_name", "form_version", "form_version_warning", "entry_status", "locked"]
        text_lines = []
        class Sink:
            def write(self, value):
                text_lines.append(value)
        writer = csv.DictWriter(Sink(), fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)
        content = "".join(text_lines).encode("utf-8-sig")
        self.send_response(200)
        self.send_header("content-type", "text/csv; charset=utf-8")
        self.send_header("content-disposition", f"attachment; filename={filename}")
        self.send_header("x-cds-deidentified-export", "1" if filters.get("deidentified") or membership.get("role") == "analyst" else "0")
        self.send_header("content-length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def export_audit_csv(self, conn, study_id: int) -> None:
        audit_rows = rows(
            conn,
            f"""
            SELECT audit_log.id, audit_log.created_at, users.username, users.display_name,
                   audit_log.action, audit_log.entity_type, audit_log.entity_id, audit_log.before_json, audit_log.after_json
            FROM audit_log
            LEFT JOIN users ON users.id = audit_log.user_id
            WHERE {STUDY_AUDIT_FILTER}
            ORDER BY audit_log.id DESC
            LIMIT 5000
            """,
            study_audit_params(study_id),
        )
        fieldnames = ["id", "created_at", "username", "display_name", "action", "entity_type", "entity_id", "before_json", "after_json"]
        text_lines = []
        class Sink:
            def write(self, value):
                text_lines.append(value)
        writer = csv.DictWriter(Sink(), fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows([dict(item) for item in audit_rows])
        content = "".join(text_lines).encode("utf-8-sig")
        self.send_response(200)
        self.send_header("content-type", "text/csv; charset=utf-8")
        self.send_header("content-disposition", "attachment; filename=audit_trail_export.csv")
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

    def academic_cv_rows(self, conn, study_id: int) -> list[dict]:
        data = rows(
            conn,
            """
            SELECT academic_cv_items.*, case_intakes.case_uid AS linked_case_uid, users.display_name AS updated_by_name
            FROM academic_cv_items
            LEFT JOIN case_intakes ON case_intakes.id = academic_cv_items.linked_case_id
            LEFT JOIN users ON users.id = academic_cv_items.updated_by
            WHERE academic_cv_items.study_id = ? AND academic_cv_items.active = 1
            ORDER BY academic_cv_items.item_date DESC, academic_cv_items.updated_at DESC, academic_cv_items.id DESC
            """,
            (study_id,),
        )
        for item in data:
            item["metadata"] = load_json(item.pop("metadata_json"), {})
        return data

    def academic_payload(self, conn, study_id: int, membership: dict | None = None, user: dict | None = None) -> dict:
        study = row(conn, "SELECT * FROM studies WHERE id = ?", (study_id,))
        cases = self.case_rows(conn, study_id, membership, user)
        cv_items = self.academic_cv_rows(conn, study_id)
        opportunities = publication_opportunities(cases)
        ai_review_count = row(conn, "SELECT COUNT(*) AS count FROM case_ai_reviews WHERE study_id = ?", (study_id,))["count"]
        report_count = row(conn, "SELECT COUNT(*) AS count FROM reports WHERE study_id = ?", (study_id,))["count"]
        return {
            "metrics": {
                "case_count": len(cases),
                "opportunity_count": len(opportunities),
                "cv_item_count": len(cv_items),
                "ai_review_count": ai_review_count,
                "report_count": report_count,
            },
            "opportunities": opportunities,
            "cv_items": cv_items,
            "cv_markdown": academic_cv_markdown(study, cv_items, opportunities),
            "ai": ai_status(),
            "guidance": [
                "Use Case Intake for messy notes, photos, audio, PDFs, and scanned case details.",
                "Run Academic AI review only on de-identified material unless policy explicitly allows PHI.",
                "Promote strong case groups into CV items when an abstract, poster, manuscript, audit, or presentation starts.",
                "Export the CV tracker before appraisal, grant, promotion, or manuscript planning meetings.",
            ],
        }

    def academic_workbench(self, conn, user, method, study_id, parts, query, membership) -> None:
        if method == "GET" and len(parts) == 4:
            self.send_json({"academic": self.academic_payload(conn, study_id, membership, user)})
            return
        if method == "GET" and len(parts) == 5 and parts[4] == "export":
            fmt = (query.get("format") or ["md"])[0].lower()
            payload = self.academic_payload(conn, study_id, membership, user)
            audit(conn, user["id"], "export", "academic_cv_item", study_id, None, {"format": fmt}, study_id=study_id, **self.audit_context())
            if fmt == "csv":
                fields = ["item_type", "title", "role", "status", "item_date", "citation", "notes", "linked_case_uid"]
                text_lines = []
                class Sink:
                    def write(self, value):
                        text_lines.append(value)
                writer = csv.DictWriter(Sink(), fieldnames=fields)
                writer.writeheader()
                for item in payload["cv_items"]:
                    writer.writerow({field: item.get(field, "") for field in fields})
                content = "".join(text_lines).encode("utf-8-sig")
                self.send_response(200)
                self.send_header("content-type", "text/csv; charset=utf-8")
                self.send_header("content-disposition", "attachment; filename=academic_cv_tracker.csv")
                self.send_header("content-length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            content = payload["cv_markdown"].encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "text/markdown; charset=utf-8")
            self.send_header("content-disposition", "attachment; filename=academic_portfolio.md")
            self.send_header("content-length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return
        if method == "POST" and len(parts) == 5 and parts[4] == "cv-items":
            payload = self.body()
            timestamp = now()
            title = str(payload.get("title", "")).strip()
            if not title:
                self.send_error_json("CV item title is required", 400)
                return
            linked_case_id = int(payload.get("linked_case_id") or 0) or None
            if linked_case_id and not row(conn, "SELECT id FROM case_intakes WHERE id = ? AND study_id = ?", (linked_case_id, study_id)):
                self.send_error_json("Linked case not found", 404)
                return
            item_type = normalize_code(str(payload.get("item_type", "publication")))[:40] or "publication"
            status = normalize_code(str(payload.get("status", "planned")))[:40] or "planned"
            cur = conn.execute(
                """
                INSERT INTO academic_cv_items(study_id, item_type, title, role, status, item_date, citation, notes, linked_case_id, metadata_json, active, created_by, updated_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                """,
                (
                    study_id,
                    item_type,
                    title,
                    str(payload.get("role", "")).strip()[:160],
                    status,
                    str(payload.get("item_date", "")).strip()[:40],
                    str(payload.get("citation", "")).strip(),
                    str(payload.get("notes", "")).strip(),
                    linked_case_id,
                    json.dumps(payload.get("metadata", {})),
                    user["id"],
                    user["id"],
                    timestamp,
                    timestamp,
                ),
            )
            after = row(conn, "SELECT * FROM academic_cv_items WHERE id = ?", (cur.lastrowid,))
            audit(conn, user["id"], "create", "academic_cv_item", cur.lastrowid, None, after, study_id=study_id, **self.audit_context())
            conn.commit()
            self.send_json({"cv_item": after}, 201)
            return
        if method == "PATCH" and len(parts) == 6 and parts[4] == "cv-items":
            item_id = int(parts[5])
            before = row(conn, "SELECT * FROM academic_cv_items WHERE id = ? AND study_id = ?", (item_id, study_id))
            if not before:
                self.send_error_json("CV item not found", 404)
                return
            payload = self.body()
            linked_case_id = payload.get("linked_case_id", before.get("linked_case_id"))
            linked_case_id = int(linked_case_id or 0) or None
            if linked_case_id and not row(conn, "SELECT id FROM case_intakes WHERE id = ? AND study_id = ?", (linked_case_id, study_id)):
                self.send_error_json("Linked case not found", 404)
                return
            conn.execute(
                """
                UPDATE academic_cv_items
                SET item_type = ?, title = ?, role = ?, status = ?, item_date = ?, citation = ?, notes = ?, linked_case_id = ?, metadata_json = ?, active = ?, updated_by = ?, updated_at = ?
                WHERE id = ? AND study_id = ?
                """,
                (
                    normalize_code(str(payload.get("item_type", before["item_type"])))[:40] or before["item_type"],
                    str(payload.get("title", before["title"])).strip() or before["title"],
                    str(payload.get("role", before["role"])).strip()[:160],
                    normalize_code(str(payload.get("status", before["status"])))[:40] or before["status"],
                    str(payload.get("item_date", before["item_date"])).strip()[:40],
                    str(payload.get("citation", before["citation"])).strip(),
                    str(payload.get("notes", before["notes"])).strip(),
                    linked_case_id,
                    json.dumps(payload.get("metadata", load_json(before["metadata_json"], {}))),
                    1 if payload.get("active", bool(before["active"])) else 0,
                    user["id"],
                    now(),
                    item_id,
                    study_id,
                ),
            )
            after = row(conn, "SELECT * FROM academic_cv_items WHERE id = ?", (item_id,))
            audit(conn, user["id"], "update", "academic_cv_item", item_id, before, after, study_id=study_id, **self.audit_context())
            conn.commit()
            self.send_json({"cv_item": after})
            return
        self.send_error_json("Unsupported academic workbench operation", 405)

    def export_odm(self, conn, study_id: int) -> None:
        meta = self.metadata_payload(conn, study_id)
        root = ElementTree.Element("ODM", {"ODMVersion": "1.3.2", "FileType": "Snapshot", "Description": "Clinical Data Studio ODM-like export"})
        study_el = ElementTree.SubElement(root, "Study", {"OID": f"STUDY.{study_id}"})
        ElementTree.SubElement(study_el, "GlobalVariables")
        metadata = ElementTree.SubElement(study_el, "MetaDataVersion", {"OID": f"MDV.{study_id}", "Name": meta["project"]["name"]})
        for instrument in meta["instruments"]:
            form_def = ElementTree.SubElement(metadata, "FormDef", {"OID": f"FORM.{instrument['instrument_name']}", "Name": instrument["instrument_label"], "Repeating": "Yes" if instrument["repeatable"] else "No"})
            for field in [item for item in meta["data_dictionary"] if item["form_name"] == instrument["instrument_name"]]:
                item_group = ElementTree.SubElement(form_def, "ItemGroupRef", {"ItemGroupOID": f"IG.{instrument['instrument_name']}.{field['field_name']}", "Mandatory": "Yes" if field["required_field"] else "No"})
                item_group.set("OrderNumber", str(field["question_number"]))
                item_def = ElementTree.SubElement(metadata, "ItemDef", {"OID": f"ITEM.{instrument['instrument_name']}.{field['field_name']}", "Name": field["field_name"], "DataType": "text"})
                ElementTree.SubElement(item_def, "Question").text = field["field_label"]
        content = ElementTree.tostring(root, encoding="utf-8", xml_declaration=True)
        self.send_response(200)
        self.send_header("content-type", "application/xml; charset=utf-8")
        self.send_header("content-disposition", "attachment; filename=clinical_data_project.xml")
        self.send_header("content-length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def export_stats_package(self, conn, study_id: int, membership, package: str) -> None:
        records = self.record_payload(conn, study_id, membership, {})
        fields = list(records[0].keys()) if records else ["study_uid"]
        syntax = {
            "r": "data <- read.csv('clinical_data_export.csv', stringsAsFactors = FALSE)\nstr(data)\nsummary(data)\n",
            "sas": "proc import datafile='clinical_data_export.csv' out=clinical_data dbms=csv replace;\n  guessingrows=max;\nrun;\nproc contents data=clinical_data; run;\n",
            "spss": "GET DATA /TYPE=TXT /FILE='clinical_data_export.csv' /DELCASE=LINE /DELIMITERS=',' /ARRANGEMENT=DELIMITED /FIRSTCASE=2 /VARIABLES=" + " ".join(f"{field} A255" for field in fields) + ".\nEXECUTE.\n",
            "stata": "import delimited using \"clinical_data_export.csv\", clear\ncodebook\nsummarize\n",
        }
        if package not in syntax:
            self.send_error_json("Unsupported statistical package type", 400)
            return
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as temporary:
            archive_path = Path(temporary.name)
        try:
            with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
                csv_lines = []
                class Sink:
                    def write(self, value):
                        csv_lines.append(value)
                writer = csv.DictWriter(Sink(), fieldnames=fields)
                writer.writeheader()
                writer.writerows(records)
                archive.writestr("clinical_data_export.csv", "".join(csv_lines))
                extension = "R" if package == "r" else package
                archive.writestr(f"clinical_data_import.{extension}", syntax[package])
                archive.writestr("README.txt", "Generated by Clinical Data Studio. Review variable labels and coding before final analysis.\n")
            content = archive_path.read_bytes()
        finally:
            if archive_path.exists():
                archive_path.unlink()
        self.send_response(200)
        self.send_header("content-type", "application/zip")
        self.send_header("content-disposition", f"attachment; filename=clinical_data_{package}_package.zip")
        self.send_header("content-length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def backups(self, conn, user, method, study_id, parts) -> None:
        BACKUPS.mkdir(parents=True, exist_ok=True)
        if method == "GET" and len(parts) == 4:
            self.send_json({"backups": backup_files_for_study(study_id)})
            return
        if method == "POST" and len(parts) == 4:
            payload = self.body()
            conn.commit()
            passphrase = str(payload.get("passphrase", "")) or SETTINGS.backup_passphrase
            backup = create_database_backup(passphrase, study_id)
            audit(conn, user["id"], "create_encrypted" if backup["encrypted"] else "create", "backup", study_id, None, {"filename": backup["name"], "backend": backup["backend"]}, study_id=study_id, **self.audit_context())
            self.send_json({"backup": backup}, 201)
            return
        if method == "GET" and len(parts) == 5:
            filename = Path(parts[4]).name
            if not filename.startswith(f"study_{study_id}_") or not (filename.endswith(".sqlite3") or filename.endswith(".cdsenc") or filename.endswith(".dump")):
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
            if not filename.startswith(f"study_{study_id}_") or not (filename.endswith(".sqlite3") or filename.endswith(".cdsenc") or filename.endswith(".dump")):
                self.send_error_json("Backup not found", 404)
                return
            target = (BACKUPS / filename).resolve()
            if not str(target).startswith(str(BACKUPS.resolve())) or not target.exists():
                self.send_error_json("Backup not found", 404)
                return
            result = restore_database_backup(target, str(payload.get("passphrase", "")) or SETTINGS.backup_passphrase)
            audit(conn, user["id"], "restore", "backup", study_id, None, {"filename": filename, "backend": result["backend"]}, study_id=study_id, **self.audit_context())
            self.send_json(result)
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


def validate_startup() -> None:
    if SETTINGS.production:
        weak_secrets = {"change-me", "please-change-me", "change_me", "changeme", "secret", "password"}
        if not SETTINGS.secret_key or len(SETTINGS.secret_key) < MIN_PRODUCTION_SECRET_LENGTH or SETTINGS.secret_key.lower() in weak_secrets:
            raise RuntimeError("Production startup refused: set CDS_SECRET_KEY to a long random value.")
        if not SETTINGS.admin_password or len(SETTINGS.admin_password) < PRODUCTION_ADMIN_PASSWORD_MIN_LENGTH or SETTINGS.admin_password == "admin123":
            raise RuntimeError("Production startup refused: set CDS_ADMIN_PASSWORD to a strong non-default value.")
        if DATABASE_BACKEND == "sqlite" and os.environ.get("CDS_ALLOW_SQLITE_PRODUCTION", "").strip().lower() not in {"1", "true", "yes", "on"}:
            raise RuntimeError("Production startup refused: use PostgreSQL or set CDS_ALLOW_SQLITE_PRODUCTION=true for an explicit temporary exception.")
        if DATABASE_BACKEND == "postgres" and (not DATABASE_URL or "change_me" in DATABASE_URL.lower()):
            raise RuntimeError("Production startup refused: set DATABASE_URL or POSTGRES_PASSWORD for PostgreSQL.")
        if not SETTINGS.require_https:
            LOGGER.warning("CDS_REQUIRE_HTTPS=false in production. Use this only behind a trusted HTTPS reverse proxy.")
        if HOST in {"0.0.0.0", "::"}:
            LOGGER.warning("Clinical Data Studio is bound to all network interfaces in production. Use HTTPS and a firewall.")
        if SETTINGS.require_https and SETTINGS.public_base_url and not SETTINGS.public_base_url.startswith("https://"):
            raise RuntimeError("Production startup refused: CDS_REQUIRE_HTTPS=true but CDS_PUBLIC_BASE_URL is not HTTPS.")
    elif HOST in {"0.0.0.0", "::"}:
        raise RuntimeError("Development startup refused: public binding is allowed only with CDS_ENV=production.")


def create_admin_from_env() -> dict:
    password = SETTINGS.admin_password
    if len(password) < PRODUCTION_ADMIN_PASSWORD_MIN_LENGTH:
        raise RuntimeError("CDS_ADMIN_PASSWORD must be at least 12 characters for create-admin.")
    force_reset = os.environ.get("CDS_FORCE_ADMIN_RESET", "").strip().lower() in {"1", "true", "yes", "on"}
    with closing(db()) as conn, conn:
        migrate()
        existing = row(conn, "SELECT id, username, display_name, role, active, must_change_password FROM users WHERE username = ?", (SETTINGS.admin_username,))
        timestamp = now()
        if existing:
            if not force_reset:
                return existing
            conn.execute(
                "UPDATE users SET password_hash = ?, display_name = ?, role = 'super_admin', active = 1, must_change_password = 0 WHERE id = ?",
                (encode_password(password), SETTINGS.admin_display_name, existing["id"]),
            )
            after = row(conn, "SELECT id, username, display_name, role, active, must_change_password FROM users WHERE id = ?", (existing["id"],))
            audit(conn, None, "create_admin", "user", existing["id"], existing, after)
            return after
        cur = conn.execute(
            "INSERT INTO users(username, password_hash, display_name, role, active, must_change_password, created_at) VALUES (?, ?, ?, 'super_admin', 1, 0, ?)",
            (SETTINGS.admin_username, encode_password(password), SETTINGS.admin_display_name, timestamp),
        )
        after = row(conn, "SELECT id, username, display_name, role, active, must_change_password FROM users WHERE id = ?", (cur.lastrowid,))
        audit(conn, None, "create_admin", "user", cur.lastrowid, None, after)
        return after


def cli_restore(path_arg: str) -> dict:
    backup_path = Path(path_arg)
    if not backup_path.is_absolute():
        backup_path = BACKUPS / backup_path
    return restore_database_backup(backup_path, SETTINGS.backup_passphrase)


def handle_cli(argv: list[str]) -> bool:
    if len(argv) <= 1:
        return False
    command = argv[1].strip().lower()
    if command == "migrate":
        validate_startup()
        migrate()
        print("Migrations complete.")
        return True
    if command == "create-admin":
        user = create_admin_from_env()
        print(json.dumps({"created_or_updated": user}, indent=2))
        return True
    if command == "healthcheck":
        payload = health_payload()
        print(json.dumps(payload, indent=2))
        raise SystemExit(0 if payload["ok"] else 1)
    if command == "backup":
        backup = create_database_backup(SETTINGS.backup_passphrase)
        print(json.dumps({"backup": backup}, indent=2))
        return True
    if command == "backup-full":
        backup = create_full_backup(SETTINGS.backup_passphrase)
        print(json.dumps({"backup": backup}, indent=2))
        return True
    if command in {"verify-backup", "restore-full-dry-run"}:
        if len(argv) < 3:
            raise SystemExit(f"Usage: python server.py {command} <full_backup_file_or_name>")
        backup_path = Path(argv[2])
        if not backup_path.is_absolute():
            backup_path = BACKUPS / backup_path.name
        verification = verify_full_backup(backup_path, SETTINGS.backup_passphrase, record=command == "verify-backup")
        print(json.dumps({"verification": verification, "dry_run": True}, indent=2))
        raise SystemExit(0 if verification["ok"] else 1)
    if command == "restore":
        if len(argv) < 3:
            raise SystemExit("Usage: python server.py restore <backup_file>")
        result = cli_restore(argv[2])
        print(json.dumps(result, indent=2))
        return True
    return False


def main() -> None:
    if handle_cli(sys.argv):
        return
    validate_startup()
    migrate()
    server = ThreadingHTTPServer((HOST, PORT), App)
    scheme = "https" if SETTINGS.require_https and SETTINGS.public_base_url.startswith("https://") else "http"
    display_host = HOST if HOST not in {"0.0.0.0", "::"} else "your-server-ip"
    LOGGER.info("Clinical Data Studio running at %s://%s:%s", scheme, display_host, PORT)
    if HOST in {"0.0.0.0", "::"}:
        LOGGER.warning("Public network binding is enabled. Keep HTTPS, backups, firewall, and named user accounts active.")
    server.serve_forever()


if __name__ == "__main__":
    main()
