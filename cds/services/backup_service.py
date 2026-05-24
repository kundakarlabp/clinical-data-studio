import base64
import ctypes
import hashlib
import hmac
import json
import logging
import os
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import time
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any
from contextlib import closing
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import config
from cds.db import db, DB_PATH, DATABASE_BACKEND, DATABASE_URL, BACKUPS, UPLOADS, DATA

LOGGER = logging.getLogger("clinical-data-studio")

PBKDF2_ROUNDS = 260_000
FILE_ATTRIBUTE_ENCRYPTED = 0x4000

# Legacy CDSENC1 implementation
def archive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, PBKDF2_ROUNDS)

def hmac_stream(key: bytes, nonce: bytes, length: int) -> bytes:
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        block = hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        stream.extend(block)
        counter += 1
    return bytes(stream[:length])

def xor_bytes(data: bytes, stream: bytes) -> bytes:
    return bytes(left ^ right for left, right in zip(data, stream))

def legacy_decrypt(archive: bytes, passphrase: str) -> bytes:
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

# AES-GCM (CDSENC2) implementation
def encrypted_archive_bytes(plain: bytes, passphrase: str) -> bytes:
    if len(passphrase) < 15:
        raise ValueError("Encrypted archive passphrase must be at least 15 characters")
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)  # Standard 96-bit nonce for GCM
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, PBKDF2_ROUNDS)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plain, associated_data=b"CDSENC2")
    
    # Format: CDSENC2\n + salt (16 bytes) + nonce (12 bytes) + ciphertext
    return b"CDSENC2\n" + salt + nonce + ciphertext

def decrypted_archive_bytes(archive: bytes, passphrase: str) -> bytes:
    if archive.startswith(b"CDSENC1\n"):
        return legacy_decrypt(archive, passphrase)
        
    if not archive.startswith(b"CDSENC2\n"):
        raise ValueError("Unsupported encrypted archive format")
        
    if len(archive) < 8 + 16 + 12 + 16:  # Magic prefix + salt + nonce + tag (at least 16 bytes for GCM tag)
        raise ValueError("Encrypted archive file is truncated or damaged")
        
    salt = archive[8:24]
    nonce = archive[24:36]
    ciphertext = archive[36:]
    
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, PBKDF2_ROUNDS)
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data=b"CDSENC2")
    except Exception as exc:
        raise ValueError("Encrypted archive passphrase is incorrect or the file is damaged") from exc

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
    try:
        target = str(path.resolve())
        attributes = ctypes.windll.kernel32.GetFileAttributesW(target)
        if attributes == -1:
            return False
        return bool(attributes & FILE_ATTRIBUTE_ENCRYPTED)
    except Exception:
        return False

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
        "verification_status": "not_verified",
        "includes_uploads": False,
        "includes_manifest": False,
        "checksum_verified": False,
    }
    if backup_type:
        info["backup_type"] = backup_type
    return info

def git_commit() -> str:
    configured = os.environ.get("CDS_COMMIT", "").strip()
    if configured:
        return configured
    try:
        result = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=config.ROOT, capture_output=True, text=True, timeout=5, check=True)
        return result.stdout.strip()
    except Exception:
        return "unknown"

def backup_name(prefix: str = "system") -> str:
    return f"{prefix}_{time.strftime('%Y%m%d_%H%M%S', time.localtime())}"

def create_database_backup(passphrase: str = "", study_id: int | None = None) -> dict:
    BACKUPS.mkdir(parents=True, exist_ok=True)
    prefix = f"study_{study_id}" if study_id else "system"
    stem = backup_name(prefix)
    settings = config.load_settings()
    
    if DATABASE_BACKEND == "postgres":
        dump_target = BACKUPS / f"{stem}.dump"
        command = ["pg_dump", "--format=custom", "--file", str(dump_target), DATABASE_URL]
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=300)
        if passphrase:
            encrypted = BACKUPS / f"{stem}.cdsenc"
            encrypted.parent.mkdir(parents=True, exist_ok=True)
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
        encrypted.parent.mkdir(parents=True, exist_ok=True)
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
    settings = config.load_settings()
    passphrase = passphrase or settings.backup_passphrase
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
        db_real_name = write_database_dump(db_path)
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
            "database_dump": db_real_name,
            "uploads_archive": uploads_path.name,
            "upload_file_count": upload_count,
            "encryption": {
                "format": "CDSENC2",
                "kdf": "pbkdf2_hmac_sha256",
                "passphrase_stored": False,
                "algorithm": "AES-GCM",
                "key_size_bits": 256,
                "nonce_size_bytes": 12,
                "pbkdf2_rounds": PBKDF2_ROUNDS
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
        
    info = latest_full_backup_info(target)
    if info:
        info.update({"backend": DATABASE_BACKEND, "uploads_included": True, "verified": False})
    else:
        info = backup_file_info(target, "full")
    return info

def verify_full_backup(backup_file: Path, passphrase: str = "", record: bool = False) -> dict:
    settings = config.load_settings()
    passphrase = passphrase or settings.backup_passphrase
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
        "includes_uploads": False,
        "includes_manifest": False,
        "checksum_verified": False,
        "database_dump_nonempty": False,
        "archive_readable": False,
        "uploads_archive_readable": False,
        "errors": [],
    }
    
    try:
        with zipfile.ZipFile(BytesIO(archive_bytes), "r") as archive:
            bad_file = archive.testzip()
            if bad_file:
                result["errors"].append(f"Archive contains unreadable member: {bad_file}")
            else:
                result["archive_readable"] = True
                
            names = archive.namelist()
            result["contents"] = names
            required = {"manifest.json", "SHA256SUMS.txt", "uploads.zip"}
            missing = sorted(required - set(names))
            if missing:
                result["errors"].append(f"Missing required file(s): {', '.join(missing)}")
                
            result["includes_manifest"] = "manifest.json" in names
            manifest = json.loads(archive.read("manifest.json").decode("utf-8")) if "manifest.json" in names else {}
            result["manifest"] = manifest
            result["database_dump"] = str(manifest.get("database_dump") or "")
            result["uploads_archive"] = str(manifest.get("uploads_archive") or "")
            
            if result["database_dump"] not in names:
                result["errors"].append("Database dump is missing")
            elif len(archive.read(result["database_dump"])) == 0:
                result["errors"].append("Database dump is empty")
            else:
                result["database_dump_nonempty"] = True
                
            if result["uploads_archive"] not in names:
                result["errors"].append("Uploads archive is missing")
            else:
                result["includes_uploads"] = True
                
            if manifest.get("backup_type") != "full":
                result["errors"].append("Manifest backup_type is not full")
                
            if "SHA256SUMS.txt" in names:
                checksum_ok = True
                checksum_lines = archive.read("SHA256SUMS.txt").decode("utf-8").splitlines()
                for line in checksum_lines:
                    if not line.strip():
                        continue
                    parts = line.split(None, 1)
                    if len(parts) != 2:
                        continue
                    expected, filename = parts
                    filename = filename.strip()
                    if filename not in names:
                        result["errors"].append(f"Checksum target missing: {filename}")
                        checksum_ok = False
                        continue
                    actual = sha256_bytes(archive.read(filename))
                    if actual != expected:
                        result["errors"].append(f"Checksum mismatch: {filename}")
                        checksum_ok = False
                result["checksum_verified"] = checksum_ok and bool(checksum_lines)
                
            if result["uploads_archive"] in names:
                with zipfile.ZipFile(BytesIO(archive.read(result["uploads_archive"])), "r") as uploads:
                    bad_upload = uploads.testzip()
                    if bad_upload:
                        result["errors"].append(f"Uploads archive contains unreadable member: {bad_upload}")
                    else:
                        result["uploads_archive_readable"] = True
                    result["upload_file_count"] = len([name for name in uploads.namelist() if not name.endswith("/") and name != "EMPTY_UPLOADS.txt"])
                    
        result["ok"] = not result["errors"]
    except Exception as exc:
        result["errors"].append(str(exc))
        result["ok"] = False
        
    if record:
        verification_sidecar_path(target).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    return result

def verification_sidecar_path(path: Path) -> Path:
    return path.parent / f"{path.name}.verify.json"

def full_backup_candidates() -> list[Path]:
    if not BACKUPS.exists():
        return []
    candidates = []
    for item in BACKUPS.iterdir():
        if item.is_file() and not item.name.endswith(".verify.json") and (item.name.startswith("full_") or ".full." in item.name) and item.suffix == ".cdsenc":
            candidates.append(item)
    return sorted(candidates, key=lambda item: item.stat().st_mtime, reverse=True)

def latest_full_backup_info(path: Path) -> dict | None:
    if not path.exists():
        return None
    info = backup_file_info(path, "full")
    sidecar = verification_sidecar_path(path)
    info["verified"] = sidecar.exists()
    if sidecar.exists():
        try:
            data = json.loads(sidecar.read_text(encoding="utf-8"))
            info["verified"] = data.get("ok", False)
            info["checksum_verified"] = data.get("checksum_verified", False)
            info["upload_file_count"] = data.get("upload_file_count", 0)
        except Exception:
            pass
    return info

def restore_database_backup(backup_file: Path, passphrase: str = "") -> dict:
    settings = config.load_settings()
    passphrase = passphrase or settings.backup_passphrase
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

def restore_full_backup(backup_file: Path, passphrase: str = "") -> dict:
    # Check/verify first
    verification = verify_full_backup(backup_file, passphrase, record=False)
    if not verification["ok"]:
        raise ValueError(f"Backup verification failed: {', '.join(verification['errors'])}")
        
    archive_bytes = decrypted_archive_bytes(backup_file.resolve().read_bytes(), passphrase)
    
    with tempfile.TemporaryDirectory(dir=BACKUPS) as tmp_name:
        tmp = Path(tmp_name)
        with zipfile.ZipFile(BytesIO(archive_bytes), "r") as archive:
            # Extract database dump and uploads zip
            db_dump_name = verification["database_dump"]
            uploads_zip_name = verification["uploads_archive"]
            
            db_dump_path = tmp / db_dump_name
            uploads_zip_path = tmp / uploads_zip_name
            
            db_dump_path.write_bytes(archive.read(db_dump_name))
            uploads_zip_path.write_bytes(archive.read(uploads_zip_name))
            
            # 1. Restore database
            if DATABASE_BACKEND == "postgres":
                subprocess.run(["pg_restore", "--clean", "--if-exists", "--no-owner", "--dbname", DATABASE_URL, str(db_dump_path)], check=True, capture_output=True, text=True, timeout=300)
            else:
                source = sqlite3.connect(db_dump_path)
                try:
                    with closing(db()) as conn:
                        source.backup(conn)
                finally:
                    source.close()
                    
            # 2. Restore uploads folder
            # Clear current uploads folder first
            if UPLOADS.exists():
                shutil.rmtree(UPLOADS)
            UPLOADS.mkdir(parents=True, exist_ok=True)
            
            with zipfile.ZipFile(uploads_zip_path, "r") as uploads_archive:
                for file_name in uploads_archive.namelist():
                    if file_name != "EMPTY_UPLOADS.txt":
                        uploads_archive.extract(file_name, UPLOADS)
                        
    return {"restored": backup_file.name, "backend": DATABASE_BACKEND, "uploads_restored": True}

def latest_verified_full_backup_info() -> dict | None:
    verified = [info for info in (latest_full_backup_info(item) for item in full_backup_candidates()) if info and info.get("verified")]
    return verified[0] if verified else None

def backup_files_for_study(study_id: int) -> list[dict]:
    BACKUPS.mkdir(parents=True, exist_ok=True)
    files = []
    prefix = f"study_{study_id}_"
    for item in sorted(BACKUPS.iterdir(), key=lambda path: path.stat().st_mtime, reverse=True):
        if item.is_file() and item.name.startswith(prefix) and not item.name.endswith(".verify.json"):
            files.append(backup_file_info(item, "database"))
    return files
