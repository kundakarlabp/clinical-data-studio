import json
import logging
from pathlib import Path
from typing import Any

from cds.services.backup_service import (
    create_database_backup,
    create_full_backup as service_create_full_backup,
    verify_full_backup,
    restore_database_backup,
    restore_full_backup,
    backup_files_for_study,
    latest_full_backup_info,
    backup_file_info,
    full_backup_candidates,
    BACKUPS
)
from cds.services.audit_service import audit
import config

LOGGER = logging.getLogger("clinical-data-studio")

def list_backups_api(handler: Any, conn: Any, user: Any) -> None:
    BACKUPS.mkdir(parents=True, exist_ok=True)
    files = []
    for item in sorted(BACKUPS.iterdir(), key=lambda path: path.stat().st_mtime, reverse=True):
        if item.is_file() and not item.name.endswith(".verify.json") and item.suffix in {".sqlite3", ".cdsenc", ".dump", ".gz"}:
            backup_type = "full" if item.name.startswith("full_") or ".full." in item.name else ("postgres" if item.name.startswith("postgres_") or item.name.endswith(".dump") else "database")
            files.append(latest_full_backup_info(item) if backup_type == "full" else backup_file_info(item, backup_type))
            
    # health payload call
    from cds.routes.studies import get_health_payload
    health = get_health_payload(handler)
    handler.send_json({"backups": files, "summary": health["backup"]})

def create_database_backup_api(handler: Any, conn: Any, user: Any, study_id: int | None = None) -> None:
    payload = handler.body()
    conn.commit()
    settings = config.load_settings()
    passphrase = str(payload.get("passphrase", "")) or settings.backup_passphrase
    
    backup = create_database_backup(passphrase, study_id)
    audit(conn, user["id"], "create_encrypted" if backup["encrypted"] else "create", "backup", study_id, None, backup, study_id=study_id)
    conn.commit()
    handler.send_json({"backup": backup}, 201)

def create_full_backup_api(handler: Any, conn: Any, user: Any) -> None:
    payload = handler.body()
    conn.commit()
    settings = config.load_settings()
    passphrase = str(payload.get("passphrase", "")) or settings.backup_passphrase
    
    backup = service_create_full_backup(passphrase)
    audit(conn, user["id"], "create_full", "backup", None, None, backup)
    conn.commit()
    handler.send_json({"backup": backup}, 201)

def verify_backup_api(handler: Any, conn: Any, user: Any) -> None:
    payload = handler.body()
    filename = Path(str(payload.get("filename", ""))).name
    target = (BACKUPS / filename).resolve() if filename else (full_backup_candidates()[0] if full_backup_candidates() else None)
    
    if not target or not str(target).startswith(str(BACKUPS.resolve())) or not target.exists():
        handler.send_error_json("Full backup not found", 404)
        return
        
    settings = config.load_settings()
    passphrase = str(payload.get("passphrase", "")) or settings.backup_passphrase
    verification = verify_full_backup(target, passphrase, record=True)
    audit(conn, user["id"], "verify", "backup", None, None, {"filename": target.name, "ok": verification["ok"]})
    handler.send_json({"verification": verification})

def dry_run_backup_api(handler: Any, conn: Any, user: Any) -> None:
    payload = handler.body()
    filename = Path(str(payload.get("filename", ""))).name
    target = (BACKUPS / filename).resolve() if filename else (full_backup_candidates()[0] if full_backup_candidates() else None)
    
    if not target or not str(target).startswith(str(BACKUPS.resolve())) or not target.exists():
        handler.send_error_json("Full backup not found", 404)
        return
        
    settings = config.load_settings()
    passphrase = str(payload.get("passphrase", "")) or settings.backup_passphrase
    verification = verify_full_backup(target, passphrase, record=False)
    audit(conn, user["id"], "restore_dry_run", "backup", None, None, {"filename": target.name, "ok": verification["ok"]})
    handler.send_json({"dry_run": True, "verification": verification})

def download_backup_api(handler: Any, conn: Any, user: Any, filename: str, study_id: int | None = None) -> None:
    filename = Path(filename).name
    if study_id:
        if not filename.startswith(f"study_{study_id}_") or not (filename.endswith(".sqlite3") or filename.endswith(".cdsenc") or filename.endswith(".dump")):
            handler.send_error_json("Backup not found", 404)
            return
    else:
        if filename.endswith(".verify.json"):
            handler.send_error_json("Backup not found", 404)
            return
            
    target = (BACKUPS / filename).resolve()
    if not str(target).startswith(str(BACKUPS.resolve())) or not target.exists():
        handler.send_error_json("Backup not found", 404)
        return
        
    content = target.read_bytes()
    handler.send_response(200)
    handler.send_header("content-type", "application/octet-stream")
    handler.send_header("content-disposition", f"attachment; filename={target.name}")
    handler.send_header("content-length", str(len(content)))
    handler.end_headers()
    handler.wfile.write(content)

def restore_backup_api(handler: Any, conn: Any, user: Any, filename: str, study_id: int | None = None) -> None:
    payload = handler.body()
    filename = Path(filename).name
    if study_id:
        if not filename.startswith(f"study_{study_id}_") or not (filename.endswith(".sqlite3") or filename.endswith(".cdsenc") or filename.endswith(".dump")):
            handler.send_error_json("Backup not found", 404)
            return
    else:
        if not (filename.endswith(".sqlite3") or filename.endswith(".cdsenc") or filename.endswith(".dump")):
            handler.send_error_json("Backup not found", 404)
            return
            
    target = (BACKUPS / filename).resolve()
    if not str(target).startswith(str(BACKUPS.resolve())) or not target.exists():
        handler.send_error_json("Backup not found", 404)
        return
        
    settings = config.load_settings()
    passphrase = str(payload.get("passphrase", "")) or settings.backup_passphrase
    
    # Check if this is a full backup or database backup
    is_full = "full" in filename or filename.startswith("full_")
    if is_full:
        result = restore_full_backup(target, passphrase)
    else:
        result = restore_database_backup(target, passphrase)
        
    audit(conn, user["id"], "restore", "backup", study_id, None, {"filename": filename, "backend": result["backend"]}, study_id=study_id)
    handler.send_json(result)
