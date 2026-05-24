import os
import sys
import json
import logging
import time
import subprocess
from pathlib import Path
from contextlib import closing
from http.server import ThreadingHTTPServer

import config
from cds.db import db, row
from cds.db.migrations import run_migrations

LOGGER = logging.getLogger("clinical-data-studio")
SETTINGS = config.load_settings()

MIN_PRODUCTION_SECRET_LENGTH = 32
PRODUCTION_ADMIN_PASSWORD_MIN_LENGTH = 12

def now() -> int:
    return int(time.time())

def validate_startup() -> None:
    if SETTINGS.production:
        weak_secrets = {"change-me", "please-change-me", "change_me", "changeme", "secret", "password"}
        if not SETTINGS.secret_key or len(SETTINGS.secret_key) < MIN_PRODUCTION_SECRET_LENGTH or SETTINGS.secret_key.lower() in weak_secrets:
            raise RuntimeError("Production startup refused: set CDS_SECRET_KEY to a long random value.")
        if not SETTINGS.admin_password or len(SETTINGS.admin_password) < PRODUCTION_ADMIN_PASSWORD_MIN_LENGTH or SETTINGS.admin_password == "admin123":
            raise RuntimeError("Production startup refused: set CDS_ADMIN_PASSWORD to a strong non-default value.")
        if SETTINGS.database_backend == "sqlite" and os.environ.get("CDS_ALLOW_SQLITE_PRODUCTION", "").strip().lower() not in {"1", "true", "yes", "on"}:
            raise RuntimeError("Production startup refused: use PostgreSQL or set CDS_ALLOW_SQLITE_PRODUCTION=true for an explicit temporary exception.")
        if SETTINGS.database_backend == "postgres" and (not SETTINGS.database_url or "change_me" in SETTINGS.database_url.lower()):
            raise RuntimeError("Production startup refused: set DATABASE_URL or POSTGRES_PASSWORD for PostgreSQL.")
        if not SETTINGS.require_https:
            LOGGER.warning("CDS_REQUIRE_HTTPS=false in production. Use this only behind a trusted HTTPS reverse proxy.")
        if SETTINGS.host in {"0.0.0.0", "::"}:
            LOGGER.warning("Clinical Data Studio is bound to all network interfaces in production. Use HTTPS and a firewall.")
        if SETTINGS.require_https and SETTINGS.public_base_url and not SETTINGS.public_base_url.startswith("https://"):
            raise RuntimeError("Production startup refused: CDS_REQUIRE_HTTPS=true but CDS_PUBLIC_BASE_URL is not HTTPS.")
    elif SETTINGS.host in {"0.0.0.0", "::"}:
        raise RuntimeError("Development startup refused: public binding is allowed only with CDS_ENV=production.")

def create_admin_from_env() -> dict:
    from cds.security.passwords import encode_password
    from cds.services.audit_service import audit
    
    password = SETTINGS.admin_password
    if len(password) < PRODUCTION_ADMIN_PASSWORD_MIN_LENGTH:
        raise RuntimeError("CDS_ADMIN_PASSWORD must be at least 12 characters for create-admin.")
    force_reset = os.environ.get("CDS_FORCE_ADMIN_RESET", "").strip().lower() in {"1", "true", "yes", "on"}
    
    with closing(db()) as conn, conn:
        run_migrations(conn)
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
    from cds.services.backup_service import restore_database_backup
    backup_path = Path(path_arg)
    if not backup_path.is_absolute():
        backup_path = SETTINGS.backup_dir / backup_path
    return restore_database_backup(backup_path, SETTINGS.backup_passphrase)

def handle_cli(argv: list[str]) -> bool:
    from cds.services.backup_service import create_database_backup, create_full_backup, verify_full_backup
    from server import health_payload
    
    if len(argv) <= 1:
        return False
    command = argv[1].strip().lower()
    if command == "migrate":
        validate_startup()
        with closing(db()) as conn:
            run_migrations(conn)
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
            backup_path = SETTINGS.backup_dir / backup_path.name
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

def bootstrap_main(app_class: Any) -> None:
    if handle_cli(sys.argv):
        return
    validate_startup()
    with closing(db()) as conn:
        run_migrations(conn)
    server = ThreadingHTTPServer((SETTINGS.host, SETTINGS.port), app_class)
    scheme = "https" if SETTINGS.require_https and SETTINGS.public_base_url.startswith("https://") else "http"
    display_host = SETTINGS.host if SETTINGS.host not in {"0.0.0.0", "::"} else "your-server-ip"
    LOGGER.info("Clinical Data Studio running at %s://%s:%s", scheme, display_host, SETTINGS.port)
    if SETTINGS.host in {"0.0.0.0", "::"}:
        LOGGER.warning("Public network binding is enabled. Keep HTTPS, backups, firewall, and named user accounts active.")
    server.serve_forever()
