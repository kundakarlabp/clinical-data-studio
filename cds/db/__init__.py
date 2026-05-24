import config
import sqlite3
from pathlib import Path
from storage import connect_database

SETTINGS = config.load_settings()
DATA = SETTINGS.data_dir
BACKUPS = SETTINGS.backup_dir
UPLOADS = SETTINGS.upload_dir
DB_PATH = SETTINGS.sqlite_path
DATABASE_BACKEND = SETTINGS.database_backend
DATABASE_URL = SETTINGS.database_url

import json
from typing import Any

def db():
    DATA.mkdir(parents=True, exist_ok=True)
    BACKUPS.mkdir(parents=True, exist_ok=True)
    UPLOADS.mkdir(parents=True, exist_ok=True)
    return connect_database(DATABASE_BACKEND, DB_PATH, DATABASE_URL)

def rows(conn, sql: str, params: tuple = ()) -> list[dict]:
    return [dict(row) for row in conn.execute(sql, params).fetchall()]

def row(conn, sql: str, params: tuple = ()) -> dict | None:
    result = conn.execute(sql, params).fetchone()
    return dict(result) if result else None

def load_json(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback

