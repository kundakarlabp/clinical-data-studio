from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os


ROOT = Path(__file__).resolve().parent


def load_env_file(path: Path | None = None) -> None:
    target = path or ROOT / ".env"
    if not target.exists():
        return
    for raw_line in target.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_path(name: str, default: Path) -> Path:
    value = os.environ.get(name, "").strip()
    if not value:
        return default
    return Path(value).expanduser()


@dataclass(frozen=True)
class Settings:
    env: str
    host: str
    port: int
    secret_key: str
    database_url: str
    database_backend: str
    require_https: bool
    public_base_url: str
    data_dir: Path
    backup_dir: Path
    backup_passphrase: str
    ai_provider: str
    ai_enabled: bool
    ai_allow_phi: bool
    log_level: str
    log_dir: Path
    admin_username: str
    admin_password: str
    admin_display_name: str

    @property
    def production(self) -> bool:
        return self.env == "production"

    @property
    def sqlite_path(self) -> Path:
        if self.database_url.startswith("sqlite:///"):
            return Path(self.database_url.removeprefix("sqlite:///"))
        return self.data_dir / "clinical_data_studio.sqlite3"


def load_settings() -> Settings:
    load_env_file()
    env = os.environ.get("CDS_ENV", "development").strip().lower() or "development"
    if env not in {"development", "production"}:
        env = "development"
    default_host = "127.0.0.1"
    host = os.environ.get("CDS_HOST", default_host).strip() or default_host
    if env != "production" and host in {"0.0.0.0", "::"}:
        host = "127.0.0.1"
    data_dir = env_path("CDS_DATA_DIR", ROOT / "data")
    backup_dir = env_path("CDS_BACKUP_DIR", data_dir / "backups")
    database_backend = os.environ.get("CDS_DATABASE_BACKEND", "sqlite").strip().lower() or "sqlite"
    database_url = os.environ.get("DATABASE_URL", "").strip()
    if database_backend == "postgres" and not database_url:
        postgres_password = os.environ.get("POSTGRES_PASSWORD", "").strip()
        if postgres_password:
            database_url = f"postgresql://clinical:{postgres_password}@db:5432/clinical_data_studio"
    if not database_url:
        database_url = f"sqlite:///{data_dir / 'clinical_data_studio.sqlite3'}"
    return Settings(
        env=env,
        host=host,
        port=int(os.environ.get("CDS_PORT", "8765")),
        secret_key=os.environ.get("CDS_SECRET_KEY", "").strip(),
        database_url=database_url,
        database_backend=database_backend,
        require_https=env_bool("CDS_REQUIRE_HTTPS", env == "production"),
        public_base_url=os.environ.get("CDS_PUBLIC_BASE_URL", "").strip(),
        data_dir=data_dir,
        backup_dir=backup_dir,
        backup_passphrase=os.environ.get("CDS_BACKUP_PASSPHRASE", "").strip(),
        ai_provider=os.environ.get("CDS_AI_PROVIDER", "local").strip().lower() or "local",
        ai_enabled=env_bool("CDS_AI_ENABLED", False),
        ai_allow_phi=env_bool("CDS_AI_ALLOW_PHI", False),
        log_level=os.environ.get("CDS_LOG_LEVEL", "INFO").strip().upper() or "INFO",
        log_dir=env_path("CDS_LOG_DIR", ROOT / "logs"),
        admin_username=os.environ.get("CDS_ADMIN_USERNAME", "admin").strip() or "admin",
        admin_password=os.environ.get("CDS_ADMIN_PASSWORD", "").strip(),
        admin_display_name=os.environ.get("CDS_ADMIN_DISPLAY_NAME", "Administrator").strip() or "Administrator",
    )

