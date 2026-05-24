import hashlib
import hmac
import time
from typing import Any
import config

SESSION_TTL_SECONDS = 60 * 60 * 24 * 14  # 14 days

def now() -> int:
    return int(time.time())

def get_secret_key() -> str:
    settings = config.load_settings()
    return settings.secret_key or "clinical-data-studio-development-session-key"

def csrf_token(session_digest: str, timestamp: int | None = None) -> str:
    issued_at = timestamp or now()
    secret = get_secret_key()
    signature = hmac.new(
        secret.encode("utf-8"),
        f"{session_digest}:{issued_at}".encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return f"{issued_at}.{signature}"

def verify_csrf_token(session_digest: str, token: str) -> bool:
    if not token or not session_digest:
        return False
    try:
        issued_raw, signature = token.split(".", 1)
        issued_at = int(issued_raw)
    except Exception:
        return False
    if issued_at <= 0 or now() - issued_at > SESSION_TTL_SECONDS:
        return False
    # Validate signature by generating expected token
    expected = csrf_token(session_digest, issued_at)
    return hmac.compare_digest(expected, token)
