import hashlib
import hmac
import secrets
import time
from typing import Any
import config

SESSION_INACTIVITY_TIMEOUT = 3600  # 1 hour
SESSION_ABSOLUTE_TIMEOUT = 86400    # 24 hours

def now() -> int:
    return int(time.time())

def session_token_digest(token: str) -> str:
    settings = config.load_settings()
    secret = settings.secret_key or "clinical-data-studio-development-session-key"
    return hmac.new(secret.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()

def create_session(conn: Any, user_id: int, mfa_verified: int = 1) -> str:
    token = secrets.token_urlsafe(32)
    current_time = now()
    # Note: expires_at is kept for legacy compatibility but timeouts are enforced via created_at and last_action_at
    expires_at = current_time + SESSION_ABSOLUTE_TIMEOUT
    digest = session_token_digest(token)
    
    conn.execute(
        """
        INSERT INTO sessions (token, user_id, expires_at, created_at, last_action_at, mfa_verified)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (digest, user_id, expires_at, current_time, current_time, mfa_verified),
    )
    return token

def verify_session(conn: Any, token: str) -> dict[str, Any] | None:
    current_time = now()
    
    # First prune expired sessions to keep db clean
    prune_expired_sessions(conn)
    
    # Retrieve session and user
    row = conn.execute(
        """
        SELECT sessions.*, users.username, users.display_name, users.role, users.active, users.must_change_password
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.token = ? AND users.active = 1
        """,
        (token,),
    ).fetchone()
    
    if not row:
        return None
        
    session = dict(row)
    
    # Enforce Absolute Timeout
    created_at = session.get("created_at") or session.get("expires_at", 0) - SESSION_ABSOLUTE_TIMEOUT
    if current_time - created_at > SESSION_ABSOLUTE_TIMEOUT:
        delete_session(conn, token)
        return None
        
    # Enforce Inactivity Timeout
    last_action_at = session.get("last_action_at") or created_at
    if current_time - last_action_at > SESSION_INACTIVITY_TIMEOUT:
        delete_session(conn, token)
        return None
        
    # Update last action time
    conn.execute(
        "UPDATE sessions SET last_action_at = ? WHERE token = ?",
        (current_time, token),
    )
    
    return session

def delete_session(conn: Any, token: str) -> None:
    conn.execute("DELETE FROM sessions WHERE token = ?", (token,))

def invalidate_user_sessions(conn: Any, user_id: int, keep_token: str | None = None) -> None:
    if keep_token:
        conn.execute("DELETE FROM sessions WHERE user_id = ? AND token != ?", (user_id, keep_token))
    else:
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

def prune_expired_sessions(conn: Any) -> None:
    current_time = now()
    # Delete sessions exceeding absolute timeout
    conn.execute("DELETE FROM sessions WHERE ? - created_at > ?", (current_time, SESSION_ABSOLUTE_TIMEOUT))
    # Delete sessions exceeding inactivity timeout
    conn.execute("DELETE FROM sessions WHERE ? - last_action_at > ?", (current_time, SESSION_INACTIVITY_TIMEOUT))
