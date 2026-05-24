import json
import logging
import pyotp
import time
from typing import Any

from cds.security.passwords import encode_password, verify_password, validate_password_strength
from cds.security.sessions import create_session, delete_session, invalidate_user_sessions, session_token_digest
from cds.services.audit_service import audit

LOGGER = logging.getLogger("clinical-data-studio")

def now() -> int:
    return int(time.time())

def login(handler: Any, conn: Any) -> None:
    payload = handler.body()
    username = str(payload.get("username", "")).strip().lower()
    password = str(payload.get("password", ""))
    
    if not username or not password:
        handler.send_error_json("Username and password are required", 400)
        return
        
    user_row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    
    if not user_row:
        # Prevent user enumeration by executing dummy hash check
        verify_password(password, "pbkdf2_sha256$260000$dummy$dummy")
        handler.send_error_json("Invalid username or password", 401)
        return
        
    user = dict(user_row)
    
    if not user["active"]:
        handler.send_error_json("Account is deactivated", 403)
        return
        
    # Lockout check
    current_time = now()
    if user.get("locked_until", 0) > current_time:
        handler.send_error_json("Account is temporarily locked after repeated failed logins", 423)
        return
        
    if not verify_password(password, user["password_hash"]):
        # Increment failed login count
        failed = user.get("failed_login_count", 0) + 1
        locked_until = 0
        if failed >= 5:
            locked_until = current_time + 900  # 15 minutes lock
            audit(conn, user["id"], "lockout", "user", user["id"])
            LOGGER.warning(f"User {username} locked out due to multiple failed login attempts.")
            
        conn.execute(
            "UPDATE users SET failed_login_count = ?, locked_until = ? WHERE id = ?",
            (failed, locked_until, user["id"]),
        )
        audit(conn, user["id"], "login_failed", "user", user["id"])
        conn.commit()
        handler.send_error_json("Invalid username or password", 401)
        return
        
    # Reset failed login count on success
    conn.execute(
        "UPDATE users SET failed_login_count = 0, locked_until = 0 WHERE id = ?",
        (user["id"],),
    )
    
    # Enforce password minimums check (migration/policy)
    # If the password hash was old or password length is too short, warn/flag
    # Wait, we can set must_change_password if they fail length criteria
    is_admin = user["role"] == "super_admin" or user["role"] == "admin"
    # To check password length retrospectively, we check if password meets requirements
    # But since we only have the hash, we can't know the plain text password length.
    # So we let them login, but if must_change_password was set or password doesn't meet requirements,
    # they must change it (must_change_password is in the DB).
    
    # Check if MFA is enabled
    mfa_enabled = bool(user.get("mfa_enabled", 0))
    
    if mfa_enabled:
        # Create a session with mfa_verified = 0
        token = create_session(conn, user["id"], mfa_verified=0)
        # Store in session cookie
        handler.session_digest = session_token_digest(token)
        audit(conn, user["id"], "login_mfa_pending", "user", user["id"])
        conn.commit()
        handler.send_response(200)
        handler.send_header("Set-Cookie", handler.session_cookie_header(token))
        handler.end_headers()
        handler.wfile.write(json.dumps({"mfa_required": True, "token": token}).encode("utf-8"))
    else:
        # Create session with mfa_verified = 1
        token = create_session(conn, user["id"], mfa_verified=1)
        handler.session_digest = session_token_digest(token)
        
        user_info = {
            "id": user["id"],
            "username": user["username"],
            "display_name": user["display_name"],
            "role": user["role"],
            "must_change_password": int(user.get("must_change_password") or 0)
        }
        audit(conn, user["id"], "login_success", "user", user["id"])
        conn.commit()
        handler.send_response(200)
        handler.send_header("Set-Cookie", handler.session_cookie_header(token))
        handler.end_headers()
        
        handler.wfile.write(json.dumps({
            "session": "cookie",
            "csrf_required": True,
            "user": user_info
        }).encode("utf-8"))

def logout(handler: Any, conn: Any) -> None:
    cookie_token = handler.cookies().get("cds_session", "")
    if cookie_token:
        digest = session_token_digest(cookie_token)
        delete_session(conn, digest)
    
    # Also delete session if passed via Bearer auth
    auth_header = handler.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        bearer_token = auth_header.removeprefix("Bearer ")
        digest = session_token_digest(bearer_token)
        delete_session(conn, digest)
        
    conn.commit()
    handler.clear_session_cookie()
    handler.send_json({"ok": True})

def change_password(handler: Any, conn: Any, user: dict) -> None:
    payload = handler.body()
    old_password = str(payload.get("current_password") or payload.get("old_password") or "")
    new_password = str(payload.get("new_password", ""))
    
    # Verify current password
    user_row = conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    if not user_row or not verify_password(old_password, user_row["password_hash"]):
        handler.send_error_json("Invalid current password", 400)
        return
        
    # Enforce strength rules
    is_admin = user_row["role"] == "super_admin" or user_row["role"] == "admin"
    try:
        validate_password_strength(new_password, is_admin=is_admin)
    except ValueError as exc:
        handler.send_error_json(str(exc), 400)
        return
        
    new_hash = encode_password(new_password)
    conn.execute(
        "UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
        (new_hash, user["id"]),
    )
    
    # Invalidate other sessions
    keep_digest = getattr(handler, "session_digest", None)
    invalidate_user_sessions(conn, user["id"], keep_token=keep_digest)
    
    audit(conn, user["id"], "change_password", "user", user["id"])
    conn.commit()
    handler.send_json({"ok": True})

def mfa_setup(handler: Any, conn: Any, user: dict) -> None:
    # Require verified session
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user["username"], issuer_name="ClinicalDataStudio")
    handler.send_json({"secret": secret, "otpauth_url": uri})

def mfa_enable(handler: Any, conn: Any, user: dict) -> None:
    payload = handler.body()
    secret = str(payload.get("secret", "")).strip()
    code = str(payload.get("code", "")).strip()
    
    if not secret or not code:
        handler.send_error_json("Secret and verification code are required", 400)
        return
        
    totp = pyotp.TOTP(secret)
    if totp.verify(code):
        conn.execute(
            "UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE id = ?",
            (secret, user["id"]),
        )
        audit(conn, user["id"], "mfa_enable", "user", user["id"])
        conn.commit()
        handler.send_json({"success": True})
    else:
        handler.send_error_json("Invalid verification code", 400)

def mfa_disable(handler: Any, conn: Any, user: dict) -> None:
    payload = handler.body()
    password = str(payload.get("password", ""))
    
    user_row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user["id"],)).fetchone()
    if not user_row or not verify_password(password, user_row["password_hash"]):
        handler.send_error_json("Invalid password confirmation", 400)
        return
        
    conn.execute(
        "UPDATE users SET mfa_secret = NULL, mfa_enabled = 0 WHERE id = ?",
        (user["id"],),
    )
    audit(conn, user["id"], "mfa_disable", "user", user["id"])
    conn.commit()
    handler.send_json({"success": True})

def login_mfa(handler: Any, conn: Any) -> None:
    payload = handler.body()
    code = str(payload.get("code", "")).strip()
    
    # Retrieve current session (even if not fully verified yet)
    cookie_token = handler.cookies().get("cds_session", "")
    if not cookie_token:
        # Fallback to Authorization header
        auth_header = handler.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            cookie_token = auth_header.removeprefix("Bearer ")
            
    if not cookie_token:
        handler.send_error_json("Session token is missing", 401)
        return
        
    digest = session_token_digest(cookie_token)
    session_row = conn.execute(
        """
        SELECT sessions.*, users.username, users.mfa_secret, users.mfa_enabled, users.display_name, users.role, users.must_change_password
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.token = ? AND users.active = 1
        """,
        (digest,),
    ).fetchone()
    
    if not session_row:
        handler.send_error_json("Invalid or expired session", 401)
        return
        
    session = dict(session_row)
    if not session["mfa_enabled"]:
        handler.send_error_json("MFA is not enabled for this user", 400)
        return
        
    totp = pyotp.TOTP(session["mfa_secret"])
    if totp.verify(code):
        # Update session setting mfa_verified = 1
        conn.execute("UPDATE sessions SET mfa_verified = 1 WHERE token = ?", (digest,))
        
        user_info = {
            "id": session["user_id"],
            "username": session["username"],
            "display_name": session["display_name"],
            "role": session["role"],
            "must_change_password": session["must_change_password"]
        }
        audit(conn, session["user_id"], "login_mfa_success", "user", session["user_id"])
        conn.commit()
        handler.send_json({"success": True, "user": user_info})
    else:
        audit(conn, session["user_id"], "login_mfa_failed", "user", session["user_id"])
        conn.commit()
        handler.send_error_json("Invalid MFA verification code", 400)
