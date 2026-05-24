import base64
import hashlib
import hmac
import secrets

PBKDF2_ROUNDS = 260_000

def encode_password(password: str, salt: bytes | None = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"

def verify_password(password: str, encoded: str) -> bool:
    if not encoded.startswith("pbkdf2_sha256$"):
        return False
    parts = encoded.split("$")
    if len(parts) != 4:
        return False
    try:
        rounds = int(parts[1])
        salt = base64.b64decode(parts[2])
        digest = base64.b64decode(parts[3])
    except Exception:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return hmac.compare_digest(digest, actual)

def validate_password_strength(password: str, is_admin: bool = False) -> None:
    if not password:
        raise ValueError("Password cannot be empty")
    
    min_len = 18 if is_admin else 15
    if len(password) < min_len:
        role_str = "Admin password" if is_admin else "Password"
        raise ValueError(f"{role_str} must be at least {min_len} characters long")
        
    if len(password) > 128:
        raise ValueError("Password cannot be longer than 128 characters")
