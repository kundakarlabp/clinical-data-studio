import re
import logging
import threading
from typing import Any

# Thread-local storage for request correlation
thread_local = threading.local()

def set_request_id(request_id: str) -> None:
    thread_local.request_id = request_id

def get_request_id() -> str:
    return getattr(thread_local, "request_id", "GLOBAL")

def clear_request_id() -> None:
    if hasattr(thread_local, "request_id"):
        del thread_local.request_id

# Regexes for sanitization
API_TOKEN_RE = re.compile(r'\bcds_[a-zA-Z0-9_-]{16,}\b')
SESSION_TOKEN_RE = re.compile(r'\bcds_session=[a-zA-Z0-9_-]{16,}\b')
PASSWORD_JSON_RE = re.compile(r'(?i)"?password"?\s*[:= ]\s*"[^"]*"')
PASSWORD_HASH_JSON_RE = re.compile(r'(?i)"?password_hash"?\s*[:= ]\s*"[^"]*"')
EMAIL_RE = re.compile(r'\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b')
PHONE_RE = re.compile(r'\b(?:\+?\d{1,3}[- .]?)?\(?\d{3}\)?[- .]?\d{3}[- .]?\d{4}\b')
PHI_NAME_RE = re.compile(r'(?i)\b(?:patient_name|patient name|john doe|jane doe)\b')

def sanitize_log_message(msg: str) -> str:
    if not isinstance(msg, str):
        return msg
    # Redact API tokens
    msg = API_TOKEN_RE.sub("cds_REDACTED", msg)
    # Redact session cookies/tokens
    msg = SESSION_TOKEN_RE.sub("cds_session=REDACTED", msg)
    # Redact passwords in json
    msg = PASSWORD_JSON_RE.sub('"password": "REDACTED"', msg)
    msg = PASSWORD_HASH_JSON_RE.sub('"password_hash": "REDACTED"', msg)
    # Redact emails
    msg = EMAIL_RE.sub("[EMAIL REDACTED]", msg)
    # Redact phone numbers
    msg = PHONE_RE.sub("[PHONE REDACTED]", msg)
    # Redact common PHI names
    msg = PHI_NAME_RE.sub("[PHI REDACTED]", msg)
    return msg

class SanitizingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        record.request_id = get_request_id()
        formatted = super().format(record)
        return sanitize_log_message(formatted)
