import json
import logging
from typing import Any

from cds.services.audit_service import verify_audit_chain, audit
from server import rows, is_super_admin, study_audit_params, audit_filters

LOGGER = logging.getLogger("clinical-data-studio")

def verify_audit_api(handler: Any, conn: Any, user: Any) -> None:
    if not is_super_admin(user):
        handler.send_error_json("Admin permission required", 403)
        return
        
    verification = verify_audit_chain(conn)
    audit(conn, user["id"], "verify_audit_chain", "system", None, None, {"ok": verification["ok"]})
    handler.send_json(verification)

def get_system_audit_api(handler: Any, conn: Any, user: Any) -> None:
    if not is_super_admin(user):
        handler.send_error_json("Admin permission required", 403)
        return
    # Return last 250 audit log records
    records = rows(conn, "SELECT audit_log.*, users.display_name FROM audit_log LEFT JOIN users ON users.id = audit_log.user_id ORDER BY audit_log.id DESC LIMIT 250")
    handler.send_json({"audit": records})

def get_study_audit_api(handler: Any, conn: Any, user: Any, study_id: int, query: dict[str, list[str]]) -> None:
    audit_where, audit_params = audit_filters(study_id, query)
    audit_rows = rows(
        conn,
        f"""
        SELECT audit_log.*, users.username, users.display_name
        FROM audit_log
        LEFT JOIN users ON users.id = audit_log.user_id
        WHERE {audit_where}
        ORDER BY audit_log.id DESC
        LIMIT 250
        """,
        audit_params,
    )
    suspicious_actions = {"failed_login", "export", "download", "create_full", "create_encrypted", "ai_request", "api_request", "sync_conflict"}
    suspicious = [item for item in audit_rows if item["action"] in suspicious_actions or item["entity_type"] in {"backup", "case_file", "case_ai_review", "ai_audit"}]
    handler.send_json({"audit": audit_rows, "suspicious": suspicious[:50]})
