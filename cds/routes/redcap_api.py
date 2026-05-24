import json
import logging
from typing import Any

from cds.services.audit_service import audit

LOGGER = logging.getLogger("clinical-data-studio")

def redcap_api(handler: Any, conn: Any, method: str, query: dict[str, list[str]]) -> None:
    if method not in {"GET", "POST"}:
        handler.send_error_json("Unsupported REDCap-style API method", 405)
        return
        
    values = {key: value[-1] for key, value in query.items() if value}
    if method == "POST":
        values.update(handler.request_values())
        
    raw_token = str(values.get("token") or handler.headers.get("x-cds-api-token", "")).strip()
    user, token_row = handler.user_from_api_token(conn, raw_token)
    if not user:
        handler.send_error_json("Invalid API token", 401)
        return
        
    study_id = token_row["study_id"]
    from server import user_membership, membership_has, row, rows
    membership = user_membership(conn, user, study_id)
    if not membership:
        handler.send_error_json("Study access denied", 403)
        return
        
    content = str(values.get("content", "project")).strip().lower()
    action = str(values.get("action", "export")).strip().lower()
    output_format = str(values.get("format", "json")).strip().lower()
    
    audit(conn, user["id"], "api_request", "api_token", token_row["id"], None, 
          {"content": content, "action": action, "format": output_format}, study_id=study_id)
          
    if content in {"version", "api_version"}:
        handler.send_redcap_payload({"api_version": "local-redcap-style-v1", "application": "Clinical Data Studio"}, output_format)
        return
        
    if content in {"project", "project_info"}:
        if not handler.require_token_scope(token_row, "metadata:read"):
            return
        payload = row(conn, "SELECT * FROM studies WHERE id = ?", (study_id,))
        handler.send_redcap_payload(payload, output_format)
        return
        
    if content in {"metadata", "data_dictionary"}:
        if not handler.require_token_scope(token_row, "metadata:read"):
            return
        payload = handler.metadata_payload(conn, study_id)["data_dictionary"]
        handler.send_redcap_payload(payload, output_format)
        return
        
    if content in {"instrument", "instruments"}:
        if not handler.require_token_scope(token_row, "metadata:read"):
            return
        payload = handler.metadata_payload(conn, study_id)["instruments"]
        handler.send_redcap_payload(payload, output_format)
        return
        
    if content in {"event", "events"}:
        if not handler.require_token_scope(token_row, "metadata:read"):
            return
        payload = rows(conn, "SELECT name AS event_name, code AS unique_event_name, arm_name, day_offset FROM study_events WHERE study_id = ? ORDER BY display_order", (study_id,))
        handler.send_redcap_payload(payload, output_format)
        return
        
    if content in {"arm", "arms"}:
        if not handler.require_token_scope(token_row, "metadata:read"):
            return
        payload = handler.arm_payload(conn, study_id)
        handler.send_redcap_payload(payload, output_format)
        return
        
    if content in {"dag", "dags", "data_access_group", "data_access_groups"}:
        if not handler.require_token_scope(token_row, "metadata:read"):
            return
        if not membership_has(membership, "manage_users"):
            handler.send_error_json("User management permission required", 403)
            return
        payload = rows(conn, "SELECT code AS unique_group_name, name AS data_access_group_name FROM data_groups WHERE study_id = ? ORDER BY name", (study_id,))
        handler.send_redcap_payload(payload, output_format)
        return
        
    if content in {"user", "users", "user_rights"}:
        if not handler.require_token_scope(token_row, "metadata:read"):
            return
        if not membership_has(membership, "manage_users"):
            handler.send_error_json("User management permission required", 403)
            return
        payload = handler.user_rights_payload(conn, study_id)
        handler.send_redcap_payload(payload, output_format)
        return
        
    if content in {"record", "records"}:
        if action == "import":
            if not handler.require_token_scope(token_row, "records:write"):
                return
            if not membership_has(membership, "enter_data"):
                handler.send_error_json("Data entry permission required", 403)
                return
            csv_text = str(values.get("data", ""))
            if not csv_text and output_format == "json":
                records = json.loads(str(values.get("records", "[]")))
                csv_text = handler.records_json_to_csv(records)
            handler.import_records_from_csv(conn, user, study_id, membership, csv_text)
            return
            
        if not handler.require_token_scope(token_row, "records:read"):
            return
        if not membership_has(membership, "export_data") and not membership_has(membership, "view_analysis"):
            handler.send_error_json("Export permission required", 403)
            return
            
        payload = handler.record_payload(conn, study_id, membership, {})
        handler.send_redcap_payload(payload, output_format, handler.record_fieldnames(conn, study_id))
        return
        
    if content == "randomization":
        if action != "allocate":
            if not handler.require_token_scope(token_row, "metadata:read"):
                return
            payload = rows(conn, "SELECT * FROM randomization_lists WHERE study_id = ? AND active = 1", (study_id,))
            handler.send_redcap_payload(payload, output_format)
            return
            
        if not handler.require_token_scope(token_row, "randomization:write"):
            return
        participant_uid = str(values.get("study_uid", "")).strip()
        list_id = int(values.get("list_id") or 0)
        participant = row(conn, "SELECT id FROM participants WHERE study_id = ? AND study_uid = ?", (study_id, participant_uid))
        if not participant:
            handler.send_error_json("Participant not found", 404)
            return
            
        allocation = handler.allocate_randomization(conn, user, study_id, list_id, participant["id"])
        conn.commit()
        handler.send_redcap_payload(allocation, output_format)
        return
        
    handler.send_error_json("Unsupported REDCap-style content", 400)
