import json
import logging
import time
from typing import Any

from cds.db import row, rows, load_json
from cds.services.audit_service import audit

LOGGER = logging.getLogger("clinical-data-studio")

def now() -> int:
    return int(time.time())

def entries_route(handler: Any, conn: Any, user: dict, method: str, study_id: int, parts: list[str], query: dict[str, list[str]], membership: dict) -> None:
    from server import (
        normalize_entry_status,
        form_lifecycle_state,
        form_schema_snapshot,
        validate_entry_data,
        entry_hash,
        membership_has,
        FORM_ENTRY_ALLOWED_STATES
    )
    
    if method == "GET" and len(parts) == 6 and parts[5] == "history":
        entry_id = int(parts[4])
        entry = row(conn, "SELECT * FROM entries WHERE id = ? AND study_id = ?", (entry_id, study_id))
        if not entry:
            handler.send_error_json("Entry not found", 404)
            return
        participant = row(conn, "SELECT * FROM participants WHERE id = ?", (entry["participant_id"],))
        if membership.get("data_group_id") and participant and participant.get("data_group_id") != membership["data_group_id"]:
            handler.send_error_json("Entry is outside your data access group", 403)
            return
        history = rows(
            conn,
            """
            SELECT audit_log.*, users.display_name
            FROM audit_log
            LEFT JOIN users ON users.id = audit_log.user_id
            WHERE audit_log.entity_type = 'entry' AND audit_log.entity_id = ?
            ORDER BY audit_log.created_at DESC, audit_log.id DESC
            """,
            (entry_id,),
        )
        for item in history:
            item["before"] = load_json(item.pop("before_json"), None)
            item["after"] = load_json(item.pop("after_json"), None)
        states = rows(conn, "SELECT field_states.*, users.display_name FROM field_states LEFT JOIN users ON users.id = field_states.user_id WHERE entry_id = ? ORDER BY created_at DESC", (entry_id,))
        handler.send_json({"history": history, "field_states": states})
        return

    if method == "GET":
        participant_id = int((query.get("participant_id") or ["0"])[0])
        params = (study_id,)
        sql = "SELECT entries.*, forms.name AS form_name, forms.code AS form_code, participants.study_uid, study_events.name AS mapped_event_name, study_events.code AS event_code FROM entries JOIN forms ON forms.id = entries.form_id JOIN participants ON participants.id = entries.participant_id LEFT JOIN study_events ON study_events.id = entries.event_id WHERE entries.study_id = ?"
        if membership.get("data_group_id"):
            sql += " AND participants.data_group_id = ?"
            params = (study_id, membership["data_group_id"])
        if participant_id:
            sql += " AND participant_id = ?"
            params = (*params, participant_id)
        entries_list = rows(conn, sql + " ORDER BY entries.updated_at DESC", params)
        for entry in entries_list:
            entry["data"] = load_json(entry.pop("data_json"), {})
            entry["schema_snapshot"] = load_json(entry.pop("schema_snapshot_json"), {})
        handler.send_json({"entries": entries_list})
        return

    if method == "POST":
        payload = handler.body()
        timestamp = now()
        participant_id = int(payload["participant_id"])
        form_id = int(payload["form_id"])
        event_id = payload.get("event_id")
        event = None
        if event_id:
            event = row(conn, "SELECT * FROM study_events WHERE id = ? AND study_id = ?", (int(event_id), study_id))
            if not event:
                handler.send_error_json("Event not found", 404)
                return
            event_id = event["id"]
        event_name = str(payload.get("event_name", "")).strip()
        if event:
            event_name = event["code"]
        if not event_name:
            event_name = "Baseline"
        repeat_instance = max(int(payload.get("repeat_instance", 1) or 1), 1)
        data = payload.get("data", {})
        status = normalize_entry_status(payload.get("status"), "draft")
        form = row(conn, "SELECT * FROM forms WHERE id = ? AND study_id = ?", (form_id, study_id))
        participant = row(conn, "SELECT * FROM participants WHERE id = ? AND study_id = ?", (participant_id, study_id))
        if not form or not participant:
            handler.send_error_json("Participant or form not found", 404)
            return
        if event_id and not row(conn, "SELECT id FROM form_events WHERE study_id = ? AND event_id = ? AND form_id = ?", (study_id, event_id, form_id)):
            handler.send_error_json("This CRF is not assigned to the selected event", 400)
            return
        if membership.get("data_group_id") and participant.get("data_group_id") != membership["data_group_id"]:
            handler.send_error_json("Participant is outside your data access group", 403)
            return
        existing = row(conn, "SELECT * FROM entries WHERE participant_id = ? AND form_id = ? AND event_name = ? AND repeat_instance = ?", (participant_id, form_id, event_name, repeat_instance))
        lifecycle_state = form_lifecycle_state(form)
        if lifecycle_state not in FORM_ENTRY_ALLOWED_STATES:
            handler.send_error_json(f"CRF is {lifecycle_state}; data entry is allowed only for published CRFs.", 423 if lifecycle_state == "locked" else 409)
            return
        schema = load_json(form["schema_json"], {"fields": []})
        snapshot = form_schema_snapshot(form, schema)
        form_version = int(form.get("version") or 1)
        if repeat_instance > 1 and not schema.get("repeatable"):
            handler.send_error_json("This CRF is not configured as repeatable", 400)
            return
        cleaned, issues = validate_entry_data(schema, data)
        if issues:
            handler.send_json({"errors": issues}, 422)
            return
        digest = entry_hash(cleaned, form_version, snapshot)
        snapshot_json = json.dumps(snapshot, sort_keys=True)
        if existing:
            if_match_updated_at = payload.get("if_match_updated_at")
            if_match_entry_hash = str(payload.get("if_match_entry_hash") or "").strip()
            try:
                client_updated_at = int(if_match_updated_at or 0)
            except (TypeError, ValueError):
                client_updated_at = -1
            stale_timestamp = if_match_updated_at not in (None, "") and client_updated_at != int(existing.get("updated_at") or 0)
            stale_hash = bool(if_match_entry_hash) and if_match_entry_hash != str(existing.get("entry_hash") or "")
            if stale_timestamp or stale_hash:
                conflict_payload = {
                    "entry_id": existing["id"],
                    "updated_at": existing.get("updated_at"),
                    "entry_hash": existing.get("entry_hash", ""),
                    "data": load_json(existing.get("data_json"), {}),
                }
                audit(conn, user["id"], "sync_conflict", "entry", existing["id"], {"if_match_updated_at": if_match_updated_at, "if_match_entry_hash": if_match_entry_hash}, conflict_payload, study_id=study_id, **handler.audit_context())
                handler.send_json({"error": "Entry was changed on the server. Review conflict before syncing.", "server_entry": conflict_payload}, 409)
                return
            if existing.get("status") == "frozen":
                handler.send_error_json("Entry is frozen for analysis. Unfreeze with a reason before editing.", 423)
                return
            if existing.get("locked_at"):
                if not (membership_has(membership, "review_data") or membership_has(membership, "manage_study")):
                    handler.send_error_json("Entry is locked and cannot be edited by data entry users.", 423)
                    return
                reason = str(payload.get("change_reason", "")).strip()
                if not reason:
                    handler.send_error_json("Change reason is required before editing a locked CRF", 423)
                    return
            before = existing
            conn.execute(
                "UPDATE entries SET event_id = ?, data_json = ?, status = ?, form_version = ?, schema_snapshot_json = ?, entry_hash = ?, updated_by = ?, updated_at = ?, locked_at = NULL, locked_by = NULL, lock_reason = '' WHERE id = ?",
                (event_id, json.dumps(cleaned), status, form_version, snapshot_json, digest, user["id"], timestamp, existing["id"]),
            )
            after = row(conn, "SELECT * FROM entries WHERE id = ?", (existing["id"],))
            audit(conn, user["id"], "update", "entry", existing["id"], before, {"entry": after, "change_reason": payload.get("change_reason", "")})
            conn.commit()
            handler.send_json({"entry": after})
            return
        cur = conn.execute(
            "INSERT INTO entries(study_id, participant_id, form_id, event_id, event_name, repeat_instance, status, data_json, form_version, schema_snapshot_json, entry_hash, created_by, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (study_id, participant_id, form_id, event_id, event_name, repeat_instance, status, json.dumps(cleaned), form_version, snapshot_json, digest, user["id"], user["id"], timestamp, timestamp),
        )
        after = row(conn, "SELECT * FROM entries WHERE id = ?", (cur.lastrowid,))
        audit(conn, user["id"], "create", "entry", cur.lastrowid, None, after)
        conn.commit()
        handler.send_json({"entry": after}, 201)
        return

    if method == "PATCH" and len(parts) == 5:
        entry_id = int(parts[4])
        before = row(conn, "SELECT * FROM entries WHERE id = ? AND study_id = ?", (entry_id, study_id))
        if not before:
            handler.send_error_json("Entry not found", 404)
            return
        participant = row(conn, "SELECT * FROM participants WHERE id = ?", (before["participant_id"],))
        if membership.get("data_group_id") and participant and participant.get("data_group_id") != membership["data_group_id"]:
            handler.send_error_json("Entry is outside your data access group", 403)
            return
        payload = handler.body()
        action = str(payload.get("action", "")).strip()
        if action in {"lock", "freeze"}:
            if not (membership_has(membership, "review_data") or membership_has(membership, "manage_study")):
                handler.send_error_json("Review permission required", 403)
                return
            reason = str(payload.get("reason", "")).strip()
            if not reason:
                handler.send_error_json("Reason is required", 400)
                return
            next_status = "frozen" if action == "freeze" else "locked"
            conn.execute("UPDATE entries SET locked_at = ?, locked_by = ?, lock_reason = ?, status = ?, updated_by = ?, updated_at = ? WHERE id = ?", (now(), user["id"], reason, next_status, user["id"], now(), entry_id))
            after = row(conn, "SELECT * FROM entries WHERE id = ?", (entry_id,))
            audit(conn, user["id"], action, "entry", entry_id, before, after, study_id=study_id, **handler.audit_context())
            conn.commit()
            handler.send_json({"entry": after})
            return
        if action in {"unlock", "unfreeze"}:
            if not (membership_has(membership, "review_data") or membership_has(membership, "manage_study")):
                handler.send_error_json("Review permission required", 403)
                return
            reason = str(payload.get("reason", "")).strip()
            if not reason:
                handler.send_error_json("Unlock reason is required", 400)
                return
            next_status = "reviewed" if action in {"unlock", "unfreeze"} else before.get("status", "complete")
            if next_status in {"locked", "frozen"}:
                next_status = "reviewed"
            conn.execute("UPDATE entries SET locked_at = NULL, locked_by = NULL, lock_reason = '', status = ?, updated_by = ?, updated_at = ? WHERE id = ?", (next_status, user["id"], now(), entry_id))
            after = row(conn, "SELECT * FROM entries WHERE id = ?", (entry_id,))
            audit(conn, user["id"], action, "entry", entry_id, before, {"entry": after, "reason": reason}, study_id=study_id, **handler.audit_context())
            conn.commit()
            handler.send_json({"entry": after})
            return
        if action in {"verify_field", "freeze_field"}:
            from server import normalize_code
            field_code = normalize_code(str(payload.get("field_code", "")))
            if not field_code:
                handler.send_error_json("Field code is required", 400)
                return
            state = "verified" if action == "verify_field" else "frozen"
            reason = str(payload.get("reason", "")).strip()
            conn.execute(
                """
                INSERT OR REPLACE INTO field_states(entry_id, field_code, state, reason, user_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (entry_id, field_code, state, reason, user["id"], now()),
            )
            audit(conn, user["id"], action, "entry", entry_id, before, {"field_code": field_code, "state": state, "reason": reason}, study_id=study_id, **handler.audit_context())
            conn.commit()
            handler.send_json({"field_state": {"entry_id": entry_id, "field_code": field_code, "state": state}})
            return
        handler.send_error_json("Unsupported entry action", 405)
        return
    handler.send_error_json("Unsupported entries operation", 405)
