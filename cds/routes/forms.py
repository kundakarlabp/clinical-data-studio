import json
import logging
import os
import time
from typing import Any
from urllib.request import Request as UrlRequest, urlopen as urlopen_request

from cds.db import row, rows, load_json
from cds.services.audit_service import audit

LOGGER = logging.getLogger("clinical-data-studio")

FORM_LIFECYCLE_STATES = {"draft", "published", "retired", "locked"}

def now() -> int:
    return int(time.time())

def forms_route(handler: Any, conn: Any, user: dict, method: str, study_id: int, parts: list[str]) -> None:
    from server import user_membership, membership_has, assert_external_ai_safe, record_ai_audit, DEFAULT_OPENAI_MODEL, SETTINGS, extract_openai_text, normalize_schema, form_schema_diff, validate_crf_for_publish, form_lifecycle_state, normalize_code
    
    membership = user_membership(conn, user, study_id)
    if not membership:
        handler.send_error_json("Study access denied", 403)
        return
        
    if method == "POST" and len(parts) == 6 and parts[5] == "ai-optimize":
        if not membership_has(membership, "review_data"):
            handler.send_error_json("Review permission required to trigger AI", 403)
            return
        form_id = int(parts[4])
        form = row(conn, "SELECT * FROM forms WHERE id = ? AND study_id = ?", (form_id, study_id))
        if not form:
            handler.send_error_json("Form not found", 404)
            return
        payload = handler.body()
        user_prompt = str(payload.get("prompt", "")).strip()
        current_schema = load_json(form["schema_json"], {"fields": []})
        try:
            assert_external_ai_safe(json.dumps(current_schema))
            if user_prompt:
                assert_external_ai_safe(user_prompt)
        except Exception as exc:
            handler.send_error_json(f"AI Safety check failed: {exc}", 400)
            return
        api_key = os.environ.get("OPENAI_API_KEY", "").strip()
        if not api_key:
            handler.send_error_json("OPENAI_API_KEY is not configured", 500)
            return
        model = SETTINGS.ai_model or DEFAULT_OPENAI_MODEL
        schema_format = {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "fields": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "code": {"type": "string"},
                            "label": {"type": "string"},
                            "type": {"type": "string", "enum": ["text", "textarea", "number", "date", "select", "checkbox", "file"]},
                            "required": {"type": "boolean"},
                            "options": {"type": "array", "items": {"type": "string"}},
                        },
                        "required": ["code", "label", "type", "required", "options"],
                    },
                }
            },
            "required": ["fields"],
        }
        prompt_content = f"Optimize this clinical CRF schema. Standardize field naming, correct validation constraints, align checkboxes/options, and suggest missing clinical fields if relevant.\n"
        if user_prompt:
            prompt_content += f"User feedback/instructions for optimization: {user_prompt}\n"
        prompt_content += f"Current schema:\n{json.dumps(current_schema, indent=2)}"
        request_payload = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a world-class clinical research architect. Optimize the clinical CRF schema provided."
                },
                {
                    "role": "user",
                    "content": prompt_content
                }
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "optimized_schema",
                    "strict": True,
                    "schema": schema_format
                }
            }
        }
        try:
            request = UrlRequest(
                "https://api.openai.com/v1/chat/completions",
                data=json.dumps(request_payload).encode("utf-8"),
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                method="POST",
            )
            with urlopen_request(request, timeout=30) as response:
                res_body = json.loads(response.read().decode("utf-8"))
            output_text = extract_openai_text(res_body)
            if not output_text:
                handler.send_error_json("AI response did not contain text output", 500)
                return
            optimized_schema = normalize_schema(json.loads(output_text))
            ai_audit_id = record_ai_audit(
                conn,
                user["id"],
                study_id=study_id,
                purpose="crf_optimize",
                input_type="json",
                mode="openai",
                phi_detected=0,
                status_value="ok"
            )
            audit(conn, user["id"], "ai_request", "ai_audit", ai_audit_id, None, {"purpose": "crf_optimize", "form_id": form_id}, study_id=study_id, **handler.audit_context())
            conn.commit()
            handler.send_json({"optimized_schema": optimized_schema, "diff": form_schema_diff(current_schema, optimized_schema)})
        except Exception as exc:
            handler.send_error_json(f"AI optimization failed: {exc}", 500)
        return

    if method == "GET" and len(parts) == 6 and parts[5] == "versions":
        form_id = int(parts[4])
        current = row(conn, "SELECT * FROM forms WHERE id = ? AND study_id = ?", (form_id, study_id))
        if not current:
            handler.send_error_json("Form not found", 404)
            return
        versions = rows(conn, "SELECT id, form_id, study_id, version, name, code, schema_json, saved_by, saved_at FROM form_versions WHERE form_id = ? AND study_id = ? ORDER BY version DESC", (form_id, study_id))
        current_schema = load_json(current["schema_json"], {"fields": []})
        for version in versions:
            prior_schema = load_json(version.pop("schema_json"), {"fields": []})
            version["diff_to_current"] = form_schema_diff(prior_schema, current_schema)
        current_payload = {
            "id": current["id"],
            "form_id": current["id"],
            "study_id": study_id,
            "version": current["version"],
            "name": current["name"],
            "code": current["code"],
            "saved_by": None,
            "saved_at": current["updated_at"],
            "diff_to_current": {"fields_added": [], "fields_removed": [], "fields_changed": []},
            "current": True,
        }
        versions.insert(0, current_payload)
        handler.send_json({"versions": versions})
        return

    if method == "GET":
        forms = rows(conn, "SELECT * FROM forms WHERE study_id = ? ORDER BY id", (study_id,))
        for form in forms:
            form["schema"] = load_json(form.pop("schema_json"), {"fields": []})
        handler.send_json({"forms": forms})
        return

    if method == "POST" and len(parts) == 4:
        payload = handler.body()
        timestamp = now()
        schema = normalize_schema(payload.get("schema") or {"fields": []})
        lifecycle_state = str(payload.get("lifecycle_state") or "published").strip().lower()
        if lifecycle_state not in FORM_LIFECYCLE_STATES:
            lifecycle_state = "published"
        cur = conn.execute(
            "INSERT INTO forms(study_id, name, code, schema_json, lifecycle_state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (study_id, str(payload.get("name", "")).strip() or "Untitled Form", normalize_code(str(payload.get("code", "")), f"form_{timestamp}"), json.dumps(schema), lifecycle_state, timestamp, timestamp),
        )
        event_ids = payload.get("event_ids") or []
        if not event_ids:
            baseline = row(conn, "SELECT id FROM study_events WHERE study_id = ? AND code = 'baseline'", (study_id,))
            event_ids = [baseline["id"]] if baseline else []
        for event_id in event_ids:
            if row(conn, "SELECT id FROM study_events WHERE id = ? AND study_id = ?", (event_id, study_id)):
                conn.execute(
                    """
                    INSERT OR IGNORE INTO form_events(study_id, event_id, form_id, required, created_at, updated_at)
                    VALUES (?, ?, ?, 1, ?, ?)
                    """,
                    (study_id, event_id, cur.lastrowid, timestamp, timestamp),
                )
        after = row(conn, "SELECT * FROM forms WHERE id = ?", (cur.lastrowid,))
        audit(conn, user["id"], "create", "form", cur.lastrowid, None, after)
        conn.commit()
        handler.send_json({"form": after}, 201)
        return

    if method == "PATCH" and len(parts) == 5:
        form_id = int(parts[4])
        before = row(conn, "SELECT * FROM forms WHERE id = ? AND study_id = ?", (form_id, study_id))
        if not before:
            handler.send_error_json("Form not found", 404)
            return
        payload = handler.body()
        action = str(payload.get("action", "")).strip().lower()
        if action in {"validate", "publish", "retire", "lock", "unlock", "save_draft"}:
            current_schema = load_json(before["schema_json"], {"fields": []})
            errors = validate_crf_for_publish(current_schema)
            if action == "validate":
                handler.send_json({"valid": not errors, "errors": errors, "lifecycle_state": form_lifecycle_state(before)})
                return
            if action == "publish" and errors:
                handler.send_json({"errors": errors}, 422)
                return
            next_state = {
                "publish": "published",
                "retire": "retired",
                "lock": "locked",
                "unlock": "published",
                "save_draft": "draft",
            }[action]
            conn.execute("UPDATE forms SET lifecycle_state = ?, active = ?, updated_at = ? WHERE id = ? AND study_id = ?", (next_state, 0 if next_state == "retired" else 1, now(), form_id, study_id))
            after = row(conn, "SELECT * FROM forms WHERE id = ?", (form_id,))
            audit(conn, user["id"], action, "form", form_id, before, after, study_id=study_id, **handler.audit_context())
            conn.commit()
            handler.send_json({"form": after})
            return
        schema = normalize_schema(payload.get("schema", load_json(before["schema_json"], {})))
        lifecycle_state = str(payload.get("lifecycle_state") or before.get("lifecycle_state") or "published").strip().lower()
        if lifecycle_state not in FORM_LIFECYCLE_STATES:
            lifecycle_state = form_lifecycle_state(before)
        conn.execute(
            "INSERT INTO form_versions(form_id, study_id, version, name, code, schema_json, saved_by, saved_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (form_id, study_id, before["version"], before["name"], before["code"], before["schema_json"], user["id"], now()),
        )
        conn.execute(
            "UPDATE forms SET name = ?, code = ?, schema_json = ?, lifecycle_state = ?, version = version + 1, updated_at = ? WHERE id = ? AND study_id = ?",
            (str(payload.get("name", before["name"])).strip(), normalize_code(str(payload.get("code", before["code"])), before["code"]), json.dumps(schema), lifecycle_state, now(), form_id, study_id),
        )
        after = row(conn, "SELECT * FROM forms WHERE id = ?", (form_id,))
        audit(conn, user["id"], "update", "form", form_id, before, after)
        conn.commit()
        handler.send_json({"form": after})
        return

    handler.send_error_json("Unsupported forms operation", 405)
