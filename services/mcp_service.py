from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import time
from typing import Any

from authz import membership_has
from mcp.deidentify import assert_no_phi
from mcp.rate_limit import check_rate_limit
from mcp.schemas import READ_ONLY_TOOLS

MCP_TOOLS = set(READ_ONLY_TOOLS)
MCP_SCOPES = {meta["scope"] for meta in READ_ONLY_TOOLS.values()}
DEFAULT_MCP_SCOPES = sorted(MCP_SCOPES)
DEFAULT_MCP_TOOLS = sorted(MCP_TOOLS)


def _now() -> int:
    return int(time.time())


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _row(conn, sql: str, params: tuple = ()) -> dict | None:
    cur = conn.execute(sql, params)
    data = cur.fetchone()
    return dict(data) if data is not None else None


def _rows(conn, sql: str, params: tuple = ()) -> list[dict]:
    cur = conn.execute(sql, params)
    return [dict(item) for item in cur.fetchall()]


def _load_json(value: str | None, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


def _field_code(field: dict) -> str:
    return str(field.get("code") or field.get("variable") or field.get("field_name") or "").strip()


def _field_label(field: dict) -> str:
    return str(field.get("label") or field.get("field_label") or _field_code(field)).strip()


def _field_type(field: dict) -> str:
    return str(field.get("type") or field.get("field_type") or "text").strip()


def _is_identifier_field(field: dict) -> bool:
    code = _field_code(field).lower()
    label = _field_label(field).lower()
    haystack = f"{code} {label}"
    risky = {"name", "uhid", "mrn", "mrd", "phone", "mobile", "email", "address", "aadhaar", "aadhar", "dob"}
    return bool(field.get("identifier") or field.get("phi") or any(item in haystack for item in risky))


def _safe_number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class McpService:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def token_digest(self, token: str) -> str:
        return _digest(token)

    def create_token(self, conn, *, display_name: str, created_by: int, allowed_study_ids: list[int], scopes: list[str], expires_at: int, rate_limit_per_hour: int = 100) -> dict:
        raw_token = "cds_mcp_" + secrets.token_urlsafe(32)
        safe_scopes = sorted(scope for scope in set(scopes or DEFAULT_MCP_SCOPES) if scope in MCP_SCOPES)
        if not safe_scopes:
            raise ValueError("Select at least one MCP scope")
        safe_studies = sorted({int(study_id) for study_id in allowed_study_ids if int(study_id) > 0})
        if not safe_studies:
            raise ValueError("Select at least one study for this MCP token")
        cur = conn.execute(
            """
            INSERT INTO mcp_tokens(
                token_digest, display_name, created_by, created_at, expires_at, allowed_study_ids_json,
                scopes_json, read_only, deidentified_only, allow_phi, allow_files, rate_limit_per_hour, metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1, 0, 0, ?, ?)
            """,
            (
                _digest(raw_token),
                display_name[:120] or "ChatGPT MCP token",
                created_by,
                _now(),
                expires_at,
                json.dumps(safe_studies),
                json.dumps(safe_scopes),
                max(int(rate_limit_per_hour or 100), 1),
                json.dumps({"allowed_tools": DEFAULT_MCP_TOOLS}),
            ),
        )
        record = _row(conn, "SELECT * FROM mcp_tokens WHERE id = ?", (cur.lastrowid,))
        return {"token": raw_token, "record": self.public_token(record)}

    def public_token(self, token: dict | None) -> dict:
        if not token:
            return {}
        metadata = _load_json(token.get("metadata_json"), {})
        return {
            "id": token["id"],
            "display_name": token.get("display_name", ""),
            "created_by": token.get("created_by"),
            "created_at": token.get("created_at"),
            "expires_at": token.get("expires_at"),
            "revoked_at": token.get("revoked_at"),
            "last_used_at": token.get("last_used_at"),
            "allowed_study_ids": _load_json(token.get("allowed_study_ids_json"), []),
            "scopes": _load_json(token.get("scopes_json"), []),
            "read_only": bool(token.get("read_only", 1)),
            "deidentified_only": bool(token.get("deidentified_only", 1)),
            "allow_phi": bool(token.get("allow_phi", 0)),
            "allow_files": bool(token.get("allow_files", 0)),
            "rate_limit_per_hour": token.get("rate_limit_per_hour", 100),
            "allowed_tools": metadata.get("allowed_tools", DEFAULT_MCP_TOOLS),
        }

    def list_tokens(self, conn, study_id: int) -> dict:
        tokens = _rows(
            conn,
            """
            SELECT mcp_tokens.*, users.username, users.display_name AS created_by_name
            FROM mcp_tokens
            LEFT JOIN users ON users.id = mcp_tokens.created_by
            WHERE allowed_study_ids_json LIKE ?
            ORDER BY mcp_tokens.created_at DESC
            """,
            (f"%{study_id}%",),
        )
        audits = _rows(
            conn,
            """
            SELECT *
            FROM mcp_audit
            WHERE study_id = ?
               OR token_id IN (SELECT id FROM mcp_tokens WHERE allowed_study_ids_json LIKE ?)
            ORDER BY created_at DESC, id DESC
            LIMIT 100
            """,
            (study_id, f"%{study_id}%"),
        )
        public = []
        for token in tokens:
            record = self.public_token(token)
            record["username"] = token.get("username")
            record["created_by_name"] = token.get("created_by_name")
            record["call_count"] = _row(conn, "SELECT COUNT(*) AS count FROM mcp_audit WHERE token_id = ?", (token["id"],))["count"]
            record["blocked_phi_attempts"] = _row(conn, "SELECT COUNT(*) AS count FROM mcp_audit WHERE token_id = ? AND phi_blocked = 1", (token["id"],))["count"]
            public.append(record)
        return {"tokens": public, "audit": audits}

    def revoke_token(self, conn, token_id: int, study_id: int) -> dict:
        token = _row(conn, "SELECT * FROM mcp_tokens WHERE id = ?", (token_id,))
        if not token or study_id not in _load_json(token.get("allowed_study_ids_json"), []):
            raise ValueError("MCP token not found")
        conn.execute("UPDATE mcp_tokens SET revoked_at = ? WHERE id = ?", (_now(), token_id))
        return self.public_token(_row(conn, "SELECT * FROM mcp_tokens WHERE id = ?", (token_id,)))

    def authenticate(self, conn, raw_token: str, request_context: dict) -> dict:
        if not self.enabled:
            raise PermissionError("MCP connector is disabled. Set CDS_MCP_ENABLED=true to enable it.")
        if not raw_token:
            self.audit(conn, None, None, None, "", [], {}, "denied", False, 0, 0, request_context, "Missing MCP token")
            conn.commit()
            raise PermissionError("MCP token required")
        token = _row(conn, "SELECT * FROM mcp_tokens WHERE token_digest = ?", (_digest(raw_token),))
        if not token:
            self.audit(conn, None, None, None, "", [], {}, "denied", False, 0, 0, request_context, "Invalid MCP token")
            conn.commit()
            raise PermissionError("Invalid MCP token")
        if token.get("revoked_at"):
            self.audit(conn, token, None, token.get("created_by"), "", [], {}, "denied", False, 0, 0, request_context, "Revoked MCP token")
            conn.commit()
            raise PermissionError("MCP token revoked")
        if int(token.get("expires_at") or 0) <= _now():
            self.audit(conn, token, None, token.get("created_by"), "", [], {}, "denied", False, 0, 0, request_context, "Expired MCP token")
            conn.commit()
            raise PermissionError("MCP token expired")
        if not token.get("read_only", 1) or token.get("allow_phi", 0) or token.get("allow_files", 0):
            self.audit(conn, token, None, token.get("created_by"), "", [], {}, "denied", False, 0, 0, request_context, "Unsafe MCP token flags")
            conn.commit()
            raise PermissionError("MCP token is not safe for read-only de-identified access")
        return token

    def call_tool(self, conn, raw_token: str, tool_name: str, arguments: dict, request_context: dict) -> dict:
        token = self.authenticate(conn, raw_token, request_context)
        required_scope = READ_ONLY_TOOLS.get(tool_name, {}).get("scope")
        if not required_scope:
            self.audit(conn, token, None, token.get("created_by"), tool_name, [], arguments, "denied", False, 0, 0, request_context, "Unknown or unavailable MCP tool")
            conn.commit()
            raise PermissionError("Unknown or unavailable MCP tool")
        scopes = set(_load_json(token.get("scopes_json"), []))
        if required_scope not in scopes:
            self.audit(conn, token, None, token.get("created_by"), tool_name, [required_scope], arguments, "denied", False, 0, 0, request_context, "MCP token missing required scope")
            conn.commit()
            raise PermissionError("MCP token missing required scope")
        study_id = self.study_id_for_call(token, tool_name, arguments)
        ok, reason = check_rate_limit(token["id"], request_context.get("ip_address", ""), study_id, int(token.get("rate_limit_per_hour") or 100))
        if not ok:
            self.audit(conn, token, study_id, token.get("created_by"), tool_name, [required_scope], arguments, "rate_limited", False, 0, 0, request_context, reason)
            conn.commit()
            raise PermissionError(reason)
        try:
            result = getattr(self, f"tool_{tool_name}")(conn, token, arguments)
            assert_no_phi(result)
            records_count = self.records_count(result)
            aggregate_count = self.aggregate_count(result)
            self.audit(conn, token, study_id, token.get("created_by"), tool_name, [required_scope], arguments, "ok", False, records_count, aggregate_count, request_context, "")
            conn.execute("UPDATE mcp_tokens SET last_used_at = ? WHERE id = ?", (_now(), token["id"]))
            conn.commit()
            return result
        except ValueError as exc:
            phi_blocked = "PHI" in str(exc) or "file" in str(exc).lower()
            self.audit(conn, token, study_id, token.get("created_by"), tool_name, [required_scope], arguments, "blocked" if phi_blocked else "error", phi_blocked, 0, 0, request_context, str(exc))
            conn.commit()
            raise

    def study_id_for_call(self, token: dict, tool_name: str, arguments: dict) -> int | None:
        allowed = set(_load_json(token.get("allowed_study_ids_json"), []))
        if tool_name in {"search_studies", "get_cv_items", "get_ai_audit_summary"} and not arguments.get("study_id"):
            return sorted(allowed)[0] if allowed else None
        study_id = int(arguments.get("study_id") or 0)
        if not study_id or study_id not in allowed:
            raise PermissionError("MCP token is not scoped to this study")
        return study_id

    def allowed_studies(self, token: dict) -> list[int]:
        return [int(item) for item in _load_json(token.get("allowed_study_ids_json"), [])]

    def require_study_access(self, conn, token: dict, study_id: int) -> dict:
        if study_id not in self.allowed_studies(token):
            raise PermissionError("MCP token is not scoped to this study")
        study = _row(conn, "SELECT * FROM studies WHERE id = ?", (study_id,))
        if not study:
            raise PermissionError("Study not found or not allowed")
        membership = _row(conn, "SELECT * FROM study_memberships WHERE study_id = ? AND user_id = ? AND active = 1", (study_id, token.get("created_by")))
        user = _row(conn, "SELECT id, role, active FROM users WHERE id = ? AND active = 1", (token.get("created_by"),))
        if not user:
            raise PermissionError("Linked MCP user is inactive")
        if not membership and user.get("role") not in {"admin", "super_admin"}:
            raise PermissionError("Linked MCP user does not have study access")
        if membership and not (membership_has(membership, "view_analysis") or membership_has(membership, "review_data") or membership_has(membership, "manage_study")):
            raise PermissionError("Linked MCP user does not have safe read permission")
        return study

    def tool_search_studies(self, conn, token: dict, arguments: dict) -> dict:
        query = str(arguments.get("query") or "").strip().lower()
        studies = []
        for study_id in self.allowed_studies(token):
            study = self.require_study_access(conn, token, study_id)
            if query and query not in study.get("name", "").lower() and query not in study.get("protocol_id", "").lower():
                continue
            studies.append(
                {
                    "study_id": study["id"],
                    "title": study.get("name", ""),
                    "short_title": study.get("protocol_id", ""),
                    "status": study.get("status", ""),
                    "participant_count": _row(conn, "SELECT COUNT(*) AS count FROM participants WHERE study_id = ?", (study_id,))["count"],
                    "form_count": _row(conn, "SELECT COUNT(*) AS count FROM forms WHERE study_id = ? AND active = 1", (study_id,))["count"],
                }
            )
        return {"studies": studies}

    def tool_get_study_summary(self, conn, token: dict, arguments: dict) -> dict:
        study_id = int(arguments["study_id"])
        study = self.require_study_access(conn, token, study_id)
        missing = self._missing_summary(conn, study_id, None, "required_only")
        return {
            "study_id": study_id,
            "title": study.get("name", ""),
            "participant_count": _row(conn, "SELECT COUNT(*) AS count FROM participants WHERE study_id = ?", (study_id,))["count"],
            "form_count": _row(conn, "SELECT COUNT(*) AS count FROM forms WHERE study_id = ? AND active = 1", (study_id,))["count"],
            "entry_count": _row(conn, "SELECT COUNT(*) AS count FROM entries WHERE study_id = ?", (study_id,))["count"],
            "open_query_count": _row(conn, "SELECT COUNT(*) AS count FROM queries WHERE study_id = ? AND status = 'open'", (study_id,))["count"],
            "locked_entry_count": _row(conn, "SELECT COUNT(*) AS count FROM entries WHERE study_id = ? AND status IN ('locked', 'frozen')", (study_id,))["count"],
            "reviewed_entry_count": _row(conn, "SELECT COUNT(*) AS count FROM entries WHERE study_id = ? AND status IN ('reviewed', 'locked', 'frozen')", (study_id,))["count"],
            "missing_required_field_count": sum(item["missing_count"] for item in missing),
            "last_updated_at": _row(conn, "SELECT MAX(updated_at) AS updated_at FROM entries WHERE study_id = ?", (study_id,)).get("updated_at"),
        }

    def tool_get_crf_dictionary(self, conn, token: dict, arguments: dict) -> dict:
        study_id = int(arguments["study_id"])
        self.require_study_access(conn, token, study_id)
        params: list[Any] = [study_id]
        where = "study_id = ? AND active = 1"
        if arguments.get("form_id"):
            where += " AND id = ?"
            params.append(int(arguments["form_id"]))
        forms = []
        for form in _rows(conn, f"SELECT * FROM forms WHERE {where} ORDER BY id", tuple(params)):
            schema = _load_json(form.get("schema_json"), {"fields": []})
            fields = []
            for field in schema.get("fields", []):
                fields.append(
                    {
                        "variable": _field_code(field),
                        "label": _field_label(field),
                        "type": _field_type(field),
                        "required": bool(field.get("required")),
                        "choices": field.get("choices") or None,
                        "validation": field.get("validation") or field.get("validation_type") or "",
                        "min": field.get("min"),
                        "max": field.get("max"),
                        "units": field.get("units") or "",
                        "phi": bool(field.get("phi") or field.get("identifier")),
                    }
                )
            forms.append({"form_id": form["id"], "name": form.get("code", ""), "title": form.get("name", ""), "version": form.get("version", 1), "state": form.get("lifecycle_state", ""), "fields": fields})
        return {"forms": forms}

    def tool_get_missing_data_summary(self, conn, token: dict, arguments: dict) -> dict:
        study_id = int(arguments["study_id"])
        self.require_study_access(conn, token, study_id)
        return {"missing": self._missing_summary(conn, study_id, arguments.get("form_id"), str(arguments.get("severity") or "required_only"))}

    def _missing_summary(self, conn, study_id: int, form_id: int | None, severity: str) -> list[dict]:
        params: list[Any] = [study_id]
        where = "entries.study_id = ?"
        if form_id:
            where += " AND entries.form_id = ?"
            params.append(int(form_id))
        entries = _rows(conn, f"SELECT entries.*, forms.name AS form_name, forms.schema_json FROM entries JOIN forms ON forms.id = entries.form_id WHERE {where}", tuple(params))
        totals: dict[str, dict] = {}
        for entry in entries:
            schema = _load_json(entry.get("schema_snapshot_json"), {}) or _load_json(entry.get("schema_json"), {"fields": []})
            data = _load_json(entry.get("data_json"), {})
            for field in schema.get("fields", []):
                required = bool(field.get("required"))
                if severity == "required_only" and not required:
                    continue
                code = _field_code(field)
                if not code or _is_identifier_field(field) or _field_type(field) in {"file", "textarea", "descriptive"}:
                    continue
                key = f"{entry['form_id']}::{code}"
                record = totals.setdefault(key, {"form": entry.get("form_name", ""), "field": code, "label": _field_label(field), "required": required, "missing_count": 0, "total_expected": 0})
                record["total_expected"] += 1
                if data.get(code) in (None, "", []):
                    record["missing_count"] += 1
        result = []
        for record in totals.values():
            total = record["total_expected"] or 1
            record["percent_missing"] = round(record["missing_count"] * 100 / total, 1)
            if record["missing_count"]:
                result.append(record)
        return sorted(result, key=lambda item: item["missing_count"], reverse=True)

    def tool_get_deidentified_dataset_summary(self, conn, token: dict, arguments: dict) -> dict:
        study_id = int(arguments["study_id"])
        self.require_study_access(conn, token, study_id)
        form_id = int(arguments.get("form_id") or 0)
        params: list[Any] = [study_id]
        where = "entries.study_id = ?"
        if form_id:
            where += " AND entries.form_id = ?"
            params.append(form_id)
        entries = _rows(conn, f"SELECT entries.*, forms.name AS form_name, forms.schema_json FROM entries JOIN forms ON forms.id = entries.form_id WHERE {where}", tuple(params))
        numeric: dict[str, list[float]] = {}
        categorical: dict[str, dict[str, int]] = {}
        date_coverage: dict[str, dict[str, Any]] = {}
        for entry in entries:
            schema = _load_json(entry.get("schema_snapshot_json"), {}) or _load_json(entry.get("schema_json"), {"fields": []})
            data = _load_json(entry.get("data_json"), {})
            for field in schema.get("fields", []):
                if _is_identifier_field(field) or _field_type(field) in {"textarea", "file", "descriptive", "section"}:
                    continue
                code = _field_code(field)
                if not code:
                    continue
                value = data.get(code)
                if value in (None, "", []):
                    continue
                name = f"{entry.get('form_name', '')}: {code}"
                if _field_type(field) in {"integer", "decimal", "number", "calculated"}:
                    number = _safe_number(value)
                    if number is not None:
                        numeric.setdefault(name, []).append(number)
                elif _field_type(field) in {"date", "datetime"}:
                    text = str(value)[:10]
                    cov = date_coverage.setdefault(name, {"count": 0, "earliest": text, "latest": text})
                    cov["count"] += 1
                    cov["earliest"] = min(cov["earliest"], text)
                    cov["latest"] = max(cov["latest"], text)
                else:
                    counts = categorical.setdefault(name, {})
                    label = str(value)[:80]
                    counts[label] = counts.get(label, 0) + 1
        numeric_summary = {
            key: {"count": len(values), "mean": round(sum(values) / len(values), 2), "min": min(values), "max": max(values)}
            for key, values in numeric.items()
            if values
        }
        return {
            "summary": {
                "participants": _row(conn, "SELECT COUNT(*) AS count FROM participants WHERE study_id = ?", (study_id,))["count"],
                "forms_completed": len(entries),
                "categorical_counts": categorical,
                "numeric_summary": numeric_summary,
                "date_coverage": date_coverage,
            },
            "limitations": ["Raw rows, identifiers, file links, and free-text fields are excluded to reduce PHI risk."],
        }

    def tool_get_publication_opportunities(self, conn, token: dict, arguments: dict) -> dict:
        study_id = int(arguments["study_id"])
        self.require_study_access(conn, token, study_id)
        case_count = _row(conn, "SELECT COUNT(*) AS count FROM case_intakes WHERE study_id = ?", (study_id,))["count"]
        entry_count = _row(conn, "SELECT COUNT(*) AS count FROM entries WHERE study_id = ?", (study_id,))["count"]
        open_queries = _row(conn, "SELECT COUNT(*) AS count FROM queries WHERE study_id = ? AND status = 'open'", (study_id,))["count"]
        opportunities = []
        if case_count:
            opportunities.append({"type": "case_series", "suggested_title": "Retrospective case series from de-identified case intake records", "rationale": f"{case_count} case intake record(s) are available for grouping.", "needed_data": ["confirm age/sex/outcome completeness", "resolve identifiers in free text", "manual literature review"], "caution": "AI-style suggestion only; novelty requires manual literature review."})
        if entry_count:
            opportunities.append({"type": "audit", "suggested_title": "Clinical audit from structured CRF completion and query patterns", "rationale": f"{entry_count} CRF entrie(s) and {open_queries} open query item(s) can support data quality or process audit.", "needed_data": ["define audit standard", "lock analysis dataset", "document missing data"], "caution": "AI-style suggestion only; novelty requires manual literature review."})
        return {"opportunities": opportunities}

    def tool_get_cv_items(self, conn, token: dict, arguments: dict) -> dict:
        category = str(arguments.get("category") or "").strip().lower()
        study_filter = int(arguments.get("study_id") or 0)
        if study_filter:
            self.require_study_access(conn, token, study_filter)
            allowed = [study_filter]
        else:
            allowed = [sid for sid in self.allowed_studies(token) if self.require_study_access(conn, token, sid)]
        params: list[Any] = allowed
        where = [f"study_id IN ({','.join('?' for _ in allowed)})", "active = 1"]
        if category:
            where.append("category = ?")
            params.append(category)
        items = _rows(conn, f"SELECT category, title, item_date, role, status FROM academic_cv_items WHERE {' AND '.join(where)} ORDER BY item_date DESC, id DESC LIMIT 100", tuple(params))
        return {"items": [{"category": item.get("category", ""), "title": item.get("title", ""), "date": item.get("item_date", ""), "role": item.get("role", ""), "status": item.get("status", "")} for item in items]}

    def tool_get_ai_audit_summary(self, conn, token: dict, arguments: dict) -> dict:
        days = min(max(int(arguments.get("days") or 30), 1), 365)
        since = _now() - days * 86400
        study_id = int(arguments.get("study_id") or 0)
        if study_id:
            self.require_study_access(conn, token, study_id)
            study_filter = "AND study_id = ?"
            params: tuple[Any, ...] = (since, study_id)
        else:
            allowed = [sid for sid in self.allowed_studies(token) if self.require_study_access(conn, token, sid)]
            study_filter = f"AND study_id IN ({','.join('?' for _ in allowed)})" if allowed else "AND 1=0"
            params = tuple([since, *allowed])
        ai_calls = _row(conn, f"SELECT COUNT(*) AS count FROM ai_audit WHERE created_at >= ? {study_filter}", params)["count"]
        mcp_calls = _row(conn, f"SELECT COUNT(*) AS count FROM mcp_audit WHERE created_at >= ? {study_filter}", params)["count"]
        blocked = _row(conn, f"SELECT COUNT(*) AS count FROM mcp_audit WHERE created_at >= ? AND phi_blocked = 1 {study_filter}", params)["count"]
        top_tools = _rows(conn, f"SELECT tool_name, COUNT(*) AS count FROM mcp_audit WHERE created_at >= ? {study_filter} GROUP BY tool_name ORDER BY count DESC LIMIT 8", params)
        return {"calls_total": ai_calls + mcp_calls, "mcp_calls": mcp_calls, "blocked_phi_attempts": blocked, "external_ai_calls": _row(conn, f"SELECT COUNT(*) AS count FROM ai_audit WHERE created_at >= ? AND mode = 'external' {study_filter}", params)["count"], "top_tools": top_tools}

    def records_count(self, result: dict) -> int:
        for key in ("studies", "forms", "items", "opportunities", "missing"):
            if isinstance(result.get(key), list):
                return len(result[key])
        return 0

    def aggregate_count(self, result: dict) -> int:
        return len(json.dumps(result, ensure_ascii=False))

    def audit(self, conn, token: dict | None, study_id: int | None, user_id: int | None, tool_name: str, scopes: list[str], request_params: dict, status: str, phi_blocked: bool, records_count: int, aggregate_count: int, context: dict, error: str) -> None:
        cur = conn.execute(
            """
            INSERT INTO mcp_audit(
                token_id, token_display_name, user_id, study_id, tool_name, scopes_checked, request_params_json,
                response_status, phi_blocked, records_count, aggregate_count, ip_address, user_agent, error_message, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                token.get("id") if token else None,
                token.get("display_name", "") if token else "",
                user_id,
                study_id,
                tool_name[:80],
                json.dumps(scopes),
                json.dumps(request_params, sort_keys=True),
                status[:40],
                1 if phi_blocked else 0,
                int(records_count or 0),
                int(aggregate_count or 0),
                str(context.get("ip_address", ""))[:120],
                str(context.get("user_agent", ""))[:240],
                error[:1000],
                _now(),
            ),
        )
        conn.execute(
            """
            INSERT INTO audit_log(user_id, action, entity_type, entity_id, before_json, after_json, created_at, study_id, ip_address, user_agent, request_id)
            VALUES (?, 'mcp_call', 'mcp_audit', ?, NULL, ?, ?, ?, ?, ?, '')
            """,
            (
                user_id,
                cur.lastrowid,
                json.dumps({"tool_name": tool_name, "status": status, "phi_blocked": bool(phi_blocked), "error": error}, sort_keys=True),
                _now(),
                study_id,
                str(context.get("ip_address", ""))[:120],
                str(context.get("user_agent", ""))[:240],
            ),
        )
