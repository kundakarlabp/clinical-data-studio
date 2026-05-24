import hashlib
import json
import time
from typing import Any

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

def now() -> int:
    return int(time.time())

def compute_row_hash(
    user_id: int | None,
    action: str,
    entity_type: str,
    entity_id: int | None,
    before_json: str | None,
    after_json: str | None,
    created_at: int,
    study_id: int | None,
    ip_address: str,
    user_agent: str,
    request_id: str,
    previous_hash: str,
) -> str:
    row_data = {
        "user_id": user_id,
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "before_json": before_json,
        "after_json": after_json,
        "created_at": created_at,
        "study_id": study_id,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "request_id": request_id,
        "previous_hash": previous_hash,
    }
    serialized = json.dumps(row_data, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

def audit(
    conn: Any,
    user_id: int | None,
    action: str,
    entity_type: str,
    entity_id: int | None,
    before=None,
    after=None,
    study_id: int | None = None,
    ip_address: str = "",
    user_agent: str = "",
    request_id: str = "",
) -> None:
    created_at = now()
    before_json = json.dumps(before, sort_keys=True) if before is not None else None
    after_json = json.dumps(after, sort_keys=True) if after is not None else None
    
    # 1. Fetch previous hash
    last_row = conn.execute(
        "SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    
    previous_hash = GENESIS_HASH
    if last_row and last_row["row_hash"]:
        previous_hash = last_row["row_hash"]
        
    # 2. Compute current row hash
    row_hash = compute_row_hash(
        user_id,
        action,
        entity_type,
        entity_id,
        before_json,
        after_json,
        created_at,
        study_id,
        ip_address[:120],
        user_agent[:240],
        request_id[:80],
        previous_hash,
    )
    
    # 3. Insert record
    conn.execute(
        """
        INSERT INTO audit_log (
            user_id, action, entity_type, entity_id, before_json, after_json, 
            created_at, study_id, ip_address, user_agent, request_id, 
            previous_hash, row_hash
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            action,
            entity_type,
            entity_id,
            before_json,
            after_json,
            created_at,
            study_id,
            ip_address[:120],
            user_agent[:240],
            request_id[:80],
            previous_hash,
            row_hash,
        ),
    )

def verify_audit_chain(conn: Any) -> dict[str, Any]:
    rows = conn.execute(
        """
        SELECT id, user_id, action, entity_type, entity_id, before_json, after_json,
               created_at, study_id, ip_address, user_agent, request_id, 
               previous_hash, row_hash
        FROM audit_log
        ORDER BY id ASC
        """
    ).fetchall()
    
    expected_previous = GENESIS_HASH
    for i, row in enumerate(rows):
        row_dict = dict(row)
        
        # Check link
        if row_dict["previous_hash"] != expected_previous:
            return {
                "ok": False,
                "break_at_id": row_dict["id"],
                "reason": f"Chain link break: expected previous hash '{expected_previous}', but got '{row_dict['previous_hash']}'",
            }
            
        # Re-compute and verify hash
        computed = compute_row_hash(
            row_dict["user_id"],
            row_dict["action"],
            row_dict["entity_type"],
            row_dict["entity_id"],
            row_dict["before_json"],
            row_dict["after_json"],
            row_dict["created_at"],
            row_dict["study_id"],
            row_dict["ip_address"],
            row_dict["user_agent"],
            row_dict["request_id"],
            row_dict["previous_hash"],
        )
        
        if row_dict["row_hash"] != computed:
            return {
                "ok": False,
                "break_at_id": row_dict["id"],
                "reason": f"Hash mismatch: stored row_hash '{row_dict['row_hash']}' does not match computed hash '{computed}'",
            }
            
        expected_previous = row_dict["row_hash"]
        
    return {"ok": True, "count": len(rows)}

def backfill_audit_chain(conn: Any) -> None:
    # Used during schema migration to retroactively link existing records.
    rows = conn.execute(
        """
        SELECT id, user_id, action, entity_type, entity_id, before_json, after_json,
               created_at, study_id, ip_address, user_agent, request_id
        FROM audit_log
        ORDER BY id ASC
        """
    ).fetchall()
    
    expected_previous = GENESIS_HASH
    for row in rows:
        row_dict = dict(row)
        computed = compute_row_hash(
            row_dict["user_id"],
            row_dict["action"],
            row_dict["entity_type"],
            row_dict["entity_id"],
            row_dict["before_json"],
            row_dict["after_json"],
            row_dict["created_at"],
            row_dict["study_id"],
            row_dict["ip_address"] or "",
            row_dict["user_agent"] or "",
            row_dict["request_id"] or "",
            expected_previous,
        )
        conn.execute(
            "UPDATE audit_log SET previous_hash = ?, row_hash = ? WHERE id = ?",
            (expected_previous, computed, row_dict["id"]),
        )
        expected_previous = computed
