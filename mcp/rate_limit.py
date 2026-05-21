from __future__ import annotations

import os
import time

RATE_BUCKETS: dict[tuple[str, str, int], int] = {}


def _limit(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def check_rate_limit(token_id: int, ip_address: str, study_id: int | None, token_limit: int | None = None) -> tuple[bool, str]:
    hour = int(time.time() // 3600)
    checks = [
        ("token", str(token_id), token_limit or _limit("CDS_MCP_RATE_LIMIT_PER_TOKEN_PER_HOUR", 100)),
        ("ip", ip_address or "unknown", _limit("CDS_MCP_RATE_LIMIT_PER_IP_PER_HOUR", 200)),
    ]
    if study_id:
        checks.append(("study", str(study_id), _limit("CDS_MCP_RATE_LIMIT_PER_STUDY_PER_HOUR", 200)))
    for bucket, value, limit in checks:
        key = (bucket, value, hour)
        if RATE_BUCKETS.get(key, 0) >= max(limit, 1):
            return False, f"MCP rate limit exceeded for {bucket}"
    for bucket, value, _limit_value in checks:
        key = (bucket, value, hour)
        RATE_BUCKETS[key] = RATE_BUCKETS.get(key, 0) + 1
    return True, ""

