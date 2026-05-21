from __future__ import annotations

import json
import re
from typing import Any

PHI_PATTERNS = [
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    re.compile(r"\b(?:\+?91[-\s]?)?[6-9]\d{9}\b"),
    re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
    re.compile(r"\b(?:UHID|MRN|MRD|Aadhaar|Aadhar|patient\s+name|DOB|date\s+of\s+birth)\s*[:#-]\s*[A-Za-z0-9/ ._-]{2,}\b", re.IGNORECASE),
    re.compile(r"\b\d{1,2}[/-]\d{1,2}[/-](?:19|20)\d{2}\b"),
    re.compile(r"\b(?:address|mobile|phone)\s*[:#-]\s*[A-Za-z0-9, ./_-]{6,}\b", re.IGNORECASE),
    re.compile(r"https?://[^\s\"']+", re.IGNORECASE),
    re.compile(r"\b(?:uploads|case_files|case-intake)/[^\s\"']+", re.IGNORECASE),
]

RAW_NOTE_KEYS = {"source_text", "notes", "note", "clinical_notes", "transcript", "dictation", "raw_text", "text"}


def _walk_strings(value: Any, parent_key: str = ""):
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key) in RAW_NOTE_KEYS and isinstance(child, str) and len(child) > 80:
                yield f"{key}: raw-note"
            else:
                yield from _walk_strings(child, str(key))
    elif isinstance(value, list):
        for child in value:
            yield from _walk_strings(child, parent_key)
    elif isinstance(value, str):
        yield value


def phi_findings(payload: Any) -> list[str]:
    findings: list[str] = []
    for text in _walk_strings(payload):
        for pattern in PHI_PATTERNS:
            if pattern.search(text):
                findings.append(pattern.pattern)
                break
        if len(findings) >= 10:
            break
    return findings


def assert_no_phi(payload: Any) -> None:
    findings = phi_findings(payload)
    if findings:
        raise ValueError("Response blocked because it may contain PHI. Use a narrower aggregate query.")


def safe_json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)

