import os
import json
import logging
from typing import Any

from ai.safety import ai_status_payload, assert_external_ai_safe as assert_ai_text_safe, deidentify_for_ai as deidentify_text_for_ai, phi_findings as detect_phi_findings
import config

LOGGER = logging.getLogger("clinical-data-studio")
SETTINGS = config.load_settings()

DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_TRANSCRIBE_MODEL = "gpt-4o-transcribe"

AI_ALLOWED_PURPOSES = {
    "protocol_to_crf", "case_summary", "missing_fields", "inconsistency_detection", 
    "publication_idea", "cv_item", "case_publication_review", "crf_optimize", 
    "case_eligibility", "crf_review"
}

def default_ai_policy() -> dict:
    return {
        "enabled": True,
        "local_ai_allowed": True,
        "external_ai_allowed": False,
        "phi_allowed": False,
        "multimodal_allowed": False,
        "allowed_purposes": sorted(AI_ALLOWED_PURPOSES),
        "monthly_budget_limit": "",
    }

def normalize_ai_policy(value: Any) -> dict:
    if isinstance(value, str):
        try:
            raw = json.loads(value)
        except Exception:
            raw = {}
    elif isinstance(value, dict):
        raw = value
    else:
        raw = {}
        
    policy = default_ai_policy()
    if isinstance(raw, dict):
        policy.update({key: raw[key] for key in policy.keys() if key in raw})
        
    policy["enabled"] = bool(policy.get("enabled"))
    policy["local_ai_allowed"] = bool(policy.get("local_ai_allowed"))
    policy["external_ai_allowed"] = bool(policy.get("external_ai_allowed"))
    policy["phi_allowed"] = bool(policy.get("phi_allowed"))
    policy["multimodal_allowed"] = bool(policy.get("multimodal_allowed"))
    
    requested = policy.get("allowed_purposes") or []
    if isinstance(requested, str):
        requested = [item.strip() for item in requested.split(",")]
    policy["allowed_purposes"] = sorted({item for item in requested if item in AI_ALLOWED_PURPOSES}) or sorted(AI_ALLOWED_PURPOSES)
    return policy

def study_ai_policy(conn: Any, study_id: int) -> dict:
    row = conn.execute("SELECT ai_policy_json FROM studies WHERE id = ?", (study_id,)).fetchone()
    return normalize_ai_policy(row["ai_policy_json"] if row else {})

def ai_policy_allows(
    policy: dict, purpose: str, external: bool = False, input_type: str = "text", phi_detected: bool = False
) -> tuple[bool, str]:
    purpose = purpose.strip().lower().replace("-", "_")
    if not policy.get("enabled"):
        return False, "AI is disabled for this project."
    if purpose not in set(policy.get("allowed_purposes") or []):
        return False, "This AI purpose is not allowed for this project."
    if external:
        if not policy.get("external_ai_allowed"):
            return False, "External AI is disabled for this project."
        if phi_detected and not policy.get("phi_allowed"):
            return False, "Project policy blocks sending likely PHI to external AI."
        if input_type in {"image", "pdf", "audio", "mixed"} and not policy.get("multimodal_allowed"):
            return False, "Project policy blocks external file/photo/audio AI."
    elif not policy.get("local_ai_allowed"):
        return False, "Local AI helpers are disabled for this project."
    return True, ""

def phi_findings(text: str) -> list[str]:
    return detect_phi_findings(text)

def deidentify_for_ai(text: str, replacement: str = "Study participant") -> str:
    return deidentify_text_for_ai(text, replacement)

def assert_external_ai_safe(text: str) -> None:
    assert_ai_text_safe(text)

def ai_status() -> dict:
    return ai_status_payload(SETTINGS, os.environ, DEFAULT_OPENAI_MODEL, DEFAULT_TRANSCRIBE_MODEL)
