from __future__ import annotations

import re
from collections.abc import Mapping


PHI_PATTERNS = [
    ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)),
    ("phone", re.compile(r"(?:\+?\d[\s-]?){10,14}")),
    ("aadhaar_like", re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")),
    ("exact_dob", re.compile(r"\b(?:dob|date\s*of\s*birth)\b\s*[:#-]\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", re.IGNORECASE)),
    ("identifier_label", re.compile(r"\b(?:mrd|mrn|uhid|aadhaar|aadhar|hospital\s*number|phone|mobile|email|address)\b\s*[:#-]", re.IGNORECASE)),
    ("patient_name_label", re.compile(r"\b(?:patient\s*name|name)\b\s*[:#-]\s*[A-Za-z][A-Za-z .'-]{2,}", re.IGNORECASE)),
]


def env_enabled(environ: Mapping[str, str], key: str, default: bool = False) -> bool:
    value = environ.get(key)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def ai_status_payload(settings, environ: Mapping[str, str], default_model: str, default_transcribe_model: str) -> dict:
    provider = settings.ai_provider
    ai_enabled = bool(settings.ai_enabled)
    external_enabled = ai_enabled and provider == "openai" and bool(environ.get("OPENAI_API_KEY", "").strip())
    multimodal_enabled = external_enabled and bool(getattr(settings, "ai_multimodal", False))
    return {
        "provider": provider if external_enabled else "local",
        "ai_enabled": ai_enabled,
        "external_ai_enabled": external_enabled,
        "model": (getattr(settings, "ai_model", default_model) or default_model) if external_enabled else "local-rules",
        "transcribe_model": (getattr(settings, "ai_transcribe_model", default_transcribe_model) or default_transcribe_model) if external_enabled else "local-rules",
        "multimodal_enabled": multimodal_enabled,
        "phi_allowed": bool(settings.ai_allow_phi),
        "max_file_mb": int(getattr(settings, "ai_max_file_mb", 8)),
        "monthly_budget_limit": getattr(settings, "ai_monthly_budget_limit", ""),
        "note": "External AI is disabled unless CDS_AI_ENABLED=true, CDS_AI_PROVIDER=openai, and OPENAI_API_KEY are configured. Uploaded evidence files are sent only when CDS_AI_MULTIMODAL=true.",
    }


def phi_findings(text: str) -> list[str]:
    findings = []
    for label, pattern in PHI_PATTERNS:
        if pattern.search(text or ""):
            findings.append(label)
    return sorted(set(findings))


def deidentify_for_ai(text: str, replacement: str = "Study participant") -> str:
    cleaned = text or ""
    cleaned = PHI_PATTERNS[0][1].sub("[email removed]", cleaned)
    cleaned = PHI_PATTERNS[1][1].sub("[phone removed]", cleaned)
    cleaned = PHI_PATTERNS[2][1].sub("[identifier removed]", cleaned)
    cleaned = PHI_PATTERNS[3][1].sub("DOB: [removed]", cleaned)
    cleaned = re.sub(r"\b(patient\s*name|name)\b\s*[:#-]\s*[^\n,;]+", f"Patient name: {replacement}", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\b(address)\b\s*[:#-]\s*[^\n]+", "Address: [removed]", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\b(mrd|mrn|uhid|aadhaar|aadhar|hospital\s*number)\b\s*[:#-]\s*[^\s,;]+", r"\1: [removed]", cleaned, flags=re.IGNORECASE)
    return cleaned


def assert_external_ai_safe(text: str, status: dict) -> None:
    if not status["external_ai_enabled"] or status["phi_allowed"]:
        return
    findings = phi_findings(text)
    if findings:
        raise ValueError(
            "External AI is blocked because the case text appears to contain identifiers: "
            + ", ".join(findings)
            + ". Remove identifiers or keep CDS_AI_ALLOW_PHI=false and use local AI only."
        )
