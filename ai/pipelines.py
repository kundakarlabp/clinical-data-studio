from __future__ import annotations

from .deidentify import preview_deidentification
from .openai_client import require_external_ai


def prepare_external_case_text(text: str, status: dict, replacement: str) -> dict:
    """Prepare text for an external model without bypassing the PHI policy gate."""
    require_external_ai(status)
    preview = preview_deidentification(text, replacement)
    if not status.get("phi_allowed") and preview["output_findings"]:
        raise ValueError("Text still appears to contain identifiers after de-identification.")
    return preview

