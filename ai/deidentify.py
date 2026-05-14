from __future__ import annotations

from .safety import deidentify_for_ai, phi_findings


def preview_deidentification(text: str, replacement: str = "Study participant") -> dict:
    cleaned = deidentify_for_ai(text, replacement)
    return {
        "input_findings": phi_findings(text),
        "output_findings": phi_findings(cleaned),
        "cleaned_text": cleaned,
    }

