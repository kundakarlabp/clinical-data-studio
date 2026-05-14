from __future__ import annotations


def local_case_summary_seed(text: str, title: str = "") -> dict:
    """Return a stable placeholder payload for local, non-external extraction."""
    return {
        "title": title,
        "source_text": text,
        "mode": "local",
    }

