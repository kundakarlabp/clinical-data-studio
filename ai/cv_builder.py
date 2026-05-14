from __future__ import annotations


def cv_item_suggestion(title: str, item_type: str = "case_report", status: str = "idea") -> dict:
    return {
        "title": title.strip() or "Untitled academic item",
        "item_type": item_type,
        "status": status,
    }

