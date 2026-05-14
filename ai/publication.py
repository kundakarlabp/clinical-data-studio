from __future__ import annotations


def publication_angle_prompt_terms(case_group: str, diagnosis: str = "") -> list[str]:
    terms = [part for part in [case_group, diagnosis, "case report", "case series", "clinical audit"] if part]
    return list(dict.fromkeys(terms))

