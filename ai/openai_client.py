from __future__ import annotations


class ExternalAIDisabled(RuntimeError):
    """Raised when an external AI pipeline is requested but not enabled."""


def require_external_ai(status: dict) -> None:
    if not status.get("external_ai_enabled"):
        raise ExternalAIDisabled("External AI is disabled by policy/configuration.")

