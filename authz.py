from __future__ import annotations

from dataclasses import dataclass
from typing import Any


SYSTEM_ADMIN_ROLES = {"admin", "super_admin"}
PROJECT_ADMIN_ROLES = {"owner", "project_admin", "pi"}

PERMISSIONS = {
    "system_admin",
    "manage_users",
    "manage_study",
    "manage_forms",
    "enter_data",
    "review_data",
    "export_data",
    "view_analysis",
    "use_ai",
    "manage_backups",
}

ROLE_PERMISSIONS = {
    "super_admin": PERMISSIONS,
    "admin": PERMISSIONS,
    "owner": {"manage_users", "manage_study", "manage_forms", "enter_data", "review_data", "export_data", "view_analysis", "use_ai", "manage_backups"},
    "project_admin": {"manage_users", "manage_study", "manage_forms", "enter_data", "review_data", "export_data", "view_analysis", "use_ai", "manage_backups"},
    "pi": {"manage_users", "manage_study", "manage_forms", "enter_data", "review_data", "export_data", "view_analysis", "use_ai", "manage_backups"},
    "data_entry": {"enter_data"},
    "reviewer": {"review_data", "view_analysis"},
    "analyst": {"export_data", "view_analysis"},
    "viewer": {"view_analysis"},
    "read_only": {"view_analysis"},
}

ACTION_PERMISSIONS = {
    "study.read": "view_analysis",
    "study.manage": "manage_study",
    "forms.manage": "manage_forms",
    "forms.read": "view_analysis",
    "participants.create": "enter_data",
    "participants.edit": "enter_data",
    "entries.create": "enter_data",
    "entries.edit": "enter_data",
    "entries.review": "review_data",
    "queries.manage": "review_data",
    "export.read": "export_data",
    "audit.read": "review_data",
    "users.manage": "manage_users",
    "backups.manage": "manage_backups",
    "ai.use": "use_ai",
}


def safe_role(role: str | None) -> str:
    return (role or "").strip().lower()


def is_super_admin(user: dict | None) -> bool:
    return bool(user and safe_role(user.get("role")) in SYSTEM_ADMIN_ROLES)


def role_has(role: str | None, permission: str) -> bool:
    if permission not in PERMISSIONS:
        return False
    return permission in ROLE_PERMISSIONS.get(safe_role(role), set())


def membership_has(membership: dict | None, permission: str) -> bool:
    return bool(membership and role_has(membership.get("role"), permission))


def can(user: dict | None, action: str, membership: dict | None = None, obj: dict | None = None) -> bool:
    if not user:
        return False
    if is_super_admin(user):
        return True
    permission = ACTION_PERMISSIONS.get(action, action)
    if not permission:
        return False
    if not membership_has(membership, permission):
        return False
    if obj and membership and membership.get("data_group_id"):
        object_group = obj.get("data_group_id")
        if object_group not in (None, membership.get("data_group_id")):
            return False
    return True


@dataclass
class AuthorizationResult:
    ok: bool
    message: str = ""
    status: int = 403


def require_permission(user: dict | None, action: str, membership: dict | None = None, obj: dict | None = None) -> AuthorizationResult:
    if can(user, action, membership, obj):
        return AuthorizationResult(True)
    return AuthorizationResult(False, "Permission denied", 403)


def require_study_access(user: dict | None, membership: dict | None) -> AuthorizationResult:
    if is_super_admin(user) or membership:
        return AuthorizationResult(True)
    return AuthorizationResult(False, "Study access denied", 403)


def require_data_group_access(membership: dict | None, obj: dict | None, object_name: str = "Record") -> AuthorizationResult:
    if not membership or not membership.get("data_group_id") or not obj:
        return AuthorizationResult(True)
    if obj.get("data_group_id") == membership.get("data_group_id"):
        return AuthorizationResult(True)
    return AuthorizationResult(False, f"{object_name} is outside your data access group", 403)


def role_summary(role: str) -> dict[str, Any]:
    normalized = safe_role(role)
    return {"role": normalized, "permissions": sorted(ROLE_PERMISSIONS.get(normalized, set()))}
