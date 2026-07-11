"""Project-scoped read authorization for dossier's cross-project window.

The policy is a deployment input, not work state. Regista remains authoritative
for projects, ownership, events, and workflow; dossier decides which of those
projects an authenticated human face may disclose.
"""

from __future__ import annotations

import json
import hashlib
import hmac
import os
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from ._platform import open_no_follow
from .actors import Actor

AccessMode = Literal["open", "audit", "enforce"]

_MAX_POLICY_BYTES = 1024 * 1024
_TOP_LEVEL_KEYS = frozenset({"version", "administrators", "projects"})
_GRANT_KEYS = frozenset({"principals", "groups"})
_PROJECT_KEYS = _GRANT_KEYS | {"public"}


@dataclass(frozen=True, slots=True)
class AccessGrant:
    principals: frozenset[str]
    groups: frozenset[str]

    def matches(self, actor: Actor) -> bool:
        return actor.actor_id in self.principals or bool(
            self.groups.intersection(actor.groups)
        )


@dataclass(frozen=True, slots=True)
class ProjectGrant:
    public: bool
    access: AccessGrant


@dataclass(frozen=True, slots=True)
class AccessDecision:
    allowed: bool
    reason: str


@dataclass(frozen=True, slots=True)
class ProjectAccessPolicy:
    administrators: AccessGrant
    projects: dict[str, ProjectGrant]

    def decide(self, actor: Actor, project: str) -> AccessDecision:
        if self.administrators.matches(actor):
            return AccessDecision(True, "explicit-administrator")
        grant = self.projects.get(project)
        if grant is None:
            return AccessDecision(False, "project-not-declared")
        if grant.public:
            return AccessDecision(True, "explicit-public-project")
        if grant.access.matches(actor):
            return AccessDecision(True, "project-membership")
        return AccessDecision(False, "no-matching-principal-or-group")


def can_read_project(
    actor: Actor,
    project: str,
    policy: ProjectAccessPolicy | None = None,
) -> bool:
    """The single project-read authorization seam.

    ``policy=None`` preserves the v1 open posture. Deployed audit/enforcement
    paths pass a validated policy. Keeping the compatibility behavior here lets
    existing single-team installations upgrade without silently denying access.
    """
    if policy is None:
        return True
    return policy.decide(actor, project).allowed


def load_project_access_policy(
    path: str,
    *,
    group_claim_key: bytes | None = None,
) -> ProjectAccessPolicy:
    """Load and strictly validate an owner-controlled JSON ACL.

    Symlinks and group/world-writable files are refused on POSIX. Duplicate or
    unknown JSON fields are errors so a misspelled security control cannot be
    silently ignored. Every undeclared project is denied by construction.
    """
    if not path.strip():
        raise RuntimeError("DOSSIER_PROJECT_ACL_PATH is required")
    raw = _read_policy(Path(path).expanduser())
    try:
        parsed = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid project ACL JSON: {type(exc).__name__}") from None
    except ValueError as exc:
        # object_pairs_hook raises only our ref/path-free duplicate-key error.
        raise ValueError(str(exc)) from None
    if not isinstance(parsed, dict):
        raise ValueError("project ACL must be a JSON object")
    _reject_unknown_keys(parsed, _TOP_LEVEL_KEYS, "policy")
    if parsed.get("version") != 1:
        raise ValueError("project ACL version must be 1")
    administrators = _parse_grant(
        parsed.get("administrators", {}),
        "administrators",
        _GRANT_KEYS,
        group_claim_key,
    )
    projects_raw = parsed.get("projects")
    if not isinstance(projects_raw, dict):
        raise ValueError("project ACL projects must be an object")

    projects: dict[str, ProjectGrant] = {}
    for project, value in projects_raw.items():
        _validate_identifier(project, "project")
        if not isinstance(value, dict):
            raise ValueError(f"project {project!r} grant must be an object")
        _reject_unknown_keys(value, _PROJECT_KEYS, f"project {project!r}")
        public = value.get("public", False)
        if not isinstance(public, bool):
            raise ValueError(f"project {project!r} public must be boolean")
        grant = _parse_grant(
            value, f"project {project!r}", _PROJECT_KEYS, group_claim_key
        )
        if public and (grant.principals or grant.groups):
            raise ValueError(
                f"project {project!r} cannot combine public with membership grants"
            )
        if not public and not grant.principals and not grant.groups:
            raise ValueError(
                f"project {project!r} must be public or name a principal/group"
            )
        projects[project] = ProjectGrant(public=public, access=grant)

    return ProjectAccessPolicy(
        administrators=administrators,
        projects=projects,
    )


def parse_access_mode(value: str) -> AccessMode:
    normalized = value.strip().lower()
    if normalized not in {"open", "audit", "enforce"}:
        raise ValueError(
            "DOSSIER_PROJECT_ACCESS_MODE must be open, audit, or enforce"
        )
    return cast(AccessMode, normalized)


def _read_policy(path: Path) -> bytes:
    fd = open_no_follow(str(path), os.O_RDONLY)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise PermissionError("project ACL must be a regular file")
        if os.name == "posix" and info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PermissionError("project ACL must not be group/world writable")
        if info.st_size > _MAX_POLICY_BYTES:
            raise ValueError("project ACL exceeds 1 MiB limit")
        chunks: list[bytes] = []
        remaining = _MAX_POLICY_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > _MAX_POLICY_BYTES:
            raise ValueError("project ACL exceeds 1 MiB limit")
        return data
    finally:
        os.close(fd)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate project ACL key: {key!r}")
        result[key] = value
    return result


def _reject_unknown_keys(
    value: dict[str, Any], allowed: frozenset[str], context: str
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"unknown {context} fields: {', '.join(unknown)}")


def _parse_grant(
    value: object,
    context: str,
    allowed: frozenset[str],
    group_claim_key: bytes | None,
) -> AccessGrant:
    if not isinstance(value, dict):
        raise ValueError(f"{context} must be an object")
    _reject_unknown_keys(value, allowed, context)
    principals = _parse_identifiers(value.get("principals", []), f"{context} principals")
    groups = _parse_identifiers(value.get("groups", []), f"{context} groups")
    for group in groups:
        _validate_group_claim(group, context)
    if group_claim_key is not None:
        groups = [encode_group_claim(group, group_claim_key) for group in groups]
    return AccessGrant(frozenset(principals), frozenset(groups))


def _parse_identifiers(value: object, context: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{context} must be an array")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{context} entries must be strings")
        _validate_identifier(item, context)
        result.append(item)
    if len(set(result)) != len(result):
        raise ValueError(f"{context} contains duplicates")
    return result


def _validate_identifier(value: str, context: str) -> None:
    if not value or len(value) > 256 or value != value.strip():
        raise ValueError(f"invalid {context} identifier")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"invalid {context} identifier")


def _validate_group_claim(value: str, context: str) -> None:
    if value.startswith("guid:"):
        raw = value.removeprefix("guid:")
        try:
            parsed = uuid.UUID(raw)
        except ValueError:
            raise ValueError(f"invalid {context} group GUID") from None
        if str(parsed) != raw:
            raise ValueError(f"{context} group GUID must be canonical lowercase")
        return
    if value.startswith("name:"):
        raw = value.removeprefix("name:")
        if not raw or raw != raw.casefold():
            raise ValueError(f"{context} group name must be non-empty and case-folded")
        return
    raise ValueError(f"{context} group must use guid: or name: prefix")


def encode_group_claim(value: str, key: bytes) -> str:
    """Blind a canonical group identity for safe client-side session storage."""
    if len(key) < 32:
        raise ValueError("group claim key must be at least 32 bytes")
    _validate_group_claim(value, "authorization")
    digest = hmac.new(
        key,
        b"dossier-project-group-v1\x00" + value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"hmac-sha256:{digest}"
