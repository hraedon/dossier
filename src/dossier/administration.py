"""Administration provider — project metadata, access, and policy surfaces.

Reads project catalog, access policy, and principal roster. Does not
mutate bootstrap-owned configuration.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .actors import Actor
from .gateway import RegistaGateway
from .multi import project_to_slug


@dataclass(frozen=True, slots=True)
class ProjectInfo:
    schema_name: str
    display_name: str | None
    owner: str | None
    created_at: datetime | None


@dataclass(frozen=True, slots=True)
class AccessPolicy:
    project_slug: str
    readable_projects: tuple[str, ...]
    is_admin: bool
    admin_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AdminSummary:
    projects: tuple[ProjectInfo, ...]
    access: AccessPolicy | None
    principal_count: int
    findings: tuple[str, ...]


def _extract_project_info(schema_name: str, gateway: RegistaGateway) -> ProjectInfo:
    display_name: str | None = None
    owner: str | None = None
    created_at: datetime | None = None

    try:
        entry = gateway.get_project_catalog_entry()
        if entry is not None:
            dn = getattr(entry, "display_name", None)
            if dn:
                display_name = str(dn)
            ow = getattr(entry, "owner_actor_id", None)
            if ow:
                owner = str(ow)
            ca = getattr(entry, "created_at", None)
            if ca is not None:
                created_at = ca if isinstance(ca, datetime) else None
    except Exception:
        pass

    return ProjectInfo(
        schema_name=schema_name,
        display_name=display_name,
        owner=owner,
        created_at=created_at,
    )


def read_project_list(gateway: RegistaGateway) -> list[ProjectInfo]:
    """List all projects from the catalog.

    Returns a list of :class:`ProjectInfo` sorted by schema name.
    """
    project_names = gateway.list_catalog_projects()
    if not project_names:
        project_names = [gateway._project_name]

    infos: list[ProjectInfo] = []
    for name in project_names:
        infos.append(_extract_project_info(name, gateway))

    infos.sort(key=lambda p: p.schema_name)
    return infos


def read_access_policy(
    gateway: RegistaGateway,
    project_slug: str,
    *,
    actor: Actor,
    is_admin: bool,
    admin_ids: tuple[str, ...] = (),
    readable_projects: tuple[str, ...] = (),
) -> AccessPolicy:
    """Build an access policy view for the current actor.

    When ``readable_projects`` is empty, falls back to the catalog list.
    ``admin_ids`` defaults to empty — the caller supplies the configured set.
    """
    if not readable_projects:
        readable_projects = tuple(
            project_to_slug(p) for p in gateway.list_catalog_projects()
        )

    return AccessPolicy(
        project_slug=project_slug,
        readable_projects=readable_projects,
        is_admin=is_admin,
        admin_ids=admin_ids,
    )


def read_admin_summary(
    gateway: RegistaGateway,
    actor: Actor,
    is_admin: bool,
    *,
    project_slug: str = "",
    admin_ids: tuple[str, ...] = (),
    readable_projects: tuple[str, ...] = (),
) -> AdminSummary:
    """Read project catalog, access policy, and principal count.

    Returns a composed summary suitable for the admin index page.
    """
    findings: list[str] = []

    projects = read_project_list(gateway)
    if not projects:
        findings.append("no projects in catalog")

    access = read_access_policy(
        gateway,
        project_slug,
        actor=actor,
        is_admin=is_admin,
        admin_ids=admin_ids,
        readable_projects=readable_projects,
    )

    principal_count = 0
    try:
        principals = gateway.list_principals()
        principal_count = len(principals)
    except Exception:
        findings.append("failed to read principal count")

    if not is_admin:
        findings.append("current user is not an administrator")

    return AdminSummary(
        projects=tuple(projects),
        access=access,
        principal_count=principal_count,
        findings=tuple(findings),
    )
