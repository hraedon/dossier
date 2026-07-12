"""Closed, presentation-only contracts for dossier's replaceable UI shell.

These types deliberately contain no provider objects or acting behavior.  Routes
and providers normalize their results before templates see them; templates can
therefore render known states without inspecting component internals.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from .actors import Actor


class ConsoleArea(StrEnum):
    WORK = "work"
    KNOWLEDGE = "knowledge"
    ACTIVITY = "activity"
    EVIDENCE = "evidence"
    OPERATIONS = "operations"
    ADMINISTRATION = "administration"


class Availability(StrEnum):
    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    UNSUPPORTED = "unsupported"
    UNREACHABLE = "unreachable"
    NOT_CONFIGURED = "not_configured"
    UNKNOWN = "unknown"


class Freshness(StrEnum):
    CURRENT = "current"
    STALE = "stale"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class Status(StrEnum):
    OK = "ok"
    INFO = "info"
    WARNING = "warning"
    FAILED = "failed"
    UNKNOWN = "unknown"


class ActionRisk(StrEnum):
    ROUTINE = "routine"
    SENSITIVE = "sensitive"
    HIGH = "high"
    IRREVERSIBLE = "irreversible"


@dataclass(frozen=True, slots=True)
class Breadcrumb:
    label: str
    href: str | None = None


@dataclass(frozen=True, slots=True)
class NavigationItem:
    area: ConsoleArea
    label: str
    href: str | None
    availability: Availability
    active: bool = False


@dataclass(frozen=True, slots=True)
class ProviderAvailability:
    provider: str
    availability: Availability
    detail: str | None = None
    observed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    label: str
    status: Status
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class PageAction:
    label: str
    href: str
    risk: ActionRisk = ActionRisk.ROUTINE
    required_authority: str | None = None
    method: str = "GET"

    def __post_init__(self) -> None:
        method = self.method.upper()
        if method not in {"GET", "POST"}:
            raise ValueError("page actions support only GET or POST")
        object.__setattr__(self, "method", method)


@dataclass(frozen=True, slots=True)
class PageMetadata:
    area: ConsoleArea
    title: str
    description: str | None = None
    breadcrumbs: tuple[Breadcrumb, ...] = ()
    source: str = "dossier"
    observed_at: datetime | None = None
    effective_revision: str | None = None
    freshness: Freshness = Freshness.UNKNOWN
    status: Status = Status.UNKNOWN
    findings: tuple[Finding, ...] = ()
    actions: tuple[PageAction, ...] = ()
    help_href: str | None = None
    correlation_id: str | None = None


@dataclass(frozen=True, slots=True)
class ShellView:
    actor: Actor
    area: ConsoleArea
    navigation: tuple[NavigationItem, ...]
    page: PageMetadata
    providers: tuple[ProviderAvailability, ...] = ()


_ROUTE_TITLES = {
    "/": "Dashboard",
    "/review": "Review queue",
    "/my-work": "My work",
    "/feed": "Activity feed",
    "/search": "Search",
    "/sessions": "Agent activity",
    "/activity": "Activity",
    "/evidence": "Evidence",
    "/evidence/integrity": "Integrity report",
    "/evidence/events": "Event verification",
    "/operations": "Operations",
    "/admin": "Administration",
    "/admin/projects": "Projects",
    "/admin/access": "Access policy",
    "/admin/principals": "Principal roster",
    "/me/identity": "My signing identity",
    "/me/signing-history": "My signing history",
    "/knowledge": "Knowledge",
    "/knowledge/search": "Search knowledge",
    "/knowledge/new": "New note",
}


def area_for_path(path: str) -> ConsoleArea:
    """Return a known area for a route; unknown current routes fail into Work."""
    if (
        path == "/sessions"
        or path.startswith("/sessions/")
        or "/sessions/" in path
        or path == "/activity"
    ):
        return ConsoleArea.ACTIVITY
    if path == "/evidence" or path.startswith("/evidence/"):
        return ConsoleArea.EVIDENCE
    if path == "/operations" or path.startswith("/operations/"):
        return ConsoleArea.OPERATIONS
    if path == "/knowledge" or path.startswith("/knowledge/"):
        return ConsoleArea.KNOWLEDGE
    if path.startswith("/admin/") or path.startswith("/me/") or path == "/admin":
        return ConsoleArea.ADMINISTRATION
    return ConsoleArea.WORK


def build_shell(path: str, actor: Actor, *, is_admin: bool) -> ShellView:
    """Build the route-level shell without consulting any component provider."""
    area = area_for_path(path)
    destinations: tuple[tuple[ConsoleArea, str, str | None, Availability], ...] = (
        (ConsoleArea.WORK, "Work", "/", Availability.AVAILABLE),
        (ConsoleArea.KNOWLEDGE, "Knowledge", "/knowledge", Availability.AVAILABLE),
        (ConsoleArea.ACTIVITY, "Activity", "/activity", Availability.AVAILABLE),
        (ConsoleArea.EVIDENCE, "Evidence", "/evidence", Availability.AVAILABLE),
        (ConsoleArea.OPERATIONS, "Operations", "/operations", Availability.AVAILABLE),
        (
            ConsoleArea.ADMINISTRATION,
            "Administration",
            "/admin" if is_admin else "/me/identity",
            Availability.AVAILABLE,
        ),
    )
    navigation = tuple(
        NavigationItem(
            area=item_area,
            label=label,
            href=href,
            availability=availability,
            active=item_area is area,
        )
        for item_area, label, href, availability in destinations
    )
    title = _ROUTE_TITLES.get(path)
    if title is None:
        title = "Issue" if "/issues/" in path else "Dossier"
    page = PageMetadata(area=area, title=title)
    return ShellView(actor=actor, area=area, navigation=navigation, page=page)
