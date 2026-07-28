from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .contracts import CONTRACT_VERSION, ProviderDescriptor
from .gateway import RegistaGateway
from .provenance import read_session_detail, read_session_summaries
from .shell import Availability
from .views import read_activity_feed


def describe_activity() -> ProviderDescriptor:
    """Self-description for the activity provider (Plan 015 WI-1.1)."""
    return ProviderDescriptor(
        name="activity",
        contract_version=CONTRACT_VERSION,
        availability=Availability.AVAILABLE,
        capabilities=("list", "get", "feed"),
    )


class ActivityProviderAdapter:
    """Thin adapter binding provenance/feed functions to a gateway and project,
    satisfying the :class:`~dossier.contracts.ActivityProvider` Protocol.

    The adapter does not reimplement the read logic; it delegates to
    :func:`~dossier.provenance.read_session_summaries`,
    :func:`~dossier.provenance.read_session_detail`, and
    :func:`~dossier.views.read_activity_feed`, then converts the typed
    presentation objects into the plain dicts the Protocol declares.
    """

    def __init__(self, gateway: RegistaGateway, project_slug: str) -> None:
        self._gateway = gateway
        self._project_slug = project_slug

    def describe_activity(self) -> ProviderDescriptor:
        return describe_activity()

    def list_sessions(self, *, limit: int = 50) -> list[dict[str, Any]]:
        summaries = read_session_summaries(self._gateway, self._project_slug)
        return [asdict(s) for s in summaries[:limit]]

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        detail = read_session_detail(
            self._gateway, session_id, self._project_slug
        )
        if detail is None:
            return None
        return asdict(detail)

    def activity_feed(self, *, limit: int = 50) -> list[dict[str, Any]]:
        entries = read_activity_feed(
            self._gateway, self._project_slug, limit=limit
        )
        return [asdict(e) for e in entries]
