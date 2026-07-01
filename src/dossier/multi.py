from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from .gateway import RegistaGateway

if TYPE_CHECKING:
    from .config import Settings


def slug_to_project(slug: str) -> str:
    """Convert a URL slug to a regista project (schema) name.

    regista schema names forbid hyphens (``validate_project_name`` in
    ``regista._connection``), so slugs like ``cert-watch`` map to
    ``cert_watch``. This MUST match the mapping agent-notes uses
    (``face_factory.regista_project_name``) so the two faces address the
    same schema for the same software-project.
    """
    from regista._connection import validate_project_name

    return str(validate_project_name(slug.replace("-", "_")))


def project_to_slug(project: str) -> str:
    """Reverse of :func:`slug_to_project` — schema name to URL slug."""
    return project.replace("_", "-")


class GatewayRegistry:
    """Per-project gateway cache (Plan 011 WI-1).

    Holds a ``dict[str, RegistaGateway]`` keyed by regista project (schema)
    name, building lazily on first access **only for projects in the known
    set**. Unknown projects raise :class:`KeyError` — this is the allowlist
    gate that prevents unauthorised schema access.

    For tests, call :meth:`add` to pre-register ``InMemoryRegista``-backed
    gateways — no DSN or HMAC key needed.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        known_projects: list[str] | None = None,
    ) -> None:
        self._settings = settings
        self._gateways: dict[str, RegistaGateway] = {}
        if known_projects:
            self._known_projects: set[str] = set(known_projects)
        elif settings:
            self._known_projects = {settings.project}
        else:
            self._known_projects = set()
        self._lock = threading.Lock()

    def add(self, project: str, gateway: RegistaGateway) -> None:
        """Pre-register a gateway (used by tests)."""
        self._gateways[project] = gateway
        self._known_projects.add(project)

    def get(self, project: str) -> RegistaGateway:
        """Return the gateway for *project*.

        Raises :class:`KeyError` if *project* is not in the known set.
        Builds lazily on first access (thread-safe via double-checked
        locking).
        """
        gw = self._gateways.get(project)
        if gw is not None:
            return gw
        if project not in self._known_projects:
            raise KeyError(f"project {project!r} is not in the known set")
        if self._settings is None:
            raise KeyError(
                f"No gateway for project {project!r} and no settings to build one"
            )
        with self._lock:
            gw = self._gateways.get(project)
            if gw is not None:
                return gw
            gw = self._build(project)
            self._gateways[project] = gw
            return gw

    def list_projects(self) -> list[str]:
        """Return known project names sorted alphabetically."""
        return sorted(self._known_projects)

    def close_all(self) -> None:
        for gw in self._gateways.values():
            gw.close()
        self._gateways.clear()

    def _build(self, project: str) -> RegistaGateway:
        import regista

        assert self._settings is not None
        s = self._settings
        reg = regista.Regista(
            s.database_url,
            project,
            s.hmac_key_path,
            require_ssl=s.require_ssl,
        )
        gw = RegistaGateway(reg, project_name=project)
        gw.register_workflow()
        return gw
