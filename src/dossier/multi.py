from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Any

from .gateway import RegistaGateway
from . import secrets as suite_secrets

if TYPE_CHECKING:
    from .config import Settings

logger = logging.getLogger("dossier.multi")


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
        # Per-project key-set manifest cleanups (Plan 013 WI-4.1). When the
        # HMAC key-set is sourced from a remote backend (env:/vault:/azure:),
        # ``materialize_key_manifest`` writes a 0600 temp file and returns a
        # cleanup; we hold it and scrub on close so no material outlives the
        # process. A literal/bare-path manifest returns ``None`` cleanup, so
        # today's plaintext installs incur nothing here.
        self._key_cleanups: dict[str, suite_secrets.CleanupFn] = {}
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
        """Return known project names sorted alphabetically.

        In v1, projects are statically configured via the known set
        (DOSSIER_PROJECTS env var). Plan 014 WI-1.1 calls for dynamic
        discovery so new projects appear without a redeploy — when the
        regista backend supports ``list_projects``, we merge its catalog
        with the static set so both configured and catalog-discovered
        projects are visible.
        """
        if not self._settings or not self._gateways:
            return sorted(self._known_projects)
        discovered = self._discover_from_catalog()
        merged = self._known_projects | discovered
        return sorted(merged)

    def _discover_from_catalog(self) -> set[str]:
        """Query the project catalog from any connected gateway.

        regista's ``InMemoryRegista.list_projects`` (a classmethod) reads
        the shared in-memory catalog; the real ``Regista.list_projects``
        reads the ``public.projects`` table. Both return
        ``ProjectCatalogEntry`` objects with ``schema_name``.

        This is a best-effort merge — catalog entries for projects not in
        the static known set are included so they appear in the dashboard.
        A gateway for a discovered project is built lazily on first access.
        """
        discovered: set[str] = set()
        for gw in list(self._gateways.values()):
            try:
                discovered.update(set(gw.list_catalog_projects()))
            except Exception:
                logger.debug("catalog discovery from a gateway failed", exc_info=True)
        return discovered

    def close_all(self) -> None:
        for gw in self._gateways.values():
            try:
                gw.close()
            except Exception:
                logger.debug("gateway close failed during close_all", exc_info=True)
        # Scrub any materialized key-set temp files so they do not outlive the
        # registry (Plan 013 WI-4.1). atexit is the safety net; this is the
        # prompt path so a process that re-uses the registry (CLI doctor) does
        # not accumulate stale manifests between calls.
        for cleanup in self._key_cleanups.values():
            try:
                cleanup()
            except Exception:
                logger.debug("key cleanup failed during close_all", exc_info=True)
        self._key_cleanups.clear()
        self._gateways.clear()

    def _build(self, project: str) -> RegistaGateway:
        import regista

        assert self._settings is not None
        s = self._settings
        # Resolve suite secrets through the backend (Plan 013 WI-4.1). A
        # literal DSN / bare key path passes through unchanged (no regression);
        # a backend ref resolves at use time. The key-set manifest may
        # materialize to a 0600 temp file whose cleanup is tracked alongside
        # the gateway and scrubbed on close_all.
        #
        # The resolved values are bound to short-lived locals and consumed
        # immediately: a resolved DSN may contain a plaintext password, and a
        # construction failure traceback that renders locals would otherwise
        # echo it. If Regista() or register_workflow() raises, we scrub the
        # materialized manifest before re-raising so a retry loop (e.g. a
        # dashboard rebuild on each request) cannot accumulate temp files.
        key_path, cleanup = suite_secrets.materialize_key_manifest(s.hmac_key_path)
        reg: Any = None
        try:
            reg = regista.Regista(
                suite_secrets.resolve_dsn(s.database_url),
                project,
                key_path,
                require_ssl=s.require_ssl,
            )
            gw = RegistaGateway(reg, project_name=project)
            gw.register_workflow()
        except BaseException:
            # Scrub the materialized manifest AND release the connection pool
            # if Regista() opened one before register_workflow() raised. A
            # retry loop (e.g. a dashboard rebuild on each request) must not
            # accumulate temp files or idle Postgres connections.
            if reg is not None:
                try:
                    reg.close()
                except Exception:
                    logger.debug("reg.close failed during _build cleanup", exc_info=True)
            if cleanup is not None:
                cleanup()
            raise
        del key_path
        if cleanup is not None:
            self._key_cleanups[project] = cleanup
        return gw
