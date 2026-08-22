from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

from . import secrets as suite_secrets
from .gateway import RegistaGateway

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
    import re

    _schema_re = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
    _reserved_schemas = frozenset(
        {"public", "information_schema", "pg_catalog", "pg_toast"}
    )

    name = slug.replace("-", "_")
    if not _schema_re.match(name):
        raise ValueError(
            f"Invalid project name {name!r}: must be 1-63 chars, lowercase "
            "alphanumeric/underscore, start with letter or underscore"
        )
    if name in _reserved_schemas or name.startswith("pg_"):
        raise ValueError(
            f"Invalid project name {name!r}: reserved schema name"
        )
    return str(name)


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
        # One estate-wide trust-log connection is shared by every work-project
        # gateway. It is registry-owned so individual gateways cannot close it
        # while another project is still using the lifecycle facade.
        self._lifecycle_regista: Any | None = None
        self._lifecycle_verified_at: float | None = None
        self._lifecycle_verification_report: Any | None = None
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
        if self._lifecycle_regista is not None:
            try:
                self._lifecycle_regista.close()
            except Exception:
                logger.debug("shared lifecycle close failed during close_all", exc_info=True)
            self._lifecycle_regista = None
            self._lifecycle_verified_at = None
            self._lifecycle_verification_report = None
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

    def verify_lifecycle_trust(self, *, max_age_seconds: float = 30.0) -> Any:
        """Verify the shared trust log, caching only successful reports briefly.

        Health pollers must not turn an O(n) cryptographic chain walk into an
        unbounded per-request load. Failures are never cached, so recovery is
        visible on the next probe.
        """
        if max_age_seconds < 0:
            raise ValueError("max_age_seconds must be non-negative")
        with self._lock:
            lifecycle = self._lifecycle_regista
            if lifecycle is None:
                raise RuntimeError("the estate-wide lifecycle project is not configured")
            now = time.monotonic()
            if (
                self._lifecycle_verified_at is not None
                and self._lifecycle_verification_report is not None
                and now - self._lifecycle_verified_at <= max_age_seconds
            ):
                return self._lifecycle_verification_report
            report = lifecycle.verify_trust_log()
            self._lifecycle_verified_at = time.monotonic()
            self._lifecycle_verification_report = report
            return report

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
        from .auth.step_up import DossierApprovalVerifier

        key_path, cleanup = suite_secrets.materialize_key_manifest(s.hmac_key_path)
        reg: Any = None
        lifecycle_reg: Any = None
        created_lifecycle = False
        try:
            dsn = suite_secrets.resolve_dsn(s.database_url)
            if dsn is None:
                raise ValueError("a database URL is required to build a regista gateway")
            reg = regista.Regista(
                dsn,
                project,
                key_path,
                require_ssl=s.require_ssl,
                approval_verifier=DossierApprovalVerifier(s.session_secret),
            )
            if s.trust_log_project:
                if s.trust_log_project == project:
                    raise ValueError(
                        "REGISTA_TRUST_LOG_PROJECT must be distinct from the work project"
                    )
                lifecycle_reg = self._lifecycle_regista
                if lifecycle_reg is None:
                    # The trust-genesis keyword is introduced by the sibling
                    # lifecycle contract. Keep construction compatible with
                    # the published lock's older type surface while passing
                    # the argument at runtime when the feature is available.
                    regista_constructor = cast(Callable[..., Any], regista.Regista)
                    lifecycle_reg = regista_constructor(
                        dsn,
                        s.trust_log_project,
                        key_path,
                        require_ssl=s.require_ssl,
                        approval_verifier=DossierApprovalVerifier(s.session_secret),
                        trust_genesis_path=s.trust_genesis_path or None,
                    )
                    self._lifecycle_regista = lifecycle_reg
                    created_lifecycle = True
            gw = RegistaGateway(
                reg,
                project_name=project,
                human_signing=s.human_signing,
                lifecycle_regista=lifecycle_reg,
                owns_lifecycle_regista=False,
            )
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
            if created_lifecycle and lifecycle_reg is not None:
                try:
                    lifecycle_reg.close()
                except Exception:
                    logger.debug(
                        "lifecycle_reg.close failed during _build cleanup",
                        exc_info=True,
                    )
                self._lifecycle_regista = None
            if cleanup is not None:
                cleanup()
            raise
        del key_path
        if cleanup is not None:
            self._key_cleanups[project] = cleanup
        return gw
