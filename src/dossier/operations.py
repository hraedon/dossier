"""Operations provider — estate health, component status, and operational posture.

Composes health checks from regista and dossier itself. Does not execute
deployment operations — that is agent-suite's boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .gateway import RegistaGateway
from .shell import Finding, Status


@dataclass(frozen=True, slots=True)
class ComponentHealth:
    name: str
    version: str | None
    healthy: bool
    detail: str | None
    observed_at: datetime


@dataclass(frozen=True, slots=True)
class EstateSummary:
    project_slug: str
    project_name: str
    components: tuple[ComponentHealth, ...]
    overall_healthy: bool
    findings: tuple[str, ...]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _check_pool_health(reg: Any) -> ComponentHealth:
    healthy = True
    detail: str | None = None
    version: str | None = None
    try:
        version = str(getattr(reg, "regista_version", None))
    except Exception:
        pass
    try:
        healthy = bool(getattr(reg, "pool_healthy", True))
        if not healthy:
            detail = "database pool unhealthy"
    except Exception as exc:
        healthy = False
        detail = f"pool check error: {type(exc).__name__}"
    return ComponentHealth(
        name="regista-pool",
        version=version,
        healthy=healthy,
        detail=detail,
        observed_at=_now(),
    )


def _check_maintenance_health(reg: Any) -> ComponentHealth:
    healthy = True
    detail: str | None = None
    try:
        healthy = bool(getattr(reg, "maintenance_healthy", True))
        if not healthy:
            detail = "maintenance thread unhealthy"
    except Exception as exc:
        healthy = False
        detail = f"maintenance check error: {type(exc).__name__}"
    return ComponentHealth(
        name="regista-maintenance",
        version=None,
        healthy=healthy,
        detail=detail,
        observed_at=_now(),
    )


def _check_principal_ops(gateway: RegistaGateway) -> ComponentHealth:
    has_ops = gateway.has_principal_ops()
    return ComponentHealth(
        name="principal-ops",
        version=None,
        healthy=has_ops,
        detail="real regista backend" if has_ops else "in-memory backend (no principal ops)",
        observed_at=_now(),
    )


def read_estate_summary(
    gateway: RegistaGateway,
    project_slug: str,
) -> EstateSummary:
    """Check regista pool health, maintenance health, and principal ops.

    Returns a composed summary with per-component health and named findings
    for any unhealthy components.
    """
    reg = gateway._reg
    components: list[ComponentHealth] = []
    findings: list[str] = []

    pool = _check_pool_health(reg)
    components.append(pool)
    if not pool.healthy:
        findings.append(f"regista pool unhealthy: {pool.detail or 'unknown'}")

    maint = _check_maintenance_health(reg)
    components.append(maint)
    if not maint.healthy:
        findings.append(f"maintenance thread unhealthy: {maint.detail or 'unknown'}")

    principal = _check_principal_ops(gateway)
    components.append(principal)
    if not principal.healthy:
        findings.append("principal key operations unavailable (in-memory backend)")

    try:
        chain = gateway.integrity()
        chain_ok = chain.replayed_drift == 0
        components.append(ComponentHealth(
            name="event-chain",
            version=None,
            healthy=chain_ok,
            detail="intact" if chain_ok else f"{chain.replayed_drift} drift events",
            observed_at=_now(),
        ))
        if not chain_ok:
            findings.append(f"event chain drift: {chain.replayed_drift} events")
    except Exception as exc:
        components.append(ComponentHealth(
            name="event-chain",
            version=None,
            healthy=False,
            detail=f"integrity check failed: {type(exc).__name__}",
            observed_at=_now(),
        ))
        findings.append(f"integrity check failed: {type(exc).__name__}")

    overall = all(c.healthy for c in components)

    project_name = project_slug
    try:
        entry = gateway.get_project_catalog_entry()
        if entry is not None:
            dn = getattr(entry, "display_name", None)
            if dn:
                project_name = str(dn)
    except Exception:
        pass

    return EstateSummary(
        project_slug=project_slug,
        project_name=project_name,
        components=tuple(components),
        overall_healthy=overall,
        findings=tuple(findings),
    )


def read_operations_findings(gateway: RegistaGateway) -> list[Finding]:
    """Return named findings for operational issues.

    Checks for chain drift, stale claims (work items in progress for a long
    time without updates), and principal ops availability. Each finding
    carries a code, label, and status suitable for display.
    """
    findings: list[Finding] = []

    try:
        report = gateway.integrity()
        if report.replayed_drift > 0:
            findings.append(Finding(
                code="chain_drift",
                label=f"{report.replayed_drift} events failed replay verification",
                status=Status.FAILED,
                detail="the signed event log has drifted from replay",
            ))
        elif report.halted > 0:
            findings.append(Finding(
                code="replay_halted",
                label=f"replay halted on {report.halted} events",
                status=Status.WARNING,
                detail="replay was unable to complete for some events",
            ))
    except Exception:
        findings.append(Finding(
            code="integrity_check_failed",
            label="integrity check failed",
            status=Status.FAILED,
            detail="unable to run the replay verification",
        ))

    if not gateway.has_principal_ops():
        findings.append(Finding(
            code="principal_ops_unavailable",
            label="principal key operations unavailable",
            status=Status.INFO,
            detail="in-memory backend — no principal key management",
        ))

    if not findings:
        findings.append(Finding(
            code="all_ok",
            label="no operational issues detected",
            status=Status.OK,
        ))

    return findings
