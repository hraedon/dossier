"""Evidence provider — surfaces integrity, verification, and audit data.

Reads from regista's integrity/replay APIs and event verification. Does not
recompute cryptographic verdicts — delegates to regista's signed event log.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from .contracts import CONTRACT_VERSION, ProviderDescriptor
from .gateway import RegistaGateway
from .shell import Availability


@dataclass(frozen=True, slots=True)
class EvidenceSummary:
    project_slug: str
    total_events: int
    verified_events: int
    unverified_events: int
    chain_intact: bool
    last_verified_at: datetime | None
    findings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EventVerification:
    event_id: str
    work_item_id: str
    transition: str | None
    actor_id: str
    timestamp: datetime
    verified: bool
    principal_id: str | None
    fingerprint: str | None
    scheme: str | None


def _to_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=UTC)
    return ts


def read_evidence_summary(
    gateway: RegistaGateway,
    project_slug: str,
) -> EvidenceSummary:
    """Build an evidence summary for a project.

    Runs the full replay for chain integrity, then counts verified vs
    unverified events from recent events. The chain is intact when
    ``replayed_drift == 0``.
    """
    chain_intact = True
    findings: list[str] = []
    last_verified_at: datetime | None = None

    try:
        report = gateway.integrity()
        chain_intact = report.replayed_drift == 0
        if not chain_intact:
            findings.append(
                f"chain drift detected: {report.replayed_drift} events "
                f"failed replay verification"
            )
        if report.halted > 0:
            findings.append(
                f"replay halted on {report.halted} events"
            )
        if report.warnings > 0:
            findings.append(
                f"{report.warnings} replay warnings"
            )
    except Exception as exc:
        chain_intact = False
        findings.append(f"integrity check failed: {type(exc).__name__}")

    events = gateway.read_recent_events(limit=200)
    total = len(events)
    verified = 0
    unverified = 0

    for ev in events:
        try:
            info = gateway.verify_event(ev)
            if info.get("verified"):
                verified += 1
                ts = _to_utc(ev.timestamp)
                if last_verified_at is None or ts > last_verified_at:
                    last_verified_at = ts
            else:
                unverified += 1
        except Exception:
            unverified += 1

    if unverified > 0:
        findings.append(
            f"{unverified} of {total} recent events failed signature verification"
        )

    return EvidenceSummary(
        project_slug=project_slug,
        total_events=total,
        verified_events=verified,
        unverified_events=unverified,
        chain_intact=chain_intact,
        last_verified_at=last_verified_at,
        findings=tuple(findings),
    )


def read_event_verifications(
    gateway: RegistaGateway,
    *,
    limit: int = 100,
) -> list[EventVerification]:
    """Read recent events and verify each one's signature.

    Returns a list of :class:`EventVerification` in descending time order.
    Each entry carries the verification verdict from regista's
    ``verify_event_signature`` and the signer's principal info.
    """
    events = gateway.read_recent_events(limit=limit)
    results: list[EventVerification] = []

    for ev in events:
        info: dict[str, Any] = {
            "verified": False,
            "principal_id": None,
            "fingerprint": None,
            "scheme": None,
        }
        try:
            info = gateway.verify_event(ev)
        except Exception:
            pass

        results.append(EventVerification(
            event_id=str(getattr(ev, "event_id", getattr(ev, "event_seq", ""))),
            work_item_id=str(ev.work_item_id),
            transition=getattr(ev, "transition", None),
            actor_id=str(getattr(ev, "actor_id", "")),
            timestamp=ev.timestamp,
            verified=bool(info.get("verified", False)),
            principal_id=info.get("principal_id"),
            fingerprint=info.get("fingerprint"),
            scheme=info.get("scheme"),
        ))

    results.sort(key=lambda v: v.timestamp, reverse=True)
    return results


def read_integrity_report(
    gateway: RegistaGateway,
    work_item_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    """Wrap ``gateway.integrity()`` and format the replay report for display.

    Returns a dict with ``replayed_ok``, ``replayed_drift``, ``halted``,
    ``warnings``, ``chain_intact``, and ``work_item_id``.
    """
    report = gateway.integrity(work_item_id=work_item_id)
    chain_intact = report.replayed_drift == 0
    return {
        "replayed_ok": report.replayed_ok,
        "replayed_drift": report.replayed_drift,
        "halted": report.halted,
        "warnings": report.warnings,
        "chain_intact": chain_intact,
        "work_item_id": str(work_item_id) if work_item_id else None,
    }


def describe_evidence() -> ProviderDescriptor:
    """Self-description for the evidence provider (Plan 015 WI-1.1)."""
    return ProviderDescriptor(
        name="evidence",
        contract_version=CONTRACT_VERSION,
        availability=Availability.AVAILABLE,
        capabilities=("summary", "events", "integrity"),
    )


class EvidenceProviderAdapter:
    """Thin adapter binding the evidence module functions to a gateway and
    project, satisfying the :class:`~dossier.contracts.EvidenceProvider`
    Protocol.

    The adapter delegates to :func:`read_evidence_summary`,
    :func:`read_event_verifications`, and :func:`read_integrity_report`,
    converting dataclass results into the plain dicts/lists the Protocol
    declares.
    """

    def __init__(self, gateway: RegistaGateway, project_slug: str) -> None:
        self._gateway = gateway
        self._project_slug = project_slug

    def describe_evidence(self) -> ProviderDescriptor:
        return describe_evidence()

    def evidence_summary(self) -> dict[str, Any]:
        return asdict(read_evidence_summary(self._gateway, self._project_slug))

    def event_verifications(self, *, limit: int = 100) -> list[dict[str, Any]]:
        return [asdict(v) for v in read_event_verifications(
            self._gateway, limit=limit
        )]

    def integrity_report(self, *, work_item_id: Any = None) -> dict[str, Any]:
        return read_integrity_report(
            self._gateway, work_item_id=work_item_id
        )
