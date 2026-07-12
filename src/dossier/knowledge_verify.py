from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from .gateway import RegistaGateway
from .knowledge import list_notes, verify_note


@dataclass(frozen=True, slots=True)
class VerificationResult:
    note_id: str
    verified: bool
    chain_intact: bool
    signer_principal: str | None
    fingerprint: str | None
    scheme: str | None
    findings: tuple[str, ...]
    verified_at: datetime


def verify_note_chain(gateway: RegistaGateway, note_id: str) -> VerificationResult:
    result = verify_note(gateway, note_id)
    return VerificationResult(
        note_id=note_id,
        verified=result.get("verified", False),
        chain_intact=result.get("chain_intact", False),
        signer_principal=result.get("principal_id"),
        fingerprint=result.get("fingerprint"),
        scheme=result.get("scheme"),
        findings=tuple(result.get("findings", [])),
        verified_at=datetime.now(UTC),
    )


def verify_all_notes(gateway: RegistaGateway) -> list[VerificationResult]:
    notes = list_notes(gateway, limit=500)
    results: list[VerificationResult] = []
    for note in notes:
        result = verify_note_chain(gateway, note.note_id)
        results.append(result)
    return results
