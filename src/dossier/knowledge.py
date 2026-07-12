from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from regista import Event

from .actors import Actor
from .gateway import RegistaGateway

_NOTE_ENTITY_KIND = "note"


@dataclass(frozen=True, slots=True)
class NoteSummary:
    note_id: str
    title: str
    actor_id: str
    created_at: datetime
    updated_at: datetime
    state: str
    verification_status: str


@dataclass(frozen=True, slots=True)
class NoteDetail:
    note_id: str
    title: str
    body: str
    actor_id: str
    created_at: datetime
    updated_at: datetime
    state: str
    events: list[Event]
    verification_info: dict[str, Any]


def _extract_title(payload: dict[str, Any] | None) -> str:
    if payload is None:
        return "untitled"
    return str(payload.get("title", "untitled"))


def _extract_body(payload: dict[str, Any] | None) -> str:
    if payload is None:
        return ""
    return str(payload.get("body", ""))


def _note_state_from_events(events: list[Event]) -> str:
    for ev in reversed(events):
        if ev.transition == "superseded":
            return "superseded"
        if ev.transition == "created":
            return "active"
    return "active"


def _is_note_event(ev: Event) -> bool:
    return getattr(ev, "entity_kind", "work_item") == _NOTE_ENTITY_KIND


def list_notes(gateway: RegistaGateway, *, limit: int = 100) -> list[NoteSummary]:
    events = gateway.read_recent_events(limit=limit * 3)
    by_entity: dict[uuid.UUID, list[Event]] = {}
    for ev in events:
        if not _is_note_event(ev):
            continue
        entity_id = getattr(ev, "entity_id", None) or getattr(ev, "work_item_id", None)
        if entity_id is None:
            continue
        by_entity.setdefault(entity_id, []).append(ev)

    summaries: list[NoteSummary] = []
    for entity_id, evs in by_entity.items():
        evs.sort(key=lambda e: e.timestamp)
        created = evs[0] if evs else None
        if created is None:
            continue
        state = _note_state_from_events(evs)
        title = _extract_title(getattr(created, "payload", None))
        summaries.append(NoteSummary(
            note_id=str(entity_id),
            title=title,
            actor_id=getattr(created, "actor_id", "unknown"),
            created_at=created.timestamp,
            updated_at=evs[-1].timestamp,
            state=state,
            verification_status="unknown",
        ))

    summaries.sort(key=lambda s: s.updated_at, reverse=True)
    return summaries[:limit]


def get_note(gateway: RegistaGateway, note_id: str) -> NoteDetail | None:
    try:
        entity_uuid = uuid.UUID(note_id)
    except ValueError:
        return None
    try:
        events = gateway.history(entity_uuid)
    except Exception:
        return None
    if not events:
        return None

    events.sort(key=lambda e: e.timestamp)
    created = events[0]
    state = _note_state_from_events(events)
    payload = getattr(created, "payload", None)
    title = _extract_title(payload)
    body = _extract_body(payload)

    verification_info: dict[str, Any] = {
        "verified": False,
        "principal_id": None,
        "fingerprint": None,
        "scheme": None,
    }
    try:
        verification_info = gateway.verify_event(created)
    except Exception:
        pass

    return NoteDetail(
        note_id=note_id,
        title=title,
        body=body,
        actor_id=getattr(created, "actor_id", "unknown"),
        created_at=created.timestamp,
        updated_at=events[-1].timestamp,
        state=state,
        events=events,
        verification_info=verification_info,
    )


def search_notes(
    gateway: RegistaGateway, query: str, *, limit: int = 50
) -> list[NoteSummary]:
    query_lower = query.lower().strip()
    if not query_lower:
        return []
    all_notes = list_notes(gateway, limit=limit * 3)
    filtered = [
        s for s in all_notes
        if query_lower in s.title.lower()
    ]
    return filtered[:limit]


def create_note(
    gateway: RegistaGateway,
    *,
    actor: Actor,
    title: str,
    body: str,
) -> str:
    entity_uuid = uuid.uuid4()
    payload: dict[str, Any] = {"title": title, "body": body}
    gateway.append_note_event(
        actor=actor,
        entity_id=entity_uuid,
        transition="created",
        payload=payload,
    )
    return str(entity_uuid)


def verify_note(gateway: RegistaGateway, note_id: str) -> dict[str, Any]:
    detail = get_note(gateway, note_id)
    if detail is None:
        return {
            "verified": False,
            "principal_id": None,
            "fingerprint": None,
            "scheme": None,
            "chain_intact": False,
            "findings": ["note not found"],
        }

    findings: list[str] = []
    all_verified = True
    last_principal: str | None = None
    last_fingerprint: str | None = None
    last_scheme: str | None = None

    for ev in detail.events:
        info = gateway.verify_event(ev)
        if not info.get("verified"):
            all_verified = False
            findings.append(
                f"event {getattr(ev, 'event_seq', '?')} signature unverified"
            )
        if info.get("principal_id"):
            last_principal = info["principal_id"]
        if info.get("fingerprint"):
            last_fingerprint = info["fingerprint"]
        if info.get("scheme"):
            last_scheme = info["scheme"]

    chain_intact = True
    try:
        entity_uuid = uuid.UUID(note_id)
        report = gateway.integrity(entity_uuid)
        drift = getattr(report, "replayed_drift", 0)
        if drift:
            chain_intact = False
            findings.append(f"chain has {drift} drift event(s)")
        if getattr(report, "halted", False):
            chain_intact = False
            findings.append("integrity replay halted")
    except Exception:
        chain_intact = False
        findings.append("integrity check failed")

    return {
        "verified": all_verified and chain_intact,
        "principal_id": last_principal,
        "fingerprint": last_fingerprint,
        "scheme": last_scheme,
        "chain_intact": chain_intact,
        "findings": findings,
    }
