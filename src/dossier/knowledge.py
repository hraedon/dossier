from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from regista import Event as Event  # type: ignore[attr-defined]

from .actors import Actor
from .contracts import CONTRACT_VERSION, ProviderDescriptor
from .gateway import RegistaGateway
from .shell import Availability

_NOTE_ENTITY_KIND = "note"

# Canonical note-entity transition vocabulary. Notes are non-workflow signed
# entities (``entity_kind="note"``); they have no state machine, so their
# transitions are free-form labels. regista reserves ``"created"`` (and the
# claim/link/etc. labels) — ``append_event(transition="created")`` raises
# ``TRANSITION_VIA_APPEND_BLOCKED``. These labels mirror agent-notes (the
# knowledge owner).
NOTE_FILED = "note_filed"
NOTE_SUPERSEDED = "note_superseded"
# Legacy labels that may appear on notes created before the reservation was
# enforced; still recognised on read so historical chains render correctly.
_LEGACY_CREATED = "created"
_LEGACY_SUPERSEDED = "superseded"

# --- Canonical note payload contract (shared with agent-notes) -------------
# Both faces read AND write this exact payload shape so a note filed by either
# face rebuilds and renders correctly in the other. The shape is dictated by
# agent-notes (the knowledge owner); see agent-notes ``note_model._fold_note_events``
# for the rebuild this mirrors. The cross-face tests in
# ``tests/test_cross_face_notes.py`` pin the two declarations together — that is
# what makes the "shared note universe" claim provable, not just the shared
# transition labels.
NOTE_NAME_FIELD = "name"              # canonical title field
NOTE_LEGACY_TITLE_FIELD = "title"     # legacy dossier field, read for back-compat
DEFAULT_MEMORY_TYPE = "note"
DEFAULT_NOTE_SUBTYPE = "memory"


def _note_subtype_for(memory_type: str) -> str:
    """Map a memory_type to a note entity subtype (mirrors agent-notes)."""
    return "reflection" if memory_type == "reflection" else DEFAULT_NOTE_SUBTYPE


def canonical_note_payload(
    *,
    name: str,
    body: str,
    memory_type: str = DEFAULT_MEMORY_TYPE,
    attributes: dict[str, Any] | None = None,
    links: list[Any] | None = None,
) -> dict[str, Any]:
    """Build the canonical note ``note_filed`` payload.

    This is the exact shape agent-notes writes (``note_model.add_memory``) and
    reads back (``note_model._fold_note_events``). Dossier emits it so an
    agent-notes ``rebuild_from_regista`` reconstructs dossier-authored notes
    with the right ``name``/``memory_type``/``body`` rather than an empty name.
    """
    return {
        "name": name,
        "memory_type": memory_type,
        "note_subtype": _note_subtype_for(memory_type),
        "body": body,
        "attributes": attributes or {},
        "links": links or [],
    }


@dataclass(frozen=True, slots=True)
class NoteSummary:
    note_id: str
    title: str
    actor_id: str
    created_at: datetime
    updated_at: datetime
    state: str
    verification_status: str
    memory_type: str = DEFAULT_MEMORY_TYPE


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
    memory_type: str = DEFAULT_MEMORY_TYPE


def _extract_title(payload: dict[str, Any] | None) -> str:
    if payload is None:
        return "untitled"
    # Canonical field is "name" (agent-notes vocabulary). Fall back to the
    # legacy "title" field for notes dossier authored before the payload
    # convergence, so historical chains still render.
    name = payload.get(NOTE_NAME_FIELD) or payload.get(NOTE_LEGACY_TITLE_FIELD)
    return str(name) if name else "untitled"


def _extract_body(payload: dict[str, Any] | None) -> str:
    if payload is None:
        return ""
    return str(payload.get("body", ""))


def _extract_memory_type(payload: dict[str, Any] | None) -> str:
    """Resolve the full ``memory_type`` from a note payload.

    Mirrors agent-notes' ``_resolve_memory_type``: a present ``memory_type``
    wins; otherwise the coarse ``note_subtype`` is mapped back (``reflection``
    subtype -> ``reflection``; anything else -> ``note``).
    """
    if payload is None:
        return DEFAULT_MEMORY_TYPE
    memory_type = payload.get("memory_type")
    if memory_type:
        return str(memory_type)
    if payload.get("note_subtype") == "reflection":
        return "reflection"
    return DEFAULT_MEMORY_TYPE


def _note_state_from_events(events: list[Event]) -> str:
    for ev in reversed(events):
        if ev.transition in (NOTE_SUPERSEDED, _LEGACY_SUPERSEDED):
            return "superseded"
        if ev.transition in (NOTE_FILED, _LEGACY_CREATED):
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
        payload = getattr(created, "payload", None)
        summaries.append(NoteSummary(
            note_id=str(entity_id),
            title=_extract_title(payload),
            actor_id=getattr(created, "actor_id", "unknown"),
            created_at=created.timestamp,
            updated_at=evs[-1].timestamp,
            state=state,
            verification_status="unknown",
            memory_type=_extract_memory_type(payload),
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
        memory_type=_extract_memory_type(payload),
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
    """File a knowledge note through regista as a signed ``entity_kind="note"``
    event.

    The payload is the canonical note shape shared with agent-notes
    (:func:`canonical_note_payload`): ``name``/``memory_type``/
    ``note_subtype``/``body``/``attributes``/``links``. dossier's ``title``
    argument maps to the canonical ``name`` field, so an agent-notes
    ``rebuild_from_regista`` reconstructs the note with the right name (not an
    empty string). The read side (:func:`_extract_title`) prefers ``name`` and
    falls back to the legacy ``title`` field for notes filed before this
    convergence.
    """
    entity_uuid = uuid.uuid4()
    payload = canonical_note_payload(name=title, body=body)
    gateway.append_note_event(
        actor=actor,
        entity_id=entity_uuid,
        transition=NOTE_FILED,
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


def describe_knowledge() -> ProviderDescriptor:
    """Self-description for the knowledge provider (Plan 015 WI-1.1).

    Knowledge notes are signed ``entity_kind="note"`` events written through
    regista's ``append_event``. Dossier and agent-notes share both the
    transition vocabulary *and* the canonical note payload
    (:func:`canonical_note_payload`), so a note filed by either face renders
    and rebuilds in the other — that convergence is pinned by the cross-face
    tests in ``tests/test_cross_face_notes.py``, not merely asserted. The
    browse/search/detail/verify surface is wired and exercised by the GJ-3
    golden journey, so the descriptor reports ``AVAILABLE`` honestly.
    """
    return ProviderDescriptor(
        name="knowledge",
        contract_version=CONTRACT_VERSION,
        availability=Availability.AVAILABLE,
        capabilities=("create", "list", "get", "search", "verify"),
    )


class KnowledgeProviderAdapter:
    """Thin adapter binding the knowledge module functions to a gateway,
    satisfying the :class:`~dossier.contracts.KnowledgeProvider` Protocol as a
    real object (not just name-only module functions).

    The module-level functions (``list_notes``, ``get_note``, …) are the
    implementation; they take an explicit ``gateway`` argument. The Protocol,
    however, declares ``self``-methods. This adapter bridges that gap: it holds
    a gateway and exposes the Protocol's method surface, delegating each call
    to the corresponding module function. Nothing is reimplemented — the
    adapter is a structural binding, not a second implementation.

    The routes continue to call the module functions directly (they already
    hold a gateway); the adapter exists so the contract's ``runtime_checkable``
    Protocol is genuinely satisfied by a real object, and so a signature
    conformance test can pin the two declarations together.
    """

    def __init__(self, gateway: RegistaGateway) -> None:
        self._gateway = gateway

    def describe_knowledge(self) -> ProviderDescriptor:
        return describe_knowledge()

    def create_note(
        self,
        *,
        actor: Actor,
        title: str,
        body: str,
    ) -> str:
        # Delegates to the module-level create_note (not a recursive call —
        # the bare name resolves to the module global, not this method).
        return create_note(self._gateway, actor=actor, title=title, body=body)

    def list_notes(self, *, limit: int = 100) -> list[Any]:
        return list_notes(self._gateway, limit=limit)

    def get_note(self, note_id: str) -> Any | None:
        return get_note(self._gateway, note_id)

    def search_notes(self, query: str, *, limit: int = 50) -> list[Any]:
        return search_notes(self._gateway, query, limit=limit)

    def verify_note(self, note_id: str) -> dict[str, Any]:
        return verify_note(self._gateway, note_id)
