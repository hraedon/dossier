"""Cross-face note payload contract tests (Sol's confirmed finding).

dossier and agent-notes must read/write the SAME canonical note payload, not
merely share transition labels. These tests prove the convergence in both
directions against the real InMemoryRegista store:

- dossier -> agent-notes: a note filed by dossier's ``create_note`` carries the
  canonical fields (``name``/``memory_type``/``note_subtype``/``body``/
  ``attributes``/``links``) and folds correctly under agent-notes' rebuild
  logic (a local mirror of ``note_model._fold_note_events``). If it did not,
  an agent-notes ``rebuild_from_regista`` would reconstruct the note with an
  empty ``name``.
- agent-notes -> dossier: a note filed with a realistic agent-notes payload
  renders and is findable through dossier's list/detail/search.
- legacy: notes filed before the convergence (legacy ``title`` payload, no
  ``name``) still render in dossier.
"""

from __future__ import annotations

import uuid
from typing import Any

from helpers import ALICE

from dossier.actors import Actor
from dossier.gateway import RegistaGateway
from dossier.knowledge import (
    NOTE_FILED,
    NOTE_SUPERSEDED,
    canonical_note_payload,
    create_note,
    get_note,
    list_notes,
    search_notes,
)

# A realistic agent-notes ``note_filed`` payload (memory_type="decision"),
# exactly as ``agent_notes.core.note_model.add_memory`` would write it.
AGENT_NOTES_DECISION_PAYLOAD: dict[str, Any] = {
    "name": "Adopt token-bucket rate limiting",
    "memory_type": "decision",
    "note_subtype": "memory",
    "body": "Gate the public API with a token-bucket limiter; 100 req/min/actor.",
    "attributes": {"source": "architecture-review", "tags": ["api", "reliability"]},
    "links": [],
}

# A realistic agent-notes reflection payload (note_subtype="reflection").
AGENT_NOTES_REFLECTION_PAYLOAD: dict[str, Any] = {
    "name": "Retrospective: Q3 release cadence",
    "memory_type": "reflection",
    "note_subtype": "reflection",
    "body": "Weekly releases slipped; batch into fortnightly trains.",
    "attributes": {},
    "links": [],
}

AGENT = Actor(
    actor_id="agent:notes",
    actor_kind="agent",
    display_name="Agent Notes",
    model_lineage="notes",
)


def _fold_note_events(events: list[Any]) -> dict[str, Any]:
    """Local mirror of agent-notes ``note_model._fold_note_events``.

    This IS the rebuild contract: agent-notes folds a note entity's event log
    into its current state using exactly this logic, then upserts the folded
    state into its local ``memories`` projection. A dossier-authored note
    must fold correctly here or it rebuilds with an empty ``name`` in
    agent-notes. Kept in lock-step with agent-notes; if that fold changes,
    this mirror — and the cross-face claim — must be revisited.
    """
    sorted_events = sorted(events, key=lambda e: e.event_seq)
    state: dict[str, Any] = {
        "note_subtype": "memory",
        "memory_type": None,
        "name": "",
        "body": "",
        "attributes": {},
        "active": True,
        "superseded_by": None,
    }
    for evt in sorted_events:
        transition = evt.transition
        payload = evt.payload or {}
        if transition == NOTE_FILED:
            state["note_subtype"] = payload.get("note_subtype", "memory")
            state["memory_type"] = payload.get("memory_type")
            state["name"] = payload.get("name", "")
            state["body"] = payload.get("body", "")
            state["attributes"] = payload.get("attributes", {})
        elif transition == "note_updated":
            for key in ("memory_type", "note_subtype", "body", "attributes", "name"):
                if key in payload:
                    state[key] = payload[key]
        elif transition == NOTE_SUPERSEDED:
            state["active"] = False
            state["superseded_by"] = payload.get("superseded_by")
        elif transition == "note_deleted":
            state["active"] = False
    return state


class TestDossierWritesCanonicalPayload:
    """dossier -> agent-notes: dossier's create_note emits the canonical
    payload, and the resulting event log folds correctly under agent-notes'
    rebuild logic."""

    def test_create_note_payload_has_all_canonical_fields(
        self, gateway: RegistaGateway
    ) -> None:
        note_id = create_note(
            gateway, actor=ALICE, title="Dossier-authored note", body="the body"
        )
        events = gateway.history(uuid.UUID(note_id))
        assert len(events) == 1
        payload = events[0].payload
        assert payload["name"] == "Dossier-authored note"
        assert payload["memory_type"] == "note"
        assert payload["note_subtype"] == "memory"
        assert payload["body"] == "the body"
        assert payload["attributes"] == {}
        assert payload["links"] == []
        # No legacy title field on freshly-filed canonical notes.
        assert "title" not in payload

    def test_dossier_note_rebuilds_correctly_in_agent_notes(
        self, gateway: RegistaGateway
    ) -> None:
        """The proving test for the rebuild direction: fold a dossier-authored
        note's event log with agent-notes' fold logic and confirm the folded
        state has the right name/memory_type/body — not an empty name."""
        note_id = create_note(
            gateway, actor=ALICE, title="Rebuildable dossier note", body="rebuild me"
        )
        events = gateway.history(uuid.UUID(note_id))
        folded = _fold_note_events(events)
        assert folded["name"] == "Rebuildable dossier note"
        assert folded["memory_type"] == "note"
        assert folded["note_subtype"] == "memory"
        assert folded["body"] == "rebuild me"
        assert folded["attributes"] == {}
        assert folded["active"] is True

    def test_canonical_note_payload_helper_matches_agent_notes_shape(self) -> None:
        """The payload builder produces the exact field set agent-notes
        writes."""
        payload = canonical_note_payload(
            name="n", body="b", memory_type="decision",
            attributes={"k": "v"}, links=[{"type": "x"}],
        )
        assert set(payload) == {
            "name", "memory_type", "note_subtype", "body", "attributes", "links",
        }
        assert payload["note_subtype"] == "memory"

    def test_reflection_memory_type_maps_to_reflection_subtype(self) -> None:
        payload = canonical_note_payload(name="n", body="b", memory_type="reflection")
        assert payload["note_subtype"] == "reflection"


class TestDossierReadsAgentNotesPayload:
    """agent-notes -> dossier: notes filed with a realistic agent-notes
    canonical payload render and are findable through dossier's surface."""

    @staticmethod
    def _file_agent_note(
        gateway: RegistaGateway, payload: dict[str, Any]
    ) -> uuid.UUID:
        entity_id = uuid.uuid4()
        gateway.append_note_event(
            actor=AGENT,
            entity_id=entity_id,
            transition=NOTE_FILED,
            payload=payload,
        )
        return entity_id

    def test_list_notes_renders_agent_notes_decision(
        self, gateway: RegistaGateway
    ) -> None:
        entity_id = self._file_agent_note(gateway, AGENT_NOTES_DECISION_PAYLOAD)
        notes = list_notes(gateway)
        assert len(notes) == 1
        note = notes[0]
        assert note.note_id == str(entity_id)
        # dossier renders the canonical "name" as the title.
        assert note.title == "Adopt token-bucket rate limiting"
        assert note.memory_type == "decision"
        assert note.actor_id == "agent:notes"

    def test_get_note_detail_renders_agent_notes_payload(
        self, gateway: RegistaGateway
    ) -> None:
        entity_id = self._file_agent_note(gateway, AGENT_NOTES_DECISION_PAYLOAD)
        detail = get_note(gateway, str(entity_id))
        assert detail is not None
        assert detail.title == "Adopt token-bucket rate limiting"
        assert detail.body == AGENT_NOTES_DECISION_PAYLOAD["body"]
        assert detail.memory_type == "decision"

    def test_search_finds_agent_notes_note_by_name(
        self, gateway: RegistaGateway
    ) -> None:
        self._file_agent_note(gateway, AGENT_NOTES_DECISION_PAYLOAD)
        results = search_notes(gateway, "token-bucket")
        assert len(results) == 1
        assert results[0].title == "Adopt token-bucket rate limiting"

    def test_reflection_note_renders_with_reflection_memory_type(
        self, gateway: RegistaGateway
    ) -> None:
        entity_id = self._file_agent_note(gateway, AGENT_NOTES_REFLECTION_PAYLOAD)
        detail = get_note(gateway, str(entity_id))
        assert detail is not None
        assert detail.memory_type == "reflection"
        assert detail.title == "Retrospective: Q3 release cadence"

    def test_mixed_face_notes_coexist_and_render(
        self, gateway: RegistaGateway
    ) -> None:
        """Both faces writing into one store is the point of the shared
        payload: a dossier note and an agent-notes note coexist and each
        renders with its own author and memory_type."""
        create_note(gateway, actor=ALICE, title="Dossier note", body="db")
        self._file_agent_note(gateway, AGENT_NOTES_DECISION_PAYLOAD)
        notes = list_notes(gateway)
        assert len(notes) == 2
        by_title = {n.title: n for n in notes}
        assert by_title["Dossier note"].actor_id == "human:alice"
        assert by_title["Dossier note"].memory_type == "note"
        assert by_title["Adopt token-bucket rate limiting"].actor_id == "agent:notes"
        assert by_title["Adopt token-bucket rate limiting"].memory_type == "decision"


class TestCrossFaceRoundTrip:
    """A note authored by one face, folded by the other face's rebuild logic,
    round-trips its full canonical state."""

    def test_dossier_note_folds_same_as_agent_notes_note(self, gateway: RegistaGateway) -> None:
        """A dossier-authored note and an agent-notes-authored note with the
        same content fold to identical rebuilt state — proving dossier writes
        the canonical shape, not a near-canonical one."""
        dossier_id = create_note(
            gateway, actor=ALICE, title="Same name", body="Same body"
        )
        agent_id = uuid.uuid4()
        gateway.append_note_event(
            actor=AGENT,
            entity_id=agent_id,
            transition=NOTE_FILED,
            payload=canonical_note_payload(name="Same name", body="Same body"),
        )
        dossier_folded = _fold_note_events(gateway.history(uuid.UUID(dossier_id)))
        agent_folded = _fold_note_events(gateway.history(agent_id))
        # memory_type is "note" for dossier's default and "note" for the
        # explicit agent-notes payload built with the default — both canonical.
        assert dossier_folded["name"] == agent_folded["name"] == "Same name"
        assert dossier_folded["body"] == agent_folded["body"] == "Same body"
        assert dossier_folded["memory_type"] == agent_folded["memory_type"] == "note"
        assert dossier_folded["note_subtype"] == agent_folded["note_subtype"] == "memory"
        assert dossier_folded["attributes"] == agent_folded["attributes"] == {}


class TestLegacyTitlePayload:
    """Notes filed before the payload convergence used a ``title`` field (no
    ``name``). dossier must still render them — backward-compatible reads."""

    @staticmethod
    def _file_legacy_note(gateway: RegistaGateway, title: str) -> uuid.UUID:
        entity_id = uuid.uuid4()
        gateway.append_note_event(
            actor=ALICE,
            entity_id=entity_id,
            transition=NOTE_FILED,
            payload={"title": title, "body": "legacy body"},
        )
        return entity_id

    def test_legacy_title_renders_in_list(self, gateway: RegistaGateway) -> None:
        self._file_legacy_note(gateway, "Legacy Title Note")
        notes = list_notes(gateway)
        assert len(notes) == 1
        assert notes[0].title == "Legacy Title Note"
        assert notes[0].memory_type == "note"  # default for legacy payloads

    def test_legacy_title_renders_in_detail(self, gateway: RegistaGateway) -> None:
        entity_id = self._file_legacy_note(gateway, "Legacy Detail")
        detail = get_note(gateway, str(entity_id))
        assert detail is not None
        assert detail.title == "Legacy Detail"
        assert detail.body == "legacy body"

    def test_legacy_title_is_searchable(self, gateway: RegistaGateway) -> None:
        self._file_legacy_note(gateway, "Searchable Legacy")
        results = search_notes(gateway, "searchable")
        assert len(results) == 1
        assert results[0].title == "Searchable Legacy"

    def test_legacy_title_rebuilds_with_empty_name_in_agent_notes(
        self, gateway: RegistaGateway
    ) -> None:
        """Honest gap: a legacy ``title``-only note has no ``name`` field, so
        agent-notes' rebuild folds it to an empty name. This is the pre-
        convergence behavior the canonical payload fixes; documenting it here
        keeps the cross-face claim honest rather than over-claiming."""
        entity_id = self._file_legacy_note(gateway, "Legacy Title Note")
        folded = _fold_note_events(gateway.history(entity_id))
        assert folded["name"] == ""  # the gap the canonical payload closes
        assert folded["body"] == "legacy body"
