from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

import pytest

from dossier.knowledge import (
    NoteDetail,
    NoteSummary,
    create_note,
    get_note,
    list_notes,
    search_notes,
    verify_note,
)
from dossier.knowledge_verify import (
    VerificationResult,
    verify_all_notes,
    verify_note_chain,
)


def _make_event(
    *,
    event_seq: int = 1,
    transition: str = "created",
    actor_id: str = "test-user",
    timestamp: datetime | None = None,
    payload: dict[str, Any] | None = None,
    work_item_id=None,
    entity_kind: str = "note",
) -> MagicMock:
    ev = MagicMock()
    ev.event_seq = event_seq
    ev.transition = transition
    ev.actor_id = actor_id
    ev.timestamp = timestamp or datetime(2026, 7, 12, 12, 0, tzinfo=UTC)
    ev.payload = payload or {"title": "Test Note", "body": "Test body"}
    ev.work_item_id = work_item_id or uuid.uuid4()
    ev.entity_kind = entity_kind
    ev.entity_id = ev.work_item_id
    ev.actor_metadata = {"display_name": "Test User"}
    ev.on_behalf_of = None
    ev.key_id = None
    return ev


def _make_gateway(
    events: list[Any] | None = None,
    note_events: list[Any] | None = None,
    verify_result: dict[str, Any] | None = None,
    replay_drift: int = 0,
    replay_halted: bool = False,
) -> MagicMock:
    gw = MagicMock()
    gw.read_recent_events.return_value = events or []
    gw.history.return_value = note_events or []
    gw.verify_event.return_value = verify_result or {
        "verified": True,
        "principal_id": "test-principal",
        "fingerprint": "sha256:abc123",
        "scheme": "ed25519",
    }
    report = MagicMock()
    report.replayed_drift = replay_drift
    report.halted = replay_halted
    gw.integrity.return_value = report
    gw.append_note_event.return_value = _make_event()
    return gw


@pytest.fixture
def actor() -> MagicMock:
    a = MagicMock()
    a.actor_id = "test-user"
    a.actor_kind = "human"
    a.display_name = "Test User"
    a.model_lineage = None
    a.on_behalf_of = None
    return a


class TestListNotes:
    def test_empty_returns_empty_list(self) -> None:
        gw = _make_gateway(events=[])
        result = list_notes(gw)
        assert result == []

    def test_returns_notes_from_events(self) -> None:
        entity_id = uuid.uuid4()
        ev = _make_event(
            transition="created",
            payload={"title": "My Note", "body": "content"},
            work_item_id=entity_id,
        )
        gw = _make_gateway(events=[ev])
        result = list_notes(gw)
        assert len(result) == 1
        assert result[0].title == "My Note"
        assert result[0].state == "active"
        assert result[0].note_id == str(entity_id)

    def test_filters_out_non_note_events(self) -> None:
        note_entity = uuid.uuid4()
        work_item_entity = uuid.uuid4()
        note_ev = _make_event(
            transition="created",
            payload={"title": "Note", "body": ""},
            work_item_id=note_entity,
            entity_kind="note",
        )
        work_ev = _make_event(
            transition="created",
            payload={"title": "Bug", "body": ""},
            work_item_id=work_item_entity,
            entity_kind="work_item",
        )
        gw = _make_gateway(events=[note_ev, work_ev])
        result = list_notes(gw)
        assert len(result) == 1
        assert result[0].title == "Note"

    def test_superseded_note_shows_correct_state(self) -> None:
        entity_id = uuid.uuid4()
        created = _make_event(
            event_seq=1,
            transition="created",
            payload={"title": "Old Note", "body": "old"},
            work_item_id=entity_id,
        )
        superseded = _make_event(
            event_seq=2,
            transition="superseded",
            timestamp=datetime(2026, 7, 12, 13, 0, tzinfo=UTC),
            payload={"title": "Old Note", "body": "old"},
            work_item_id=entity_id,
        )
        gw = _make_gateway(events=[created, superseded])
        result = list_notes(gw)
        assert len(result) == 1
        assert result[0].state == "superseded"


class TestGetNote:
    def test_returns_none_when_not_found(self) -> None:
        gw = _make_gateway(note_events=[])
        result = get_note(gw, str(uuid.uuid4()))
        assert result is None

    def test_returns_none_for_invalid_uuid(self) -> None:
        gw = _make_gateway()
        result = get_note(gw, "not-a-uuid")
        assert result is None

    def test_returns_detail_with_events(self) -> None:
        entity_id = uuid.uuid4()
        ev = _make_event(
            transition="created",
            payload={"title": "Detail", "body": "body text"},
            work_item_id=entity_id,
        )
        gw = _make_gateway(note_events=[ev])
        result = get_note(gw, str(entity_id))
        assert result is not None
        assert result.title == "Detail"
        assert result.body == "body text"
        assert result.state == "active"
        assert len(result.events) == 1
        assert result.note_id == str(entity_id)


class TestSearchNotes:
    def test_empty_query_returns_empty(self) -> None:
        gw = _make_gateway()
        result = search_notes(gw, "")
        assert result == []

    def test_filters_by_title(self) -> None:
        entity1 = uuid.uuid4()
        entity2 = uuid.uuid4()
        ev1 = _make_event(
            transition="created",
            payload={"title": "Python Guide", "body": ""},
            work_item_id=entity1,
        )
        ev2 = _make_event(
            transition="created",
            payload={"title": "Deployment Notes", "body": ""},
            work_item_id=entity2,
        )
        gw = _make_gateway(events=[ev1, ev2])
        result = search_notes(gw, "python")
        assert len(result) == 1
        assert result[0].title == "Python Guide"


class TestCreateNote:
    def test_creates_note_and_returns_id(self, actor: MagicMock) -> None:
        gw = _make_gateway()
        result = create_note(gw, actor=actor, title="New Note", body="content")
        assert isinstance(result, str)
        uuid.UUID(result)
        gw.append_note_event.assert_called_once()

    def test_create_passes_correct_payload(self, actor: MagicMock) -> None:
        gw = _make_gateway()
        create_note(gw, actor=actor, title="Title", body="Body")
        call_kwargs = gw.append_note_event.call_args.kwargs
        assert call_kwargs["transition"] == "created"
        assert call_kwargs["payload"]["title"] == "Title"
        assert call_kwargs["payload"]["body"] == "Body"
        assert call_kwargs["entity_kind"] if "entity_kind" in call_kwargs else True


class TestVerifyNote:
    def test_returns_not_found_for_missing_note(self) -> None:
        gw = _make_gateway(note_events=[])
        result = verify_note(gw, str(uuid.uuid4()))
        assert result["verified"] is False
        assert result["chain_intact"] is False
        assert "note not found" in result["findings"]

    def test_returns_verified_for_valid_note(self) -> None:
        entity_id = uuid.uuid4()
        ev = _make_event(transition="created", work_item_id=entity_id)
        gw = _make_gateway(note_events=[ev])
        result = verify_note(gw, str(entity_id))
        assert result["verified"] is True
        assert result["chain_intact"] is True
        assert result["principal_id"] == "test-principal"

    def test_returns_unverified_for_bad_signature(self) -> None:
        entity_id = uuid.uuid4()
        ev = _make_event(transition="created", work_item_id=entity_id)
        gw = _make_gateway(
            note_events=[ev],
            verify_result={"verified": False, "principal_id": None, "fingerprint": None, "scheme": None},
        )
        result = verify_note(gw, str(entity_id))
        assert result["verified"] is False
        assert any("unverified" in f for f in result["findings"])

    def test_detects_chain_drift(self) -> None:
        entity_id = uuid.uuid4()
        ev = _make_event(transition="created", work_item_id=entity_id)
        gw = _make_gateway(note_events=[ev], replay_drift=2)
        result = verify_note(gw, str(entity_id))
        assert result["chain_intact"] is False
        assert any("drift" in f for f in result["findings"])


class TestVerifyNoteChain:
    def test_returns_verification_result(self) -> None:
        entity_id = uuid.uuid4()
        ev = _make_event(transition="created", work_item_id=entity_id)
        gw = _make_gateway(note_events=[ev])
        result = verify_note_chain(gw, str(entity_id))
        assert isinstance(result, VerificationResult)
        assert result.verified is True
        assert result.chain_intact is True
        assert result.signer_principal == "test-principal"
        assert result.findings == ()


class TestVerifyAllNotes:
    def test_returns_empty_for_no_notes(self) -> None:
        gw = _make_gateway(events=[])
        result = verify_all_notes(gw)
        assert result == []

    def test_returns_results_for_notes(self) -> None:
        entity_id = uuid.uuid4()
        ev = _make_event(
            transition="created",
            payload={"title": "Note", "body": ""},
            work_item_id=entity_id,
        )
        gw = _make_gateway(events=[ev])
        result = verify_all_notes(gw)
        assert len(result) >= 1
