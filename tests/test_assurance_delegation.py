"""dossier WI-012: the assurance level is delegated to regista.

These tests pin three things:

1. The computation really is regista's — ``dossier.assurance`` calls
   ``regista.gate_rationale`` and nothing else derives a level.
2. dossier renders regista's answer faithfully **except** that it never
   over-claims independence (dossier WI-014's fail-safe, preserved).
3. The degradation is honest: it is visible in the verdict and in the UI,
   with a reason, rather than silently rewriting the level.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
import regista
from regista import Event

from dossier import assurance as assurance_mod
from dossier.assurance import (
    AssuranceVerdict,
    _verdict_from_rationale,
    compute_assurance_level,
    compute_assurance_verdict,
)


def _event(
    *,
    transition: str = "created",
    actor_kind: str = "agent",
    actor_metadata: dict[str, Any] | None = None,
    event_seq: int = 0,
) -> Event:
    return Event(
        event_id=uuid.uuid4(),
        work_item_id=uuid.uuid4(),
        event_seq=event_seq,
        actor_id="test-actor",
        actor_kind=actor_kind,
        actor_metadata=actor_metadata,
        key_id="test-key",
        workflow_name="canonical",
        workflow_version=2,
        timestamp=datetime.now(UTC),
        transition=transition,
        payload=None,
        payload_canonical_hash=b"",
        signature=b"",
    )


# ── 1. The computation is regista's ──────────────────────────────────────


def test_assurance_is_bound_to_registas_public_function() -> None:
    """dossier holds a reference to regista's own gate_rationale."""
    assert assurance_mod.gate_rationale is regista.gate_rationale


def test_verdict_records_regista_as_the_source() -> None:
    verdict = compute_assurance_verdict([_event()])
    assert verdict.source == "regista"
    assert verdict.regista_level == "none"
    assert verdict.level == "unreviewed"


def test_delegation_is_the_only_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """If regista's function is not called, no level is produced.

    Guards against a future edit quietly reintroducing a local computation:
    with the delegate stubbed out, the verdict must follow the stub, not the
    events.
    """
    calls: list[int] = []

    def _fake(events: Any, profile: Any) -> dict[str, Any]:
        calls.append(len(list(events)))
        return {
            "assurance_level": "independently_reviewed",
            "reviewer_lineage": "kimi",
            "author_lineages": ["glm"],
            "reason": "cross_lineage_review",
            "profile": str(profile),
        }

    monkeypatch.setattr(assurance_mod, "gate_rationale", _fake)
    # Events that a local computation would call *unreviewed* — no review
    # verdict at all. The delegate's answer must win.
    verdict = compute_assurance_verdict(
        [_event(transition="created", actor_metadata={"model_lineage": "glm"})]
    )
    assert calls == [1]
    assert verdict.level == "independently-reviewed"
    assert verdict.regista_level == "independently_reviewed"


def test_delegation_passes_the_strict_gate_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[Any] = []

    def _fake(events: Any, profile: Any) -> dict[str, Any]:
        seen.append(profile)
        return {"assurance_level": "none", "reviewer_lineage": None, "author_lineages": []}

    monkeypatch.setattr(assurance_mod, "gate_rationale", _fake)
    compute_assurance_verdict([])
    assert seen == ["strict"]


# ── 2. Honest degradation (WI-014 preserved through the delegation) ───────


def test_undeclared_reviewer_lineage_downgrades_and_says_why() -> None:
    """regista calls this independent; dossier must not repeat that claim."""
    events = [
        _event(actor_metadata={"model_lineage": "glm"}, event_seq=0),
        _event(
            transition="adversarial_pass",
            actor_metadata=None,
            event_seq=1,
        ),
    ]
    # Confirm the engine really does over-claim, so this test keeps meaning
    # if regista's behaviour changes.
    raw = regista.gate_rationale(events, "strict")
    assert str(raw["assurance_level"]) == "independently_reviewed"

    verdict = compute_assurance_verdict(events)
    assert verdict.level == "self-reviewed"
    assert verdict.regista_level == "independently_reviewed"
    assert verdict.degraded is True
    assert verdict.degradation_reason is not None
    assert "reviewer declared no model lineage" in verdict.degradation_reason
    assert verdict.independence_verifiable is False


def test_undeclared_agent_author_downgrades_and_says_why() -> None:
    """An agent author with no declared lineage cannot be shown distinct."""
    events = [
        _event(actor_kind="agent", actor_metadata=None, event_seq=0),
        _event(
            transition="adversarial_pass",
            actor_kind="agent",
            actor_metadata={"model_lineage": "kimi"},
            event_seq=1,
        ),
    ]
    verdict = compute_assurance_verdict(events)
    assert verdict.regista_level == "independently_reviewed"
    assert verdict.level == "self-reviewed"
    assert verdict.degraded is True
    assert verdict.degradation_reason is not None
    assert "without declaring a model lineage" in verdict.degradation_reason


def test_human_author_and_declared_agent_reviewer_stays_independent() -> None:
    """A human and a model are trivially independent — no downgrade."""
    events = [
        _event(actor_kind="human", actor_metadata={"display_name": "Alice"}, event_seq=0),
        _event(
            transition="adversarial_pass",
            actor_kind="agent",
            actor_metadata={"model_lineage": "kimi"},
            event_seq=1,
        ),
    ]
    verdict = compute_assurance_verdict(events)
    assert verdict.level == "independently-reviewed"
    assert verdict.degraded is False
    assert verdict.degradation_reason is None
    assert verdict.independence_verifiable is True


def test_accepted_independent_review_degrades_to_human_accepted() -> None:
    """The accepted variant downgrades too, not just the un-accepted one."""
    events = [
        _event(actor_kind="agent", actor_metadata=None, event_seq=0),
        _event(
            transition="adversarial_pass",
            actor_kind="agent",
            actor_metadata={"model_lineage": "kimi"},
            event_seq=1,
        ),
        _event(
            transition="accept",
            actor_kind="human",
            actor_metadata={"display_name": "Alice"},
            event_seq=2,
        ),
    ]
    verdict = compute_assurance_verdict(events)
    assert verdict.regista_level == "independently_and_accepted"
    assert verdict.level == "human-accepted"
    assert verdict.degraded is True


def test_same_lineage_review_is_not_degraded() -> None:
    """A self-review is already the honest floor — no degradation flag."""
    events = [
        _event(actor_metadata={"model_lineage": "glm"}, event_seq=0),
        _event(
            transition="adversarial_pass",
            actor_metadata={"model_lineage": "glm"},
            event_seq=1,
        ),
    ]
    verdict = compute_assurance_verdict(events)
    assert verdict.level == "self-reviewed"
    assert verdict.regista_level == "self_reviewed"
    assert verdict.degraded is False


def test_unknown_regista_level_renders_the_floor() -> None:
    """A level from a newer regista must not be rendered optimistically."""
    verdict = _verdict_from_rationale(
        {
            "assurance_level": "notarized_by_three_witnesses",
            "reviewer_lineage": "kimi",
            "author_lineages": ["glm"],
        }
    )
    assert verdict.level == "unreviewed"
    assert verdict.degraded is True
    assert verdict.degradation_reason is not None
    assert "does not know how to render" in verdict.degradation_reason


def test_dossier_never_claims_more_than_regista() -> None:
    """Across every regista level, the rendered level is <= regista's."""
    rank = {
        "unreviewed": 0,
        "self-reviewed": 1,
        "independently-reviewed": 2,
        "human-accepted": 2,
    }
    regista_rank = {
        "none": 0,
        "self_reviewed": 1,
        "independently_reviewed": 2,
        "human_accepted": 2,
        "independently_and_accepted": 2,
    }
    for regista_level, expected_rank in regista_rank.items():
        for reviewer in (None, "kimi"):
            verdict = _verdict_from_rationale(
                {
                    "assurance_level": regista_level,
                    "reviewer_lineage": reviewer,
                    "author_lineages": ["glm"],
                },
                undeclared_agent_author=reviewer is None,
            )
            assert rank[verdict.level] <= expected_rank


def test_compute_assurance_level_is_the_verdict_level() -> None:
    events = [
        _event(actor_metadata={"model_lineage": "glm"}, event_seq=0),
        _event(
            transition="adversarial_pass",
            actor_metadata={"model_lineage": "glm"},
            event_seq=1,
        ),
    ]
    assert compute_assurance_level(events) == compute_assurance_verdict(events).level


# ── 3. The degradation reaches the human ─────────────────────────────────


def test_issue_detail_renders_the_degradation_reason(client, gateway) -> None:
    """A degraded verdict is visible in the UI, with its reason."""
    from conftest import login as _login

    from dossier.actors import Actor
    from helpers import AGENT_KIMI

    undeclared_agent = Actor(
        actor_id="agent-anonymous",
        actor_kind="agent",
        display_name="Undeclared Agent",
    )

    _login(client)
    wi, _ = gateway.create_issue(
        actor=undeclared_agent,
        work_item_type="bug",
        custom_fields={"title": "Degraded assurance issue"},
    )
    gateway.transition(
        actor=undeclared_agent, work_item_id=wi.work_item_id, transition_name="start"
    )
    gateway.transition(
        actor=undeclared_agent,
        work_item_id=wi.work_item_id,
        transition_name="submit_for_review",
    )
    gateway.transition(
        actor=AGENT_KIMI,
        work_item_id=wi.work_item_id,
        transition_name="adversarial_pass",
        payload={
            "review_note": "cross lineage on paper only",
            # regista's write-side validator refuses this review outright
            # unless the same-lineage risk is acknowledged — the acknowledgment
            # is what lets the event exist. gate_rationale still reports it as
            # `independently_reviewed`; this test is about what dossier renders.
            "same_lineage_acknowledged": True,
        },
    )

    resp = client.get(f"/p/dossier-test/issues/{wi.work_item_id}")
    assert resp.status_code == 200
    # The optimistic claim must not appear...
    assert "independently reviewed" not in resp.text
    # ...the honest one, and the reason, must.
    assert "self-reviewed" in resp.text
    assert "degraded assurance" in resp.text
    assert "without declaring a model lineage" in resp.text


def test_assurance_verdict_is_a_frozen_value() -> None:
    verdict = compute_assurance_verdict([_event()])
    assert isinstance(verdict, AssuranceVerdict)
    with pytest.raises(Exception):
        verdict.level = "human-accepted"  # type: ignore[misc]
