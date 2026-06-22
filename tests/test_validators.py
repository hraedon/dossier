from __future__ import annotations

from types import SimpleNamespace

import pytest
from regista import RegistaError

from dossier.actors import Actor
from dossier.validators import adversarial_review, derive_authors

from helpers import AGENT_R, ALICE, BOB, CAROL


def _evt(actor_id, actor_kind, transition):
    return SimpleNamespace(actor_id=actor_id, actor_kind=actor_kind, transition=transition)


def test_derive_authors_excludes_review_verdicts():
    events = [
        _evt("alice", "human", "created"),
        _evt("bob", "human", "start"),
        _evt("bob", "human", "submit_for_review"),
        _evt("carol", "human", "request_changes"),
        _evt("bob", "human", "submit_for_review"),
    ]
    author_ids, author_kinds = derive_authors(events)
    assert author_ids == {"alice", "bob"}
    assert "carol" not in author_ids
    assert author_kinds == {"human"}


def test_derive_authors_captures_agent_kinds():
    events = [
        _evt("agent-1", "agent", "created"),
        _evt("agent-1", "agent", "start"),
        _evt("agent-1", "agent", "submit_for_review"),
    ]
    author_ids, author_kinds = derive_authors(events)
    assert author_ids == {"agent-1"}
    assert author_kinds == {"agent"}


def test_derive_authors_includes_on_behalf_of_principal():
    delegated = SimpleNamespace(
        actor_id="agent-7",
        actor_kind="agent",
        transition="start",
        on_behalf_of={
            "principal_id": "alice",
            "principal_kind": "human",
            "principal_display_name": "Alice",
        },
    )
    author_ids, author_kinds = derive_authors([delegated])
    assert "agent-7" in author_ids
    assert "alice" in author_ids
    assert "agent" in author_kinds
    assert "human" in author_kinds


def test_adversarial_review_rejects_principal_self_review_via_agent():
    ctx = SimpleNamespace(
        actor_id="alice",
        actor_kind="human",
        prior_events=[
            SimpleNamespace(
                actor_id="agent-7",
                actor_kind="agent",
                transition="start",
                on_behalf_of={"principal_id": "alice", "principal_kind": "human"},
            )
        ],
    )
    with pytest.raises(Exception) as exc:
        adversarial_review(ctx)
    assert "self-review" in str(exc.value).lower()


def test_adversarial_review_passthrough_when_clean():
    ctx = SimpleNamespace(
        actor_id="carol",
        actor_kind="human",
        prior_events=[_evt("alice", "human", "created"), _evt("bob", "human", "start")],
    )
    adversarial_review(ctx)


def test_adversarial_review_rejects_self_review():
    ctx = SimpleNamespace(
        actor_id="bob",
        actor_kind="human",
        prior_events=[_evt("alice", "human", "created"), _evt("bob", "human", "start")],
    )
    with pytest.raises(Exception) as exc:
        adversarial_review(ctx)
    assert "self-review" in str(exc.value).lower()


def test_adversarial_review_rejects_agent_reviewer_for_agent_work():
    ctx = SimpleNamespace(
        actor_id="agent-2",
        actor_kind="agent",
        prior_events=[_evt("agent-1", "agent", "start")],
    )
    with pytest.raises(Exception) as exc:
        adversarial_review(ctx)
    assert "human reviewer" in str(exc.value).lower()


def test_validator_rejects_self_review(gateway, make_issue):
    wi = make_issue(actor=ALICE)
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="start")
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="submit_for_review")
    with pytest.raises(RegistaError):
        gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="accept")
    assert gateway.get_issue(wi.work_item_id).current_state == "in_review"


def test_validator_rejects_agent_reviewing_agent_work(gateway, make_issue):
    wi = make_issue(actor=AGENT_R)
    gateway.transition(actor=AGENT_R, work_item_id=wi.work_item_id, transition_name="start")
    gateway.transition(actor=AGENT_R, work_item_id=wi.work_item_id, transition_name="submit_for_review")
    reviewer = Actor(actor_id="agent-other", actor_kind="agent", display_name="Other Agent")
    with pytest.raises(RegistaError):
        gateway.transition(actor=reviewer, work_item_id=wi.work_item_id, transition_name="accept")


def test_validator_accepts_distinct_human_reviewer_of_agent_work(gateway, make_issue):
    wi = make_issue(actor=AGENT_R)
    gateway.transition(actor=AGENT_R, work_item_id=wi.work_item_id, transition_name="start")
    gateway.transition(actor=AGENT_R, work_item_id=wi.work_item_id, transition_name="submit_for_review")
    evt = gateway.transition(
        actor=CAROL,
        work_item_id=wi.work_item_id,
        transition_name="accept",
        payload={"review_note": "verified"},
    )
    assert evt.transition == "accept"
    assert gateway.get_issue(wi.work_item_id).current_state == "done"


def test_validator_accepts_distinct_human_reviewer_of_human_work(gateway, make_issue):
    wi = make_issue(actor=ALICE)
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="start")
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="submit_for_review")
    gateway.transition(actor=CAROL, work_item_id=wi.work_item_id, transition_name="accept")
    assert gateway.get_issue(wi.work_item_id).current_state == "done"


def test_request_changes_routes_back_to_in_progress(gateway, make_issue):
    wi = make_issue(actor=ALICE)
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="start")
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="submit_for_review")
    gateway.transition(
        actor=CAROL,
        work_item_id=wi.work_item_id,
        transition_name="request_changes",
        payload={"review_note": "needs tests"},
    )
    assert gateway.get_issue(wi.work_item_id).current_state == "in_progress"


def test_prior_reviewer_may_rereview_after_resubmit(gateway, make_issue):
    wi = make_issue(actor=ALICE)
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="start")
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="submit_for_review")
    gateway.transition(actor=CAROL, work_item_id=wi.work_item_id, transition_name="request_changes")
    assert gateway.get_issue(wi.work_item_id).current_state == "in_progress"
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="submit_for_review")
    gateway.transition(actor=CAROL, work_item_id=wi.work_item_id, transition_name="accept")
    assert gateway.get_issue(wi.work_item_id).current_state == "done"
