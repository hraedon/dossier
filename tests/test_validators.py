from __future__ import annotations

from types import SimpleNamespace

import pytest
from regista import RegistaError

from dossier.actors import Actor
from dossier.validators import adversarial_review, derive_authors, human_gate

from helpers import AGENT_GLM, AGENT_KIMI, ALICE, BOB, CAROL, DAVE


def _evt(
    actor_id,
    actor_kind,
    transition,
    *,
    actor_metadata=None,
    on_behalf_of=None,
):
    return SimpleNamespace(
        actor_id=actor_id,
        actor_kind=actor_kind,
        transition=transition,
        actor_metadata=actor_metadata,
        on_behalf_of=on_behalf_of,
    )


# --------------------------------------------------------------------------- #
# derive_authors
# --------------------------------------------------------------------------- #


def test_derive_authors_excludes_review_verdicts():
    events = [
        _evt("alice", "human", "created"),
        _evt("bob", "human", "start"),
        _evt("bob", "human", "submit_for_review"),
        _evt("carol", "human", "request_changes"),
        _evt("bob", "human", "submit_for_review"),
        _evt("carol", "human", "adversarial_pass"),
        _evt("carol", "human", "reject"),
    ]
    author_ids, author_kinds, author_lineages, undeclared = derive_authors(events)
    assert author_ids == {"alice", "bob"}
    assert "carol" not in author_ids
    assert author_kinds == {"human"}
    assert author_lineages == set()
    assert undeclared is False


def test_derive_authors_excludes_comments():
    """A comment is not authorship — a commenter may still review."""
    events = [
        _evt("alice", "human", "created"),
        _evt("carol", "human", "comment"),
        _evt("bob", "human", "start"),
    ]
    author_ids, _kinds, _lineages, _undeclared = derive_authors(events)
    assert author_ids == {"alice", "bob"}
    assert "carol" not in author_ids


def test_derive_authors_captures_agent_kinds_and_lineages():
    events = [
        _evt("agent-1", "agent", "created", actor_metadata={"model_lineage": "glm"}),
        _evt("agent-1", "agent", "start", actor_metadata={"model_lineage": "glm"}),
        _evt("agent-1", "agent", "submit_for_review", actor_metadata={"model_lineage": "glm"}),
    ]
    author_ids, author_kinds, author_lineages, undeclared = derive_authors(events)
    assert author_ids == {"agent-1"}
    assert author_kinds == {"agent"}
    assert author_lineages == {"glm"}
    assert undeclared is False


def test_derive_authors_flags_undeclared_agent_lineage():
    events = [_evt("agent-x", "agent", "start", actor_metadata={})]
    _ids, _kinds, _lineages, undeclared = derive_authors(events)
    assert undeclared is True


def test_derive_authors_includes_on_behalf_of_principal():
    delegated = _evt(
        "agent-7",
        "agent",
        "start",
        actor_metadata={"model_lineage": "kimi"},
        on_behalf_of={
            "principal_id": "alice",
            "principal_kind": "human",
            "principal_display_name": "Alice",
        },
    )
    author_ids, author_kinds, author_lineages, _undeclared = derive_authors([delegated])
    assert "agent-7" in author_ids
    assert "alice" in author_ids
    assert "agent" in author_kinds
    assert "human" in author_kinds
    assert author_lineages == {"kimi"}


def test_derive_authors_reads_principal_lineage_defensively():
    delegated = _evt(
        "agent-7",
        "agent",
        "start",
        on_behalf_of={
            "principal_id": "alice",
            "principal_kind": "human",
            "principal_lineage": "glm",
        },
    )
    _ids, _kinds, author_lineages, _undeclared = derive_authors([delegated])
    assert author_lineages == {"glm"}


# --------------------------------------------------------------------------- #
# adversarial_review — unit tests (SimpleNamespace contexts)
# --------------------------------------------------------------------------- #


def _ctx(
    *,
    actor_id="reviewer",
    actor_kind="human",
    actor_metadata=None,
    on_behalf_of=None,
    payload=None,
    prior_events=None,
    transition_name="accept",
):
    return SimpleNamespace(
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=actor_metadata,
        on_behalf_of=on_behalf_of,
        payload=payload,
        prior_events=prior_events or [],
        transition_name=transition_name,
    )


def test_adversarial_review_rejects_principal_self_review_via_agent():
    """WI-004 closure: a reviewer acting on behalf of an author is a self-review."""
    ctx = _ctx(
        actor_id="alice",
        actor_kind="human",
        prior_events=[
            _evt(
                "agent-7",
                "agent",
                "start",
                on_behalf_of={"principal_id": "alice", "principal_kind": "human"},
            )
        ],
    )
    with pytest.raises(Exception) as exc:
        adversarial_review(ctx)
    assert "self-review" in str(exc.value).lower()


def test_adversarial_review_same_lineage_no_ack_rejected():
    ctx = _ctx(
        actor_id="agent-glm-2",
        actor_kind="agent",
        actor_metadata={"model_lineage": "glm"},
        payload={"review_note": "n"},
        prior_events=[
            _evt("agent-glm-1", "agent", "start", actor_metadata={"model_lineage": "glm"}),
        ],
    )
    with pytest.raises(Exception) as exc:
        adversarial_review(ctx)
    assert "lineage" in str(exc.value).lower()


def test_adversarial_review_same_lineage_with_ack_passes():
    ctx = _ctx(
        actor_id="agent-glm-2",
        actor_kind="agent",
        actor_metadata={"model_lineage": "glm"},
        payload={"same_lineage_acknowledged": True, "review_note": "ack same lineage"},
        prior_events=[
            _evt("agent-glm-1", "agent", "start", actor_metadata={"model_lineage": "glm"}),
        ],
    )
    adversarial_review(ctx)


def test_adversarial_review_undeclared_reviewer_lineage_fail_closed():
    """An agent reviewer with no declared lineage cannot prove distinctness
    from an agent author — rejected without an explicit ack (kimi finding #1)."""
    ctx = _ctx(
        actor_id="agent-mystery",
        actor_kind="agent",
        actor_metadata={},
        payload={"review_note": "n"},
        prior_events=[
            _evt("agent-glm", "agent", "start", actor_metadata={"model_lineage": "glm"}),
        ],
    )
    with pytest.raises(Exception) as exc:
        adversarial_review(ctx)
    assert "lineage" in str(exc.value).lower()


def test_adversarial_review_undeclared_reviewer_lineage_ack_passes():
    ctx = _ctx(
        actor_id="agent-mystery",
        actor_kind="agent",
        actor_metadata={},
        payload={"same_lineage_acknowledged": True, "review_note": "ack"},
        prior_events=[
            _evt("agent-glm", "agent", "start", actor_metadata={"model_lineage": "glm"}),
        ],
    )
    adversarial_review(ctx)


def test_adversarial_review_agent_author_undeclared_lineage_fail_closed():
    """An agent author with no declared lineage makes distinctness unverifiable
    for any agent reviewer — rejected without ack."""
    ctx = _ctx(
        actor_id="agent-kimi",
        actor_kind="agent",
        actor_metadata={"model_lineage": "kimi"},
        payload={"review_note": "n"},
        prior_events=[_evt("agent-x", "agent", "start", actor_metadata={})],
    )
    with pytest.raises(Exception) as exc:
        adversarial_review(ctx)
    assert "lineage" in str(exc.value).lower()


def test_adversarial_review_cross_lineage_agent_passes():
    ctx = _ctx(
        actor_id="agent-kimi",
        actor_kind="agent",
        actor_metadata={"model_lineage": "kimi"},
        payload={"review_note": "n"},
        prior_events=[
            _evt("agent-glm", "agent", "start", actor_metadata={"model_lineage": "glm"}),
        ],
    )
    adversarial_review(ctx)


def test_adversarial_review_human_reviewer_of_agent_work_passes():
    ctx = _ctx(
        actor_id="carol",
        actor_kind="human",
        payload={"review_note": "n"},
        prior_events=[
            _evt("agent-glm", "agent", "start", actor_metadata={"model_lineage": "glm"}),
        ],
    )
    adversarial_review(ctx)


def test_adversarial_review_requires_review_note():
    ctx = _ctx(
        actor_id="agent-kimi",
        actor_kind="agent",
        actor_metadata={"model_lineage": "kimi"},
        prior_events=[
            _evt("agent-glm", "agent", "start", actor_metadata={"model_lineage": "glm"}),
        ],
    )
    with pytest.raises(Exception) as exc:
        adversarial_review(ctx)
    assert "review note" in str(exc.value).lower()


def test_adversarial_review_ack_must_be_exact_true():
    """A truthy non-bool (e.g. "yes") must not satisfy the structural flag."""
    ctx = _ctx(
        actor_id="agent-glm-2",
        actor_kind="agent",
        actor_metadata={"model_lineage": "glm"},
        payload={"same_lineage_acknowledged": "yes", "review_note": "n"},
        prior_events=[
            _evt("agent-glm-1", "agent", "start", actor_metadata={"model_lineage": "glm"}),
        ],
    )
    with pytest.raises(Exception):
        adversarial_review(ctx)


def test_adversarial_review_agent_reviewer_of_all_human_authors_no_ack():
    """The cross-lineage rule is agent-vs-agent only: an agent reviewer need not
    ack when no author is an agent."""
    ctx = _ctx(
        actor_id="agent-kimi",
        actor_kind="agent",
        actor_metadata={"model_lineage": "kimi"},
        payload={"review_note": "n"},
        prior_events=[_evt("alice", "human", "created"), _evt("bob", "human", "start")],
    )
    adversarial_review(ctx)


def test_adversarial_review_actor_metadata_none_passes_for_human():
    """A human reviewer with actor_metadata None is never blocked by lineage."""
    ctx = _ctx(
        actor_id="carol",
        actor_kind="human",
        actor_metadata=None,
        payload={"review_note": "n"},
        prior_events=[_evt("agent-glm", "agent", "start", actor_metadata={"model_lineage": "glm"})],
    )
    adversarial_review(ctx)


def test_adversarial_review_direct_self_review_rejected():
    ctx = _ctx(
        actor_id="bob",
        actor_kind="human",
        prior_events=[_evt("alice", "human", "created"), _evt("bob", "human", "start")],
    )
    with pytest.raises(Exception) as exc:
        adversarial_review(ctx)
    assert "self-review" in str(exc.value).lower()


# --------------------------------------------------------------------------- #
# human_gate — unit tests (SimpleNamespace contexts)
# --------------------------------------------------------------------------- #


def test_human_gate_rejects_agent_actor():
    ctx = _ctx(
        actor_id="agent-kimi",
        actor_kind="agent",
        actor_metadata={"model_lineage": "kimi"},
        prior_events=[_evt("alice", "human", "created"), _evt("bob", "human", "start")],
    )
    with pytest.raises(Exception) as exc:
        human_gate(ctx)
    assert "human" in str(exc.value).lower()


def test_human_gate_human_not_author_passes():
    ctx = _ctx(
        actor_id="carol",
        actor_kind="human",
        transition_name="accept",
        payload={"review_note": "ok"},
        prior_events=[_evt("alice", "human", "created"), _evt("bob", "human", "start")],
    )
    human_gate(ctx)


def test_human_gate_human_author_rejected():
    ctx = _ctx(
        actor_id="bob",
        actor_kind="human",
        payload={"review_note": "ok"},
        prior_events=[_evt("alice", "human", "created"), _evt("bob", "human", "start")],
    )
    with pytest.raises(Exception) as exc:
        human_gate(ctx)
    assert "self-review" in str(exc.value).lower()


def test_human_gate_requires_review_note():
    ctx = _ctx(
        actor_id="carol",
        actor_kind="human",
        prior_events=[_evt("alice", "human", "created"), _evt("bob", "human", "start")],
    )
    with pytest.raises(Exception) as exc:
        human_gate(ctx)
    assert "review note" in str(exc.value).lower()


def test_human_gate_rejects_accepter_equal_to_adversarial_passer():
    """Two-stage independence: the final accepter must differ from whoever did
    the most recent adversarial_pass (kimi finding #5)."""
    ctx = _ctx(
        actor_id="carol",
        actor_kind="human",
        transition_name="accept",
        payload={"review_note": "ok"},
        prior_events=[
            _evt("alice", "human", "created"),
            _evt("bob", "human", "start"),
            _evt("carol", "human", "adversarial_pass"),
        ],
    )
    with pytest.raises(Exception) as exc:
        human_gate(ctx)
    assert "independence" in str(exc.value).lower() or "differ" in str(exc.value).lower()


def test_human_gate_delegated_self_review_rejected():
    ctx = _ctx(
        actor_id="carol",
        actor_kind="human",
        on_behalf_of={"principal_id": "bob", "principal_kind": "human"},
        payload={"review_note": "ok"},
        prior_events=[_evt("alice", "human", "created"), _evt("bob", "human", "start")],
    )
    with pytest.raises(Exception) as exc:
        human_gate(ctx)
    assert "self-review" in str(exc.value).lower()


# --------------------------------------------------------------------------- #
# Integration tests (gateway + make_issue, InMemoryRegista)
# --------------------------------------------------------------------------- #


def _to_in_review(gateway, make_issue, *, author, starter=None):
    """Create an issue and advance it to in_review. Returns the work item."""
    wi = make_issue(actor=author)
    actor = starter or author
    gateway.transition(actor=actor, work_item_id=wi.work_item_id, transition_name="start")
    gateway.transition(
        actor=actor, work_item_id=wi.work_item_id, transition_name="submit_for_review"
    )
    return wi


def test_full_agentic_flow_cross_lineage_then_human_accept(gateway, make_issue):
    wi = _to_in_review(gateway, make_issue, author=AGENT_GLM)
    gateway.transition(
        actor=AGENT_KIMI,
        work_item_id=wi.work_item_id,
        transition_name="adversarial_pass",
        payload={"review_note": "cross-lineage pass"},
    )
    assert gateway.get_issue(wi.work_item_id).current_state == "in_human_review"
    gateway.transition(
        actor=ALICE,
        work_item_id=wi.work_item_id,
        transition_name="accept",
        payload={"review_note": "verified by human"},
    )
    assert gateway.get_issue(wi.work_item_id).current_state == "done"


def test_same_lineage_adversarial_review_without_ack_rejected(gateway, make_issue):
    wi = _to_in_review(gateway, make_issue, author=AGENT_GLM)
    other_glm = Actor(
        actor_id="agent-glm-2",
        actor_kind="agent",
        display_name="GLM Agent 2",
        model_lineage="glm",
    )
    with pytest.raises(RegistaError):
        gateway.transition(
            actor=other_glm,
            work_item_id=wi.work_item_id,
            transition_name="adversarial_pass",
            payload={"review_note": "n"},
        )
    assert gateway.get_issue(wi.work_item_id).current_state == "in_review"


def test_same_lineage_adversarial_review_with_ack_proceeds(gateway, make_issue):
    wi = _to_in_review(gateway, make_issue, author=AGENT_GLM)
    other_glm = Actor(
        actor_id="agent-glm-2",
        actor_kind="agent",
        display_name="GLM Agent 2",
        model_lineage="glm",
    )
    gateway.transition(
        actor=other_glm,
        work_item_id=wi.work_item_id,
        transition_name="adversarial_pass",
        payload={"same_lineage_acknowledged": True, "review_note": "ack same lineage"},
    )
    assert gateway.get_issue(wi.work_item_id).current_state == "in_human_review"


def test_non_human_accept_rejected_by_human_gate(gateway, make_issue):
    wi = _to_in_review(gateway, make_issue, author=AGENT_GLM)
    gateway.transition(
        actor=AGENT_KIMI,
        work_item_id=wi.work_item_id,
        transition_name="adversarial_pass",
        payload={"review_note": "cross-lineage pass"},
    )
    with pytest.raises(RegistaError):
        gateway.transition(
            actor=AGENT_KIMI,
            work_item_id=wi.work_item_id,
            transition_name="accept",
        )
    assert gateway.get_issue(wi.work_item_id).current_state == "in_human_review"


def test_request_changes_routes_back_to_in_progress(gateway, make_issue):
    wi = _to_in_review(gateway, make_issue, author=AGENT_GLM)
    gateway.transition(
        actor=AGENT_KIMI,
        work_item_id=wi.work_item_id,
        transition_name="request_changes",
        payload={"review_note": "needs tests"},
    )
    assert gateway.get_issue(wi.work_item_id).current_state == "in_progress"


def test_reject_from_in_human_review_routes_back_to_in_progress(gateway, make_issue):
    wi = _to_in_review(gateway, make_issue, author=AGENT_GLM)
    gateway.transition(
        actor=AGENT_KIMI,
        work_item_id=wi.work_item_id,
        transition_name="adversarial_pass",
        payload={"review_note": "pass"},
    )
    gateway.transition(
        actor=ALICE,
        work_item_id=wi.work_item_id,
        transition_name="reject",
        payload={"review_note": "not ready"},
    )
    assert gateway.get_issue(wi.work_item_id).current_state == "in_progress"


def test_self_review_via_delegation_rejected_at_adversarial_pass(gateway, make_issue):
    wi = _to_in_review(gateway, make_issue, author=AGENT_GLM)
    reviewer_on_behalf_of_author = Actor(
        actor_id="agent-kimi",
        actor_kind="agent",
        display_name="Kimi Agent",
        model_lineage="kimi",
        on_behalf_of={
            "principal_id": AGENT_GLM.actor_id,
            "principal_kind": "agent",
            "principal_display_name": AGENT_GLM.display_name,
        },
    )
    with pytest.raises(RegistaError):
        gateway.transition(
            actor=reviewer_on_behalf_of_author,
            work_item_id=wi.work_item_id,
            transition_name="adversarial_pass",
        )
    assert gateway.get_issue(wi.work_item_id).current_state == "in_review"


def test_human_only_item_full_flow(gateway, make_issue):
    wi = make_issue(actor=ALICE)
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="start")
    gateway.transition(
        actor=BOB, work_item_id=wi.work_item_id, transition_name="submit_for_review"
    )
    gateway.transition(
        actor=CAROL,
        work_item_id=wi.work_item_id,
        transition_name="adversarial_pass",
        payload={"review_note": "looks good"},
    )
    assert gateway.get_issue(wi.work_item_id).current_state == "in_human_review"
    gateway.transition(
        actor=DAVE,
        work_item_id=wi.work_item_id,
        transition_name="accept",
        payload={"review_note": "accepted"},
    )
    assert gateway.get_issue(wi.work_item_id).current_state == "done"


def test_human_gate_rejects_accepter_who_was_adversarial_pass_principal(gateway, make_issue):
    """Delegation bypass of two-stage independence (kimi HIGH finding): an agent
    performs adversarial_pass on behalf of Alice, so Alice may not then accept."""
    wi = _to_in_review(gateway, make_issue, author=AGENT_GLM)
    reviewer_for_alice = Actor(
        actor_id="agent-kimi",
        actor_kind="agent",
        display_name="Kimi Agent",
        model_lineage="kimi",
        on_behalf_of={
            "principal_id": ALICE.actor_id,
            "principal_kind": "human",
            "principal_display_name": ALICE.display_name,
        },
    )
    gateway.transition(
        actor=reviewer_for_alice,
        work_item_id=wi.work_item_id,
        transition_name="adversarial_pass",
        payload={"review_note": "pass"},
    )
    with pytest.raises(RegistaError):
        gateway.transition(
            actor=ALICE,
            work_item_id=wi.work_item_id,
            transition_name="accept",
            payload={"review_note": "ok"},
        )
    assert gateway.get_issue(wi.work_item_id).current_state == "in_human_review"
    # a distinct human who was neither author nor adversarial-pass principal may accept
    gateway.transition(
        actor=BOB,
        work_item_id=wi.work_item_id,
        transition_name="accept",
        payload={"review_note": "ok"},
    )
    assert gateway.get_issue(wi.work_item_id).current_state == "done"
    wi = make_issue(actor=ALICE)
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="start")
    gateway.transition(
        actor=BOB, work_item_id=wi.work_item_id, transition_name="submit_for_review"
    )
    gateway.transition(
        actor=CAROL,
        work_item_id=wi.work_item_id,
        transition_name="request_changes",
        payload={"review_note": "needs tests"},
    )
    assert gateway.get_issue(wi.work_item_id).current_state == "in_progress"
    gateway.transition(
        actor=BOB, work_item_id=wi.work_item_id, transition_name="submit_for_review"
    )
    gateway.transition(
        actor=CAROL,
        work_item_id=wi.work_item_id,
        transition_name="adversarial_pass",
        payload={"review_note": "pass"},
    )
    gateway.transition(
        actor=DAVE,
        work_item_id=wi.work_item_id,
        transition_name="accept",
        payload={"review_note": "accepted"},
    )
    assert gateway.get_issue(wi.work_item_id).current_state == "done"
