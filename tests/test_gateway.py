from __future__ import annotations

import pytest
import regista
from conftest import make_v6_gateway
from helpers import ALICE, BOB, CAROL, DAVE

from dossier.gateway import WORKFLOW_NAME, RegistaGateway, packaged_workflow_yaml


def test_gateway_registers_regista_canonical_verbatim():
    """WI-4 (Plan 010) anti-drift guard: dossier registers regista's single
    canonical workflow verbatim — same bytes agent-notes registers — so the two
    faces never re-fork into separate work-item universes (the convergence gap)."""
    assert packaged_workflow_yaml() == regista.canonical_workflow_yaml()
    assert WORKFLOW_NAME == "canonical"


def test_principal_registry_writes_use_the_lifecycle_project():
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    work_reg = SimpleNamespace(principals=MagicMock())
    lifecycle_reg = SimpleNamespace(principals=MagicMock())
    gateway = RegistaGateway(
        work_reg,
        project_name="work",
        lifecycle_regista=lifecycle_reg,
    )

    gateway._generate_and_register("service:example")

    lifecycle_reg.principals.register.assert_called_once()
    work_reg.principals.register.assert_not_called()


def test_delegation_claim_is_authoritative_and_payload_is_not_mutated():
    from dossier.actors import Actor
    from dossier.attribution import authoritative_payload

    actor = Actor(
        actor_id="agent:trusted",
        actor_kind="agent",
        display_name="Trusted agent",
        on_behalf_of={"principal_id": "human:trusted", "session_id": "s-1"},
    )
    caller_payload = {
        "on_behalf_of": {"principal_id": "human:attacker"},
        "review_note": "accepted",
    }

    result = authoritative_payload(actor, caller_payload)

    assert result == {
        "on_behalf_of": {"principal_id": "human:trusted", "session_id": "s-1"},
        "review_note": "accepted",
    }
    assert caller_payload["on_behalf_of"] == {"principal_id": "human:attacker"}


def test_delegation_claim_is_stripped_when_actor_has_none():
    from dossier.actors import Actor
    from dossier.attribution import authoritative_payload

    result = authoritative_payload(
        Actor(actor_id="human:trusted", actor_kind="human", display_name="Human"),
        {"on_behalf_of": {"principal_id": "human:attacker"}, "body": "comment"},
    )

    assert result == {"body": "comment"}


def test_durable_lifecycle_prepares_require_a_real_actor():
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from regista import LifecycleContractError, LifecycleErrorCode

    from dossier.actors import SYSTEM_ACTOR

    lifecycle = SimpleNamespace(principal_lifecycle=MagicMock())
    gateway = RegistaGateway(
        MagicMock(),
        project_name="work",
        lifecycle_regista=lifecycle,
    )

    for actor in (None, SYSTEM_ACTOR):
        with pytest.raises(LifecycleContractError) as exc_info:
            gateway.prepare_enrollment_with_key(
                "human:target",
                b"0" * 32,
                actor=actor,
            )
        assert exc_info.value.code is LifecycleErrorCode.INVALID_REQUEST
    lifecycle.principal_lifecycle.prepare_enrollment.assert_not_called()


def test_lifecycle_health_uses_registas_public_trust_verifier():
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    trust_verifier = MagicMock()
    lifecycle = SimpleNamespace(verify_trust_log=trust_verifier)
    gateway = RegistaGateway(
        MagicMock(),
        project_name="work",
        lifecycle_regista=lifecycle,
    )

    gateway.verify_lifecycle_trust()

    trust_verifier.assert_called_once_with()


def test_create_and_history(gateway, make_issue):
    wi = make_issue(actor=ALICE, assignee="bob", priority="high")
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="start")
    gateway.comment(actor=ALICE, work_item_id=wi.work_item_id, body="heads up")
    events = gateway.history(wi.work_item_id)
    transitions = [e.transition for e in events]
    assert transitions == ["created", "start", "comment"]
    assert all(e.actor_kind in {"human", "agent", "system"} for e in events)
    assert events[0].actor_id == "human:alice"
    assert events[1].actor_id == "human:bob"


def test_history_events_carry_actor_kind_and_on_behalf_of(gateway, make_issue):
    from dossier.actors import Actor

    delegating = Actor(
        actor_id="agent:seven",
        actor_kind="agent",
        display_name="Agent Seven",
        on_behalf_of={
            "principal_kind": "human",
            "principal_id": "human:alice",
            "principal_display_name": "Alice",
        },
    )
    wi = make_issue(actor=ALICE)
    gateway.transition(actor=delegating, work_item_id=wi.work_item_id, transition_name="start")
    events = gateway.history(wi.work_item_id)
    agent_event = next(e for e in events if e.actor_id == "agent:seven")
    assert agent_event.actor_kind == "agent"
    assert agent_event.on_behalf_of is None
    assert agent_event.payload["on_behalf_of"]["principal_id"] == "human:alice"


def test_list_issues_filters_by_state_and_assignee(gateway, make_issue):
    open_one = make_issue(actor=ALICE, assignee="bob")
    make_issue(actor=ALICE, assignee="carol")
    gateway.transition(actor=BOB, work_item_id=open_one.work_item_id, transition_name="start")

    in_progress = gateway.list_issues(current_states=["in_progress"])
    assert len(in_progress.items) == 1
    assert in_progress.items[0].work_item_id == open_one.work_item_id

    bobs = gateway.list_issues(assignee="bob")
    assert len(bobs.items) == 1


def test_integrity_replay_zero_drift_on_clean_history(gateway, make_issue):
    wi = make_issue(actor=ALICE)
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="start")
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="submit_for_review")
    gateway.transition(
        actor=CAROL,
        work_item_id=wi.work_item_id,
        transition_name="adversarial_pass",
        payload={"review_note": "lgtm"},
    )
    gateway.transition(
        actor=DAVE,
        work_item_id=wi.work_item_id,
        transition_name="accept",
        payload={"review_note": "verified"},
    )
    report = gateway.integrity()
    assert report.replayed_drift == 0
    assert report.halted == 0


def test_actor_metadata_records_display_name(gateway, make_issue):
    wi = make_issue(actor=ALICE)
    events = gateway.history(wi.work_item_id)
    assert events[0].actor_metadata["display_name"] == "Alice"
    assert events[0].actor_metadata["role"] == "human"


def test_display_key_minted_on_creation(gateway, make_issue):
    wi = make_issue(actor=ALICE, title="Display key test")
    cf = getattr(wi, "custom_fields", None)
    assert isinstance(cf, dict)
    assert cf.get("display_key") == "DOSSIER_TEST-1"


def test_display_key_increments(gateway, make_issue):
    wi1 = make_issue(actor=ALICE, title="First")
    wi2 = make_issue(actor=ALICE, title="Second")
    wi3 = make_issue(actor=ALICE, title="Third")
    assert getattr(wi1, "custom_fields", {}).get("display_key") == "DOSSIER_TEST-1"
    assert getattr(wi2, "custom_fields", {}).get("display_key") == "DOSSIER_TEST-2"
    assert getattr(wi3, "custom_fields", {}).get("display_key") == "DOSSIER_TEST-3"


def test_display_key_not_overwritten_if_provided(gateway):
    from helpers import ALICE

    wi, _ = gateway.create_issue(
        actor=ALICE,
        work_item_type="bug",
        custom_fields={"title": "Pre-set key", "display_key": "CUSTOM-99"},
    )
    assert getattr(wi, "custom_fields", {}).get("display_key") == "CUSTOM-99"


def test_display_key_sanitizes_project_name(tmp_path):
    gw = make_v6_gateway(tmp_path, "agent-notes project!")
    wi, _ = gw.create_issue(
        actor=ALICE, work_item_type="bug", custom_fields={"title": "Sanitize test"}
    )
    assert getattr(wi, "custom_fields", {}).get("display_key") == "AGENT_NOTES_PROJECT-1"
    gw.close()


def test_v2_work_item_transitions_correctly(gateway, make_issue):
    """Verify that work items created under the current (v2) workflow can
    transition through the canonical lifecycle. True v1 backward-compat is
    covered by regista's own tests (the workflow registry stores versions as
    composite keys; v1 items resolve to v1 transitions)."""
    from helpers import BOB

    wi = make_issue(actor=ALICE, title="V2 transition test")
    version = getattr(wi, "workflow_version", None)
    assert version is not None
    tdefs = gateway.transitions_from("open", version)
    assert any(t.name == "start" for t in tdefs)
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="start")
    assert gateway.get_issue(wi.work_item_id) is not None
