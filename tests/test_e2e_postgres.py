from __future__ import annotations

import uuid

import pytest

from dossier.auth.backends import Principal
from dossier.auth.resolver import principal_to_actor
from dossier.gateway import RegistaGateway
from dossier.keys import generate_keyset

pytestmark = pytest.mark.postgres

DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"


def _human(stable_id, display_name):
    return principal_to_actor(Principal(stable_id=stable_id, display_name=display_name, source="local"))


@pytest.fixture(scope="module")
def pg_gateway(tmp_path_factory):
    from regista import Regista
    from regista.testing import drop_project_schema

    key_path = tmp_path_factory.mktemp("keys") / "keys.json"
    generate_keyset(key_path)
    project = f"dossier_e2e_{uuid.uuid4().hex[:8]}"
    try:
        reg = Regista.create_project(DSN, project, hmac_key_path=str(key_path))
    except Exception as exc:
        pytest.skip(f"Postgres unavailable: {exc}")
    gw = RegistaGateway(reg)
    gw.register_workflow()
    yield gw
    gw.close()
    drop_project_schema(DSN, project)


def test_full_review_lifecycle_verified_chain(pg_gateway):
    alice = _human("alice", "Alice")
    bob = _human("bob", "Bob")
    carol = _human("carol", "Carol")

    wi, _ = pg_gateway.create_issue(
        actor=alice,
        work_item_type="bug",
        custom_fields={"title": "e2e bug", "assignee": "bob", "priority": "high"},
    )
    pg_gateway.transition(actor=bob, work_item_id=wi.work_item_id, transition_name="start")
    pg_gateway.comment(actor=alice, work_item_id=wi.work_item_id, body="triaged, assigning to bob")
    pg_gateway.transition(actor=bob, work_item_id=wi.work_item_id, transition_name="submit_for_review")
    accept = pg_gateway.transition(
        actor=carol,
        work_item_id=wi.work_item_id,
        transition_name="accept",
        payload={"review_note": "verified against fixtures; lgtm"},
    )

    assert accept.transition == "accept"
    assert pg_gateway.get_issue(wi.work_item_id).current_state == "done"

    events = pg_gateway.history(wi.work_item_id)
    transitions = [e.transition for e in events]
    assert transitions == ["created", "start", "comment", "submit_for_review", "accept"]

    by_transition = {e.transition: e for e in events}
    assert by_transition["created"].actor_id == "alice"
    assert by_transition["created"].actor_kind == "human"
    assert by_transition["start"].actor_id == "bob"
    assert by_transition["accept"].actor_id == "carol"
    assert by_transition["accept"].actor_metadata["display_name"] == "Carol"
    assert by_transition["comment"].payload["body"].startswith("triaged")

    report = pg_gateway.integrity()
    assert report.replayed_drift == 0
    assert report.halted == 0


def test_verified_history_is_legible(pg_gateway):
    alice = _human("alice", "Alice")
    bob = _human("bob", "Bob")
    carol = _human("carol", "Carol")

    wi, _ = pg_gateway.create_issue(actor=alice, work_item_type="task", custom_fields={"title": "e2e task"})
    pg_gateway.transition(actor=bob, work_item_id=wi.work_item_id, transition_name="start")
    pg_gateway.transition(actor=bob, work_item_id=wi.work_item_id, transition_name="submit_for_review")
    pg_gateway.transition(actor=carol, work_item_id=wi.work_item_id, transition_name="accept")

    events = pg_gateway.history(wi.work_item_id)
    rendered = [
        f"{e.timestamp.isoformat()} | {e.transition} | by {e.actor_metadata.get('display_name', e.actor_id)} ({e.actor_kind})"
        for e in events
    ]
    joined = "\n".join(rendered)
    assert "by Alice (human)" in joined
    assert "by Bob (human)" in joined
    assert "by Carol (human)" in joined
    assert "accept" in joined
    assert pg_gateway.integrity().replayed_drift == 0


def test_adversarial_gate_enforced_on_postgres(pg_gateway):
    from regista import RegistaError

    alice = _human("alice", "Alice")
    bob = _human("bob", "Bob")

    wi, _ = pg_gateway.create_issue(actor=alice, work_item_type="bug", custom_fields={"title": "gate test"})
    pg_gateway.transition(actor=bob, work_item_id=wi.work_item_id, transition_name="start")
    pg_gateway.transition(actor=bob, work_item_id=wi.work_item_id, transition_name="submit_for_review")
    with pytest.raises(RegistaError):
        pg_gateway.transition(actor=bob, work_item_id=wi.work_item_id, transition_name="accept")
    assert pg_gateway.get_issue(wi.work_item_id).current_state == "in_review"


def test_reopen_requires_review_again(pg_gateway):
    alice = _human("alice", "Alice")
    bob = _human("bob", "Bob")
    carol = _human("carol", "Carol")

    wi, _ = pg_gateway.create_issue(actor=alice, work_item_type="bug", custom_fields={"title": "reopen test"})
    pg_gateway.transition(actor=bob, work_item_id=wi.work_item_id, transition_name="start")
    pg_gateway.transition(actor=bob, work_item_id=wi.work_item_id, transition_name="submit_for_review")
    pg_gateway.transition(actor=carol, work_item_id=wi.work_item_id, transition_name="accept")
    assert pg_gateway.get_issue(wi.work_item_id).current_state == "done"

    pg_gateway.transition(actor=alice, work_item_id=wi.work_item_id, transition_name="reopen")
    assert pg_gateway.get_issue(wi.work_item_id).current_state == "open"
    pg_gateway.transition(actor=bob, work_item_id=wi.work_item_id, transition_name="start")
    pg_gateway.transition(actor=bob, work_item_id=wi.work_item_id, transition_name="submit_for_review")
    pg_gateway.transition(actor=carol, work_item_id=wi.work_item_id, transition_name="accept")
    assert pg_gateway.get_issue(wi.work_item_id).current_state == "done"
    assert pg_gateway.integrity().replayed_drift == 0
