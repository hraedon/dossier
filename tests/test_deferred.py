from __future__ import annotations

import pytest
from regista import RegistaError

from conftest import extract_csrf as _extract_csrf, login as _login
from helpers import ALICE, BOB

# --------------------------------------------------------------------------- #
# Gateway-level: defer / resume / start cycle + invariants
# --------------------------------------------------------------------------- #


def test_defer_from_open_reaches_deferred(gateway, make_issue):
    wi = make_issue(actor=ALICE)
    gateway.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="defer")
    assert gateway.get_issue(wi.work_item_id).current_state == "deferred"


def test_defer_from_in_progress_reaches_deferred(gateway, make_issue):
    wi = make_issue(actor=ALICE)
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="start")
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="defer")
    assert gateway.get_issue(wi.work_item_id).current_state == "deferred"


def test_resume_from_deferred_back_to_open(gateway, make_issue):
    wi = make_issue(actor=ALICE)
    gateway.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="defer")
    gateway.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="resume")
    assert gateway.get_issue(wi.work_item_id).current_state == "open"


def test_start_from_deferred_to_in_progress(gateway, make_issue):
    wi = make_issue(actor=ALICE)
    gateway.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="defer")
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="start")
    assert gateway.get_issue(wi.work_item_id).current_state == "in_progress"


def test_deferred_cannot_reach_done_directly(gateway, make_issue):
    """A deferred item must re-enter the active flow and pass the review gate
    like any other — it cannot jump to done (Plan 008 §2)."""
    wi = make_issue(actor=ALICE)
    gateway.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="defer")
    with pytest.raises(RegistaError):
        gateway.transition(
            actor=ALICE, work_item_id=wi.work_item_id, transition_name="close_from_open"
        )
    assert gateway.get_issue(wi.work_item_id).current_state == "deferred"


def test_deferred_to_done_via_full_gate(gateway, make_issue):
    """A deferred item that resumes → starts → submits → passes review → accepted
    reaches done. The deferred detour does not break the canonical flow."""
    from helpers import CAROL, DAVE

    wi = make_issue(actor=ALICE)
    gateway.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="defer")
    gateway.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="resume")
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="start")
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


def test_deferred_history_records_transitions(gateway, make_issue):
    wi = make_issue(actor=ALICE)
    gateway.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="defer")
    gateway.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="resume")
    events = gateway.history(wi.work_item_id)
    transitions = [e.transition for e in events]
    assert transitions == ["created", "defer", "resume"]


def test_deferred_listable_by_state(gateway, make_issue):
    wi = make_issue(actor=ALICE)
    make_issue(actor=ALICE)
    gateway.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="defer")
    deferred = gateway.list_issues(current_states=["deferred"])
    assert len(deferred.items) == 1
    assert deferred.items[0].work_item_id == wi.work_item_id


def test_transitions_from_deferred_surfaces_resume_and_start(gateway, make_issue):
    """web.py derives transitions from the registered workflow; a deferred item
    should offer `resume` and `start` (and only those)."""
    from dossier.web import transition_tuple

    wi = make_issue(actor=ALICE)
    gateway.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="defer")
    tdefs = gateway.transitions_from("deferred", wi.workflow_version)
    names = {transition_tuple(t)[0] for t in tdefs}
    assert names == {"resume", "start"}


def test_transitions_from_open_includes_defer(gateway, make_issue):
    """The `defer` transition should be available from `open`."""
    from dossier.web import transition_tuple

    wi = make_issue(actor=ALICE)
    tdefs = gateway.transitions_from("open", wi.workflow_version)
    names = {transition_tuple(t)[0] for t in tdefs}
    assert "defer" in names
    assert "start" in names
    assert "close_from_open" in names


def test_transitions_from_in_progress_includes_defer(gateway, make_issue):
    """The `defer` transition should be available from `in_progress`."""
    from dossier.web import transition_tuple

    wi = make_issue(actor=ALICE)
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="start")
    tdefs = gateway.transitions_from("in_progress", wi.workflow_version)
    names = {transition_tuple(t)[0] for t in tdefs}
    assert "defer" in names


# --------------------------------------------------------------------------- #
# UI rendering
# --------------------------------------------------------------------------- #


def test_deferred_renders_on_board(client, gateway):
    _login(client)
    new_page = client.get("/issues/new")
    csrf = _extract_csrf(new_page.text)
    resp = client.post(
        "/issues",
        data={"type": "bug", "title": "Deferred item", "csrf_token": csrf},
        follow_redirects=False,
    )
    issue_url = resp.headers["location"]
    import uuid

    wi_id = uuid.UUID(issue_url.split("/")[-1])
    gateway.transition(actor=ALICE, work_item_id=wi_id, transition_name="defer")

    index = client.get("/?status=deferred")
    assert "Deferred item" in index.text
    assert "deferred" in index.text


def test_deferred_detail_page_shows_resume_and_start(client, gateway):
    _login(client)
    new_page = client.get("/issues/new")
    csrf = _extract_csrf(new_page.text)
    resp = client.post(
        "/issues",
        data={"type": "bug", "title": "Deferred detail", "csrf_token": csrf},
        follow_redirects=False,
    )
    issue_url = resp.headers["location"]
    import uuid

    wi_id = uuid.UUID(issue_url.split("/")[-1])
    gateway.transition(actor=ALICE, work_item_id=wi_id, transition_name="defer")

    detail = client.get(issue_url)
    assert "Resume" in detail.text
    assert "Start work" in detail.text


def test_deferred_history_renders_defer_and_resume(client, gateway):
    _login(client)
    new_page = client.get("/issues/new")
    csrf = _extract_csrf(new_page.text)
    resp = client.post(
        "/issues",
        data={"type": "bug", "title": "Deferred history", "csrf_token": csrf},
        follow_redirects=False,
    )
    issue_url = resp.headers["location"]
    import uuid

    wi_id = uuid.UUID(issue_url.split("/")[-1])
    gateway.transition(actor=ALICE, work_item_id=wi_id, transition_name="defer")
    gateway.transition(actor=ALICE, work_item_id=wi_id, transition_name="resume")

    detail = client.get(issue_url)
    assert "deferred" in detail.text.lower()
    assert "resumed" in detail.text.lower()


def test_deferred_status_filter_option_present(client):
    _login(client)
    index = client.get("/")
    assert 'value="deferred"' in index.text
    assert ">deferred<" in index.text


# --------------------------------------------------------------------------- #
# Negative: invalid transitions to/from deferred
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "transition_name, setup_state",
    [
        ("defer", "blocked"),
        ("defer", "in_review"),
        ("defer", "in_human_review"),
        ("defer", "done"),
        ("resume", "open"),
        ("resume", "in_progress"),
        ("resume", "blocked"),
        ("resume", "in_review"),
        ("resume", "done"),
        ("start", "blocked"),
        ("start", "in_review"),
        ("start", "done"),
    ],
)
def test_invalid_deferred_transition_rejected(gateway, make_issue, transition_name, setup_state):
    """Transitions to/from `deferred` are only valid from the declared states."""
    wi = make_issue(actor=ALICE)
    if setup_state == "in_progress":
        gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="start")
    elif setup_state == "blocked":
        gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="start")
        gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="block")
    elif setup_state == "deferred":
        gateway.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="defer")
    elif setup_state == "in_review":
        gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="start")
        gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="submit_for_review")
    elif setup_state == "in_human_review":
        from helpers import AGENT_GLM, AGENT_KIMI

        gateway.transition(actor=AGENT_GLM, work_item_id=wi.work_item_id, transition_name="start")
        gateway.transition(actor=AGENT_GLM, work_item_id=wi.work_item_id, transition_name="submit_for_review")
        gateway.transition(
            actor=AGENT_KIMI, work_item_id=wi.work_item_id,
            transition_name="adversarial_pass", payload={"review_note": "pass"},
        )
    elif setup_state == "done":
        gateway.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="close_from_open")

    with pytest.raises(RegistaError):
        gateway.transition(
            actor=ALICE, work_item_id=wi.work_item_id, transition_name=transition_name
        )


def test_defer_from_already_deferred_rejected(gateway, make_issue):
    """Deferring an already-deferred item is a no-op that regista rejects."""
    wi = make_issue(actor=ALICE)
    gateway.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="defer")
    with pytest.raises(RegistaError):
        gateway.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="defer")


def test_defer_makes_actor_an_author_for_review(gateway, make_issue):
    """An actor who defers an item becomes an author; they cannot then
    adversarial-review it (separation of duties)."""
    wi = make_issue(actor=ALICE)
    gateway.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="defer")
    gateway.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="resume")
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="start")
    gateway.transition(actor=BOB, work_item_id=wi.work_item_id, transition_name="submit_for_review")
    with pytest.raises(RegistaError):
        gateway.transition(
            actor=ALICE, work_item_id=wi.work_item_id,
            transition_name="adversarial_pass", payload={"review_note": "pass"},
        )
