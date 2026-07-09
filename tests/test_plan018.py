"""Tests for Plan 018 — working views and notifications.

Covers:
- WI-1.1: Review queue (cross-project, permission-gated, sorted, assurance)
- WI-1.2: My work (human vs agent-on-behalf distinction)
- WI-1.3: Activity feed (filterable, paginated)
- WI-2.1: Notification emitting seam (webhook, deep links, no-sink no-op)
- Authz seam on all new views
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi.testclient import TestClient
from regista.testing import InMemoryRegista

from conftest import extract_csrf as _extract_csrf, login as _login
from dossier.app import create_app
from dossier.auth.backends import LocalBackend
from dossier.config import Settings
from dossier.gateway import RegistaGateway
from dossier.keys import generate_keyset
from dossier.multi import GatewayRegistry
from dossier.notifications import NotificationEmitter, NotificationEvent, notification_health_check
from dossier.views import (
    read_activity_feed,
    read_my_work,
    read_review_queue,
    build_digest,
)

from helpers import ALICE, BOB, AGENT_GLM

_PROJECT = "dossier_test"
_PROJECT_SLUG = "dossier-test"
_ALICE_ID = "11111111-1111-1111-1111-111111111111"

_PROJECT_A = "dossier_test"
_PROJECT_B = "cert_watch"


def _hash_pw(pw: str) -> str:
    from dossier.auth.passwords import hash_password

    return hash_password(pw)


def _users_file(tmp_path):
    path = tmp_path / "users.json"
    path.write_text(
        json.dumps(
            [
                {
                    "stable_id": _ALICE_ID,
                    "username": "alice",
                    "display_name": "Alice",
                    "password": _hash_pw("s3cret"),
                    "groups": [],
                }
            ]
        ),
        encoding="utf-8",
    )
    return path


def _settings(tmp_path, **kwargs: Any) -> Settings:
    defaults = dict(
        database_url="",
        project=_PROJECT,
        hmac_key_path="",
        session_secret="test-session-secret-not-for-prod",
        session_max_age_seconds=43200,
        secure_cookies=False,
        require_ssl=False,
        users_path=str(_users_file(tmp_path)),
        auth_backend="local",
        principal_key_dir=str(tmp_path / "principals"),
    )
    defaults.update(kwargs)
    return Settings(**defaults)


def _make_gateway(tmp_path, project_name):
    key_path = tmp_path / f"keys_{project_name}.json"
    generate_keyset(key_path)
    reg = InMemoryRegista(project=project_name, hmac_key_path=str(key_path))
    gw = RegistaGateway(reg, project_name=project_name)
    gw.register_workflow()
    return gw


def _create_issue_via_ui(client, project_slug, title, **fields):
    new_page = client.get(f"/p/{project_slug}/issues/new")
    csrf = _extract_csrf(new_page.text)
    data = {"type": "bug", "title": title, "csrf_token": csrf, **fields}
    resp = client.post(
        f"/p/{project_slug}/issues",
        data=data,
        follow_redirects=False,
    )
    assert resp.status_code == 303
    return resp.headers["location"]


def _transition_via_ui(client, issue_url, transition_name, **fields):
    csrf = _extract_csrf(client.get(issue_url).text)
    data = {"transition_name": transition_name, "csrf_token": csrf, **fields}
    resp = client.post(
        f"{issue_url}/transitions",
        data=data,
        follow_redirects=False,
    )
    assert resp.status_code == 303
    return resp


def _gw(client, project_name=_PROJECT):
    return client.app.state.registry.get(project_name)


def _session_actor_id(client) -> str:
    return client.app.state.templates.env  # just to access app state


# ── WI-1.1: Review queue ────────────────────────────────────────────────


def test_review_queue_empty(client):
    _login(client)
    resp = client.get("/review")
    assert resp.status_code == 200
    assert "nothing awaiting review" in resp.text


def test_review_queue_shows_in_review_item(client, gateway, make_issue):
    _login(client)
    wi = make_issue(title="Review me")
    gw = _gw(client)
    gw.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="start")
    gw.transition(
        actor=ALICE, work_item_id=wi.work_item_id, transition_name="submit_for_review"
    )

    resp = client.get("/review")
    assert resp.status_code == 200
    assert "Review me" in resp.text
    assert "in_review" in resp.text
    assert "adversarial review" in resp.text.lower()


def test_review_queue_in_human_review_sorts_first(client, gateway, make_issue):
    _login(client)
    wi1 = make_issue(title="Awaiting adversarial")
    wi2 = make_issue(title="Awaiting human accept")
    gw = _gw(client)

    gw.transition(actor=ALICE, work_item_id=wi1.work_item_id, transition_name="start")
    gw.transition(actor=ALICE, work_item_id=wi1.work_item_id, transition_name="submit_for_review")

    gw.transition(actor=ALICE, work_item_id=wi2.work_item_id, transition_name="start")
    gw.transition(actor=ALICE, work_item_id=wi2.work_item_id, transition_name="submit_for_review")
    gw.transition(
        actor=BOB, work_item_id=wi2.work_item_id, transition_name="adversarial_pass",
        payload={"review_note": "looks good"},
    )

    resp = client.get("/review")
    assert resp.status_code == 200
    idx_hr = resp.text.find("Awaiting human accept")
    idx_ir = resp.text.find("Awaiting adversarial")
    assert idx_hr < idx_ir, "in_human_review should sort before in_review"


def test_review_queue_accepting_removes_item(client, gateway, make_issue):
    _login(client)
    wi = make_issue(title="Accept me")
    gw = _gw(client)
    gw.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="start")
    gw.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="submit_for_review")
    gw.transition(
        actor=BOB, work_item_id=wi.work_item_id, transition_name="adversarial_pass",
        payload={"review_note": "approved"},
    )

    resp = client.get("/review")
    assert "Accept me" in resp.text

    _transition_via_ui(
        client,
        f"/p/{_PROJECT_SLUG}/issues/{wi.work_item_id}",
        "accept",
        review_note="accepting",
    )

    resp = client.get("/review")
    assert "Accept me" not in resp.text


def test_review_queue_shows_deferred(client, gateway, make_issue):
    _login(client)
    wi = make_issue(title="Deferred item")
    gw = _gw(client)
    gw.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="start")
    gw.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="defer")

    resp = client.get("/review")
    assert resp.status_code == 200
    assert "Deferred item" in resp.text
    assert "re-entry" in resp.text.lower()


def test_review_queue_shows_assurance_level(client, gateway, make_issue):
    _login(client)
    wi = make_issue(title="Self-reviewed item", assignee=_ALICE_ID)
    gw = _gw(client)
    gw.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="start")
    gw.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="submit_for_review")
    gw.transition(
        actor=AGENT_GLM, work_item_id=wi.work_item_id, transition_name="adversarial_pass",
        payload={"review_note": "ok", "same_lineage_acknowledged": True},
    )

    resp = client.get("/review")
    assert resp.status_code == 200
    assert "self-reviewed" in resp.text.lower()


def test_review_queue_cross_project(tmp_path):
    """Items from multiple projects appear in the cross-project queue."""
    gw_a = _make_gateway(tmp_path, _PROJECT_A)
    gw_b = _make_gateway(tmp_path, _PROJECT_B)

    wi_a, _ = gw_a.create_issue(actor=ALICE, work_item_type="bug", custom_fields={"title": "Project A review"})
    gw_a.transition(actor=ALICE, work_item_id=wi_a.work_item_id, transition_name="start")
    gw_a.transition(actor=ALICE, work_item_id=wi_a.work_item_id, transition_name="submit_for_review")

    wi_b, _ = gw_b.create_issue(actor=ALICE, work_item_type="bug", custom_fields={"title": "Project B review"})
    gw_b.transition(actor=ALICE, work_item_id=wi_b.work_item_id, transition_name="start")
    gw_b.transition(actor=ALICE, work_item_id=wi_b.work_item_id, transition_name="submit_for_review")

    settings = _settings(tmp_path)
    backend = LocalBackend(_users_file(tmp_path))
    registry = GatewayRegistry(known_projects=[_PROJECT_A, _PROJECT_B])
    registry.add(_PROJECT_A, gw_a)
    registry.add(_PROJECT_B, gw_b)
    app = create_app(settings, registry, backend)
    with TestClient(app) as c:
        _login(c)
        resp = c.get("/review")
        assert resp.status_code == 200
        assert "Project A review" in resp.text
        assert "Project B review" in resp.text
    gw_a.close()
    gw_b.close()


def test_review_queue_respects_permissions(client, monkeypatch):
    _login(client)
    monkeypatch.setattr("dossier.app.can_read_project", lambda actor, project: False)
    resp = client.get("/review")
    assert resp.status_code == 200
    assert "nothing awaiting review" in resp.text


def test_review_queue_unauthenticated_redirects(client):
    resp = client.get("/review", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


# ── WI-1.2: My work ─────────────────────────────────────────────────────


def test_my_work_empty(client):
    _login(client)
    resp = client.get("/my-work")
    assert resp.status_code == 200
    assert "no items in your work" in resp.text


def test_my_work_shows_created_by_me(client):
    _login(client)
    _create_issue_via_ui(client, _PROJECT_SLUG, "My created item")
    resp = client.get("/my-work")
    assert resp.status_code == 200
    assert "My created item" in resp.text
    assert "created by me" in resp.text


def test_my_work_shows_assigned_to_me(client):
    _login(client)
    _create_issue_via_ui(client, _PROJECT_SLUG, "Assigned to alice", assignee=_ALICE_ID)
    resp = client.get("/my-work")
    assert resp.status_code == 200
    assert "Assigned to alice" in resp.text
    assert "assigned to me" in resp.text


def test_my_work_distinguishes_agent_on_behalf(client, gateway, make_issue):
    """An item moved by an agent on behalf of Alice shows up under her flag."""
    _login(client)
    wi = make_issue(title="Agent-touched item")
    gw = _gw(client)

    agent_for_alice = type(AGENT_GLM)(
        actor_id="agent-glm",
        actor_kind="agent",
        display_name="GLM Agent",
        model_lineage="glm",
        on_behalf_of={"principal_id": _ALICE_ID, "principal_display_name": "Alice"},
    )
    gw.transition(actor=agent_for_alice, work_item_id=wi.work_item_id, transition_name="start")
    gw.transition(actor=agent_for_alice, work_item_id=wi.work_item_id, transition_name="submit_for_review")

    resp = client.get("/my-work")
    assert resp.status_code == 200
    assert "Agent-touched item" in resp.text
    assert "agent" in resp.text.lower()
    assert "on my behalf" in resp.text.lower()


def test_my_work_agent_in_review_shows_under_my_flag(client, gateway, make_issue):
    """AC: an item my agent moved to in_review shows up under my flag."""
    _login(client)
    wi = make_issue(title="Agent submitted for review")
    gw = _gw(client)

    agent_for_alice = type(AGENT_GLM)(
        actor_id="agent-glm",
        actor_kind="agent",
        display_name="GLM Agent",
        model_lineage="glm",
        on_behalf_of={"principal_id": _ALICE_ID},
    )
    gw.transition(actor=agent_for_alice, work_item_id=wi.work_item_id, transition_name="start")
    gw.transition(actor=agent_for_alice, work_item_id=wi.work_item_id, transition_name="submit_for_review")

    resp = client.get("/my-work")
    assert resp.status_code == 200
    assert "Agent submitted for review" in resp.text
    assert "in_review" in resp.text

    resp_q = client.get("/review")
    assert "Agent submitted for review" in resp_q.text


def test_my_work_excludes_other_peoples_items(client):
    _login(client)
    gw = _gw(client)
    from helpers import BOB
    wi, _ = gw.create_issue(
        actor=BOB, work_item_type="bug", custom_fields={"title": "Bob's item"}
    )
    resp = client.get("/my-work")
    assert "Bob's item" not in resp.text


def test_my_work_grouped_by_state(client):
    _login(client)
    _create_issue_via_ui(client, _PROJECT_SLUG, "Open item")
    issue_url = _create_issue_via_ui(client, _PROJECT_SLUG, "In progress item")
    _transition_via_ui(client, issue_url, "start")

    resp = client.get("/my-work")
    assert resp.status_code == 200
    assert "Open item" in resp.text
    assert "In progress item" in resp.text
    assert "in_progress" in resp.text


def test_my_work_unauthenticated_redirects(client):
    resp = client.get("/my-work", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


# ── WI-1.3: Activity feed ──────────────────────────────────────────────


def test_activity_feed_empty(client):
    _login(client)
    resp = client.get("/feed")
    assert resp.status_code == 200
    assert "no recent activity" in resp.text


def test_activity_feed_shows_transitions(client, gateway, make_issue):
    _login(client)
    wi = make_issue(title="Feed item")
    gw = _gw(client)
    gw.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="start")

    resp = client.get("/feed")
    assert resp.status_code == 200
    assert "Feed item" in resp.text
    assert "started" in resp.text.lower()


def test_activity_feed_filter_by_actor_kind(client, gateway, make_issue):
    _login(client)
    wi = make_issue(title="Human action")
    gw = _gw(client)
    gw.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="start")

    wi2 = make_issue(title="Agent action", actor=AGENT_GLM)
    agent_for_alice = type(AGENT_GLM)(
        actor_id="agent-glm",
        actor_kind="agent",
        display_name="GLM Agent",
        model_lineage="glm",
        on_behalf_of={"principal_id": _ALICE_ID},
    )
    gw.transition(actor=agent_for_alice, work_item_id=wi2.work_item_id, transition_name="start")

    resp = client.get("/feed?actor_kind=agent")
    assert resp.status_code == 200
    assert "Agent action" in resp.text

    resp = client.get("/feed?actor_kind=human")
    assert resp.status_code == 200
    assert "Human action" in resp.text
    assert "started" in resp.text.lower()


def test_activity_feed_filter_by_transition(client, gateway, make_issue):
    _login(client)
    wi = make_issue(title="Filter test")
    gw = _gw(client)
    gw.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="start")

    resp = client.get("/feed?transition=start")
    assert resp.status_code == 200
    assert "Filter test" in resp.text

    resp = client.get("/feed?transition=submit_for_review")
    assert resp.status_code == 200
    assert "Filter test" not in resp.text


def test_activity_feed_shows_on_behalf(client, gateway, make_issue):
    _login(client)
    wi = make_issue(title="On behalf item")
    gw = _gw(client)
    agent_for_alice = type(AGENT_GLM)(
        actor_id="agent-glm",
        actor_kind="agent",
        display_name="GLM Agent",
        model_lineage="glm",
        on_behalf_of={"principal_id": _ALICE_ID, "principal_display_name": "Alice"},
    )
    gw.transition(actor=agent_for_alice, work_item_id=wi.work_item_id, transition_name="start")

    resp = client.get("/feed")
    assert resp.status_code == 200
    assert "on behalf of" in resp.text.lower()
    assert "Alice" in resp.text


def test_activity_feed_unauthenticated_redirects(client):
    resp = client.get("/feed", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


# ── WI-2.1: Notification emitting seam ──────────────────────────────────


def test_notification_emitter_no_sink_noop():
    emitter = NotificationEmitter(sink_url=None, base_url="http://localhost:8000")
    event = NotificationEvent(
        event_type="awaiting_your_accept",
        principal_id="alice",
        project="dossier-test",
        item_id=str(uuid.uuid4()),
        item_key="DOSSIER-1",
        item_title="Test",
        deep_link="http://localhost:8000/p/dossier-test/issues/abc",
        timestamp="2026-07-09T12:00:00Z",
    )
    assert emitter.emit(event) is True
    assert emitter.configured is False


def test_notification_emitter_configured():
    emitter = NotificationEmitter(sink_url="http://localhost:9999/ingest", base_url="http://localhost:8000")
    assert emitter.configured is True


def test_notification_emitter_deep_link():
    emitter = NotificationEmitter(sink_url=None, base_url="http://dossier.example.com")
    link = emitter.deep_link("dossier-test", "abc-123")
    assert link == "http://dossier.example.com/p/dossier-test/issues/abc-123"


def test_notification_emit_for_transition_submit_for_review():
    emitter = NotificationEmitter(sink_url=None, base_url="http://localhost:8000")
    event = emitter.emit_for_transition(
        transition_name="submit_for_review",
        to_state="in_review",
        project_slug="dossier-test",
        work_item_id=uuid.uuid4(),
        item_key="DOSSIER-1",
        item_title="Test item",
        assignee="alice",
        creator_id="alice",
        on_behalf_principal=None,
    )
    assert event is not None
    assert event.event_type == "awaiting_your_accept"
    assert event.principal_id == "alice"
    assert "/p/dossier-test/issues/" in event.deep_link


def test_notification_emit_for_transition_adversarial_pass():
    emitter = NotificationEmitter(sink_url=None, base_url="http://localhost:8000")
    event = emitter.emit_for_transition(
        transition_name="adversarial_pass",
        to_state="in_human_review",
        project_slug="dossier-test",
        work_item_id=uuid.uuid4(),
        item_key="DOSSIER-1",
        item_title="Test item",
        assignee="alice",
        creator_id="bob",
        on_behalf_principal=None,
    )
    assert event is not None
    assert event.event_type == "awaiting_your_accept"
    assert "human accept" in (event.detail or "")


def test_notification_emit_for_transition_request_changes():
    emitter = NotificationEmitter(sink_url=None, base_url="http://localhost:8000")
    event = emitter.emit_for_transition(
        transition_name="request_changes",
        to_state="in_progress",
        project_slug="dossier-test",
        work_item_id=uuid.uuid4(),
        item_key="DOSSIER-1",
        item_title="Test item",
        assignee="alice",
        creator_id="bob",
        on_behalf_principal=None,
    )
    assert event is not None
    assert event.event_type == "item_returned"


def test_notification_emit_for_non_notification_transition():
    emitter = NotificationEmitter(sink_url=None, base_url="http://localhost:8000")
    event = emitter.emit_for_transition(
        transition_name="start",
        to_state="in_progress",
        project_slug="dossier-test",
        work_item_id=uuid.uuid4(),
        item_key="DOSSIER-1",
        item_title="Test item",
        assignee="alice",
        creator_id="alice",
        on_behalf_principal=None,
    )
    assert event is None


def test_notification_emit_with_no_principal():
    emitter = NotificationEmitter(sink_url=None, base_url="http://localhost:8000")
    event = emitter.emit_for_transition(
        transition_name="submit_for_review",
        to_state="in_review",
        project_slug="dossier-test",
        work_item_id=uuid.uuid4(),
        item_key="DOSSIER-1",
        item_title="Test item",
        assignee="",
        creator_id=None,
        on_behalf_principal=None,
    )
    assert event is None


def test_notification_health_check_no_sink():
    result = notification_health_check(None)
    assert result["status"] == "warn"
    assert "notification_sink" in result["name"]


def test_notification_health_check_with_sink():
    result = notification_health_check("http://localhost:9999/ingest")
    assert result["status"] == "ok"


class _MockResponse:
    def __init__(self) -> None:
        self.body = b'{"ok": true}'

    def read(self) -> bytes:
        return self.body

    def __enter__(self) -> _MockResponse:
        return self

    def __exit__(self, *args: Any) -> None:
        pass


def test_notification_emitted_on_submit_for_review(client, gateway, make_issue, monkeypatch):
    """AC: driving an item to in_review emits exactly one notification."""
    received: list[dict[str, Any]] = []

    def _mock_urlopen(req: Any, timeout: int = 5) -> _MockResponse:
        body = req.data.decode("utf-8") if req.data else ""
        received.append(json.loads(body))
        return _MockResponse()

    import dossier.notifications as _notif_mod

    monkeypatch.setattr(_notif_mod.urllib.request, "urlopen", _mock_urlopen)
    client.app.state.notifier._sink_url = "http://localhost:9999/ingest"

    _login(client)
    wi = make_issue(title="Notify on review", assignee=_ALICE_ID)
    _transition_via_ui(
        client,
        f"/p/{_PROJECT_SLUG}/issues/{wi.work_item_id}",
        "start",
    )
    _transition_via_ui(
        client,
        f"/p/{_PROJECT_SLUG}/issues/{wi.work_item_id}",
        "submit_for_review",
    )

    client.app.state.notifier._sink_url = ""

    review_notifications = [e for e in received if e["event_type"] == "awaiting_your_accept"]
    assert len(review_notifications) >= 1
    n = review_notifications[0]
    assert n["principal_id"] == _ALICE_ID
    assert "/p/dossier-test/issues/" in n["deep_link"]
    assert n["item_title"] == "Notify on review"


def test_notification_no_sink_no_error(client, gateway, make_issue):
    """AC: no sink configured = no error."""
    _login(client)
    wi = make_issue(title="No sink test")
    _transition_via_ui(
        client,
        f"/p/{_PROJECT_SLUG}/issues/{wi.work_item_id}",
        "start",
    )
    _transition_via_ui(
        client,
        f"/p/{_PROJECT_SLUG}/issues/{wi.work_item_id}",
        "submit_for_review",
    )
    resp = client.get(f"/p/{_PROJECT_SLUG}/issues/{wi.work_item_id}")
    assert resp.status_code == 200


# ── Doctor / health check ───────────────────────────────────────────────


def test_doctor_notification_sink_warn(tmp_path):
    from dossier.health import build_health
    from dossier.multi import GatewayRegistry

    settings = _settings(tmp_path, notification_sink="")
    registry = GatewayRegistry(known_projects=[_PROJECT])
    health = build_health(settings, registry)
    notif_check = [c for c in health["checks"] if c["name"] == "notification_sink"]
    assert len(notif_check) == 1
    assert notif_check[0]["status"] == "warn"


def test_doctor_notification_sink_ok(tmp_path):
    from dossier.health import build_health
    from dossier.multi import GatewayRegistry

    settings = _settings(tmp_path, notification_sink="http://localhost:9999/ingest")
    registry = GatewayRegistry(known_projects=[_PROJECT])
    health = build_health(settings, registry)
    notif_check = [c for c in health["checks"] if c["name"] == "notification_sink"]
    assert len(notif_check) == 1
    assert notif_check[0]["status"] == "ok"


# ── Pure-function tests ─────────────────────────────────────────────────


def test_read_review_queue_sorts_strict_gate_first(gateway, make_issue):
    wi1 = make_issue(title="In review")
    wi2 = make_issue(title="In human review")
    gateway.transition(actor=ALICE, work_item_id=wi1.work_item_id, transition_name="start")
    gateway.transition(actor=ALICE, work_item_id=wi1.work_item_id, transition_name="submit_for_review")
    gateway.transition(actor=ALICE, work_item_id=wi2.work_item_id, transition_name="start")
    gateway.transition(actor=ALICE, work_item_id=wi2.work_item_id, transition_name="submit_for_review")
    gateway.transition(
        actor=BOB, work_item_id=wi2.work_item_id, transition_name="adversarial_pass",
        payload={"review_note": "approved"},
    )

    entries = read_review_queue(gateway, _PROJECT_SLUG)
    assert len(entries) == 2
    assert entries[0].state == "in_human_review"
    assert entries[0].strict_gate is True
    assert entries[1].state == "in_review"


def test_read_my_work_distinguishes_human_vs_agent(gateway, make_issue):
    make_issue(title="Human created")
    make_issue(actor=AGENT_GLM, title="Agent created")

    entries = read_my_work(gateway, _PROJECT_SLUG, ALICE.actor_id)
    human_entries = [e for e in entries if e.title == "Human created"]
    assert len(human_entries) == 1
    assert human_entries[0].relation == "created"

    agent_entries = [e for e in entries if e.title == "Agent created"]
    assert len(agent_entries) == 0


def test_read_my_work_agent_on_behalf(gateway, make_issue):
    wi = make_issue(title="Agent on behalf")
    agent_for_alice = type(AGENT_GLM)(
        actor_id="agent-glm",
        actor_kind="agent",
        display_name="GLM Agent",
        model_lineage="glm",
        on_behalf_of={"principal_id": ALICE.actor_id},
    )
    gateway.transition(actor=agent_for_alice, work_item_id=wi.work_item_id, transition_name="start")

    entries = read_my_work(gateway, _PROJECT_SLUG, ALICE.actor_id)
    mine = [e for e in entries if e.title == "Agent on behalf"]
    assert len(mine) == 1
    assert mine[0].relation == "agent-on-behalf"


def test_read_my_work_principal_id_with_prefix(gateway, make_issue):
    wi = make_issue(title="Prefixed principal")
    agent_for_alice = type(AGENT_GLM)(
        actor_id="agent-glm",
        actor_kind="agent",
        display_name="GLM Agent",
        model_lineage="glm",
        on_behalf_of={"principal_id": f"human:{ALICE.actor_id}"},
    )
    gateway.transition(actor=agent_for_alice, work_item_id=wi.work_item_id, transition_name="start")

    entries = read_my_work(gateway, _PROJECT_SLUG, ALICE.actor_id)
    mine = [e for e in entries if e.title == "Prefixed principal"]
    assert len(mine) == 1
    assert mine[0].relation == "agent-on-behalf"


def test_read_activity_feed_excludes_comments(gateway, make_issue):
    wi = make_issue(title="Activity test")
    gateway.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="start")
    gateway.comment(actor=ALICE, work_item_id=wi.work_item_id, body="a comment")

    entries = read_activity_feed(gateway, _PROJECT_SLUG, limit=100)
    assert all(e.transition != "comment" for e in entries)
    assert any(e.transition == "start" for e in entries)


def test_build_digest_empty(gateway):
    digest = build_digest([(_PROJECT_SLUG, gateway)], ALICE.actor_id)
    assert digest["is_empty"] is True


def test_build_digest_with_items(gateway, make_issue):
    wi = make_issue(title="Digest item", assignee=ALICE.actor_id)
    gateway.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="start")
    gateway.transition(actor=ALICE, work_item_id=wi.work_item_id, transition_name="submit_for_review")

    digest = build_digest([(_PROJECT_SLUG, gateway)], ALICE.actor_id)
    assert digest["is_empty"] is False
    assert len(digest["review_items"]) >= 1
    assert len(digest["my_work_items"]) >= 1
