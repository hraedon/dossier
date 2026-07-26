"""Tests for notification preferences and review/recovery deep links.

Covers Plan 018 WI-2.2 / GJ-7 (agent-suite WI-017): the per-principal
notification-preference surface, preference-respecting emission, and the
context-aware review/recovery deep links.

- The preference model and defaults (fail-open on unknown classes).
- The file-backed and in-memory stores (round-trip, corrupt-file safety).
- The emitter respecting a disabled class (no emission) and a missing store
  (back-compat: always emit).
- deep_link_for routing integrity failures to the recovery surface.
- The /me/notifications GET (renders the catalog) and POST (saves, CSRF,
  checkbox-absent = disabled).
- An end-to-end suppression: a disabled class produces no notification for a
  real transition.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import pytest
from conftest import extract_csrf as _extract_csrf
from conftest import login as _login
from fastapi.testclient import TestClient
from regista.testing import InMemoryRegista

from dossier.app import create_app
from dossier.auth.backends import LocalBackend
from dossier.config import Settings
from dossier.gateway import RegistaGateway
from dossier.keys import generate_keyset
from dossier.multi import GatewayRegistry
from dossier.notifications import (
    EVENT_CLASSES,
    FilePreferenceStore,
    MemoryPreferenceStore,
    NotificationEmitter,
    NotificationPreference,
    _preference_from_dict,
    default_preference,
)

_PROJECT = "dossier_test"
_PROJECT_SLUG = "dossier-test"
_ALICE_ID = "11111111-1111-1111-1111-111111111111"


def _hash_pw(pw: str) -> str:
    from dossier.auth.passwords import hash_password

    return hash_password(pw)


def _users_file(tmp_path: Path) -> Path:
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


def _settings(tmp_path: Path, **kwargs: Any) -> Settings:
    defaults: dict[str, Any] = dict(
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
        project_access_mode="open",
    )
    defaults.update(kwargs)
    return Settings(**defaults)


# ── Preference model and defaults ───────────────────────────────────────


def test_default_preference_enables_every_class_at_its_default_routing():
    pref = default_preference("human:alice")
    assert pref.principal_id == "human:alice"
    for ec in EVENT_CLASSES:
        assert pref.is_enabled(ec.event_type) is True
        assert pref.routing_for(ec.event_type) == ec.default_routing


def test_is_enabled_unknown_class_defaults_true():
    # A new class the catalog has not taught the UI about must not silently
    # disappear — fail-open on delivery.
    assert default_preference("p").is_enabled("some_future_event") is True


def test_routing_for_rejects_invalid_falls_back_to_default():
    pref = NotificationPreference(
        principal_id="p",
        enabled={},
        routing={"awaiting_your_accept": "carrier-pigeon"},
    )
    assert pref.routing_for("awaiting_your_accept") == "immediate"


def test_preference_from_dict_merges_new_classes_over_defaults():
    # A persisted record that predates a newly-added class: the new class
    # defaults on rather than vanishing.
    data = {"enabled": {"review_requested": False}, "routing": {}}
    pref = _preference_from_dict("p", data)
    assert pref.is_enabled("review_requested") is False
    for ec in EVENT_CLASSES:
        if ec.event_type != "review_requested":
            assert pref.is_enabled(ec.event_type) is True


def test_preference_from_dict_ignores_unknown_and_invalid_values():
    data = {
        "enabled": {"not_a_real_class": True, "awaiting_your_accept": False},
        "routing": {"item_returned": "tomorrow"},
    }
    pref = _preference_from_dict("p", data)
    assert pref.is_enabled("awaiting_your_accept") is False
    assert pref.routing_for("item_returned") == "immediate"


# ── FilePreferenceStore ─────────────────────────────────────────────────


def test_file_store_unknown_principal_returns_defaults(tmp_path):
    store = FilePreferenceStore(tmp_path / "prefs")
    pref = store.get("human:alice")
    assert pref.principal_id == "human:alice"
    for ec in EVENT_CLASSES:
        assert pref.is_enabled(ec.event_type) is True


def test_file_store_round_trip(tmp_path):
    store = FilePreferenceStore(tmp_path / "prefs")
    saved = NotificationPreference(
        principal_id="human:alice",
        enabled={"awaiting_your_accept": False},
        routing={"review_requested": "digest"},
    )
    store.save("human:alice", saved)
    # A fresh store instance reads the same file (no in-process cache).
    again = FilePreferenceStore(tmp_path / "prefs")
    pref = again.get("human:alice")
    assert pref.is_enabled("awaiting_your_accept") is False
    assert pref.is_enabled("review_requested") is True
    assert pref.routing_for("review_requested") == "digest"


def test_file_store_sanitizes_colon_principal_id(tmp_path):
    store = FilePreferenceStore(tmp_path / "prefs")
    store.save("human:alice", default_preference("human:alice"))
    # No path traversal / odd filename; the sanitized file exists.
    files = list((tmp_path / "prefs").glob("*.json"))
    assert len(files) == 1
    assert ":" not in files[0].name


def test_file_store_corrupt_file_returns_defaults(tmp_path):
    store = FilePreferenceStore(tmp_path / "prefs")
    path = tmp_path / "prefs" / "human_alice.json"
    path.write_text("{not valid json", encoding="utf-8")
    pref = store.get("human:alice")
    # A corrupt preference never blocks a notification.
    for ec in EVENT_CLASSES:
        assert pref.is_enabled(ec.event_type) is True


# ── MemoryPreferenceStore ───────────────────────────────────────────────


def test_memory_store_round_trip_and_defaults():
    store = MemoryPreferenceStore()
    assert store.get("nobody").is_enabled("awaiting_your_accept") is True
    store.save(
        "p",
        NotificationPreference(
            principal_id="p", enabled={"item_returned": False}, routing={}
        ),
    )
    assert store.get("p").is_enabled("item_returned") is False
    assert store.get("p").is_enabled("awaiting_your_accept") is True


# ── Emitter: preference-respecting emission ─────────────────────────────


def _emitter(store: MemoryPreferenceStore | None = None) -> NotificationEmitter:
    return NotificationEmitter(
        sink_url=None, base_url="http://localhost:8000", preference_store=store
    )


def test_emitter_no_store_emits_back_compat():
    # An emitter with no preference store behaves exactly as before.
    event = _emitter(None).emit_for_transition(
        transition_name="submit_for_review",
        to_state="in_review",
        project_slug=_PROJECT_SLUG,
        work_item_id=uuid.uuid4(),
        item_key="DOSSIER-1",
        item_title="t",
        assignee="alice",
        creator_id="alice",
        on_behalf_principal=None,
    )
    assert event is not None


def test_emitter_disabled_class_is_suppressed():
    store = MemoryPreferenceStore()
    store.save(
        "alice",
        NotificationPreference(
            principal_id="alice",
            enabled={"awaiting_your_accept": False},
            routing={},
        ),
    )
    event = _emitter(store).emit_for_transition(
        transition_name="submit_for_review",
        to_state="in_review",
        project_slug=_PROJECT_SLUG,
        work_item_id=uuid.uuid4(),
        item_key="DOSSIER-1",
        item_title="t",
        assignee="alice",
        creator_id=None,
        on_behalf_principal=None,
    )
    assert event is None


def test_emitter_enabled_class_emits():
    store = MemoryPreferenceStore()
    # Alice has the default (all enabled).
    event = _emitter(store).emit_for_transition(
        transition_name="submit_for_review",
        to_state="in_review",
        project_slug=_PROJECT_SLUG,
        work_item_id=uuid.uuid4(),
        item_key="DOSSIER-1",
        item_title="t",
        assignee="alice",
        creator_id=None,
        on_behalf_principal=None,
    )
    assert event is not None
    assert event.principal_id == "alice"


# ── Emitter: review/recovery deep links ─────────────────────────────────


def test_deep_link_for_review_event_targets_the_item():
    link = _emitter().deep_link_for(
        "awaiting_your_accept", _PROJECT_SLUG, "abc-123"
    )
    assert link == "http://localhost:8000/p/dossier-test/issues/abc-123"


def test_deep_link_for_integrity_failure_targets_recovery_surface():
    link = _emitter().deep_link_for("chain_verify_failed", _PROJECT_SLUG, "abc")
    assert link == "http://localhost:8000/evidence/integrity"


def test_emit_for_transition_uses_context_aware_deep_link():
    event = _emitter().emit_for_transition(
        transition_name="submit_for_review",
        to_state="in_review",
        project_slug=_PROJECT_SLUG,
        work_item_id=uuid.uuid4(),
        item_key="DOSSIER-1",
        item_title="t",
        assignee="alice",
        creator_id="alice",
        on_behalf_principal=None,
    )
    assert event is not None
    assert "/p/dossier-test/issues/" in event.deep_link


# ── /me/notifications route ─────────────────────────────────────────────


def _app(tmp_path, **kwargs):
    settings = _settings(tmp_path, **kwargs)
    key_path = tmp_path / "keys.json"
    generate_keyset(key_path)
    reg = InMemoryRegista(project=_PROJECT, hmac_key_path=str(key_path))
    gw = RegistaGateway(reg, project_name=_PROJECT)
    gw.register_workflow()
    InMemoryRegista._catalog.clear()
    registry = GatewayRegistry(known_projects=[_PROJECT])
    registry.add(_PROJECT, gw)
    backend = LocalBackend(_users_file(tmp_path))
    return create_app(settings, registry, backend)


@pytest.fixture
def prefs_client(tmp_path):
    app = _app(tmp_path)
    with TestClient(app) as c:
        yield c


def test_notifications_route_unauthenticated_redirects(prefs_client):
    resp = prefs_client.get("/me/notifications", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_notifications_route_renders_catalog(prefs_client):
    _login(prefs_client)
    resp = prefs_client.get("/me/notifications")
    assert resp.status_code == 200
    # Every event class label renders, including the recovery one.
    for ec in EVENT_CLASSES:
        assert ec.label in resp.text
    assert "integrity report" in resp.text.lower()


def test_notifications_route_shows_sink_not_configured(prefs_client):
    _login(prefs_client)
    resp = prefs_client.get("/me/notifications")
    assert "No notification sink is configured" in resp.text


def test_notifications_save_round_trips_through_the_form(prefs_client):
    _login(prefs_client)
    page = prefs_client.get("/me/notifications")
    csrf = _extract_csrf(page.text)

    # awaiting_your_accept unchecked (absent), routed digest; review_requested
    # checked, routed immediate.
    resp = prefs_client.post(
        "/me/notifications",
        data={
            "csrf_token": csrf,
            "review_requested_enabled": "on",
            "review_requested_routing": "immediate",
            "item_returned_enabled": "on",
            "item_returned_routing": "digest",
            "chain_verify_failed_enabled": "on",
            "chain_verify_failed_routing": "immediate",
            # awaiting_your_accept_* deliberately absent → disabled, default routing
            "awaiting_your_accept_routing": "digest",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/me/notifications"

    pref = prefs_client.app.state.preference_store.get(_ALICE_ID)
    assert pref.is_enabled("awaiting_your_accept") is False
    assert pref.is_enabled("review_requested") is True
    assert pref.routing_for("review_requested") == "immediate"
    assert pref.routing_for("item_returned") == "digest"


def test_notifications_save_requires_csrf(prefs_client):
    _login(prefs_client)
    resp = prefs_client.post(
        "/me/notifications",
        data={"awaiting_your_accept_enabled": "on"},
        follow_redirects=False,
    )
    assert resp.status_code != 303


# ── End-to-end: a disabled class suppresses a real transition notification


class _MockResponse:
    def __init__(self) -> None:
        self.body = b'{"ok": true}'

    def read(self) -> bytes:
        return self.body

    def __enter__(self) -> _MockResponse:
        return self

    def __exit__(self, *args: Any) -> None:
        pass


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


def test_disabled_class_suppresses_transition_notification(
    prefs_client, monkeypatch
):
    received: list[dict[str, Any]] = []

    def _mock_urlopen(req: Any, timeout: int = 5) -> _MockResponse:
        body = req.data.decode("utf-8") if req.data else ""
        received.append(json.loads(body))
        return _MockResponse()

    import dossier.notifications as _notif_mod

    monkeypatch.setattr(_notif_mod.urllib.request, "urlopen", _mock_urlopen)
    prefs_client.app.state.notifier._sink_url = "http://localhost:9999/ingest"

    _login(prefs_client)
    # Alice opts out of awaiting_your_accept.
    prefs_client.app.state.preference_store.save(
        _ALICE_ID,
        NotificationPreference(
            principal_id=_ALICE_ID,
            enabled={"awaiting_your_accept": False},
            routing={},
        ),
    )

    issue_url = _create_issue_via_ui(
        prefs_client, _PROJECT_SLUG, "Suppressed", assignee=_ALICE_ID
    )
    _transition_via_ui(prefs_client, issue_url, "start")
    _transition_via_ui(prefs_client, issue_url, "submit_for_review")

    await_accept = [
        e for e in received if e.get("event_type") == "awaiting_your_accept"
    ]
    assert await_accept == [], "disabled class must not be delivered"

    # Re-enabling emits on the next transition.
    prefs_client.app.state.preference_store.save(
        _ALICE_ID, default_preference(_ALICE_ID)
    )
    received.clear()
    issue_url2 = _create_issue_via_ui(
        prefs_client, _PROJECT_SLUG, "Emitted", assignee=_ALICE_ID
    )
    _transition_via_ui(prefs_client, issue_url2, "start")
    _transition_via_ui(prefs_client, issue_url2, "submit_for_review")
    await_accept = [
        e for e in received if e.get("event_type") == "awaiting_your_accept"
    ]
    assert len(await_accept) >= 1
    prefs_client.app.state.notifier._sink_url = ""
