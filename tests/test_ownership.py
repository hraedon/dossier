"""Tests for Plan 012 WI-4 — project ownership surfacing in the UI.

Covers:
- Landing page shows owner column ("unassigned" when no owner)
- Project index shows current owner + set-owner form
- POST to /p/{project}/owner updates the catalog entry
- The owner is persisted across requests
"""

from __future__ import annotations

import pytest

from conftest import extract_csrf as _extract_csrf, login as _login

_ALICE_ID = "11111111-1111-1111-1111-111111111111"


@pytest.fixture
def admin_env(monkeypatch):
    monkeypatch.setenv("DOSSIER_ADMIN_IDS", _ALICE_ID)
    from dossier.app import _configure_admin_ids

    _configure_admin_ids()
    yield
    monkeypatch.delenv("DOSSIER_ADMIN_IDS", raising=False)
    _configure_admin_ids()


def test_landing_shows_unassigned_owner(client):
    """Landing page shows 'unassigned' when no owner is set."""
    _login(client)
    resp = client.get("/")
    assert resp.status_code == 200
    assert "unassigned" in resp.text


def test_landing_shows_owner_after_set(client, gateway):
    """Landing page shows the owner after it's set."""
    _login(client)
    gateway.register_project_metadata(
        display_name="Test Project", owner_actor_id="alice-id", created_by="admin"
    )
    resp = client.get("/")
    assert resp.status_code == 200
    assert "alice-id" in resp.text


def test_project_index_shows_owner(client, gateway):
    """Project index page shows the current owner."""
    _login(client)
    gateway.register_project_metadata(owner_actor_id="bob-id", created_by="admin")
    resp = client.get("/p/dossier-test")
    assert resp.status_code == 200
    assert "bob-id" in resp.text


def test_project_index_shows_unassigned(client):
    """Project index shows 'unassigned' when no owner is set."""
    _login(client)
    resp = client.get("/p/dossier-test")
    assert resp.status_code == 200
    assert "unassigned" in resp.text


def test_set_owner_post_updates_catalog(client, gateway, admin_env):
    """POST to /p/{project}/owner updates the project's owner."""
    _login(client)
    page = client.get("/p/dossier-test")
    csrf = _extract_csrf(page.text)

    resp = client.post(
        "/p/dossier-test/owner",
        data={"owner_actor_id": "carol-id", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    entry = gateway.get_project_catalog_entry()
    assert entry is not None
    assert entry.owner_actor_id == "carol-id"


def test_set_owner_clear_with_empty_string(client, gateway, admin_env):
    """Posting an empty owner_actor_id clears the owner."""
    _login(client)
    gateway.register_project_metadata(owner_actor_id="alice", created_by="admin")

    page = client.get("/p/dossier-test")
    csrf = _extract_csrf(page.text)

    resp = client.post(
        "/p/dossier-test/owner",
        data={"owner_actor_id": "", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    entry = gateway.get_project_catalog_entry()
    assert entry is not None
    assert entry.owner_actor_id is None


def test_set_owner_requires_csrf(client):
    """POST without CSRF token is rejected."""
    _login(client)
    resp = client.post(
        "/p/dossier-test/owner",
        data={"owner_actor_id": "evil"},
        follow_redirects=False,
    )
    assert resp.status_code in (400, 403)


def test_set_owner_requires_auth(client):
    """POST without login redirects to login."""
    resp = client.post(
        "/p/dossier-test/owner",
        data={"owner_actor_id": "evil"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_set_owner_requires_admin(client):
    """POST by a non-admin user is rejected with 403."""
    _login(client)
    page = client.get("/p/dossier-test")
    csrf = _extract_csrf(page.text)
    resp = client.post(
        "/p/dossier-test/owner",
        data={"owner_actor_id": "evil", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 403


def test_owner_persists_across_requests(client, gateway, admin_env):
    """Owner set via POST is visible on subsequent landing page loads."""
    _login(client)
    page = client.get("/p/dossier-test")
    csrf = _extract_csrf(page.text)

    client.post(
        "/p/dossier-test/owner",
        data={"owner_actor_id": "dave-id", "csrf_token": csrf},
        follow_redirects=False,
    )

    landing = client.get("/")
    assert "dave-id" in landing.text
