from __future__ import annotations

import secrets

import pytest

from conftest import extract_csrf as _extract_csrf, login as _login
from dossier.principals import InMemoryPrincipalKeyStore

_ALICE_ID = "11111111-1111-1111-1111-111111111111"
_SECOND_ADMIN_ID = "22222222-2222-2222-2222-222222222222"
_NEW_PRINCIPAL_ID = "33333333-3333-3333-3333-333333333333"


# ---- fixtures ----


@pytest.fixture
def admin_env(monkeypatch):
    monkeypatch.setenv("DOSSIER_ADMIN_IDS", _ALICE_ID)
    from dossier.app import _configure_admin_ids

    _configure_admin_ids()
    yield
    monkeypatch.delenv("DOSSIER_ADMIN_IDS", raising=False)
    _configure_admin_ids()


@pytest.fixture
def admin_env_dual(monkeypatch):
    monkeypatch.setenv("DOSSIER_ADMIN_IDS", f"{_ALICE_ID},{_SECOND_ADMIN_ID}")
    from dossier.app import _configure_admin_ids

    _configure_admin_ids()
    yield
    monkeypatch.delenv("DOSSIER_ADMIN_IDS", raising=False)
    _configure_admin_ids()


@pytest.fixture
def principal_store(gateway):
    store = InMemoryPrincipalKeyStore()
    gateway._principal_store = store
    yield store
    gateway._principal_store = None


def _enroll(store, principal_id=_ALICE_ID):
    return store.register(principal_id, secrets.token_bytes(32))


# ---- /me/identity ----


def test_my_identity_not_enrolled(client, principal_store):
    _login(client)
    resp = client.get("/me/identity")
    assert resp.status_code == 200
    assert "not enrolled for signing" in resp.text.lower()


def test_my_identity_shows_key_status(client, principal_store):
    entry = _enroll(principal_store, _ALICE_ID)
    _login(client)
    resp = client.get("/me/identity")
    assert resp.status_code == 200
    assert entry["fingerprint"][:32] in resp.text
    assert "active" in resp.text.lower()
    assert entry["key_id"] in resp.text
    assert entry["scheme"] in resp.text


def test_my_identity_no_private_key_material(client, principal_store):
    entry = _enroll(principal_store, _ALICE_ID)
    _login(client)
    resp = client.get("/me/identity")
    assert resp.status_code == 200
    assert entry["public_key"] not in resp.text
    assert "secret" not in resp.text.lower()


def test_my_identity_shows_rotate_button(client, principal_store):
    _enroll(principal_store, _ALICE_ID)
    _login(client)
    resp = client.get("/me/identity")
    assert resp.status_code == 200
    assert "rotate my key" in resp.text.lower()


# ---- /me/key/rotate ----


def test_rotate_key_updates_fingerprint(client, principal_store):
    entry = _enroll(principal_store, _ALICE_ID)
    old_fingerprint = entry["fingerprint"]
    _login(client)

    identity_page = client.get("/me/identity")
    csrf = _extract_csrf(identity_page.text)

    resp = client.post("/me/key/rotate", data={"csrf_token": csrf}, follow_redirects=False)
    assert resp.status_code == 303

    resp = client.get("/me/identity")
    assert resp.status_code == 200
    assert old_fingerprint[:32] not in resp.text
    new_entry = principal_store.get_active(_ALICE_ID)
    assert new_entry["fingerprint"][:32] in resp.text


def test_rotate_key_writes_rotation_event(client, principal_store):
    old_entry = _enroll(principal_store, _ALICE_ID)
    old_key_id = old_entry["key_id"]
    _login(client)

    identity_page = client.get("/me/identity")
    csrf = _extract_csrf(identity_page.text)

    client.post("/me/key/rotate", data={"csrf_token": csrf}, follow_redirects=False)

    entries = principal_store.list(principal_id=_ALICE_ID)
    statuses = {e["key_id"]: e["status"] for e in entries}
    assert statuses[old_key_id] == "superseded"
    new_entry = principal_store.get_active(_ALICE_ID)
    assert statuses[new_entry["key_id"]] == "active"


# ---- /me/signing-history ----


def test_my_signing_history_empty(client, principal_store):
    _login(client)
    resp = client.get("/me/signing-history")
    assert resp.status_code == 200
    assert "no signed events found" in resp.text.lower()


def test_my_signing_history_shows_events(client, principal_store):
    _login(client)
    csrf = _extract_csrf(client.get("/p/dossier-test/issues/new").text)
    client.post(
        "/p/dossier-test/issues",
        data={"type": "bug", "title": "Signing history test", "csrf_token": csrf},
        follow_redirects=False,
    )
    resp = client.get("/me/signing-history")
    assert resp.status_code == 200
    assert "DOSSIER_TEST-1" in resp.text
    assert "verified" in resp.text.lower() or "unverified" in resp.text.lower()


# ---- /admin/principals ----


def test_principal_roster_requires_admin(client, principal_store):
    _login(client)
    resp = client.get("/admin/principals")
    assert resp.status_code == 403


def test_principal_roster_shows_principals(client, principal_store, admin_env):
    _enroll(principal_store, _ALICE_ID)
    _login(client)
    resp = client.get("/admin/principals")
    assert resp.status_code == 200
    assert _ALICE_ID in resp.text
    assert "active" in resp.text.lower()


def test_enroll_principal_via_ui(client, principal_store, admin_env):
    _login(client)
    roster_page = client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)

    resp = client.post(
        "/admin/principals/enroll",
        data={"principal_id": _NEW_PRINCIPAL_ID, "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/principals"

    roster = client.get("/admin/principals")
    assert _NEW_PRINCIPAL_ID in roster.text


def test_revoke_principal_via_ui(client, principal_store, admin_env):
    _enroll(principal_store, _NEW_PRINCIPAL_ID)
    _login(client)

    roster_page = client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)

    resp = client.post(
        f"/admin/principals/{_NEW_PRINCIPAL_ID}/revoke",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/principals"

    roster = client.get("/admin/principals")
    assert "revoked" in roster.text.lower()


def test_revoked_principal_history_still_verifies(client, principal_store, admin_env):
    _login(client)
    csrf = _extract_csrf(client.get("/p/dossier-test/issues/new").text)
    client.post(
        "/p/dossier-test/issues",
        data={"type": "bug", "title": "Revocation history test", "csrf_token": csrf},
        follow_redirects=False,
    )
    _enroll(principal_store, _ALICE_ID)

    roster_page = client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)
    client.post(
        f"/admin/principals/{_ALICE_ID}/revoke",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )

    resp = client.get("/me/signing-history")
    assert resp.status_code == 200
    assert "DOSSIER_TEST-1" in resp.text


# ---- /admin/break-glass ----


def test_break_glass_form_renders(client, principal_store, admin_env):
    _login(client)
    resp = client.get("/admin/break-glass")
    assert resp.status_code == 200
    assert 'name="principal_id"' in resp.text
    assert 'name="reason"' in resp.text
    assert 'name="confirmer_id"' in resp.text


def test_break_glass_requires_all_fields(client, principal_store, admin_env):
    _login(client)
    bg_page = client.get("/admin/break-glass")
    csrf = _extract_csrf(bg_page.text)
    resp = client.post(
        "/admin/break-glass",
        data={"principal_id": "", "reason": "", "confirmer_id": "", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 400


def test_break_glass_requires_different_confirmer(client, principal_store, admin_env):
    _login(client)
    bg_page = client.get("/admin/break-glass")
    csrf = _extract_csrf(bg_page.text)
    resp = client.post(
        "/admin/break-glass",
        data={
            "principal_id": _NEW_PRINCIPAL_ID,
            "reason": "emergency",
            "confirmer_id": _ALICE_ID,
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400


def test_break_glass_requires_admin_confirmer(client, principal_store, admin_env):
    _login(client)
    bg_page = client.get("/admin/break-glass")
    csrf = _extract_csrf(bg_page.text)
    resp = client.post(
        "/admin/break-glass",
        data={
            "principal_id": _NEW_PRINCIPAL_ID,
            "reason": "emergency",
            "confirmer_id": "non-admin-id",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 403


def test_break_glass_success(client, principal_store, admin_env_dual):
    _login(client)
    bg_page = client.get("/admin/break-glass")
    csrf = _extract_csrf(bg_page.text)
    resp = client.post(
        "/admin/break-glass",
        data={
            "principal_id": _NEW_PRINCIPAL_ID,
            "reason": "emergency access",
            "confirmer_id": _SECOND_ADMIN_ID,
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/principals"


# ---- auth required ----


def test_my_identity_route_requires_auth(client):
    resp = client.get("/me/identity", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_my_signing_history_requires_auth(client):
    resp = client.get("/me/signing-history", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_admin_routes_require_auth(client):
    resp = client.get("/admin/principals", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


# ---- CSRF ----


def test_csrf_on_rotate_key(client, principal_store):
    _login(client)
    resp = client.post("/me/key/rotate", data={}, follow_redirects=False)
    assert resp.status_code == 403


def test_csrf_on_enroll(client, principal_store, admin_env):
    _login(client)
    resp = client.post("/admin/principals/enroll", data={}, follow_redirects=False)
    assert resp.status_code == 403


def test_csrf_on_revoke(client, principal_store, admin_env):
    _login(client)
    resp = client.post(
        f"/admin/principals/{_NEW_PRINCIPAL_ID}/revoke", data={}, follow_redirects=False
    )
    assert resp.status_code == 403


def test_csrf_on_break_glass(client, principal_store, admin_env):
    _login(client)
    resp = client.post("/admin/break-glass", data={}, follow_redirects=False)
    assert resp.status_code == 403
