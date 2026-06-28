from __future__ import annotations

import pytest


def test_healthz_ok(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_me_without_login_is_401(client):
    resp = client.get("/me")
    assert resp.status_code == 401


def test_login_flow_sets_actor(client):
    csrf = client.get("/csrf").json()["csrf_token"]
    resp = client.post(
        "/login",
        json={"username": "alice", "password": "s3cret"},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["actor_id"] == "11111111-1111-1111-1111-111111111111"
    assert body["display_name"] == "Alice"

    me = client.get("/me").json()
    assert me["actor_id"] == "11111111-1111-1111-1111-111111111111"
    assert me["actor_kind"] == "human"
    assert me["display_name"] == "Alice"
    assert me["on_behalf_of"] is None


def test_login_wrong_password_is_401(client):
    csrf = client.get("/csrf").json()["csrf_token"]
    resp = client.post(
        "/login",
        json={"username": "alice", "password": "nope"},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 401
    assert client.get("/me").status_code == 401


def test_logout_clears_session(client):
    csrf = client.get("/csrf").json()["csrf_token"]
    login = client.post(
        "/login",
        json={"username": "alice", "password": "s3cret"},
        headers={"X-CSRF-Token": csrf},
    )
    rotated = login.json()["csrf_token"]
    assert client.get("/me").status_code == 200
    resp = client.post("/logout", headers={"X-CSRF-Token": rotated})
    assert resp.status_code == 200
    assert client.get("/me").status_code == 401


def test_login_rotates_csrf_token(client):
    pre = client.get("/csrf").json()["csrf_token"]
    resp = client.post(
        "/login",
        json={"username": "alice", "password": "s3cret"},
        headers={"X-CSRF-Token": pre},
    )
    assert resp.status_code == 200
    rotated = resp.json()["csrf_token"]
    assert rotated and rotated != pre
    assert client.get("/me").status_code == 200


def test_load_settings_rejects_short_session_secret(monkeypatch):
    from dossier.config import load_settings

    monkeypatch.setenv("DOSSIER_DATABASE_URL", "postgresql://x/x")
    monkeypatch.setenv("DOSSIER_HMAC_KEY_PATH", "/x")
    monkeypatch.setenv("DOSSIER_SESSION_SECRET", "short")
    with pytest.raises(RuntimeError):
        load_settings(strict=True)


def test_login_without_csrf_after_session_is_403(client):
    client.get("/csrf")
    resp = client.post("/login", json={"username": "alice", "password": "s3cret"})
    assert resp.status_code == 403


def test_login_before_csrf_is_403(client):
    resp = client.post("/login", json={"username": "alice", "password": "s3cret"})
    assert resp.status_code == 403


def test_spoof_prevention_body_cannot_set_actor(client):
    csrf = client.get("/csrf").json()["csrf_token"]
    resp = client.post(
        "/login",
        json={
            "username": "alice",
            "password": "s3cret",
            "actor_id": "attacker",
            "actor_kind": "system",
            "on_behalf_of": {"principal_id": "pwned"},
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["actor_id"] == "11111111-1111-1111-1111-111111111111"
    assert body["actor_id"] != "attacker"

    me = client.get("/me").json()
    assert me["actor_id"] == "11111111-1111-1111-1111-111111111111"
    assert me["actor_kind"] == "human"
    assert me["actor_kind"] != "system"
    assert me["on_behalf_of"] is None


def test_spoof_prevention_header_cannot_set_actor(client):
    csrf = client.get("/csrf").json()["csrf_token"]
    client.post(
        "/login",
        json={"username": "alice", "password": "s3cret"},
        headers={
            "X-CSRF-Token": csrf,
            "actor_id": "attacker",
            "actor_kind": "system",
        },
    )
    me = client.get("/me", headers={"actor_id": "attacker", "actor_kind": "system"})
    assert me.status_code == 200
    body = me.json()
    assert body["actor_id"] == "11111111-1111-1111-1111-111111111111"
    assert body["actor_kind"] == "human"
    assert body["on_behalf_of"] is None
