from __future__ import annotations

import pytest


def test_healthz_ok(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["component"] == "dossier"
    assert "version" in body
    assert "regista" in body
    assert "checks" in body


def test_livez_is_process_only(client):
    resp = client.get("/livez")
    assert resp.status_code == 200
    assert resp.json() == {"status": "alive"}


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

    monkeypatch.setenv("REGISTA_DSN", "postgresql://x/x")
    monkeypatch.setenv("REGISTA_KEY_PATH", "/x")
    monkeypatch.setenv("DOSSIER_SESSION_SECRET", "short")
    with pytest.raises(RuntimeError):
        load_settings(strict=True)


def test_config_prefers_regista_dsn_over_dossier_database_url(monkeypatch):
    from dossier.config import load_settings

    monkeypatch.setenv("REGISTA_DSN", "postgresql://canonical/x")
    monkeypatch.setenv("DOSSIER_DATABASE_URL", "postgresql://legacy/x")
    monkeypatch.setenv("REGISTA_KEY_PATH", "/x")
    monkeypatch.setenv("DOSSIER_SESSION_SECRET", "a" * 40)
    settings = load_settings(strict=True)
    assert settings.database_url == "postgresql://canonical/x"


def test_config_falls_back_to_dossier_database_url_with_warning(monkeypatch):
    from dossier.config import load_settings

    monkeypatch.delenv("REGISTA_DSN", raising=False)
    monkeypatch.setenv("DOSSIER_DATABASE_URL", "postgresql://legacy/x")
    monkeypatch.delenv("REGISTA_KEY_PATH", raising=False)
    monkeypatch.setenv("DOSSIER_HMAC_KEY_PATH", "/legacy-keys")
    monkeypatch.setenv("DOSSIER_SESSION_SECRET", "a" * 40)
    with pytest.warns(DeprecationWarning):
        settings = load_settings(strict=True)
    assert settings.database_url == "postgresql://legacy/x"
    assert settings.hmac_key_path == "/legacy-keys"


def test_config_canonical_only_no_warning(monkeypatch):
    from dossier.config import load_settings

    monkeypatch.setenv("REGISTA_DSN", "postgresql://canonical/x")
    monkeypatch.delenv("DOSSIER_DATABASE_URL", raising=False)
    monkeypatch.setenv("REGISTA_KEY_PATH", "/canonical-keys")
    monkeypatch.delenv("DOSSIER_HMAC_KEY_PATH", raising=False)
    monkeypatch.setenv("DOSSIER_SESSION_SECRET", "a" * 40)
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        settings = load_settings(strict=True)
    assert settings.database_url == "postgresql://canonical/x"
    assert settings.hmac_key_path == "/canonical-keys"


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


def test_login_throttle_after_max_failures(client):
    csrf = client.get("/csrf").json()["csrf_token"]
    for _ in range(5):
        resp = client.post(
            "/login",
            json={"username": "alice", "password": "wrong"},
            headers={"X-CSRF-Token": csrf},
        )
        assert resp.status_code == 401
    resp = client.post(
        "/login",
        json={"username": "alice", "password": "wrong"},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 429


def test_login_throttle_clears_on_success(client):
    csrf = client.get("/csrf").json()["csrf_token"]
    for _ in range(3):
        client.post(
            "/login",
            json={"username": "alice", "password": "wrong"},
            headers={"X-CSRF-Token": csrf},
        )
    resp = client.post(
        "/login",
        json={"username": "alice", "password": "s3cret"},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 200
    new_csrf = resp.json()["csrf_token"]
    resp = client.post(
        "/login",
        json={"username": "alice", "password": "wrong"},
        headers={"X-CSRF-Token": new_csrf},
    )
    assert resp.status_code == 401


def test_login_throttle_form_returns_html(client):
    csrf = client.get("/csrf").json()["csrf_token"]
    for _ in range(5):
        resp = client.post(
            "/login",
            data={"username": "alice", "password": "wrong", "csrf_token": csrf},
        )
        assert resp.status_code == 401
    resp = client.post(
        "/login",
        data={"username": "alice", "password": "wrong", "csrf_token": csrf},
    )
    assert resp.status_code == 429
    assert "text/html" in resp.headers.get("content-type", "")


def test_all_state_changing_routes_have_csrf_dependency(app):
    from fastapi.routing import APIRoute

    from dossier.auth.sessions import verify_csrf

    def _has_csrf(dependant) -> bool:
        for dep in dependant.dependencies:
            if dep.call is verify_csrf:
                return True
            if _has_csrf(dep):
                return True
        return False

    state_changing = {"POST", "PUT", "PATCH", "DELETE"}
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if not route.methods:
            continue
        if not (route.methods & state_changing):
            continue
        assert _has_csrf(route.dependant), f"route {route.path} lacks verify_csrf"
