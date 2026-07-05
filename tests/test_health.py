from __future__ import annotations

from dossier.config import Settings


_PROJECT = "dossier_test"


def _settings(tmp_path) -> Settings:
    return Settings(
        database_url="",
        project=_PROJECT,
        hmac_key_path="",
        session_secret="test-session-secret-not-for-prod",
        session_max_age_seconds=43200,
        secure_cookies=False,
        require_ssl=False,
        users_path=str(tmp_path / "users.json"),
        auth_backend="local",
        principal_key_dir=str(tmp_path / "principals"),
    )


def test_healthz_returns_suite_shape(app, client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["component"] == "dossier"
    assert "version" in body
    assert isinstance(body["ok"], bool)
    assert isinstance(body["degraded"], bool)
    assert "regista" in body
    assert "reachable" in body["regista"]
    assert "project" in body["regista"]
    assert "chain_ok" in body["regista"]
    assert isinstance(body["checks"], list)
    check_names = [c["name"] for c in body["checks"]]
    assert "session_secret" in check_names
    assert "auth_backend" in check_names


def test_healthz_session_secret_pass(client):
    resp = client.get("/healthz")
    body = resp.json()
    secret_check = next(c for c in body["checks"] if c["name"] == "session_secret")
    assert secret_check["status"] == "ok"


def test_healthz_auth_backend_check_present(client):
    resp = client.get("/healthz")
    body = resp.json()
    auth_check = next(c for c in body["checks"] if c["name"] == "auth_backend")
    assert auth_check["status"] in ("ok", "fail")
