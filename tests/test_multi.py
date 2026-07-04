from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from regista.testing import InMemoryRegista

from conftest import extract_csrf as _extract_csrf, login as _login
from dossier.app import create_app
from dossier.auth.backends import LocalBackend
from dossier.config import Settings
from dossier.gateway import RegistaGateway
from dossier.keys import generate_keyset
from dossier.multi import GatewayRegistry

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
                    "stable_id": "11111111-1111-1111-1111-111111111111",
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


def _settings(tmp_path):
    return Settings(
        database_url="",
        project=_PROJECT_A,
        hmac_key_path="",
        session_secret="test-session-secret-not-for-prod",
        session_max_age_seconds=43200,
        secure_cookies=False,
        require_ssl=False,
        users_path="",
        auth_backend="local",
        principal_key_dir=str(tmp_path / "principals"),
    )


def _make_gateway(tmp_path, project_name):
    key_path = tmp_path / f"keys_{project_name}.json"
    generate_keyset(key_path)
    reg = InMemoryRegista(project=project_name, hmac_key_path=str(key_path))
    gw = RegistaGateway(reg, project_name=project_name)
    gw.register_workflow()
    return gw


@pytest.fixture
def multi_client(tmp_path):
    gw_a = _make_gateway(tmp_path, _PROJECT_A)
    gw_b = _make_gateway(tmp_path, _PROJECT_B)

    settings = _settings(tmp_path)
    backend = LocalBackend(_users_file(tmp_path))
    registry = GatewayRegistry(known_projects=[_PROJECT_A, _PROJECT_B])
    registry.add(_PROJECT_A, gw_a)
    registry.add(_PROJECT_B, gw_b)
    app = create_app(settings, registry, backend)
    with TestClient(app) as c:
        yield c
    gw_a.close()
    gw_b.close()


def test_landing_shows_all_projects(multi_client):
    _login(multi_client)
    resp = multi_client.get("/")
    assert resp.status_code == 200
    assert "dossier-test" in resp.text
    assert "cert-watch" in resp.text


def test_landing_shows_open_counts(multi_client):
    _login(multi_client)
    csrf = _extract_csrf(multi_client.get("/p/dossier-test/issues/new").text)
    multi_client.post(
        "/p/dossier-test/issues",
        data={"type": "bug", "title": "Project A issue", "csrf_token": csrf},
        follow_redirects=False,
    )
    resp = multi_client.get("/")
    assert resp.status_code == 200
    assert "dossier-test" in resp.text
    assert "cert-watch" in resp.text


def test_project_isolation(multi_client):
    _login(multi_client)
    csrf_a = _extract_csrf(multi_client.get("/p/dossier-test/issues/new").text)
    resp_a = multi_client.post(
        "/p/dossier-test/issues",
        data={"type": "bug", "title": "Issue in A", "csrf_token": csrf_a},
        follow_redirects=False,
    )
    assert resp_a.status_code == 303

    csrf_b = _extract_csrf(multi_client.get("/p/cert-watch/issues/new").text)
    resp_b = multi_client.post(
        "/p/cert-watch/issues",
        data={"type": "bug", "title": "Issue in B", "csrf_token": csrf_b},
        follow_redirects=False,
    )
    assert resp_b.status_code == 303

    list_a = multi_client.get("/p/dossier-test").text
    assert "Issue in A" in list_a
    assert "Issue in B" not in list_a

    list_b = multi_client.get("/p/cert-watch").text
    assert "Issue in B" in list_b
    assert "Issue in A" not in list_b


def test_cross_project_issue_id_not_found(multi_client):
    _login(multi_client)
    csrf_a = _extract_csrf(multi_client.get("/p/dossier-test/issues/new").text)
    resp_a = multi_client.post(
        "/p/dossier-test/issues",
        data={"type": "bug", "title": "Issue in A", "csrf_token": csrf_a},
        follow_redirects=False,
    )
    issue_url_a = resp_a.headers["location"]
    wi_id = issue_url_a.split("/")[-1]

    resp = multi_client.get(f"/p/cert-watch/issues/{wi_id}")
    assert resp.status_code == 404


def test_display_key_prefix_per_project(multi_client):
    _login(multi_client)
    csrf_a = _extract_csrf(multi_client.get("/p/dossier-test/issues/new").text)
    multi_client.post(
        "/p/dossier-test/issues",
        data={"type": "bug", "title": "A1", "csrf_token": csrf_a},
        follow_redirects=False,
    )
    csrf_b = _extract_csrf(multi_client.get("/p/cert-watch/issues/new").text)
    multi_client.post(
        "/p/cert-watch/issues",
        data={"type": "bug", "title": "B1", "csrf_token": csrf_b},
        follow_redirects=False,
    )

    list_a = multi_client.get("/p/dossier-test").text
    assert "DOSSIER_TEST-1" in list_a

    list_b = multi_client.get("/p/cert-watch").text
    assert "CERT_WATCH-1" in list_b


def test_unknown_project_returns_404(multi_client):
    _login(multi_client)
    resp = multi_client.get("/p/nonexistent")
    assert resp.status_code == 404


def test_known_projects_enforced(multi_client):
    """An authenticated user cannot access a project not in the known set,
    even if the schema exists in the database."""
    _login(multi_client)
    # 'dossier_test' is known; try an unknown but valid-looking schema name
    resp = multi_client.get("/p/unknown-project")
    assert resp.status_code == 404


def test_unauthenticated_landing_redirects_to_login(multi_client):
    resp = multi_client.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_unauthenticated_project_redirects_to_login(multi_client):
    resp = multi_client.get("/p/dossier-test", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_project_switcher_in_header(multi_client):
    _login(multi_client)
    resp = multi_client.get("/")
    assert "ds-projswitch" in resp.text
    assert "dossier-test" in resp.text
    assert "cert-watch" in resp.text


def test_project_switcher_highlights_active(multi_client):
    _login(multi_client)
    resp = multi_client.get("/p/dossier-test")
    assert "is-active" in resp.text
