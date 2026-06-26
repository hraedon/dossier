from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dossier.app import create_app
from dossier.auth.backends import LocalBackend
from dossier.config import Settings

_CSRF_RE = re.compile(r'name="csrf_token"\s+value="([^"]+)"')


def _extract_csrf(html: str) -> str:
    m = _CSRF_RE.search(html)
    assert m, "csrf_token not found in HTML"
    return m.group(1)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url="",
        project="dossier_test",
        hmac_key_path="",
        session_secret="test-session-secret-not-for-prod",
        session_max_age_seconds=43200,
        secure_cookies=False,
        require_ssl=False,
        users_path="",
        auth_backend="local",
    )


def _hash(pw: str) -> str:
    from dossier.auth.passwords import hash_password

    return hash_password(pw)


def _users_file(tmp_path: Path) -> Path:
    path = tmp_path / "users.json"
    path.write_text(
        json.dumps(
            [
                {
                    "stable_id": "11111111-1111-1111-1111-111111111111",
                    "username": "alice",
                    "display_name": "Alice",
                    "password": _hash("s3cret"),
                    "groups": [],
                }
            ]
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def app(tmp_path, gateway):
    settings = _settings(tmp_path)
    backend = LocalBackend(_users_file(tmp_path))
    return create_app(settings, gateway, backend)


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


def _login(client: TestClient) -> str:
    page = client.get("/login")
    csrf = _extract_csrf(page.text)
    resp = client.post(
        "/login",
        data={"username": "alice", "password": "s3cret", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/"
    return csrf


def test_unauthenticated_get_root_redirects_to_login(client):
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_unauthenticated_get_issues_new_redirects_to_login(client):
    resp = client.get("/issues/new", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_login_form_renders(client):
    resp = client.get("/login")
    assert resp.status_code == 200
    assert "csrf_token" in resp.text
    assert "sign in" in resp.text.lower()


def test_login_form_bad_credentials_renders_error(client):
    page = client.get("/login")
    csrf = _extract_csrf(page.text)
    resp = client.post(
        "/login",
        data={"username": "alice", "password": "wrong", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 401
    assert "invalid credentials" in resp.text


def test_full_ui_flow(client):
    _login(client)

    index = client.get("/")
    assert "Alice" in index.text
    assert "new issue" in index.text.lower()

    new_page = client.get("/issues/new")
    assert new_page.status_code == 200
    csrf = _extract_csrf(new_page.text)

    resp = client.post(
        "/issues",
        data={
            "type": "bug",
            "title": "Smoke test bug",
            "description": "A description for the smoke test",
            "assignee": "bob",
            "priority": "high",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    issue_url = resp.headers["location"]

    detail = client.get(issue_url)
    assert detail.status_code == 200
    assert "Smoke test bug" in detail.text
    assert "Alice" in detail.text
    assert "chain verified" in detail.text
    assert "created" in detail.text

    csrf = _extract_csrf(detail.text)
    resp = client.post(
        f"{issue_url}/comments",
        data={"body": "This is a test comment in the chain", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    detail = client.get(issue_url)
    assert "This is a test comment in the chain" in detail.text


def test_create_issue_without_title_re_renders_form(client):
    _login(client)
    new_page = client.get("/issues/new")
    csrf = _extract_csrf(new_page.text)
    resp = client.post(
        "/issues",
        data={
            "type": "bug",
            "title": "",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "title is required" in resp.text


def test_empty_issues_state(client):
    _login(client)
    resp = client.get("/")
    assert resp.status_code == 200
    assert "no issues" in resp.text.lower()


def test_filter_by_status(client):
    _login(client)
    new_page = client.get("/issues/new")
    csrf = _extract_csrf(new_page.text)
    client.post(
        "/issues",
        data={"type": "bug", "title": "Filter me", "csrf_token": csrf},
        follow_redirects=False,
    )
    resp = client.get("/?status=open")
    assert resp.status_code == 200
    assert "Filter me" in resp.text


def test_json_login_still_works(client):
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


def test_json_logout_still_works(client):
    csrf = client.get("/csrf").json()["csrf_token"]
    login = client.post(
        "/login",
        json={"username": "alice", "password": "s3cret"},
        headers={"X-CSRF-Token": csrf},
    )
    rotated = login.json()["csrf_token"]
    resp = client.post("/logout", headers={"X-CSRF-Token": rotated})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_transition_self_review_error_renders(client):
    _login(client)
    new_page = client.get("/issues/new")
    csrf = _extract_csrf(new_page.text)
    resp = client.post(
        "/issues",
        data={"type": "bug", "title": "Review gate test", "csrf_token": csrf},
        follow_redirects=False,
    )
    issue_url = resp.headers["location"]

    from helpers import ALICE
    from dossier.gateway import RegistaGateway

    gw: RegistaGateway = client.app.state.gateway
    import uuid

    wi_id = uuid.UUID(issue_url.split("/")[-1])
    gw.transition(actor=ALICE, work_item_id=wi_id, transition_name="start")
    gw.transition(actor=ALICE, work_item_id=wi_id, transition_name="submit_for_review")

    detail = client.get(issue_url)
    csrf = _extract_csrf(detail.text)
    resp = client.post(
        f"{issue_url}/transitions",
        data={"transition_name": "adversarial_pass", "review_note": "lgtm", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "self-review" in resp.text.lower()
