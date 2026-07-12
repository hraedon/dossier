from __future__ import annotations

import pytest

from conftest import login as _login
from helpers import ALICE

_PROJECT_SLUG = "dossier-test"
_ALICE_ID = "11111111-1111-1111-1111-111111111111"


@pytest.fixture
def admin_env(monkeypatch):
    monkeypatch.setenv("DOSSIER_ADMIN_IDS", _ALICE_ID)
    from dossier.app import _configure_admin_ids

    _configure_admin_ids()
    yield
    monkeypatch.delenv("DOSSIER_ADMIN_IDS", raising=False)
    _configure_admin_ids()


def test_read_project_list(gateway, make_issue):
    make_issue(title="Project list test")
    from dossier.administration import read_project_list

    projects = read_project_list(gateway)
    assert len(projects) > 0
    for p in projects:
        assert p.schema_name
        assert p.display_name is None or isinstance(p.display_name, str)
        assert p.owner is None or isinstance(p.owner, str)


def test_read_access_policy(gateway, make_issue):
    make_issue(title="Access policy test")
    from dossier.administration import read_access_policy

    policy = read_access_policy(
        gateway,
        _PROJECT_SLUG,
        actor=ALICE,
        is_admin=False,
    )
    assert policy.project_slug == _PROJECT_SLUG
    assert isinstance(policy.readable_projects, tuple)
    assert policy.is_admin is False
    assert isinstance(policy.admin_ids, tuple)


def test_read_admin_summary(gateway, make_issue):
    make_issue(title="Admin summary test")
    from dossier.administration import read_admin_summary

    summary = read_admin_summary(
        gateway,
        ALICE,
        is_admin=True,
        project_slug=_PROJECT_SLUG,
    )
    assert len(summary.projects) > 0
    assert summary.access is not None
    assert isinstance(summary.principal_count, int)
    assert isinstance(summary.findings, tuple)


def test_read_admin_summary_non_admin(gateway, make_issue):
    make_issue(title="Non-admin summary test")
    from dossier.administration import read_admin_summary

    summary = read_admin_summary(
        gateway,
        ALICE,
        is_admin=False,
        project_slug=_PROJECT_SLUG,
    )
    assert any("not an administrator" in f for f in summary.findings)


def test_admin_index_requires_login(client):
    resp = client.get("/admin", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_admin_index_requires_admin(client):
    _login(client)
    resp = client.get("/admin")
    assert resp.status_code == 403


def test_admin_index_returns_200_for_admin(client, make_issue, admin_env):
    make_issue(title="Admin index test")
    _login(client)
    resp = client.get("/admin")
    assert resp.status_code == 200
    assert "administration" in resp.text.lower()


def test_admin_projects_requires_admin(client):
    _login(client)
    resp = client.get("/admin/projects")
    assert resp.status_code == 403


def test_admin_projects_returns_200_for_admin(client, make_issue, admin_env):
    make_issue(title="Admin projects test")
    _login(client)
    resp = client.get("/admin/projects")
    assert resp.status_code == 200
    assert "projects" in resp.text.lower()


def test_admin_access_requires_admin(client):
    _login(client)
    resp = client.get("/admin/access")
    assert resp.status_code == 403


def test_admin_access_returns_200_for_admin(client, make_issue, admin_env):
    make_issue(title="Admin access test")
    _login(client)
    resp = client.get("/admin/access")
    assert resp.status_code == 200
    assert "access" in resp.text.lower()


def test_admin_access_shows_admin_ids(client, make_issue, admin_env):
    make_issue(title="Admin IDs test")
    _login(client)
    resp = client.get("/admin/access")
    assert resp.status_code == 200
    assert _ALICE_ID in resp.text


def test_activity_index_requires_login(client):
    resp = client.get("/activity", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_activity_index_returns_200(client, make_issue):
    make_issue(title="Activity index test")
    _login(client)
    resp = client.get("/activity")
    assert resp.status_code == 200
    assert "activity" in resp.text.lower()
