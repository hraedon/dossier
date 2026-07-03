"""Tests for Plan 014 — cross-project human interface.

Covers:
- Authz seam (can_read_project) v1 open-by-default + enforcement
- Cross-project dashboard (filters, search, cap, empty estate, XSS safety)
- Estate-wide search route
- Issue detail: assurance level, verified-signer badge, "what changed" summary
- Nav links and unauthenticated redirects
"""

from __future__ import annotations

import json
import uuid

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
from helpers import ALICE, BOB, CAROL, AGENT_GLM

_PROJECT_A = "dossier_test"
_PROJECT_B = "cert_watch"
_PROJECT_C = "gpo_lens"


# ── shared fixtures (mirrors test_multi.py) ──────────────────────────────


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


@pytest.fixture
def triple_client(tmp_path):
    gw_a = _make_gateway(tmp_path, _PROJECT_A)
    gw_b = _make_gateway(tmp_path, _PROJECT_B)
    gw_c = _make_gateway(tmp_path, _PROJECT_C)

    settings = _settings(tmp_path)
    backend = LocalBackend(_users_file(tmp_path))
    registry = GatewayRegistry(known_projects=[_PROJECT_A, _PROJECT_B, _PROJECT_C])
    registry.add(_PROJECT_A, gw_a)
    registry.add(_PROJECT_B, gw_b)
    registry.add(_PROJECT_C, gw_c)
    app = create_app(settings, registry, backend)
    with TestClient(app) as c:
        yield c
    gw_a.close()
    gw_b.close()
    gw_c.close()


def _create_issue_via_ui(client, project_slug, title, **fields):
    """Create an issue through the web UI and return the issue URL."""
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


def _gw(client, project_name):
    """Get the gateway for a project from the app's registry."""
    return client.app.state.registry.get(project_name)


# ── 1. Authz seam ────────────────────────────────────────────────────────


def test_authz_seam_can_read_project_returns_true_v1():
    """can_read_project returns True for any authenticated actor in v1."""
    from dossier.authz import can_read_project

    assert can_read_project(ALICE, "dossier_test") is True
    assert can_read_project(ALICE, "cert_watch") is True
    assert can_read_project(BOB, "dossier_test") is True
    assert can_read_project(AGENT_GLM, "dossier_test") is True


def test_authz_seam_all_project_routes_go_through_seam(client, monkeypatch):
    """All project-accessing routes return 403 when can_read_project is False."""
    _login(client)
    issue_url = _create_issue_via_ui(client, "dossier-test", "Seam test")

    monkeypatch.setattr("dossier.app.can_read_project", lambda actor, project: False)

    resp = client.get("/p/dossier-test")
    assert resp.status_code == 403

    resp = client.get("/p/dossier-test/issues/new")
    assert resp.status_code == 403

    resp = client.get(issue_url)
    assert resp.status_code == 403

    csrf = _extract_csrf(client.get("/p/dossier-test/issues/new").text) if False else "dummy"
    resp = client.post(
        "/p/dossier-test/issues",
        data={"type": "bug", "title": "blocked", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 403

    wi_id = issue_url.split("/")[-1]
    resp = client.post(
        f"/p/dossier-test/issues/{wi_id}/comments",
        data={"body": "blocked comment", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 403

    resp = client.post(
        "/p/dossier-test/owner",
        data={"owner_actor_id": "evil", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 403


def test_authz_seam_blocks_unauthorized_access(multi_client, monkeypatch):
    """can_read_project returning False for one project blocks only that project."""
    _login(multi_client)

    def selective(actor, project):
        if project == _PROJECT_A:
            return False
        return True

    monkeypatch.setattr("dossier.app.can_read_project", selective)

    resp_a = multi_client.get("/p/dossier-test")
    assert resp_a.status_code == 403

    resp_b = multi_client.get("/p/cert-watch")
    assert resp_b.status_code == 200


# ── 2. Cross-project dashboard ──────────────────────────────────────────


def test_dashboard_shows_open_items_across_projects(multi_client):
    _login(multi_client)
    _create_issue_via_ui(multi_client, "dossier-test", "Issue in A")
    _create_issue_via_ui(multi_client, "cert-watch", "Issue in B")

    resp = multi_client.get("/")
    assert resp.status_code == 200
    assert "Issue in A" in resp.text
    assert "Issue in B" in resp.text


def test_dashboard_shows_project_summary_table(multi_client):
    _login(multi_client)
    _create_issue_via_ui(multi_client, "dossier-test", "Summary A")
    _create_issue_via_ui(multi_client, "cert-watch", "Summary B")

    resp = multi_client.get("/")
    assert resp.status_code == 200
    assert "dossier_test" in resp.text
    assert "cert_watch" in resp.text
    assert "owner" in resp.text.lower()
    assert "open items" in resp.text.lower()


def test_dashboard_filter_by_project(multi_client):
    _login(multi_client)
    _create_issue_via_ui(multi_client, "dossier-test", "Alpha in A")
    _create_issue_via_ui(multi_client, "cert-watch", "Beta in B")

    resp = multi_client.get("/?project=dossier-test")
    assert resp.status_code == 200
    assert "Alpha in A" in resp.text
    assert "Beta in B" not in resp.text


def test_dashboard_filter_by_status(multi_client):
    _login(multi_client)
    _create_issue_via_ui(multi_client, "dossier-test", "Open issue")

    resp = multi_client.get("/?status=open")
    assert resp.status_code == 200
    assert "Open issue" in resp.text

    resp_done = multi_client.get("/?status=done")
    assert resp_done.status_code == 200
    assert "Open issue" not in resp_done.text


def test_dashboard_search_query(multi_client):
    _login(multi_client)
    _create_issue_via_ui(multi_client, "dossier-test", "UniqueNeedle")
    _create_issue_via_ui(multi_client, "dossier-test", "OtherIssue")
    _create_issue_via_ui(multi_client, "cert-watch", "AnotherThing")

    resp = multi_client.get("/?q=UniqueNeedle")
    assert resp.status_code == 200
    assert "UniqueNeedle" in resp.text
    assert "OtherIssue" not in resp.text
    assert "AnotherThing" not in resp.text


def test_dashboard_xss_safe(multi_client):
    """Issue titles with HTML are escaped by Jinja2 autoescaping."""
    _login(multi_client)
    _create_issue_via_ui(multi_client, "dossier-test", "<script>alert(1)</script>")

    resp = multi_client.get("/")
    assert resp.status_code == 200
    assert "<script>alert(1)</script>" not in resp.text
    assert "&lt;script&gt;" in resp.text


def test_dashboard_large_estate_cap(triple_client):
    """Dashboard caps at 200 items and shows the cap message."""
    _login(triple_client)
    for project in [_PROJECT_A, _PROJECT_B, _PROJECT_C]:
        gw = triple_client.app.state.registry.get(project)
        for i in range(75):
            gw.create_issue(
                actor=ALICE,
                work_item_type="bug",
                custom_fields={"title": f"Bulk {project} {i}"},
            )

    resp = triple_client.get("/")
    assert resp.status_code == 200
    assert "showing first 200" in resp.text


def test_dashboard_empty_estate(multi_client):
    """Dashboard with no items shows the empty-estate message."""
    _login(multi_client)
    resp = multi_client.get("/")
    assert resp.status_code == 200
    assert "no open items across the estate" in resp.text


# ── 3. Estate-wide search ──────────────────────────────────────────────


def test_search_route_returns_results(multi_client):
    _login(multi_client)
    _create_issue_via_ui(multi_client, "dossier-test", "SearchableTitle")

    resp = multi_client.get("/search?q=SearchableTitle")
    assert resp.status_code == 200
    assert "SearchableTitle" in resp.text


def test_search_route_empty_query(multi_client):
    _login(multi_client)
    resp = multi_client.get("/search")
    assert resp.status_code == 200
    assert "search the estate" in resp.text.lower()


def test_search_route_no_results(multi_client):
    _login(multi_client)
    resp = multi_client.get("/search?q=nonexistentxyz123")
    assert resp.status_code == 200
    assert "no results" in resp.text.lower()


def test_search_results_across_projects(multi_client):
    _login(multi_client)
    _create_issue_via_ui(multi_client, "dossier-test", "CommonKeyword issue")
    _create_issue_via_ui(multi_client, "cert-watch", "CommonKeyword task")

    resp = multi_client.get("/search?q=CommonKeyword")
    assert resp.status_code == 200
    assert "CommonKeyword issue" in resp.text
    assert "CommonKeyword task" in resp.text


# ── 4. Issue detail: assurance, signer, what-changed ────────────────────


def test_issue_detail_shows_assurance_level_unreviewed(client):
    """A freshly created issue shows 'unreviewed' assurance."""
    _login(client)
    issue_url = _create_issue_via_ui(client, "dossier-test", "Unreviewed issue")

    detail = client.get(issue_url)
    assert detail.status_code == 200
    assert "unreviewed" in detail.text


def test_issue_detail_shows_assurance_level_human_accepted(client):
    """An issue accepted by a human shows 'human-accepted' assurance."""
    _login(client)
    issue_url = _create_issue_via_ui(client, "dossier-test", "Human accepted issue")
    wi_id = uuid.UUID(issue_url.split("/")[-1])
    gw = _gw(client, _PROJECT_A)

    gw.transition(actor=ALICE, work_item_id=wi_id, transition_name="start")
    gw.transition(actor=ALICE, work_item_id=wi_id, transition_name="submit_for_review")
    gw.transition(
        actor=BOB,
        work_item_id=wi_id,
        transition_name="adversarial_pass",
        payload={"review_note": "lgtm"},
    )
    gw.transition(
        actor=CAROL,
        work_item_id=wi_id,
        transition_name="accept",
        payload={"review_note": "accepted"},
    )

    detail = client.get(issue_url)
    assert detail.status_code == 200
    assert "human-accepted" in detail.text


def test_issue_detail_shows_verified_signer_badge(client):
    """Each event in the history shows a 'signed' or 'unverified' badge."""
    _login(client)
    issue_url = _create_issue_via_ui(client, "dossier-test", "Signer badge test")

    detail = client.get(issue_url)
    assert detail.status_code == 200
    assert "signed" in detail.text or "unverified" in detail.text


def test_issue_detail_shows_what_changed_summary(client):
    """The 'last:' chip appears when the viewer is not the creator."""
    _login(client)
    gw = _gw(client, _PROJECT_A)
    wi, _ = gw.create_issue(
        actor=BOB,
        work_item_type="bug",
        custom_fields={"title": "What changed test"},
    )
    issue_url = f"/p/dossier-test/issues/{wi.work_item_id}"

    detail = client.get(issue_url)
    assert detail.status_code == 200
    assert "last:" in detail.text


def test_issue_detail_assurance_level_self_reviewed(client):
    """A same-lineage agent review shows 'self-reviewed' assurance."""
    from dossier.actors import Actor

    AGENT_GLM_2 = Actor(
        actor_id="agent-glm-2",
        actor_kind="agent",
        display_name="GLM Agent 2",
        model_lineage="glm",
    )

    _login(client)
    gw = _gw(client, _PROJECT_A)
    wi, _ = gw.create_issue(
        actor=AGENT_GLM,
        work_item_type="bug",
        custom_fields={"title": "Self reviewed issue"},
    )

    gw.transition(actor=AGENT_GLM, work_item_id=wi.work_item_id, transition_name="start")
    gw.transition(
        actor=AGENT_GLM, work_item_id=wi.work_item_id, transition_name="submit_for_review"
    )
    gw.transition(
        actor=AGENT_GLM_2,
        work_item_id=wi.work_item_id,
        transition_name="adversarial_pass",
        payload={
            "review_note": "same lineage ack",
            "same_lineage_acknowledged": True,
        },
    )

    issue_url = f"/p/dossier-test/issues/{wi.work_item_id}"
    detail = client.get(issue_url)
    assert detail.status_code == 200
    assert "self-reviewed" in detail.text


# ── 5. Nav links and unauthenticated redirects ──────────────────────────


def test_nav_links_present(multi_client):
    """Dashboard nav has links to dashboard, search, and my identity."""
    _login(multi_client)
    resp = multi_client.get("/")
    assert resp.status_code == 200
    assert 'href="/"' in resp.text
    assert 'href="/search"' in resp.text
    assert 'href="/me/identity"' in resp.text


def test_unauthenticated_dashboard_redirects(multi_client):
    """GET / redirects to /login when not authenticated."""
    resp = multi_client.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_unauthenticated_search_redirects(multi_client):
    """GET /search redirects to /login when not authenticated."""
    resp = multi_client.get("/search", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"
