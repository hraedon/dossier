from __future__ import annotations

import re

from conftest import extract_csrf as _extract_csrf, login as _login


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


def test_unauthenticated_redirect_body_is_not_json(client):
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"
    assert "application/json" not in resp.headers.get("content-type", "")
    body = resp.text.strip()
    assert not body.startswith("{")
    assert "detail" not in body


def test_review_note_visibility_toggles_on_transition_select(client):
    _login(client)
    new_page = client.get("/issues/new")
    csrf = _extract_csrf(new_page.text)
    resp = client.post(
        "/issues",
        data={"type": "bug", "title": "Review note test", "csrf_token": csrf},
        follow_redirects=False,
    )
    issue_url = resp.headers["location"]

    from helpers import ALICE
    from dossier.gateway import RegistaGateway
    import uuid

    gw: RegistaGateway = client.app.state.gateway
    wi_id = uuid.UUID(issue_url.split("/")[-1])
    gw.transition(actor=ALICE, work_item_id=wi_id, transition_name="start")
    gw.transition(actor=ALICE, work_item_id=wi_id, transition_name="submit_for_review")

    detail = client.get(issue_url)
    assert detail.status_code == 200

    noted = re.findall(r'data-needs-note="true"', detail.text)
    assert len(noted) == 2
    assert 'value="adversarial_pass"' in detail.text
    assert 'value="request_changes"' in detail.text

    amend_opt = re.search(r'<option value="amend"[^>]*>', detail.text)
    assert amend_opt is not None
    assert "data-needs-note" not in amend_opt.group(0)

    assert 'id="transition-select"' in detail.text
    assert 'id="review-note-input"' in detail.text
    note_input = re.search(r'<input[^>]*id="review-note-input"[^>]*>', detail.text)
    assert note_input is not None
    assert 'style="display:none"' in note_input.group(0)


def test_integrity_check_is_per_work_item(client):
    _login(client)
    new_page = client.get("/issues/new")
    csrf = _extract_csrf(new_page.text)

    a = client.post(
        "/issues",
        data={"type": "bug", "title": "Issue A", "csrf_token": csrf},
        follow_redirects=False,
    )
    b = client.post(
        "/issues",
        data={"type": "bug", "title": "Issue B", "csrf_token": csrf},
        follow_redirects=False,
    )
    url_a = a.headers["location"]
    url_b = b.headers["location"]

    import uuid

    from dossier.gateway import RegistaGateway

    gw: RegistaGateway = client.app.state.gateway
    id_a = uuid.UUID(url_a.split("/")[-1])
    id_b = uuid.UUID(url_b.split("/")[-1])

    gw._reg._work_items[id_a]["current_state"] = "done"

    rpt_a = gw.integrity(work_item_id=id_a)
    rpt_b = gw.integrity(work_item_id=id_b)
    assert rpt_a.replayed_drift == 1
    assert rpt_b.replayed_drift == 0

    detail_b = client.get(url_b)
    assert detail_b.status_code == 200
    assert "chain verified" in detail_b.text
    assert "CHAIN BROKEN" not in detail_b.text
