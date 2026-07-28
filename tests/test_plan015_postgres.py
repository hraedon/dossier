"""Plan 015 wiring tests against real regista + Postgres.

These tests exercise the production code path where regista's principal-key
registry is available: enroll/rotate/revoke/idempotency. They skip cleanly when
Postgres is not reachable.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path

import pytest
from conftest import extract_csrf as _extract_csrf
from conftest import login as _login
from fastapi.testclient import TestClient
from regista import Regista
from regista.testing import InMemoryRegista, drop_project_schema

from dossier.app import create_app
from dossier.auth.backends import LocalBackend
from dossier.auth.passwords import hash_password
from dossier.config import Settings
from dossier.gateway import RegistaGateway
from dossier.keys import generate_keyset
from dossier.multi import GatewayRegistry, project_to_slug

_DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
_ALICE_ID = "11111111-1111-1111-1111-111111111111"
_BOB_ID = "22222222-2222-2222-2222-222222222222"


@pytest.fixture(scope="module")
def pg_client(tmp_path_factory):
    key_path = tmp_path_factory.mktemp("pg_keys") / "keys.json"
    generate_keyset(key_path)
    project = f"dossier_plan015_{uuid.uuid4().hex[:8]}"

    prev_admin_ids = os.environ.get("DOSSIER_ADMIN_IDS", "")
    os.environ["DOSSIER_ADMIN_IDS"] = f"{_ALICE_ID},{_BOB_ID}"

    try:
        reg = Regista.create_project(_DSN, project, hmac_key_path=str(key_path))
    except Exception as exc:
        os.environ["DOSSIER_ADMIN_IDS"] = prev_admin_ids
        pytest.skip(f"Postgres unavailable: {exc}")

    gw = RegistaGateway(reg, project_name=project)
    gw.register_workflow()
    InMemoryRegista._catalog.clear()

    tmp_path = tmp_path_factory.mktemp("pg_client")
    settings = Settings(
        database_url=_DSN,
        project=project,
        hmac_key_path=str(key_path),
        session_secret="test-session-secret-not-for-prod",
        session_max_age_seconds=43200,
        secure_cookies=False,
        require_ssl=False,
        users_path=str(_users_file(tmp_path)),
        auth_backend="local",
        principal_key_dir=str(tmp_path / "principals"),
            # explicit: this fixture exercises features, not authz (WI-017)
        project_access_mode="open",
    )
    backend = LocalBackend(_users_file(tmp_path))
    registry = GatewayRegistry(known_projects=[project])
    registry.add(project, gw)
    app = create_app(settings, registry, backend)

    try:
        with TestClient(app) as client:
            client.app.state._test_project = project
            yield client
    finally:
        InMemoryRegista._catalog.clear()
        gw.close()
        drop_project_schema(_DSN, project)
        os.environ["DOSSIER_ADMIN_IDS"] = prev_admin_ids


def _users_file(tmp_path: Path) -> Path:
    path = tmp_path / "users.json"
    path.write_text(
        json.dumps(
            [
                {
                    "stable_id": _ALICE_ID,
                    "username": "alice",
                    "display_name": "Alice",
                    "password": hash_password("s3cret"),
                    "groups": [],
                },
                {
                    "stable_id": _BOB_ID,
                    "username": "bob",
                    "display_name": "Bob",
                    "password": hash_password("s3cret"),
                    "groups": [],
                },
            ]
        ),
        encoding="utf-8",
    )
    return path


def _login_as(client: TestClient, username: str) -> None:
    from conftest import extract_csrf as _extract_csrf

    page = client.get("/login")
    csrf = _extract_csrf(page.text)
    resp = client.post(
        "/login",
        data={"username": username, "password": "s3cret", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/"


def _project(client: TestClient) -> str:
    return client.app.state._test_project


def _gw(client: TestClient) -> RegistaGateway:
    return client.app.state.registry.get(_project(client))


_OPERATION_ID_RE = re.compile(r"operation_id</[^>]+>[^<]*<[^>]+>([a-f0-9\-]+)</")


def _extract_operation_id(html: str) -> str:
    m = _OPERATION_ID_RE.search(html)
    assert m, "operation_id not found in HTML"
    return m.group(1)


def test_pg_enroll_principal_emits_event_and_shows_fingerprint(pg_client):
    _login(pg_client)
    roster_page = pg_client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)

    new_principal = f"new-user-{uuid.uuid4().hex[:8]}"
    resp = pg_client.post(
        "/admin/principals/enroll",
        data={"principal_id": new_principal, "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    roster = pg_client.get("/admin/principals")
    assert roster.status_code == 200

    gw = _gw(pg_client)
    entries = gw.list_principals(principal_id=new_principal)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["fingerprint"].startswith("ed25519:sha256:")

    assert entry["fingerprint"][:32] in roster.text
    assert entry["key_id"] in roster.text
    assert entry["public_key"] not in roster.text
    assert "private" not in roster.text.lower()

    events = gw.read_principal_enrollment_events(new_principal)
    assert len(events) == 1
    assert events[0].transition == "principal_enrolled"
    payload = events[0].payload
    assert payload["principal_id"] == new_principal
    assert payload["key_id"] == entry["key_id"]
    assert payload["fingerprint"] == entry["fingerprint"]


def test_pg_rotate_is_fail_closed(pg_client):
    # Web key rotation is disabled against real regista until the client-side
    # custody helper can produce a possession proof. See Foundation B.
    _login(pg_client)
    roster_page = pg_client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)
    pg_client.post(
        "/admin/principals/enroll",
        data={"principal_id": _ALICE_ID, "csrf_token": csrf},
        follow_redirects=False,
    )

    gw = _gw(pg_client)
    old = gw.get_principal_key(_ALICE_ID)
    assert old is not None
    old_key_id = old["key_id"]

    identity_page = pg_client.get("/me/identity")
    csrf = _extract_csrf(identity_page.text)

    resp = pg_client.post(
        "/me/key/rotate",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "not yet available" in resp.text.lower() or "disabled" in resp.text.lower()

    # No new key was registered; the enrolled key remains active.
    new = gw.get_principal_key(_ALICE_ID)
    assert new is not None
    assert new["key_id"] == old_key_id


def test_pg_revoke_key(pg_client):
    _login(pg_client)
    principal = f"revoke-user-{uuid.uuid4().hex[:8]}"
    roster_page = pg_client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)
    pg_client.post(
        "/admin/principals/enroll",
        data={"principal_id": principal, "csrf_token": csrf},
        follow_redirects=False,
    )

    gw = _gw(pg_client)
    active = gw.get_principal_key(principal)
    assert active is not None

    # Phase 1: an admin initiates revocation. The operation is prepared, not
    # approved or committed, so the key is still active.
    roster_page = pg_client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)
    resp = pg_client.post(
        f"/admin/principals/{principal}/revoke",
        data={"csrf_token": csrf, "reason": "test revoke"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert "pending approval" in resp.text.lower()
    assert gw.get_principal_key(principal) is not None

    operation_id = _extract_operation_id(resp.text)
    lifecycle = gw.principal_lifecycle
    operation = lifecycle.get_operation(operation_id)
    assert operation.state.value == "awaiting_approval"

    # Phase 2: a different admin approves and commits.
    _login_as(pg_client, "bob")
    approve_csrf = _extract_csrf(pg_client.get("/admin/principals").text)
    resp = pg_client.post(
        f"/admin/p/{project_to_slug(_project(pg_client))}/lifecycle/{operation_id}/approve",
        data={
            "csrf_token": approve_csrf,
            "approval_digest": operation.digest.value,
            "reason": "approved by bob",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303

    assert gw.get_principal_key(principal) is None
    entries = gw.list_principals(principal_id=principal)
    assert any(e["status"] == "revoked" and e["key_id"] == active["key_id"] for e in entries)

    # The durable lifecycle operation committed and emitted a signed event.
    events = gw.read_principal_enrollment_events(principal)
    revoke_events = [e for e in events if getattr(e, "transition", "") == "principal_revoked"]
    assert len(revoke_events) == 1
    assert revoke_events[0].payload["old_key_id"] == active["key_id"]

    # No private key material is exposed.
    for event in events:
        payload = event.payload if isinstance(event.payload, dict) else {}
        for forbidden in ("private_key", "private", "secret"):
            assert forbidden not in payload, f"event payload contains {forbidden!r}"


def test_pg_revoke_self_approval_rejected_http(pg_client):
    # The same admin cannot initiate and approve a protected revocation.
    _login(pg_client)
    principal = f"revoke-self-{uuid.uuid4().hex[:8]}"
    roster_page = pg_client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)
    pg_client.post(
        "/admin/principals/enroll",
        data={"principal_id": principal, "csrf_token": csrf},
        follow_redirects=False,
    )

    gw = _gw(pg_client)
    active = gw.get_principal_key(principal)
    assert active is not None

    roster_page = pg_client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)
    resp = pg_client.post(
        f"/admin/principals/{principal}/revoke",
        data={"csrf_token": csrf, "reason": "self-approval test"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    operation_id = _extract_operation_id(resp.text)
    operation = gw.principal_lifecycle.get_operation(operation_id)

    # Alice tries to approve her own initiation; the route must reject it.
    approve_csrf = _extract_csrf(pg_client.get("/admin/principals").text)
    resp = pg_client.post(
        f"/admin/p/{project_to_slug(_project(pg_client))}/lifecycle/{operation_id}/approve",
        data={
            "csrf_token": approve_csrf,
            "approval_digest": operation.digest.value,
            "reason": "self-approved",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "different approver" in resp.text.lower() or "dual-control" in resp.text.lower()

    # The key is still active because the operation was never committed.
    assert gw.get_principal_key(principal) is not None


def test_pg_revoke_digest_binding_is_server_authoritative(pg_client):
    # A tampered client-supplied digest is rejected before approval.
    _login(pg_client)
    principal = f"revoke-digest-{uuid.uuid4().hex[:8]}"
    roster_page = pg_client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)
    pg_client.post(
        "/admin/principals/enroll",
        data={"principal_id": principal, "csrf_token": csrf},
        follow_redirects=False,
    )

    gw = _gw(pg_client)
    active = gw.get_principal_key(principal)
    assert active is not None

    resp = pg_client.post(
        f"/admin/principals/{principal}/revoke",
        data={"csrf_token": csrf, "reason": "digest binding test"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    operation_id = _extract_operation_id(resp.text)

    _login_as(pg_client, "bob")
    approve_csrf = _extract_csrf(pg_client.get("/admin/principals").text)
    resp = pg_client.post(
        f"/admin/p/{project_to_slug(_project(pg_client))}/lifecycle/{operation_id}/approve",
        data={
            "csrf_token": approve_csrf,
            "approval_digest": "tampered-digest",
            "reason": "tampered",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "digest" in resp.text.lower()

    assert gw.get_principal_key(principal) is not None


def test_pg_enroll_idempotent(pg_client):
    _login(pg_client)
    principal = f"idempotent-user-{uuid.uuid4().hex[:8]}"
    roster_page = pg_client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)

    def enroll() -> None:
        pg_client.post(
            "/admin/principals/enroll",
            data={"principal_id": principal, "csrf_token": csrf},
            follow_redirects=False,
        )

    enroll()
    gw = _gw(pg_client)
    events_after_first = gw.read_principal_enrollment_events(principal)
    assert len(events_after_first) == 1
    first_key_id = events_after_first[0].payload["key_id"]

    roster_page = pg_client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)
    enroll()

    events_after_second = gw.read_principal_enrollment_events(principal)
    assert len(events_after_second) == 1
    assert events_after_second[0].payload["key_id"] == first_key_id


def test_pg_revoke_principal_lifecycle_returns_receipt_and_revokes(pg_client):
    # Drive the gateway directly so we can inspect the registry receipt.
    _login(pg_client)
    principal = f"revoke-lifecycle-{uuid.uuid4().hex[:8]}"
    roster_page = pg_client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)
    pg_client.post(
        "/admin/principals/enroll",
        data={"principal_id": principal, "csrf_token": csrf},
        follow_redirects=False,
    )

    gw = _gw(pg_client)
    active = gw.get_principal_key(principal)
    assert active is not None

    from regista import LifecycleContractError

    from dossier.actors import Actor

    initiator = Actor(
        actor_id=_ALICE_ID,
        actor_kind="human",
        display_name="Alice",
    )
    operation = gw.prepare_revocation_operation(
        principal, active["key_id"], actor=initiator, reason="test lifecycle"
    )
    assert operation["state"] == "awaiting_approval"

    # Single-call revoke_principal is disabled against the durable backend.
    with pytest.raises(LifecycleContractError):
        gw.revoke_principal(
            principal, active["key_id"], actor=initiator, approver=initiator
        )

    # A different approver with the server digest succeeds; commit finalizes.
    approver = Actor(
        actor_id=_BOB_ID,
        actor_kind="human",
        display_name="Bob",
    )
    approved = gw.approve_operation(
        operation["operation_id"],
        approver=approver,
        approval_digest=operation["digest"],
        reason="approved",
    )
    assert approved.state.value == "approved"

    receipt = gw.commit_operation(
        operation["operation_id"], expected_digest=operation["digest"]
    )
    assert receipt["status"] == "committed"
    assert receipt["key_id"] == active["key_id"]
    for forbidden in ("private_key", "private", "secret"):
        assert forbidden not in receipt, f"receipt contains {forbidden!r}"

    assert gw.get_principal_key(principal) is None
    events = gw.read_principal_enrollment_events(principal)
    revoke_events = [e for e in events if getattr(e, "transition", "") == "principal_revoked"]
    assert len(revoke_events) == 1


def test_pg_revocation_is_idempotent(pg_client):
    _login(pg_client)
    principal = f"revoke-idem-{uuid.uuid4().hex[:8]}"
    roster_page = pg_client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)
    pg_client.post(
        "/admin/principals/enroll",
        data={"principal_id": principal, "csrf_token": csrf},
        follow_redirects=False,
    )

    gw = _gw(pg_client)
    active = gw.get_principal_key(principal)
    assert active is not None

    from dossier.actors import Actor

    initiator = Actor(actor_id=_ALICE_ID, actor_kind="human", display_name="Alice")
    operation1 = gw.prepare_revocation_operation(
        principal, active["key_id"], actor=initiator, reason="idem"
    )
    operation2 = gw.prepare_revocation_operation(
        principal, active["key_id"], actor=initiator, reason="idem"
    )
    assert operation1["operation_id"] == operation2["operation_id"]

    approver = Actor(actor_id=_BOB_ID, actor_kind="human", display_name="Bob")
    gw.approve_operation(
        operation1["operation_id"],
        approver=approver,
        approval_digest=operation1["digest"],
    )
    gw.commit_operation(
        operation1["operation_id"], expected_digest=operation1["digest"]
    )

    events = gw.read_principal_enrollment_events(principal)
    revoke_events = [e for e in events if getattr(e, "transition", "") == "principal_revoked"]
    assert len(revoke_events) == 1


def test_pg_approve_operation_seam_requires_dual_control(pg_client):
    _login(pg_client)
    principal = f"approve-dual-{uuid.uuid4().hex[:8]}"
    roster_page = pg_client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)
    pg_client.post(
        "/admin/principals/enroll",
        data={"principal_id": principal, "csrf_token": csrf},
        follow_redirects=False,
    )

    gw = _gw(pg_client)
    active = gw.get_principal_key(principal)
    assert active is not None

    from regista import LifecycleContractError

    from dossier.actors import Actor

    initiator = Actor(
        actor_id=_ALICE_ID,
        actor_kind="human",
        display_name="Alice",
    )
    operation = gw.prepare_revocation_operation(
        principal,
        active["key_id"],
        actor=initiator,
        reason="test dual-control",
    )

    # Self-approval must be rejected by dossier, not silently accepted.
    with pytest.raises(LifecycleContractError) as exc_info:
        gw.approve_operation(
            operation["operation_id"],
            approver=initiator,
            approval_digest=operation["digest"],
        )
    assert "different approver" in str(exc_info.value).lower()

    # A different approver with the correct digest succeeds.
    approver = Actor(
        actor_id=_BOB_ID,
        actor_kind="human",
        display_name="Bob",
    )
    approved = gw.approve_operation(
        operation["operation_id"],
        approver=approver,
        approval_digest=operation["digest"],
        reason="approved",
    )
    assert approved.state.value == "approved"

    # Committing the approved operation revokes the key.
    receipt = gw.commit_operation(
        operation["operation_id"], expected_digest=operation["digest"]
    )
    assert receipt["status"] == "committed"
    assert gw.get_principal_key(principal) is None


def test_pg_approve_operation_seam_rejects_digest_mismatch(pg_client):
    _login(pg_client)
    principal = f"approve-digest-{uuid.uuid4().hex[:8]}"
    roster_page = pg_client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)
    pg_client.post(
        "/admin/principals/enroll",
        data={"principal_id": principal, "csrf_token": csrf},
        follow_redirects=False,
    )

    gw = _gw(pg_client)
    active = gw.get_principal_key(principal)
    assert active is not None

    from regista import LifecycleContractError

    from dossier.actors import Actor

    initiator = Actor(
        actor_id=_ALICE_ID,
        actor_kind="human",
        display_name="Alice",
    )
    operation = gw.prepare_revocation_operation(
        principal,
        active["key_id"],
        actor=initiator,
        reason="test digest mismatch",
    )

    approver = Actor(
        actor_id=_BOB_ID,
        actor_kind="human",
        display_name="Bob",
    )
    with pytest.raises(LifecycleContractError) as exc_info:
        gw.approve_operation(
            operation["operation_id"],
            approver=approver,
            approval_digest="wrong-digest",
        )
    msg = str(exc_info.value).lower()
    assert "approval digest" in msg or "digest mismatch" in msg


def test_pg_lifecycle_contract_error_is_not_500(pg_client):
    # A mismatched digest on the approval seam maps to HTTP 400, not 500.
    _login(pg_client)
    principal = f"lifecycle-http-{uuid.uuid4().hex[:8]}"
    roster_page = pg_client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)
    pg_client.post(
        "/admin/principals/enroll",
        data={"principal_id": principal, "csrf_token": csrf},
        follow_redirects=False,
    )

    gw = _gw(pg_client)
    active = gw.get_principal_key(principal)
    assert active is not None

    from regista import PrincipalKind, RevocationRequest
    from regista.principal_lifecycle import CONTRACT_VERSION

    from dossier.actors import Actor

    initiator = Actor(
        actor_id="initiator-admin",
        actor_kind="human",
        display_name="Initiator",
    )
    lifecycle = gw._reg.principal_lifecycle
    request = RevocationRequest(
        principal_id=principal,
        principal_kind=PrincipalKind.HUMAN,
        actor_id=initiator.actor_id,
        key_id=active["key_id"],
        reason="test http mapping",
        requested_authority="admin",
        policy_version=CONTRACT_VERSION,
    )
    operation = lifecycle.prepare_revocation(
        request, idempotency_key=f"http-mapping:{principal}"
    )

    resp = pg_client.post(
        f"/admin/p/{project_to_slug(_project(pg_client))}/lifecycle/{operation.operation_id}/approve",
        data={"approval_digest": "wrong", "csrf_token": csrf, "reason": "test"},
        follow_redirects=False,
    )
    assert resp.status_code == 400
