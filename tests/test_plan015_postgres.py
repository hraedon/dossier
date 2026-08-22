"""Plan 015 wiring tests against real regista + Postgres.

These tests exercise the production code path where regista's principal-key
registry is available: enroll/rotate/revoke/idempotency. They skip cleanly when
Postgres is not reachable.

Enrollment setup uses the client-signer exchange (the supported custody-isolated
flow) — the legacy in-process enrollment is fail-closed against real regista.
"""

from __future__ import annotations

import base64
import json
import os
import re
import uuid
from datetime import datetime
from pathlib import Path

import pytest
from _trust_lifecycle_fixtures import TRUST_ROOT, provision_trust_log
from conftest import extract_csrf as _extract_csrf
from conftest import login as _login
from fastapi.testclient import TestClient
from regista import Regista
from regista.client_signer import ClientSigner
from regista.principal_lifecycle import PossessionChallenge
from regista.testing import InMemoryRegista, drop_project_schema, make_v6_keyset, open_v6_epoch

from dossier.app import create_app
from dossier.auth.backends import LocalBackend
from dossier.auth.passwords import hash_password
from dossier.config import Settings
from dossier.gateway import RegistaGateway
from dossier.multi import GatewayRegistry, project_to_slug

_DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
_ALICE_ID = "human:alice"
_BOB_ID = "human:bob"


def _new_principal(label: str) -> str:
    return f"human:{label}-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def pg_client(tmp_path_factory):
    key_path = tmp_path_factory.mktemp("pg_keys") / "keys.json"
    principals = (_ALICE_ID, _BOB_ID, TRUST_ROOT)
    keyset = make_v6_keyset(key_path.parent, principals=principals, filename=key_path.name)
    work_principals = (_ALICE_ID, _BOB_ID)
    project = f"dossier_plan015_{uuid.uuid4().hex[:8]}"

    prev_admin_ids = os.environ.get("DOSSIER_ADMIN_IDS", "")
    os.environ["DOSSIER_ADMIN_IDS"] = f"{_ALICE_ID},{_BOB_ID}"

    from dossier.auth.step_up import DossierApprovalVerifier

    try:
        reg = Regista.create_project(
            _DSN,
            project,
            hmac_key_path=keyset.path,
            approval_verifier=DossierApprovalVerifier("test-session-secret-not-for-prod"),
        )
        open_v6_epoch(reg, keyset, principals=work_principals)
        trust_dir = tmp_path_factory.mktemp("trust_log")
        trust_reg, trust_genesis_path = provision_trust_log(
            _DSN,
            project,
            keyset,
            trust_dir,
            DossierApprovalVerifier("test-session-secret-not-for-prod"),
        )
    except Exception as exc:
        os.environ["DOSSIER_ADMIN_IDS"] = prev_admin_ids
        pytest.skip(f"Postgres unavailable: {exc}")

    gw = RegistaGateway(reg, project_name=project, lifecycle_regista=trust_reg)
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
        trust_log_project=f"{project}_trust",
        trust_genesis_path=str(trust_genesis_path),
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
        drop_project_schema(_DSN, f"{project}_trust")
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
                    "principal_id": _ALICE_ID,
                },
                {
                    "stable_id": _BOB_ID,
                    "username": "bob",
                    "display_name": "Bob",
                    "password": hash_password("s3cret"),
                    "groups": [],
                    "principal_id": _BOB_ID,
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


def _csrf_token(client: TestClient) -> str:
    return client.get("/csrf").json()["csrf_token"]


_SESSION_SECRET = "test-session-secret-not-for-prod"


def _step_up_evidence_json(digest: str, approver_id: str) -> str:
    """Produce valid step-up evidence JSON for direct gateway approval calls."""
    from datetime import UTC, datetime

    from dossier.auth.step_up import produce_step_up_evidence

    evidence = produce_step_up_evidence(
        _SESSION_SECRET,
        datetime.now(UTC),
        digest,
        approver_id,
    )
    return json.dumps(evidence.to_dict())


def _enroll_via_signer(client: TestClient, principal: str) -> dict:
    """Enroll a principal via the client-signer exchange (custody-isolated).

    Drives the full flow: prepare → possession proof → approve+commit (bob).
    Returns the prepared operation dict (operation_id, digest, state, etc.).
    The principal has an active key in the registry after this call.
    """
    key_dir = Path("/tmp/opencode") / f"signer-{principal}-{uuid.uuid4().hex[:6]}"
    signer = ClientSigner.generate(principal, backend="file", private_key_dir=str(key_dir))

    _login_as(client, "alice")
    slug = project_to_slug(_project(client))
    resp = client.post(
        f"/admin/p/{slug}/lifecycle/enroll/prepare",
        json={
            "principal_id": principal,
            "public_key": base64.b64encode(signer.identity.public_key).decode("ascii"),
        },
        headers={"X-CSRF-Token": _csrf_token(client)},
    )
    assert resp.status_code == 200, resp.text
    prepared = resp.json()

    challenge = PossessionChallenge(
        **{
            k: v
            for k, v in prepared["challenge"].items()
            if k not in ("domain", "issued_at", "expires_at")
        },
        issued_at=datetime.fromisoformat(prepared["challenge"]["issued_at"]),
        expires_at=datetime.fromisoformat(prepared["challenge"]["expires_at"]),
    )
    proof = signer.sign_possession(challenge)
    resp = client.post(
        f"/admin/p/{slug}/lifecycle/{prepared['operation_id']}/possession",
        json=proof.to_dict(),
        headers={"X-CSRF-Token": _csrf_token(client)},
    )
    assert resp.status_code == 200, resp.text

    _login_as(client, "bob")
    resp = client.post(
        f"/admin/p/{slug}/lifecycle/{prepared['operation_id']}/approve",
        data={
            "csrf_token": _csrf_token(client),
            "approval_digest": prepared["digest"],
            "reason": "test enrollment",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    return prepared


def test_pg_legacy_enroll_is_fail_closed(pg_client):
    """The legacy in-process enrollment route is rejected against real regista.

    Production enrollment uses the client-signer exchange; the web process
    must never generate private key material.
    """
    _login(pg_client)
    roster_page = pg_client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)

    new_principal = _new_principal("new-user")
    resp = pg_client.post(
        "/admin/principals/enroll",
        data={"principal_id": new_principal, "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "client-signer" in resp.text.lower() or "disabled" in resp.text.lower()

    # No key was registered.
    gw = _gw(pg_client)
    assert gw.get_principal_key(new_principal) is None


def test_pg_enroll_via_signer_emits_event_and_shows_fingerprint(pg_client):
    """The client-signer enrollment flow registers the key and emits an event."""
    new_principal = _new_principal("new-user")
    _enroll_via_signer(pg_client, new_principal)

    _login(pg_client)
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

    events = gw.read_principal_enrollment_events(new_principal)
    enroll_events = [e for e in events if e.transition == "principal_key_enrolled"]
    assert len(enroll_events) == 1
    payload = enroll_events[0].payload
    assert payload["principal_id"] == new_principal
    assert payload["fingerprint"] == entry["fingerprint"]


def test_pg_rotate_is_fail_closed(pg_client):
    # Web key rotation is disabled against real regista until the client-side
    # custody helper can produce a possession proof. See Foundation B.
    principal = _new_principal("rotate-fc")
    _enroll_via_signer(pg_client, principal)

    gw = _gw(pg_client)
    old = gw.get_principal_key(principal)
    assert old is not None
    old_key_id = old["key_id"]

    # The /me/key/rotate route is for the session's own identity; we test the
    # gateway-level fail-closed directly since the session user differs from
    # the enrolled principal.
    from regista import ErrorCode, RegistaError

    from dossier.actors import Actor

    actor = Actor(actor_id=principal, actor_kind="human", display_name="Test")
    with pytest.raises(RegistaError) as exc_info:
        gw.rotate_principal(principal, actor=actor)
    assert exc_info.value.code == ErrorCode.SECRET_WRITE_UNSUPPORTED

    # No new key was registered; the enrolled key remains active.
    new = gw.get_principal_key(principal)
    assert new is not None
    assert new["key_id"] == old_key_id


def test_pg_revoke_key(pg_client):
    principal = _new_principal("revoke-user")
    _enroll_via_signer(pg_client, principal)

    gw = _gw(pg_client)
    active = gw.get_principal_key(principal)
    assert active is not None

    # Phase 1: alice initiates revocation. The operation is prepared, not
    # approved or committed, so the key is still active.
    _login_as(pg_client, "alice")
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
    revoke_events = [
        e for e in events if getattr(e, "transition", "") == "principal_key_revoked"
    ]
    assert len(revoke_events) == 1
    assert revoke_events[0].payload["key_id"] == active["key_id"]

    # No private key material is exposed.
    for event in events:
        payload = event.payload if isinstance(event.payload, dict) else {}
        for forbidden in ("private_key", "private", "secret"):
            assert forbidden not in payload, f"event payload contains {forbidden!r}"


def test_pg_revoke_self_approval_rejected_http(pg_client):
    # The same admin cannot initiate and approve a protected revocation.
    principal = _new_principal("revoke-self")
    _enroll_via_signer(pg_client, principal)

    gw = _gw(pg_client)
    active = gw.get_principal_key(principal)
    assert active is not None

    _login_as(pg_client, "alice")
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
    principal = _new_principal("revoke-digest")
    _enroll_via_signer(pg_client, principal)

    gw = _gw(pg_client)
    active = gw.get_principal_key(principal)
    assert active is not None

    _login_as(pg_client, "alice")
    csrf = _extract_csrf(pg_client.get("/admin/principals").text)
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


def test_pg_enroll_idempotent_via_signer(pg_client):
    """The client-signer enrollment produces exactly one enrolled event."""
    principal = _new_principal("idempotent-user")
    _enroll_via_signer(pg_client, principal)

    gw = _gw(pg_client)
    events = gw.read_principal_enrollment_events(principal)
    enroll_events = [e for e in events if e.transition == "principal_key_enrolled"]
    assert len(enroll_events) == 1
    first_fingerprint = enroll_events[0].payload["fingerprint"]

    # The active key matches the enrolled fingerprint.
    active = gw.get_principal_key(principal)
    assert active is not None
    assert active["fingerprint"] == first_fingerprint


def test_pg_revoke_principal_lifecycle_returns_receipt_and_revokes(pg_client):
    # Drive the gateway directly so we can inspect the registry receipt.
    principal = _new_principal("revoke-lifecycle")
    _enroll_via_signer(pg_client, principal)

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
        step_up_evidence=_step_up_evidence_json(operation["digest"], _BOB_ID),
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
    revoke_events = [
        e for e in events if getattr(e, "transition", "") == "principal_key_revoked"
    ]
    assert len(revoke_events) == 1


def test_pg_revocation_is_idempotent(pg_client):
    principal = _new_principal("revoke-idem")
    _enroll_via_signer(pg_client, principal)

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
        step_up_evidence=_step_up_evidence_json(operation1["digest"], _BOB_ID),
    )
    gw.commit_operation(
        operation1["operation_id"], expected_digest=operation1["digest"]
    )

    events = gw.read_principal_enrollment_events(principal)
    revoke_events = [
        e for e in events if getattr(e, "transition", "") == "principal_key_revoked"
    ]
    assert len(revoke_events) == 1


def test_pg_approve_operation_seam_requires_dual_control(pg_client):
    principal = _new_principal("approve-dual")
    _enroll_via_signer(pg_client, principal)

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

    # A different approver with the correct digest and valid evidence succeeds.
    approver = Actor(
        actor_id=_BOB_ID,
        actor_kind="human",
        display_name="Bob",
    )
    approved = gw.approve_operation(
        operation["operation_id"],
        approver=approver,
        approval_digest=operation["digest"],
        step_up_evidence=_step_up_evidence_json(operation["digest"], _BOB_ID),
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
    principal = _new_principal("approve-digest")
    _enroll_via_signer(pg_client, principal)

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
    principal = _new_principal("lifecycle-http")
    _enroll_via_signer(pg_client, principal)

    gw = _gw(pg_client)
    active = gw.get_principal_key(principal)
    assert active is not None

    from regista import PrincipalKind, RevocationRequest
    from regista.principal_lifecycle import CONTRACT_VERSION

    from dossier.actors import Actor

    initiator = Actor(
        actor_id=_ALICE_ID,
        actor_kind="human",
        display_name="Alice",
    )
    lifecycle = gw.principal_lifecycle
    request = RevocationRequest(
        principal_id=principal,
        principal_kind=PrincipalKind.HUMAN,
        actor_id=initiator.actor_id,
        key_id=active["key_id"],
        reason="test http mapping",
        requested_authority="registrar",
        policy_version=CONTRACT_VERSION,
    )
    operation = lifecycle.prepare_revocation(
        request, idempotency_key=f"http-mapping:{principal}"
    )

    _login_as(pg_client, "bob")
    csrf = _extract_csrf(pg_client.get("/admin/principals").text)
    resp = pg_client.post(
        f"/admin/p/{project_to_slug(_project(pg_client))}/lifecycle/{operation.operation_id}/approve",
        data={"approval_digest": "wrong", "csrf_token": csrf, "reason": "test"},
        follow_redirects=False,
    )
    assert resp.status_code == 400


def test_pg_approve_requires_explicit_digest(pg_client):
    """Approval without an explicit digest is rejected (Fix 2 regression)."""
    principal = _new_principal("approve-nodigest")
    _enroll_via_signer(pg_client, principal)

    gw = _gw(pg_client)
    active = gw.get_principal_key(principal)
    assert active is not None

    _login_as(pg_client, "alice")
    csrf = _extract_csrf(pg_client.get("/admin/principals").text)
    resp = pg_client.post(
        f"/admin/principals/{principal}/revoke",
        data={"csrf_token": csrf, "reason": "digest-required test"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    operation_id = _extract_operation_id(resp.text)

    # Approve without supplying approval_digest — must be rejected.
    _login_as(pg_client, "bob")
    approve_csrf = _extract_csrf(pg_client.get("/admin/principals").text)
    resp = pg_client.post(
        f"/admin/p/{project_to_slug(_project(pg_client))}/lifecycle/{operation_id}/approve",
        data={"csrf_token": approve_csrf, "reason": "no digest"},
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "approval_digest is required" in resp.text

    # The operation is still awaiting approval.
    operation = gw.principal_lifecycle.get_operation(operation_id)
    assert operation.state.value == "awaiting_approval"


def test_pg_approve_rejects_stale_digest(pg_client):
    """Approval with a digest from a different operation is rejected."""
    principal = _new_principal("approve-stale")
    prepared = _enroll_via_signer(pg_client, principal)

    gw = _gw(pg_client)
    active = gw.get_principal_key(principal)
    assert active is not None

    _login_as(pg_client, "alice")
    csrf = _extract_csrf(pg_client.get("/admin/principals").text)
    resp = pg_client.post(
        f"/admin/principals/{principal}/revoke",
        data={"csrf_token": csrf, "reason": "stale digest test"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    operation_id = _extract_operation_id(resp.text)

    # Use the enrollment digest (from a different operation) — must be rejected.
    _login_as(pg_client, "bob")
    approve_csrf = _extract_csrf(pg_client.get("/admin/principals").text)
    resp = pg_client.post(
        f"/admin/p/{project_to_slug(_project(pg_client))}/lifecycle/{operation_id}/approve",
        data={
            "csrf_token": approve_csrf,
            "approval_digest": prepared["digest"],
            "reason": "stale digest",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "digest" in resp.text.lower()


def test_pg_roster_page_disables_legacy_enrollment_on_durable_backend(pg_client):
    """The principal roster page renders the legacy form as disabled when a
    durable lifecycle backend is configured (Item 4 regression)."""
    _login_as(pg_client, "alice")
    resp = pg_client.get("/admin/principals")
    assert resp.status_code == 200
    # Normalize whitespace for multi-line template text assertions.
    normalized = " ".join(resp.text.split()).lower()
    # The page must clearly state client-signer integration is required.
    assert "client-signer integration required" in normalized
    # The form inputs must be disabled.
    assert "disabled" in resp.text
    # The page must NOT present the form as an actionable production control.
    assert "not supported through this page" in normalized
