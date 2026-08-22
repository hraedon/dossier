"""Step-up authentication route tests (Plan 020 Phase 3, non-Entra).

The approve seam for protected lifecycle operations requires recent
authentication: a fresh login counts, an old session must re-authenticate via
POST /auth/step-up, and the produced evidence is recorded on the durable
approval. These tests drive the flow over HTTP against real regista +
Postgres and skip cleanly when Postgres is not reachable.
"""

from __future__ import annotations

import base64
import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import psycopg
import pytest
from _trust_lifecycle_fixtures import TRUST_ROOT, provision_trust_log
from conftest import extract_csrf as _extract_csrf
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner
from psycopg import sql
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
_SESSION_SECRET = "test-session-secret-not-for-prod"
_SIGNER = TimestampSigner(_SESSION_SECRET)


def _new_principal(label: str) -> str:
    return f"human:{label}-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def pg_client(tmp_path_factory):
    key_path = tmp_path_factory.mktemp("pg_keys") / "keys.json"
    principals = (_ALICE_ID, _BOB_ID, TRUST_ROOT)
    keyset = make_v6_keyset(key_path.parent, principals=principals, filename=key_path.name)
    work_principals = (_ALICE_ID, _BOB_ID)
    project = f"dossier_stepup_{uuid.uuid4().hex[:8]}"

    prev_admin_ids = os.environ.get("DOSSIER_ADMIN_IDS", "")
    os.environ["DOSSIER_ADMIN_IDS"] = f"{_ALICE_ID},{_BOB_ID}"

    from dossier.auth.step_up import DossierApprovalVerifier

    try:
        reg = Regista.create_project(
            _DSN,
            project,
            hmac_key_path=keyset.path,
            approval_verifier=DossierApprovalVerifier(_SESSION_SECRET),
        )
        open_v6_epoch(reg, keyset, principals=work_principals)
        trust_dir = tmp_path_factory.mktemp("trust_log")
        trust_reg, trust_genesis_path = provision_trust_log(
            _DSN,
            project,
            keyset,
            trust_dir,
            DossierApprovalVerifier(_SESSION_SECRET),
        )
    except Exception as exc:
        os.environ["DOSSIER_ADMIN_IDS"] = prev_admin_ids
        pytest.skip(f"Postgres unavailable: {exc}")

    gw = RegistaGateway(reg, project_name=project, lifecycle_regista=trust_reg)
    gw.register_workflow()
    InMemoryRegista._catalog.clear()

    tmp_path = tmp_path_factory.mktemp("step_up_routes")
    settings = Settings(
        database_url=_DSN,
        project=project,
        hmac_key_path=str(key_path),
        session_secret=_SESSION_SECRET,
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
            client.app.state._signer_dir = tmp_path / "signer-keys"
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
    page = client.get("/login")
    csrf = _extract_csrf(page.text)
    resp = client.post(
        "/login",
        data={"username": username, "password": "s3cret", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 302


def _project(client: TestClient) -> str:
    return client.app.state._test_project


def _slug(client: TestClient) -> str:
    return project_to_slug(_project(client))


def _gw(client: TestClient) -> RegistaGateway:
    return client.app.state.registry.get(_project(client))


def _csrf_token(client: TestClient) -> str:
    return client.get("/csrf").json()["csrf_token"]


def _session_data(client: TestClient) -> dict:
    cookie = client.cookies.get("session")
    assert cookie is not None
    return json.loads(base64.b64decode(_SIGNER.unsign(cookie)))


def _set_session(client: TestClient, data: dict) -> None:
    payload = base64.b64encode(json.dumps(data).encode("utf-8"))
    for cookie in list(client.cookies.jar):
        if cookie.name == "session":
            client.cookies.jar.clear(cookie.domain, cookie.path, cookie.name)
    # httpx stores the server's Set-Cookie under "testserver.local"; setting
    # the forged cookie on the same domain makes later server cookies replace
    # it instead of creating a conflicting sibling.
    client.cookies.set(
        "session",
        _SIGNER.sign(payload).decode("utf-8"),
        domain="testserver.local",
        path="/",
    )


def _age_session_auth_time(client: TestClient, *, seconds: int) -> None:
    """Rewrite the signed session cookie with an old auth_time.

    The test knows the fixture's session secret, so it can do what an
    attacker cannot: forge a session. This simulates an old login without
    waiting.
    """
    data = _session_data(client)
    data["auth_time"] = (datetime.now(UTC) - timedelta(seconds=seconds)).isoformat()
    _set_session(client, data)


def _step_up(client: TestClient, password: str) -> httpx.Response:
    return client.post(
        "/auth/step-up",
        json={"password": password},
        headers={"X-CSRF-Token": _csrf_token(client)},
    )


def _enrollment_awaiting_approval(client: TestClient, principal: str) -> dict:
    """Drive a signer enrollment to awaiting_approval under alice."""
    key_dir = client.app.state._signer_dir / f"{principal}-{uuid.uuid4().hex[:6]}"
    signer = ClientSigner.generate(principal, backend="file", private_key_dir=str(key_dir))
    _login_as(client, "alice")
    resp = client.post(
        f"/admin/p/{_slug(client)}/lifecycle/enroll/prepare",
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
        f"/admin/p/{_slug(client)}/lifecycle/{prepared['operation_id']}/possession",
        json=proof.to_dict(),
        headers={"X-CSRF-Token": _csrf_token(client)},
    )
    assert resp.status_code == 200, resp.text
    return prepared


def _approve(client: TestClient, prepared: dict) -> httpx.Response:
    return client.post(
        f"/admin/p/{_slug(client)}/lifecycle/{prepared['operation_id']}/approve",
        data={
            "csrf_token": _csrf_token(client),
            "approval_digest": prepared["digest"],
            "reason": "approved by second admin",
        },
        follow_redirects=False,
    )


def _read_step_up_evidence(project: str, operation_id: str) -> dict | None:
    trust_project = f"{project}_trust"
    with psycopg.connect(_DSN) as conn:
        row = conn.execute(
            sql.SQL(
                "SELECT step_up_evidence FROM {}.lifecycle_approvals WHERE operation_id = %s"
            ).format(sql.Identifier(trust_project)),
            [operation_id],
        ).fetchone()
    if row is None or row[0] is None:
        return None
    return json.loads(row[0])


def test_step_up_refreshes_auth_time(pg_client: TestClient):
    _login_as(pg_client, "alice")
    _age_session_auth_time(pg_client, seconds=3600)

    resp = _step_up(pg_client, "s3cret")
    assert resp.status_code == 204, resp.text

    auth_time = datetime.fromisoformat(_session_data(pg_client)["auth_time"])
    age = (datetime.now(UTC) - auth_time).total_seconds()
    assert 0 <= age < 60


def test_step_up_wrong_password_rejected(pg_client: TestClient):
    _login_as(pg_client, "alice")
    _age_session_auth_time(pg_client, seconds=3600)
    stale = _session_data(pg_client)["auth_time"]

    resp = _step_up(pg_client, "wrong-password")
    assert resp.status_code == 401
    # The stale auth_time is untouched by a failed re-entry.
    assert _session_data(pg_client)["auth_time"] == stale


def test_step_up_requires_authenticated_session(pg_client: TestClient):
    pg_client.cookies.clear()
    resp = pg_client.post(
        "/auth/step-up",
        json={"password": "s3cret"},
        headers={"X-CSRF-Token": _csrf_token(pg_client)},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303, 401, 403)


def test_approve_rejected_with_stale_auth_time(pg_client: TestClient):
    principal = _new_principal("stepup-stale")
    prepared = _enrollment_awaiting_approval(pg_client, principal)

    _login_as(pg_client, "bob")
    _age_session_auth_time(pg_client, seconds=3600)
    resp = _approve(pg_client, prepared)
    assert resp.status_code == 403
    assert "step-up" in resp.text.lower()

    operation = _gw(pg_client).principal_lifecycle.get_operation(prepared["operation_id"])
    assert operation.state.value == "awaiting_approval"


def test_approve_allowed_after_step_up_reentry(pg_client: TestClient):
    principal = _new_principal("stepup-reentry")
    prepared = _enrollment_awaiting_approval(pg_client, principal)

    _login_as(pg_client, "bob")
    _age_session_auth_time(pg_client, seconds=3600)
    assert _approve(pg_client, prepared).status_code == 403

    resp = _step_up(pg_client, "s3cret")
    assert resp.status_code == 204, resp.text
    resp = _approve(pg_client, prepared)
    assert resp.status_code == 303, resp.text

    operation = _gw(pg_client).principal_lifecycle.get_operation(prepared["operation_id"])
    assert operation.state.value == "committed"


def test_step_up_evidence_recorded_on_approval(pg_client: TestClient):
    principal = _new_principal("stepup-evidence")
    prepared = _enrollment_awaiting_approval(pg_client, principal)

    # Bob's fresh login is recent auth; the approval proceeds with evidence.
    _login_as(pg_client, "bob")
    resp = _approve(pg_client, prepared)
    assert resp.status_code == 303, resp.text

    evidence = _read_step_up_evidence(_project(pg_client), prepared["operation_id"])
    assert evidence is not None
    assert evidence["operation_digest"] == prepared["digest"]
    assert evidence["principal_id"] == _BOB_ID
    assert evidence["method"] == "password_reentry"
    auth_time = datetime.fromisoformat(evidence["auth_time"])
    assert (datetime.now(UTC) - auth_time).total_seconds() < 300


def test_protected_op_mapping_covers_all_lifecycle_types():
    """Every regista lifecycle operation type maps to a protected operation.

    If regista grows a new LifecycleOperationType and nobody updates
    _PROTECTED_OP_FOR_LIFECYCLE, this fails in CI rather than 500ing in
    production.
    """
    from regista.principal_lifecycle import LifecycleOperationType

    from dossier.app import _PROTECTED_OP_FOR_LIFECYCLE

    assert set(_PROTECTED_OP_FOR_LIFECYCLE) == {t.value for t in LifecycleOperationType}


def test_step_up_throttled_after_repeated_failures(pg_client: TestClient):
    # Uses bob: the throttle is keyed per-username and other tests already
    # record step-up failures for alice. The loop tolerates the lock engaging
    # one attempt early; the final correct-password attempt must still refuse.
    _login_as(pg_client, "bob")
    for _ in range(5):
        resp = _step_up(pg_client, "wrong-password")
        assert resp.status_code in (401, 429)
    resp = _step_up(pg_client, "s3cret")
    assert resp.status_code == 429


def test_approval_evidence_verified_true_in_database(pg_client: TestClient):
    """The ApprovalVerifier records evidence_verified=true on a valid approval."""
    principal = _new_principal("stepup-verified")
    prepared = _enrollment_awaiting_approval(pg_client, principal)

    _login_as(pg_client, "bob")
    resp = _approve(pg_client, prepared)
    assert resp.status_code == 303, resp.text

    # Read the evidence_verified column directly from the database.
    with psycopg.connect(_DSN) as conn:
        row = conn.execute(
            sql.SQL(
                    "SELECT evidence_verified FROM {}.lifecycle_approvals "
                    "WHERE operation_id = %s"
                ).format(sql.Identifier(f"{_project(pg_client)}_trust")),
            [prepared["operation_id"]],
        ).fetchone()
    assert row is not None
    assert row[0] is True


def test_approval_without_evidence_rejected_by_core(pg_client: TestClient):
    """Bypassing the route: a direct gateway approval with no step-up evidence
    is rejected by the regista ApprovalVerifier (APPROVAL_EVIDENCE_REQUIRED)."""
    from regista import LifecycleContractError, LifecycleErrorCode

    from dossier.actors import Actor

    principal = _new_principal("stepup-noev")
    prepared = _enrollment_awaiting_approval(pg_client, principal)

    gw = _gw(pg_client)
    approver = Actor(actor_id=_BOB_ID, actor_kind="human", display_name="Bob")
    with pytest.raises(LifecycleContractError) as exc_info:
        gw.approve_operation(
            prepared["operation_id"],
            approver=approver,
            approval_digest=prepared["digest"],
            step_up_evidence=None,  # No evidence — verifier must reject.
        )
    assert exc_info.value.code is LifecycleErrorCode.APPROVAL_EVIDENCE_REQUIRED


def test_approval_with_forged_evidence_rejected_by_core(pg_client: TestClient):
    """A forged step-up evidence string is rejected by the ApprovalVerifier."""
    from regista import LifecycleContractError, LifecycleErrorCode

    from dossier.actors import Actor

    principal = _new_principal("stepup-forged")
    prepared = _enrollment_awaiting_approval(pg_client, principal)

    gw = _gw(pg_client)
    approver = Actor(actor_id=_BOB_ID, actor_kind="human", display_name="Bob")
    with pytest.raises(LifecycleContractError) as exc_info:
        gw.approve_operation(
            prepared["operation_id"],
            approver=approver,
            approval_digest=prepared["digest"],
            step_up_evidence='{"forged": true}',
        )
    assert exc_info.value.code is LifecycleErrorCode.APPROVAL_EVIDENCE_REQUIRED
