"""Client-signer lifecycle exchange tests (Plan 031 §5 / Plan 015 v1).

These tests drive the full custody-boundary flow over HTTP against real
regista + Postgres: the out-of-process client signer generates and custodies
the Ed25519 keypair (file custody), dossier initiates and approves, and the
signer produces the possession and effective-use proofs. The web process
never sees private key material. They skip cleanly when Postgres is not
reachable.
"""

from __future__ import annotations

import base64
import json
import os
import uuid
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import httpx
import pytest
from _trust_lifecycle_fixtures import TRUST_ROOT, provision_trust_log
from conftest import extract_csrf as _extract_csrf
from fastapi.testclient import TestClient
from regista import Regista
from regista.client_signer import ClientSigner
from regista.principal_lifecycle import (
    EffectiveChallenge,
    PossessionChallenge,
)
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
_CHARLIE_ID = "human:charlie"


def _new_principal(label: str) -> str:
    return f"human:{label}-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def pg_client(tmp_path_factory):
    key_path = tmp_path_factory.mktemp("pg_keys") / "keys.json"
    principals = (_ALICE_ID, _BOB_ID, _CHARLIE_ID, TRUST_ROOT)
    keyset = make_v6_keyset(key_path.parent, principals=principals, filename=key_path.name)
    work_principals = (_ALICE_ID, _BOB_ID, _CHARLIE_ID)
    project = f"dossier_signer_{uuid.uuid4().hex[:8]}"

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

    tmp_path = tmp_path_factory.mktemp("signer_flow")
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
                {
                    "stable_id": _CHARLIE_ID,
                    "username": "charlie",
                    "display_name": "Charlie",
                    "password": hash_password("s3cret"),
                    "groups": [],
                    "principal_id": _CHARLIE_ID,
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
    assert resp.headers["location"] == "/"


def _project(client: TestClient) -> str:
    return client.app.state._test_project


def _slug(client: TestClient) -> str:
    return project_to_slug(_project(client))


def _gw(client: TestClient) -> RegistaGateway:
    return client.app.state.registry.get(_project(client))


def _csrf_token(client: TestClient) -> str:
    return client.get("/csrf").json()["csrf_token"]


# Response transcript for the private-key-leak assertions: every helper that
# performs an HTTP call appends the raw response body, so the end-to-end test
# can assert private material never crossed the wire in ANY response — not
# just the two the original assertions happened to name.
_TRANSCRIPT: list[str] = []


def _record(resp: httpx.Response) -> None:
    _TRANSCRIPT.append(resp.text)


def _new_signer(client: TestClient, principal: str) -> ClientSigner:
    key_dir = client.app.state._signer_dir / f"{principal}-{uuid.uuid4().hex[:6]}"
    return ClientSigner.generate(
        principal,
        backend="file",
        private_key_dir=str(key_dir),
    )


def _possession_challenge(data: dict) -> PossessionChallenge:
    return PossessionChallenge(
        challenge_id=data["challenge_id"],
        operation_id=data["operation_id"],
        operation_digest=data["operation_digest"],
        project=data["project"],
        principal_id=data["principal_id"],
        fingerprint=data["fingerprint"],
        scheme=data["scheme"],
        verifier_nonce=data["verifier_nonce"],
        issued_at=datetime.fromisoformat(data["issued_at"]),
        expires_at=datetime.fromisoformat(data["expires_at"]),
        trust_domain_id=data.get("trust_domain_id"),
        enrollment_request_digest=data.get("enrollment_request_digest"),
    )


def _effective_challenge(data: dict) -> EffectiveChallenge:
    return EffectiveChallenge(
        challenge_id=data["challenge_id"],
        operation_id=data["operation_id"],
        operation_digest=data["operation_digest"],
        project=data["project"],
        principal_id=data["principal_id"],
        fingerprint=data["fingerprint"],
        scheme=data["scheme"],
        verifier_nonce=data["verifier_nonce"],
        issued_at=datetime.fromisoformat(data["issued_at"]),
        expires_at=datetime.fromisoformat(data["expires_at"]),
    )


def _prepare_enrollment(client: TestClient, signer: ClientSigner, principal: str) -> dict:
    resp = client.post(
        f"/admin/p/{_slug(client)}/lifecycle/enroll/prepare",
        json={
            "principal_id": principal,
            "public_key": base64.b64encode(signer.identity.public_key).decode("ascii"),
        },
        headers={"X-CSRF-Token": _csrf_token(client)},
    )
    _record(resp)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _submit_possession(client: TestClient, operation_id: str, proof: dict) -> TestClient.Response:
    resp = client.post(
        f"/admin/p/{_slug(client)}/lifecycle/{operation_id}/possession",
        json=proof,
        headers={"X-CSRF-Token": _csrf_token(client)},
    )
    _record(resp)
    return resp


def _approve_and_commit(client: TestClient, operation_id: str, digest: str) -> None:
    """A second admin (bob) approves and commits; alice initiated."""
    _login_as(client, "bob")
    resp = client.post(
        f"/admin/p/{_slug(client)}/lifecycle/{operation_id}/approve",
        data={
            "csrf_token": _csrf_token(client),
            "approval_digest": digest,
            "reason": "approved by second admin",
        },
        follow_redirects=False,
    )
    _record(resp)
    assert resp.status_code == 303, resp.text


def _complete_effective(client: TestClient, signer: ClientSigner, operation_id: str) -> dict:
    resp = client.post(
        f"/admin/p/{_slug(client)}/lifecycle/{operation_id}/effective-challenge",
        headers={"X-CSRF-Token": _csrf_token(client)},
    )
    _record(resp)
    assert resp.status_code == 200, resp.text
    challenge = _effective_challenge(resp.json())
    receipt = signer.sign_effective(challenge)
    resp = client.post(
        f"/admin/p/{_slug(client)}/lifecycle/{operation_id}/effective-receipt",
        json=receipt.to_dict(),
        headers={"X-CSRF-Token": _csrf_token(client)},
    )
    _record(resp)
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_signer_enrollment_end_to_end(pg_client: TestClient):
    _TRANSCRIPT.clear()
    principal = _new_principal("signer-enroll")
    signer = _new_signer(pg_client, principal)

    _login_as(pg_client, "alice")
    prepared = _prepare_enrollment(pg_client, signer, principal)
    assert prepared["principal_id"] == principal
    challenge_data = prepared["challenge"]
    assert challenge_data["principal_id"] == principal
    assert challenge_data["fingerprint"] == signer.identity.fingerprint

    proof = signer.sign_possession(_possession_challenge(challenge_data))
    resp = _submit_possession(pg_client, prepared["operation_id"], proof.to_dict())
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "awaiting_approval"

    _approve_and_commit(pg_client, prepared["operation_id"], prepared["digest"])
    operation = _gw(pg_client).principal_lifecycle.get_operation(prepared["operation_id"])
    assert operation.state.value == "committed"

    result = _complete_effective(pg_client, signer, prepared["operation_id"])
    assert result["state"] == "effective"

    # The committed key is the active registry key for the principal.
    active = _gw(pg_client).get_principal_key(principal)
    assert active is not None

    # No private key material crossed the wire in ANY response of the flow —
    # prepare, possession, approve, effective-challenge, effective-receipt.
    # The transcript assertion covers every HTTP response, not a named subset.
    private_bytes = (Path(signer.identity.secret_ref.removeprefix("file:"))).read_bytes()
    private_b64 = base64.b64encode(private_bytes).decode("ascii")
    private_hex = private_bytes.hex()
    transcript = "\n".join(_TRANSCRIPT)
    assert "operation_id" in transcript  # sanity: the transcript is real
    assert private_b64 not in transcript
    assert private_hex not in transcript


def test_signer_rotation_end_to_end(pg_client: TestClient):
    principal = _new_principal("signer-rotate")
    signer_v1 = _new_signer(pg_client, principal)

    _login_as(pg_client, "alice")
    prepared = _prepare_enrollment(pg_client, signer_v1, principal)
    proof = signer_v1.sign_possession(_possession_challenge(prepared["challenge"]))
    resp = _submit_possession(pg_client, prepared["operation_id"], proof.to_dict())
    assert resp.status_code == 200, resp.text
    _approve_and_commit(pg_client, prepared["operation_id"], prepared["digest"])
    result = _complete_effective(pg_client, signer_v1, prepared["operation_id"])
    assert result["state"] == "effective"
    old_key_id = _gw(pg_client).get_principal_key(principal)["key_id"]

    # Rotation: the client generates a NEW keypair; the old key is superseded.
    signer_v2 = _new_signer(pg_client, principal)
    _login_as(pg_client, "alice")
    resp = pg_client.post(
        f"/admin/p/{_slug(pg_client)}/lifecycle/rotate/prepare",
        json={
            "principal_id": principal,
            "public_key": base64.b64encode(signer_v2.identity.public_key).decode("ascii"),
            "old_key_id": old_key_id,
        },
        headers={"X-CSRF-Token": _csrf_token(pg_client)},
    )
    assert resp.status_code == 200, resp.text
    rotated = resp.json()
    proof = signer_v2.sign_possession(_possession_challenge(rotated["challenge"]))
    resp = _submit_possession(pg_client, rotated["operation_id"], proof.to_dict())
    assert resp.status_code == 200, resp.text
    old_signature = signer_v1.sign_rotation_authorization(
        base64.b64decode(resp.json()["old_key_authorization"], validate=True)
    )
    resp = pg_client.post(
        f"/admin/p/{_slug(pg_client)}/lifecycle/{rotated['operation_id']}"
        "/rotation-authorization",
        json={"old_key_signature": base64.b64encode(old_signature).decode("ascii")},
        headers={"X-CSRF-Token": _csrf_token(pg_client)},
    )
    assert resp.status_code == 200, resp.text
    _approve_and_commit(pg_client, rotated["operation_id"], rotated["digest"])
    result = _complete_effective(pg_client, signer_v2, rotated["operation_id"])
    assert result["state"] == "effective"

    entries = _gw(pg_client).list_principals(principal_id=principal)
    statuses = {e["key_id"]: e["status"] for e in entries}
    assert statuses[_gw(pg_client).get_principal_key(principal)["key_id"]] == "active"
    assert statuses[old_key_id] != "active"


def test_possession_rejects_forged_signature(pg_client: TestClient):
    principal = _new_principal("signer-forge")
    signer = _new_signer(pg_client, principal)

    _login_as(pg_client, "alice")
    prepared = _prepare_enrollment(pg_client, signer, principal)
    proof = signer.sign_possession(_possession_challenge(prepared["challenge"]))
    forged = proof.to_dict()
    forged["signature"] = base64.b64encode(b"\x00" * 64).decode("ascii")
    resp = _submit_possession(pg_client, prepared["operation_id"], forged)
    assert resp.status_code == 400


def test_possession_rejects_wrong_key_signature(pg_client: TestClient):
    # A structurally valid proof signed by a DIFFERENT key than the one being
    # enrolled must fail verification — the server checks against the
    # operation's public key, not just signature well-formedness.
    principal = _new_principal("signer-wrongkey")
    signer = _new_signer(pg_client, principal)
    attacker = _new_signer(pg_client, principal)

    _login_as(pg_client, "alice")
    prepared = _prepare_enrollment(pg_client, signer, principal)
    challenge = _possession_challenge(prepared["challenge"])
    # The attacker signer's identity check refuses to sign a challenge bound to
    # another fingerprint, so rebind the challenge to the attacker's identity:
    # the resulting real Ed25519 signature is over the wrong envelope and the
    # server must reject it against the enrolled public key.
    attacker_challenge = replace(challenge, fingerprint=attacker.identity.fingerprint)
    forged_proof = attacker.sign_possession(attacker_challenge)
    resp = _submit_possession(pg_client, prepared["operation_id"], forged_proof.to_dict())
    assert resp.status_code == 400


def test_possession_challenge_replay_rejected(pg_client: TestClient):
    principal = _new_principal("signer-replay")
    signer = _new_signer(pg_client, principal)

    _login_as(pg_client, "alice")
    prepared = _prepare_enrollment(pg_client, signer, principal)
    proof = signer.sign_possession(_possession_challenge(prepared["challenge"]))
    resp = _submit_possession(pg_client, prepared["operation_id"], proof.to_dict())
    assert resp.status_code == 200, resp.text
    replay = _submit_possession(pg_client, prepared["operation_id"], proof.to_dict())
    assert replay.status_code in (400, 409)


def test_effective_challenge_rejected_before_commit(pg_client: TestClient):
    principal = _new_principal("signer-earlyeff")
    signer = _new_signer(pg_client, principal)

    _login_as(pg_client, "alice")
    prepared = _prepare_enrollment(pg_client, signer, principal)
    proof = signer.sign_possession(_possession_challenge(prepared["challenge"]))
    resp = _submit_possession(pg_client, prepared["operation_id"], proof.to_dict())
    assert resp.status_code == 200, resp.text

    # The operation is awaiting approval, not committed: no effective challenge.
    resp = pg_client.post(
        f"/admin/p/{_slug(pg_client)}/lifecycle/{prepared['operation_id']}/effective-challenge",
        headers={"X-CSRF-Token": _csrf_token(pg_client)},
    )
    assert resp.status_code == 409


def test_effective_receipt_replay_rejected(pg_client: TestClient):
    principal = _new_principal("signer-effreplay")
    signer = _new_signer(pg_client, principal)

    _login_as(pg_client, "alice")
    prepared = _prepare_enrollment(pg_client, signer, principal)
    proof = signer.sign_possession(_possession_challenge(prepared["challenge"]))
    resp = _submit_possession(pg_client, prepared["operation_id"], proof.to_dict())
    assert resp.status_code == 200, resp.text
    _approve_and_commit(pg_client, prepared["operation_id"], prepared["digest"])

    resp = pg_client.post(
        f"/admin/p/{_slug(pg_client)}/lifecycle/{prepared['operation_id']}/effective-challenge",
        headers={"X-CSRF-Token": _csrf_token(pg_client)},
    )
    assert resp.status_code == 200, resp.text
    challenge = _effective_challenge(resp.json())
    receipt = signer.sign_effective(challenge).to_dict()
    first = pg_client.post(
        f"/admin/p/{_slug(pg_client)}/lifecycle/{prepared['operation_id']}/effective-receipt",
        json=receipt,
        headers={"X-CSRF-Token": _csrf_token(pg_client)},
    )
    assert first.status_code == 200, first.text
    replay = pg_client.post(
        f"/admin/p/{_slug(pg_client)}/lifecycle/{prepared['operation_id']}/effective-receipt",
        json=receipt,
        headers={"X-CSRF-Token": _csrf_token(pg_client)},
    )
    assert replay.status_code in (400, 409)


def test_prepare_requires_admin(pg_client: TestClient):
    principal = _new_principal("signer-nonadmin")
    signer = _new_signer(pg_client, principal)

    _login_as(pg_client, "charlie")  # not in DOSSIER_ADMIN_IDS
    resp = pg_client.post(
        f"/admin/p/{_slug(pg_client)}/lifecycle/enroll/prepare",
        json={
            "principal_id": principal,
            "public_key": base64.b64encode(signer.identity.public_key).decode("ascii"),
        },
        headers={"X-CSRF-Token": _csrf_token(pg_client)},
    )
    assert resp.status_code == 403


def test_prepare_rejects_malformed_requests(pg_client: TestClient):
    principal = _new_principal("signer-badreq")
    _login_as(pg_client, "alice")
    url = f"/admin/p/{_slug(pg_client)}/lifecycle/enroll/prepare"

    # Not valid JSON.
    resp = pg_client.post(
        url,
        content=b"not-json",
        headers={"X-CSRF-Token": _csrf_token(pg_client), "Content-Type": "application/json"},
    )
    assert resp.status_code == 400

    # Not base64.
    resp = pg_client.post(
        url,
        json={"principal_id": principal, "public_key": "!!!not-base64!!!"},
        headers={"X-CSRF-Token": _csrf_token(pg_client)},
    )
    assert resp.status_code == 400

    # Wrong key length (16 bytes, not 32).
    resp = pg_client.post(
        url,
        json={
            "principal_id": principal,
            "public_key": base64.b64encode(b"\x01" * 16).decode("ascii"),
        },
        headers={"X-CSRF-Token": _csrf_token(pg_client)},
    )
    assert resp.status_code == 400

    # Missing principal_id.
    resp = pg_client.post(
        url,
        json={"public_key": base64.b64encode(b"\x01" * 32).decode("ascii")},
        headers={"X-CSRF-Token": _csrf_token(pg_client)},
    )
    assert resp.status_code == 400


def test_possession_operation_id_mismatch_rejected(pg_client: TestClient):
    principal = _new_principal("signer-mismatch")
    signer = _new_signer(pg_client, principal)

    _login_as(pg_client, "alice")
    prepared = _prepare_enrollment(pg_client, signer, principal)
    proof = signer.sign_possession(_possession_challenge(prepared["challenge"]))
    mismatched = proof.to_dict()
    mismatched["operation_id"] = str(uuid.uuid4())
    resp = _submit_possession(pg_client, prepared["operation_id"], mismatched)
    assert resp.status_code == 400


def test_effective_receipt_rejects_future_observed_at(pg_client: TestClient):
    """A receipt with observed_at after the challenge window is rejected by
    regista core chronology validation (RECEIPT_OBSERVED_AT_INVALID → 400)."""
    principal = _new_principal("signer-future")
    signer = _new_signer(pg_client, principal)

    _login_as(pg_client, "alice")
    prepared = _prepare_enrollment(pg_client, signer, principal)
    proof = signer.sign_possession(_possession_challenge(prepared["challenge"]))
    resp = _submit_possession(pg_client, prepared["operation_id"], proof.to_dict())
    assert resp.status_code == 200, resp.text
    _approve_and_commit(pg_client, prepared["operation_id"], prepared["digest"])

    resp = pg_client.post(
        f"/admin/p/{_slug(pg_client)}/lifecycle/{prepared['operation_id']}/effective-challenge",
        headers={"X-CSRF-Token": _csrf_token(pg_client)},
    )
    assert resp.status_code == 200, resp.text
    challenge = _effective_challenge(resp.json())
    receipt = signer.sign_effective(challenge).to_dict()
    # Tamper observed_at to far future — outside the challenge window.
    receipt["observed_at"] = "2099-01-01T00:00:00+00:00"
    resp = pg_client.post(
        f"/admin/p/{_slug(pg_client)}/lifecycle/{prepared['operation_id']}/effective-receipt",
        json=receipt,
        headers={"X-CSRF-Token": _csrf_token(pg_client)},
    )
    assert resp.status_code == 400
    assert "observed_at" in resp.text.lower()


def test_effective_receipt_rejects_predated_observed_at(pg_client: TestClient):
    """A receipt with observed_at before the challenge window is rejected by
    regista core chronology validation (RECEIPT_OBSERVED_AT_INVALID → 400)."""
    principal = _new_principal("signer-predated")
    signer = _new_signer(pg_client, principal)

    _login_as(pg_client, "alice")
    prepared = _prepare_enrollment(pg_client, signer, principal)
    proof = signer.sign_possession(_possession_challenge(prepared["challenge"]))
    resp = _submit_possession(pg_client, prepared["operation_id"], proof.to_dict())
    assert resp.status_code == 200, resp.text
    _approve_and_commit(pg_client, prepared["operation_id"], prepared["digest"])

    resp = pg_client.post(
        f"/admin/p/{_slug(pg_client)}/lifecycle/{prepared['operation_id']}/effective-challenge",
        headers={"X-CSRF-Token": _csrf_token(pg_client)},
    )
    assert resp.status_code == 200, resp.text
    challenge = _effective_challenge(resp.json())
    receipt = signer.sign_effective(challenge).to_dict()
    # Tamper observed_at to before the challenge was issued.
    receipt["observed_at"] = "2020-01-01T00:00:00+00:00"
    resp = pg_client.post(
        f"/admin/p/{_slug(pg_client)}/lifecycle/{prepared['operation_id']}/effective-receipt",
        json=receipt,
        headers={"X-CSRF-Token": _csrf_token(pg_client)},
    )
    assert resp.status_code == 400
    assert "observed_at" in resp.text.lower()


def test_effective_receipt_rejects_naive_observed_at(pg_client: TestClient):
    """A receipt with a timezone-naive observed_at is rejected (dossier parsing
    layer requires timezone-aware timestamps)."""
    principal = _new_principal("signer-naive")
    signer = _new_signer(pg_client, principal)

    _login_as(pg_client, "alice")
    prepared = _prepare_enrollment(pg_client, signer, principal)
    proof = signer.sign_possession(_possession_challenge(prepared["challenge"]))
    resp = _submit_possession(pg_client, prepared["operation_id"], proof.to_dict())
    assert resp.status_code == 200, resp.text
    _approve_and_commit(pg_client, prepared["operation_id"], prepared["digest"])

    resp = pg_client.post(
        f"/admin/p/{_slug(pg_client)}/lifecycle/{prepared['operation_id']}/effective-challenge",
        headers={"X-CSRF-Token": _csrf_token(pg_client)},
    )
    assert resp.status_code == 200, resp.text
    challenge = _effective_challenge(resp.json())
    receipt = signer.sign_effective(challenge).to_dict()
    # Tamper observed_at to be timezone-naive.
    receipt["observed_at"] = "2026-07-29T12:00:00"
    resp = pg_client.post(
        f"/admin/p/{_slug(pg_client)}/lifecycle/{prepared['operation_id']}/effective-receipt",
        json=receipt,
        headers={"X-CSRF-Token": _csrf_token(pg_client)},
    )
    assert resp.status_code == 400
    assert "timezone" in resp.text.lower()
