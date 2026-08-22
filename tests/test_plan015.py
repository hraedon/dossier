from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from _doubles import InMemoryPrincipalKeyStore, inject_test_store
from conftest import extract_csrf as _extract_csrf
from conftest import login as _login
from regista import LifecycleContractError

from dossier.keys import generate_ed25519_keypair

# These tests exercise the file-backend key-custody path (regista Plan 029's
# FileProvider: 0o600 atomic writes, 0o700 parent dirs, Unix mode assertions).
# That path is POSIX-only; a Windows deployment uses the DPAPI/Windows secret
# backend instead. Skip on Windows CI rather than assert POSIX file semantics
# there (regista's own CI is Linux-only, so file-custody is exercised on Linux).
pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="file-backend key custody is POSIX; Windows uses the DPAPI backend",
)

_ALICE_ID = "human:alice"
_SECOND_ADMIN_ID = "human:second-admin"
_NEW_PRINCIPAL_ID = "human:new-user"


# ---- fixtures ----


@pytest.fixture
def admin_env(monkeypatch):
    monkeypatch.setenv("DOSSIER_ADMIN_IDS", _ALICE_ID)
    from dossier.app import _configure_admin_ids

    _configure_admin_ids()
    yield
    monkeypatch.delenv("DOSSIER_ADMIN_IDS", raising=False)
    _configure_admin_ids()


@pytest.fixture
def principal_store(gateway):
    store = InMemoryPrincipalKeyStore()
    inject_test_store(gateway, store)
    yield store
    inject_test_store(gateway, None)


def _enroll(store, principal_id=_ALICE_ID):
    _priv, pub = generate_ed25519_keypair()
    return store.register(principal_id, pub)


# ---- /me/identity ----


def test_my_identity_not_enrolled(client, principal_store):
    _login(client)
    resp = client.get("/me/identity")
    assert resp.status_code == 200
    assert "not enrolled for signing" in resp.text.lower()


def test_my_identity_shows_key_status(client, principal_store):
    entry = _enroll(principal_store, _ALICE_ID)
    _login(client)
    resp = client.get("/me/identity")
    assert resp.status_code == 200
    assert entry["fingerprint"][:32] in resp.text
    assert "active" in resp.text.lower()
    assert entry["key_id"] in resp.text
    assert entry["scheme"] in resp.text


def test_my_identity_no_private_key_material(client, principal_store):
    entry = _enroll(principal_store, _ALICE_ID)
    _login(client)
    resp = client.get("/me/identity")
    assert resp.status_code == 200
    assert entry["public_key"] not in resp.text
    assert "secret" not in resp.text.lower()


def test_my_identity_shows_rotate_button(client, principal_store):
    _enroll(principal_store, _ALICE_ID)
    _login(client)
    resp = client.get("/me/identity")
    assert resp.status_code == 200
    assert "rotate my key" in resp.text.lower()


# ---- /me/key/rotate ----


def test_rotate_key_produces_valid_ed25519_public_key(client, principal_store, tmp_path):
    _enroll(principal_store, _ALICE_ID)
    _login(client)

    identity_page = client.get("/me/identity")
    csrf = _extract_csrf(identity_page.text)

    client.post("/me/key/rotate", data={"csrf_token": csrf}, follow_redirects=False)

    new_entry = principal_store.get_active(_ALICE_ID)
    public_key_bytes = bytes.fromhex(new_entry["public_key"])
    assert len(public_key_bytes) == 32

    import nacl.signing

    nacl.signing.VerifyKey(public_key_bytes)
    priv_path = tmp_path / "principals" / f"{_ALICE_ID}_ed25519.key"
    assert not priv_path.exists()


def test_rotate_key_updates_fingerprint(client, principal_store):
    entry = _enroll(principal_store, _ALICE_ID)
    old_fingerprint = entry["fingerprint"]
    _login(client)

    identity_page = client.get("/me/identity")
    csrf = _extract_csrf(identity_page.text)

    resp = client.post("/me/key/rotate", data={"csrf_token": csrf}, follow_redirects=False)
    assert resp.status_code == 303

    resp = client.get("/me/identity")
    assert resp.status_code == 200
    assert old_fingerprint[:32] not in resp.text
    new_entry = principal_store.get_active(_ALICE_ID)
    assert new_entry["fingerprint"][:32] in resp.text


def test_rotate_key_writes_rotation_event(client, principal_store):
    old_entry = _enroll(principal_store, _ALICE_ID)
    old_key_id = old_entry["key_id"]
    _login(client)

    identity_page = client.get("/me/identity")
    csrf = _extract_csrf(identity_page.text)

    client.post("/me/key/rotate", data={"csrf_token": csrf}, follow_redirects=False)

    entries = principal_store.list(principal_id=_ALICE_ID)
    statuses = {e["key_id"]: e["status"] for e in entries}
    assert statuses[old_key_id] == "superseded"
    new_entry = principal_store.get_active(_ALICE_ID)
    assert statuses[new_entry["key_id"]] == "active"


# ---- /me/signing-history ----


def test_my_signing_history_empty(client, principal_store):
    _login(client)
    resp = client.get("/me/signing-history")
    assert resp.status_code == 200
    assert "no signed events found" in resp.text.lower()


def test_my_signing_history_shows_events(client, principal_store):
    _login(client)
    csrf = _extract_csrf(client.get("/p/dossier-test/issues/new").text)
    client.post(
        "/p/dossier-test/issues",
        data={"type": "bug", "title": "Signing history test", "csrf_token": csrf},
        follow_redirects=False,
    )
    resp = client.get("/me/signing-history")
    assert resp.status_code == 200
    assert "DOSSIER_TEST-1" in resp.text
    assert "verified" in resp.text.lower() or "unverified" in resp.text.lower()


# ---- /admin/principals ----


def test_principal_roster_requires_admin(client, principal_store):
    _login(client)
    resp = client.get("/admin/principals")
    assert resp.status_code == 403


def test_principal_roster_shows_principals(client, principal_store, admin_env):
    _enroll(principal_store, _ALICE_ID)
    _login(client)
    resp = client.get("/admin/principals")
    assert resp.status_code == 200
    assert _ALICE_ID in resp.text
    assert "active" in resp.text.lower()


def test_enroll_principal_via_ui(client, principal_store, admin_env):
    _login(client)
    roster_page = client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)

    resp = client.post(
        "/admin/principals/enroll",
        data={"principal_id": _NEW_PRINCIPAL_ID, "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/principals"

    roster = client.get("/admin/principals")
    assert _NEW_PRINCIPAL_ID in roster.text


def test_revoke_principal_via_ui(client, principal_store, admin_env):
    _enroll(principal_store, _NEW_PRINCIPAL_ID)
    _login(client)

    roster_page = client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)

    resp = client.post(
        f"/admin/principals/{_NEW_PRINCIPAL_ID}/revoke",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/principals"

    roster = client.get("/admin/principals")
    assert "revoked" in roster.text.lower()


def test_revoked_principal_history_still_verifies(client, principal_store, admin_env):
    _login(client)
    csrf = _extract_csrf(client.get("/p/dossier-test/issues/new").text)
    client.post(
        "/p/dossier-test/issues",
        data={"type": "bug", "title": "Revocation history test", "csrf_token": csrf},
        follow_redirects=False,
    )
    _enroll(principal_store, _ALICE_ID)

    roster_page = client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)
    client.post(
        f"/admin/principals/{_ALICE_ID}/revoke",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )

    resp = client.get("/me/signing-history")
    assert resp.status_code == 200
    assert "DOSSIER_TEST-1" in resp.text


# ---- /admin/break-glass ----

# Break-glass registration of a new signing key requires a client-side
# possession proof from a key-custody helper that does not exist yet.  The
# web process must not generate or hold private keys, so the route is
# intentionally fail-closed (HTTP 501) in this increment.


def test_break_glass_form_shows_not_available(client, principal_store, admin_env):
    _login(client)
    resp = client.get("/admin/break-glass")
    assert resp.status_code == 200
    assert "not yet available" in resp.text.lower()
    assert 'name="confirmer_id"' not in resp.text
    assert "execute break-glass" not in resp.text.lower()


def test_break_glass_action_returns_not_implemented(client, principal_store, admin_env):
    _login(client)
    bg_page = client.get("/admin/break-glass")
    csrf = _extract_csrf(bg_page.text)
    resp = client.post(
        "/admin/break-glass",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 501
    assert "not yet available" in resp.text.lower()


def test_break_glass_does_not_register_or_revoke(client, principal_store, admin_env):
    _enroll(principal_store, _NEW_PRINCIPAL_ID)
    old_key = principal_store.get_active(_NEW_PRINCIPAL_ID)
    _login(client)
    bg_page = client.get("/admin/break-glass")
    csrf = _extract_csrf(bg_page.text)
    client.post(
        "/admin/break-glass",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    # No break-glass key was minted; the existing key is unchanged.
    assert principal_store.get_active(_NEW_PRINCIPAL_ID)["key_id"] == old_key["key_id"]


def test_approve_operation_seam_requires_durable_backend(gateway, principal_store):
    from dossier.actors import Actor

    approver = Actor(
        actor_id="human:second-admin",
        actor_kind="human",
        display_name="Second Admin",
        principal_id=_SECOND_ADMIN_ID,
    )
    with pytest.raises(LifecycleContractError):
        gateway.approve_operation(
            "any-operation-id",
            approver=approver,
            approval_digest="any-digest",
        )


# ---- auth required ----


def test_my_identity_route_requires_auth(client):
    resp = client.get("/me/identity", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_my_signing_history_requires_auth(client):
    resp = client.get("/me/signing-history", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_admin_routes_require_auth(client):
    resp = client.get("/admin/principals", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


# ---- CSRF ----


def test_csrf_on_rotate_key(client, principal_store):
    _login(client)
    resp = client.post("/me/key/rotate", data={}, follow_redirects=False)
    assert resp.status_code == 403


def test_csrf_on_enroll(client, principal_store, admin_env):
    _login(client)
    resp = client.post("/admin/principals/enroll", data={}, follow_redirects=False)
    assert resp.status_code == 403


def test_csrf_on_revoke(client, principal_store, admin_env):
    _login(client)
    resp = client.post(
        f"/admin/principals/{_NEW_PRINCIPAL_ID}/revoke", data={}, follow_redirects=False
    )
    assert resp.status_code == 403


def test_csrf_on_break_glass(client, principal_store, admin_env):
    _login(client)
    resp = client.post("/admin/break-glass", data={}, follow_redirects=False)
    assert resp.status_code == 403


# ---- key generation correctness ----


def test_generate_ed25519_keypair_produces_valid_keys():
    priv1, pub1 = generate_ed25519_keypair()
    assert len(priv1) == 32
    assert len(pub1) == 32

    import nacl.signing

    signing_key = nacl.signing.SigningKey(priv1)
    assert bytes(signing_key.verify_key) == pub1

    priv2, pub2 = generate_ed25519_keypair()
    assert pub1 != pub2
    assert priv1 != priv2


def test_enrollment_produces_valid_ed25519_key(client, principal_store, admin_env, tmp_path):
    _login(client)
    roster_page = client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)

    resp = client.post(
        "/admin/principals/enroll",
        data={"principal_id": _NEW_PRINCIPAL_ID, "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    entry = principal_store.get_active(_NEW_PRINCIPAL_ID)
    public_key_bytes = bytes.fromhex(entry["public_key"])
    assert len(public_key_bytes) == 32

    import nacl.signing

    nacl.signing.VerifyKey(public_key_bytes)
    priv_path = tmp_path / "principals" / f"{_NEW_PRINCIPAL_ID}_ed25519.key"
    assert not priv_path.exists()


def test_gateway_custody_never_returns_private_key(gateway, principal_store, tmp_path):
    from dossier.actors import Actor

    actor = Actor(
        actor_id="human:custody-test-actor",
        actor_kind="human",
        display_name="Custody Test",
        principal_id="human:custody-test-actor",
        model_lineage=None,
        on_behalf_of=None,
    )
    result = gateway.enroll_principal(
        "human:custody-test-principal",
        actor=actor,
        private_key_dir=str(tmp_path / "principals"),
    )
    assert result is not None
    for key in ("private_key", "private", "secret", "secret_ref"):
        assert key not in result, f"gateway result must not contain {key!r}"
    assert "public_key" in result
    assert "fingerprint" in result
    assert "key_id" in result
    assert "scheme" in result


def test_rotation_result_has_no_private_key_material(client, principal_store, admin_env):
    _enroll(principal_store, _ALICE_ID)
    _login(client)
    identity_page = client.get("/me/identity")
    csrf = _extract_csrf(identity_page.text)
    client.post("/me/key/rotate", data={"csrf_token": csrf}, follow_redirects=False)

    new_entry = principal_store.get_active(_ALICE_ID)
    for key in ("private_key", "private", "secret", "secret_ref"):
        assert key not in new_entry, f"rotation result must not contain {key!r}"


def test_principal_key_manager_stores_private_key(tmp_path):
    from dossier.keys import PrincipalKeyManager

    mgr = PrincipalKeyManager(tmp_path / "principals")
    public_key = mgr.generate_and_store("human:test-principal")
    assert len(public_key) == 32

    import os

    key_path = tmp_path / "principals" / "human:test-principal_ed25519.key"
    assert os.path.exists(key_path)
    mode = os.stat(key_path).st_mode & 0o777
    assert mode == 0o600

    loaded = key_path.read_bytes()
    assert len(loaded) == 32

    import nacl.signing

    signing_key = nacl.signing.SigningKey(loaded)
    assert bytes(signing_key.verify_key) == public_key


def test_principal_key_manager_rejects_invalid_principal_id(tmp_path):
    from dossier.keys import PrincipalKeyManager

    mgr = PrincipalKeyManager(tmp_path / "principals")
    with pytest.raises(ValueError):
        mgr.generate_and_store("../etc/passwd")
    with pytest.raises(ValueError):
        mgr.generate_and_store("user@example.com")
    with pytest.raises(ValueError):
        mgr.generate_and_store("")


# ---- adversarial review fixes (Plan 015 follow-up) ----


def _users_file_for(tmp_path: Path) -> Path:
    from dossier.auth.passwords import hash_password

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
                }
            ]
        ),
        encoding="utf-8",
    )
    return path


def test_key_manifest_written_with_owner_only_permissions(tmp_path):
    import os

    from dossier.keys import PrincipalKeyManager

    key_dir = tmp_path / "principals"
    manifest_path = tmp_path / "keys.json"
    mgr = PrincipalKeyManager(key_dir, key_manifest_path=manifest_path)
    private_key, _public_key = mgr.generate("human:test-principal")
    mgr.store_private_key("human:test-principal", "pk_test", private_key)

    assert manifest_path.exists()
    mode = os.stat(manifest_path).st_mode & 0o777
    assert mode == 0o600


def test_rotate_rolls_back_on_registration_failure(client, principal_store, admin_env, monkeypatch):
    entry = _enroll(principal_store, _ALICE_ID)
    _login(client)

    def _fail(*args, **kwargs):
        raise RuntimeError("registration failed")

    monkeypatch.setattr(
        "dossier.gateway.RegistaGateway._generate_and_register",
        _fail,
    )

    identity_page = client.get("/me/identity")
    csrf = _extract_csrf(identity_page.text)
    resp = client.post("/me/key/rotate", data={"csrf_token": csrf}, follow_redirects=False)

    assert resp.status_code == 500
    active = principal_store.get_active(_ALICE_ID)
    assert active["public_key"] == entry["public_key"]


def test_enroll_principal_fail_closed_against_real_regista():
    """Legacy in-process enrollment is rejected when principal ops are available."""
    from unittest.mock import MagicMock

    import pytest
    from helpers import ALICE
    from regista import ErrorCode, RegistaError

    from dossier.gateway import RegistaGateway

    reg = MagicMock()
    # MagicMock has all attributes, so has_principal_ops() is True.
    gw = RegistaGateway(reg, project_name="test")

    with pytest.raises(RegistaError) as exc_info:
        gw.enroll_principal("alice", actor=ALICE)
    assert exc_info.value.code == ErrorCode.SECRET_WRITE_UNSUPPORTED
    assert "client-signer" in exc_info.value.message
    # The underlying reg.enroll_principal was never called.
    reg.enroll_principal.assert_not_called()


def test_rotation_rate_limit_blocks_repeat(client, principal_store, admin_env):
    _enroll(principal_store, _ALICE_ID)
    _login(client)

    identity_page = client.get("/me/identity")
    assert "try again later" not in identity_page.text.lower()

    csrf = _extract_csrf(identity_page.text)
    resp = client.post("/me/key/rotate", data={"csrf_token": csrf}, follow_redirects=False)
    assert resp.status_code == 303

    identity_page = client.get("/me/identity")
    assert "rotation is rate-limited" in identity_page.text.lower()

    csrf = _extract_csrf(identity_page.text)
    resp = client.post("/me/key/rotate", data={"csrf_token": csrf}, follow_redirects=False)
    assert resp.status_code == 429


def test_gateway_test_store_guard_requires_testing_flag(gateway):
    import dossier.gateway as gw_module

    prev = gw_module._TESTING
    try:
        gw_module._TESTING = False
        store = InMemoryPrincipalKeyStore()
        store.register("alice", b"0" * 32)
        gateway._principal_store = store
        assert gateway.list_principals("alice") == []
    finally:
        gateway._principal_store = None
        gw_module._TESTING = prev


def test_inmemory_rotation_works_without_custody(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from regista.testing import InMemoryRegista

    from dossier.app import _configure_admin_ids, create_app
    from dossier.auth.backends import LocalBackend
    from dossier.config import Settings
    from dossier.gateway import RegistaGateway
    from dossier.keys import generate_keyset
    from dossier.multi import GatewayRegistry

    monkeypatch.setenv("DOSSIER_ADMIN_IDS", f"{_ALICE_ID},{_SECOND_ADMIN_ID}")
    _configure_admin_ids()

    try:
        key_path = tmp_path / "keys.json"
        generate_keyset(key_path)
        project = "dossier_test"
        reg = InMemoryRegista(project=project, hmac_key_path=str(key_path))
        gw = RegistaGateway(reg, project_name=project)
        gw.register_workflow()

        settings = Settings(
            database_url="",
            project=project,
            hmac_key_path=str(key_path),
            session_secret="test-session-secret-not-for-prod",
            session_max_age_seconds=43200,
            secure_cookies=False,
            require_ssl=False,
            users_path=str(_users_file_for(tmp_path)),
            auth_backend="local",
            principal_key_dir=str(tmp_path / "principals"),
                    # explicit: this fixture exercises features, not authz (WI-017)
            project_access_mode="open",
        )
        backend = LocalBackend(_users_file_for(tmp_path))
        registry = GatewayRegistry(known_projects=[project])
        registry.add(project, gw)
        app = create_app(settings, registry, backend)

        with TestClient(app) as client:
            _login(client)

            from _doubles import InMemoryPrincipalKeyStore, inject_test_store

            store = InMemoryPrincipalKeyStore()
            inject_test_store(gw, store)
            store.register(_ALICE_ID, b"\x01" * 32)

            identity_page = client.get("/me/identity")
            csrf = _extract_csrf(identity_page.text)
            resp = client.post(
                "/me/key/rotate",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            assert resp.status_code == 303

            new_entry = store.get_active(_ALICE_ID)
            assert new_entry["status"] == "active"
            assert new_entry["public_key"] != b"\x01" * 32
    finally:
        _configure_admin_ids()
        monkeypatch.delenv("DOSSIER_ADMIN_IDS", raising=False)
        _configure_admin_ids()
