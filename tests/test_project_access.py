"""Project ACL qualification: parsing, identity binding, audit, and enforcement."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from regista.testing import InMemoryRegista

from conftest import extract_csrf, login
from dossier.actors import Actor
from dossier.app import create_app
from dossier.auth.backends import GroupIdentity, LocalBackend, Principal
from dossier.auth.resolver import principal_to_actor
from dossier.authz import load_project_access_policy
from dossier.config import Settings
from dossier.config import load_settings
from dossier.gateway import RegistaGateway
from dossier.health import build_health
from dossier.keys import generate_keyset
from dossier.multi import GatewayRegistry

_ALICE_ID = "11111111-1111-1111-1111-111111111111"
_BOB_ID = "22222222-2222-2222-2222-222222222222"
_PROJECT_A = "project_alpha"
_PROJECT_B = "project_beta"


def _write_acl(path: Path, body: dict[str, object]) -> Path:
    path.write_text(json.dumps(body), encoding="utf-8")
    if os.name == "posix":
        path.chmod(0o600)
    return path


def _acl_body() -> dict[str, object]:
    return {
        "version": 1,
        "administrators": {
            "principals": ["security-admin"],
            "groups": ["guid:00000000-0000-0000-0000-000000000001"],
        },
        "projects": {
            _PROJECT_A: {"principals": [_ALICE_ID]},
            _PROJECT_B: {"groups": ["name:team-b"]},
            "public_example": {"public": True},
        },
    }


def test_policy_decisions_are_default_deny(tmp_path: Path) -> None:
    policy = load_project_access_policy(
        str(_write_acl(tmp_path / "acl.json", _acl_body()))
    )
    alice = Actor(_ALICE_ID, "human", "Alice")
    bob = Actor(_BOB_ID, "human", "Bob", groups=("name:team-b",))
    outsider = Actor("outsider", "human", "Outsider")
    admin = Actor("security-admin", "human", "Security")

    assert policy.decide(alice, _PROJECT_A).reason == "project-membership"
    assert policy.decide(bob, _PROJECT_B).allowed is True
    assert policy.decide(outsider, "public_example").allowed is True
    assert policy.decide(admin, "undeclared_project").allowed is True
    denied = policy.decide(outsider, "undeclared_project")
    assert denied.allowed is False
    assert denied.reason == "project-not-declared"


@pytest.mark.parametrize(
    "body, message",
    [
        ({"version": 99, "projects": {}}, "version"),
        ({"version": 1, "projects": {}, "typo": True}, "unknown"),
        (
            {
                "version": 1,
                "projects": {"x": {"public": True, "principals": ["alice"]}},
            },
            "cannot combine",
        ),
        (
            {"version": 1, "projects": {"x": {"principals": []}}},
            "must be public",
        ),
        (
            {
                "version": 1,
                "projects": {"x": {"principals": ["alice", "alice"]}},
            },
            "duplicates",
        ),
        (
            {"version": 1, "projects": {"x": {"groups": ["team-a"]}}},
            "guid: or name:",
        ),
        (
            {"version": 1, "projects": {"x": {"groups": ["name:Team-A"]}}},
            "case-folded",
        ),
    ],
)
def test_policy_rejects_ambiguous_or_unsafe_shapes(
    tmp_path: Path, body: dict[str, object], message: str
) -> None:
    path = _write_acl(tmp_path / "acl.json", body)
    with pytest.raises(ValueError, match=message):
        load_project_access_policy(str(path))


def test_policy_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "acl.json"
    path.write_text('{"version":1,"version":1,"projects":{}}', encoding="utf-8")
    if os.name == "posix":
        path.chmod(0o600)
    with pytest.raises(ValueError, match="duplicate"):
        load_project_access_policy(str(path))


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode-bit policy")
def test_policy_rejects_group_writable_file(tmp_path: Path) -> None:
    path = _write_acl(tmp_path / "acl.json", _acl_body())
    path.chmod(0o620)
    with pytest.raises(PermissionError, match="writable"):
        load_project_access_policy(str(path))


@pytest.mark.skipif(os.name != "posix", reason="O_NOFOLLOW policy")
def test_policy_rejects_symlink(tmp_path: Path) -> None:
    target = _write_acl(tmp_path / "real-acl.json", _acl_body())
    link = tmp_path / "linked-acl.json"
    link.symlink_to(target)
    with pytest.raises(OSError):
        load_project_access_policy(str(link))


def test_settings_require_acl_for_audit_or_enforce(monkeypatch) -> None:
    monkeypatch.setenv("DOSSIER_PROJECT_ACCESS_MODE", "enforce")
    monkeypatch.delenv("DOSSIER_PROJECT_ACL_PATH", raising=False)
    with pytest.raises(RuntimeError, match="ACL_PATH is required"):
        load_settings(strict=False)


def test_settings_reject_unknown_access_mode(monkeypatch) -> None:
    monkeypatch.setenv("DOSSIER_PROJECT_ACCESS_MODE", "permissive")
    with pytest.raises(ValueError, match="open, audit, or enforce"):
        load_settings(strict=False)


def test_principal_groups_become_stable_authorization_claims() -> None:
    principal = Principal(
        stable_id=_ALICE_ID,
        display_name="Alice",
        source="ldap:example",
        raw_attributes={
            "groups": [
                GroupIdentity(
                    guid="AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
                    name="Renamable Team",
                    dn="CN=Renamable Team,OU=Groups,DC=example,DC=com",
                ),
                GroupIdentity(guid="", name="Local Team", dn=""),
            ]
        },
    )
    actor = principal_to_actor(principal)
    assert actor.groups == (
        "guid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "name:local team",
    )
    assert all("CN=" not in claim for claim in actor.groups)


def test_principal_groups_are_blinded_for_signed_cookie_storage() -> None:
    principal = Principal(
        stable_id=_ALICE_ID,
        display_name="Alice",
        source="ldap:example",
        raw_attributes={
            "groups": [
                GroupIdentity(
                    guid="AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
                    name="Sensitive Team",
                    dn="CN=Sensitive Team,OU=Groups,DC=example,DC=com",
                )
            ]
        },
    )
    actor = principal_to_actor(principal, group_claim_key=b"k" * 32)
    assert len(actor.groups) == 1
    assert actor.groups[0].startswith("hmac-sha256:")
    assert "aaaaaaaa" not in actor.groups[0]
    assert "sensitive" not in actor.groups[0]


def _hash_password(password: str) -> str:
    from dossier.auth.passwords import hash_password

    return hash_password(password)


def _users_path(tmp_path: Path) -> Path:
    path = tmp_path / "users.json"
    path.write_text(
        json.dumps(
            [
                {
                    "stable_id": _ALICE_ID,
                    "username": "alice",
                    "display_name": "Alice",
                    "password": _hash_password("alice-password"),
                    "groups": ["team-a"],
                },
                {
                    "stable_id": _BOB_ID,
                    "username": "bob",
                    "display_name": "Bob",
                    "password": _hash_password("bob-password"),
                    "groups": ["team-b"],
                },
            ]
        ),
        encoding="utf-8",
    )
    return path


def _gateway(tmp_path: Path, project: str) -> RegistaGateway:
    key_path = tmp_path / f"{project}-keys.json"
    generate_keyset(key_path)
    gateway = RegistaGateway(
        InMemoryRegista(project=project, hmac_key_path=str(key_path)),
        project_name=project,
    )
    gateway.register_workflow()
    return gateway


def _settings(
    tmp_path: Path, users_path: Path, acl_path: Path, mode: str = "enforce"
) -> Settings:
    return Settings(
        database_url="",
        project=_PROJECT_A,
        hmac_key_path="",
        session_secret="test-session-secret-not-for-prod",
        session_max_age_seconds=43200,
        secure_cookies=False,
        require_ssl=False,
        users_path=str(users_path),
        auth_backend="local",
        principal_key_dir=str(tmp_path / "principals"),
        project_access_mode=mode,  # type: ignore[arg-type]
        project_acl_path=str(acl_path),
    )


@pytest.fixture
def enforced_client(tmp_path: Path):
    users_path = _users_path(tmp_path)
    acl_path = _write_acl(
        tmp_path / "acl.json",
        {
            "version": 1,
            "projects": {
                _PROJECT_A: {"principals": [_ALICE_ID]},
                _PROJECT_B: {"groups": ["name:team-b"]},
            },
        },
    )
    gateway_a = _gateway(tmp_path, _PROJECT_A)
    gateway_b = _gateway(tmp_path, _PROJECT_B)
    registry = GatewayRegistry(known_projects=[_PROJECT_A, _PROJECT_B])
    registry.add(_PROJECT_A, gateway_a)
    registry.add(_PROJECT_B, gateway_b)
    app = create_app(
        _settings(tmp_path, users_path, acl_path),
        registry,
        LocalBackend(users_path),
    )
    with TestClient(app) as client:
        yield client
    gateway_a.close()
    gateway_b.close()


def test_enforcement_filters_navigation_and_blocks_direct_reads(enforced_client) -> None:
    login(enforced_client, "alice", "alice-password")
    dashboard = enforced_client.get("/")
    assert dashboard.status_code == 200
    assert "project-alpha" in dashboard.text
    assert "project-beta" not in dashboard.text
    assert enforced_client.get("/p/project-alpha").status_code == 200
    assert enforced_client.get("/p/project-beta").status_code == 403


def test_enforcement_uses_authenticated_group_claim(enforced_client) -> None:
    login(enforced_client, "bob", "bob-password")
    dashboard = enforced_client.get("/")
    assert "project-beta" in dashboard.text
    assert "project-alpha" not in dashboard.text
    assert enforced_client.get("/p/project-beta").status_code == 200
    assert "groups" not in enforced_client.get("/me").json()


def test_enforcement_blocks_direct_mutation(enforced_client) -> None:
    login(enforced_client, "alice", "alice-password")
    csrf = extract_csrf(enforced_client.get("/p/project-alpha/issues/new").text)
    response = enforced_client.post(
        "/p/project-beta/issues",
        data={"type": "bug", "title": "must not write", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 403


def test_audit_mode_logs_denial_but_allows_access(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    users_path = _users_path(tmp_path)
    acl_path = _write_acl(
        tmp_path / "acl.json",
        {"version": 1, "projects": {_PROJECT_B: {"groups": ["name:team-b"]}}},
    )
    gateway = _gateway(tmp_path, _PROJECT_B)
    registry = GatewayRegistry(known_projects=[_PROJECT_B])
    registry.add(_PROJECT_B, gateway)
    app = create_app(
        _settings(tmp_path, users_path, acl_path, mode="audit"),
        registry,
        LocalBackend(users_path),
    )
    with TestClient(app) as client:
        login(client, "alice", "alice-password")
        with caplog.at_level("WARNING", logger="dossier.authz"):
            assert client.get("/p/project-beta").status_code == 200
    gateway.close()
    assert "would be denied" in caplog.text


def test_health_names_open_audit_and_enforced_postures(tmp_path: Path) -> None:
    users_path = _users_path(tmp_path)
    acl_path = _write_acl(tmp_path / "acl.json", _acl_body())
    registry = GatewayRegistry(known_projects=[])

    open_health = build_health(
        _settings(tmp_path, users_path, acl_path, mode="open"), registry
    )
    open_check = next(c for c in open_health["checks"] if c["name"] == "project_access")
    assert open_check["status"] == "warn"

    audit_health = build_health(
        _settings(tmp_path, users_path, acl_path, mode="audit"), registry
    )
    audit_check = next(c for c in audit_health["checks"] if c["name"] == "project_access")
    assert audit_check["status"] == "warn"

    enforce_health = build_health(
        _settings(tmp_path, users_path, acl_path, mode="enforce"), registry
    )
    enforce_check = next(
        c for c in enforce_health["checks"] if c["name"] == "project_access"
    )
    assert enforce_check["status"] == "ok"


def test_health_fails_for_acl_changed_to_invalid_after_startup(tmp_path: Path) -> None:
    users_path = _users_path(tmp_path)
    acl_path = _write_acl(tmp_path / "acl.json", _acl_body())
    settings = _settings(tmp_path, users_path, acl_path, mode="enforce")
    # Startup would have loaded the prior valid policy. Doctor reparses disk so
    # an unsafe deployment change cannot continue reporting a green posture.
    acl_path.write_text('{"version":1,"projects":{"x":{}}}', encoding="utf-8")
    if os.name == "posix":
        acl_path.chmod(0o600)
    health = build_health(settings, GatewayRegistry(known_projects=[]))
    check = next(c for c in health["checks"] if c["name"] == "project_access")
    assert check["status"] == "fail"
