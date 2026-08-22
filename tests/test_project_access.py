"""Project ACL qualification: parsing, identity binding, audit, and enforcement."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from conftest import extract_csrf, login, make_v6_gateway
from fastapi.testclient import TestClient

from dossier.actors import Actor
from dossier.app import create_app
from dossier.auth.backends import GroupIdentity, LocalBackend, Principal
from dossier.auth.resolver import principal_to_actor
from dossier.authz import (
    build_project_access_policy,
    load_project_access_policy,
    parse_bootstrap_administrators,
)
from dossier.config import Settings, load_settings
from dossier.gateway import RegistaGateway
from dossier.health import build_health
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


def test_enforce_without_any_policy_resolves_but_denies(monkeypatch) -> None:
    """WI-017: enforce with no ACL and no bootstrap admins must not crash.

    It resolves — so ``/healthz`` and ``dossier doctor`` still run and can
    explain the state — and it denies everything.
    """
    monkeypatch.setenv("DOSSIER_PROJECT_ACCESS_MODE", "enforce")
    monkeypatch.delenv("DOSSIER_PROJECT_ACL_PATH", raising=False)
    monkeypatch.delenv("DOSSIER_BOOTSTRAP_ADMINS", raising=False)
    settings = load_settings(strict=False)
    assert settings.project_access_mode == "enforce"
    assert settings.project_acl_path == ""
    assert settings.bootstrap_administrators == ()

    policy = build_project_access_policy("", ())
    assert policy.is_empty
    decision = policy.decide(Actor("anyone", "human", "Anyone"), _PROJECT_A)
    assert decision.allowed is False
    assert decision.reason == "no-access-policy-configured"


def test_settings_reject_malformed_bootstrap_admins(monkeypatch) -> None:
    """A typo in a security control fails at config load, not at first use."""
    monkeypatch.setenv("DOSSIER_PROJECT_ACCESS_MODE", "enforce")
    monkeypatch.delenv("DOSSIER_PROJECT_ACL_PATH", raising=False)
    monkeypatch.setenv("DOSSIER_BOOTSTRAP_ADMINS", "guid:not-a-guid")
    with pytest.raises(ValueError, match="group GUID"):
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
                    "principal_id": "human:alice",
                },
                {
                    "stable_id": _BOB_ID,
                    "username": "bob",
                    "display_name": "Bob",
                    "password": _hash_password("bob-password"),
                    "groups": ["team-b"],
                    "principal_id": "human:bob",
                },
            ]
        ),
        encoding="utf-8",
    )
    return path


def _gateway(tmp_path: Path, project: str) -> RegistaGateway:
    return make_v6_gateway(tmp_path, project)


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
    assert "project 'x' must be public or name a principal/group" in check["detail"]


# ── WI-017: deny-by-default + the bootstrap recovery path ────────────────


def test_bootstrap_admin_recovers_access_with_no_acl_file(tmp_path: Path) -> None:
    """The documented way out of a locked-out enforce deployment.

    One env var, no ACL file: the named principal gets in, everyone else is
    still denied. This is the migration path — not a fallback to open.
    """
    policy = build_project_access_policy("", (_ALICE_ID,))
    alice = Actor(_ALICE_ID, "human", "Alice")
    bob = Actor(_BOB_ID, "human", "Bob")

    assert policy.is_empty is False
    assert policy.decide(alice, _PROJECT_A).reason == "explicit-administrator"
    assert policy.decide(alice, "any_project_at_all").allowed is True
    assert policy.decide(bob, _PROJECT_A).allowed is False


def test_bootstrap_admin_accepts_group_claims() -> None:
    policy = build_project_access_policy("", ("name:platform-team",))
    member = Actor("someone", "human", "Someone", groups=("name:platform-team",))
    outsider = Actor("nobody", "human", "Nobody")
    assert policy.decide(member, _PROJECT_A).allowed is True
    assert policy.decide(outsider, _PROJECT_A).allowed is False


def test_bootstrap_admins_compose_with_an_acl(tmp_path: Path) -> None:
    """Bootstrap admins add to the ACL's administrators; they do not replace."""
    acl_path = _write_acl(tmp_path / "acl.json", _acl_body())
    policy = build_project_access_policy(str(acl_path), ("break-glass",))
    assert policy.decide(Actor("security-admin", "human", "S"), "x").allowed is True
    assert policy.decide(Actor("break-glass", "human", "B"), "x").allowed is True
    # The per-project grants survive.
    assert policy.decide(Actor(_ALICE_ID, "human", "A"), _PROJECT_A).allowed is True


def test_bootstrap_admins_reject_malformed_entries() -> None:
    with pytest.raises(ValueError, match="group GUID"):
        parse_bootstrap_administrators(["guid:nope"])
    with pytest.raises(ValueError, match="case-folded"):
        parse_bootstrap_administrators(["name:Mixed-Case"])
    with pytest.raises(ValueError, match="duplicates"):
        parse_bootstrap_administrators(["alice", "alice"])


def test_bootstrap_admins_ignore_blank_entries() -> None:
    grant = parse_bootstrap_administrators(["alice", "", "  ", "bob"])
    assert grant.principals == frozenset({"alice", "bob"})


def test_health_fails_when_enforce_has_no_policy_at_all(tmp_path: Path) -> None:
    """The lockout state is diagnosable, with the remediation in the detail."""
    users_path = _users_path(tmp_path)
    settings = Settings(
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
        project_access_mode="enforce",
        project_acl_path="",
    )
    health = build_health(settings, GatewayRegistry(known_projects=[]))
    check = next(c for c in health["checks"] if c["name"] == "project_access")
    assert check["status"] == "fail"
    assert "DOSSIER_BOOTSTRAP_ADMINS" in check["detail"]
    assert "every project is denied" in check["detail"]


def test_health_warns_when_only_bootstrap_admins_are_configured(
    tmp_path: Path,
) -> None:
    """Recovered but not yet migrated — honest middle state, not 'ok'."""
    users_path = _users_path(tmp_path)
    settings = Settings(
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
        project_access_mode="enforce",
        project_acl_path="",
        bootstrap_administrators=(_ALICE_ID,),
    )
    health = build_health(settings, GatewayRegistry(known_projects=[]))
    check = next(c for c in health["checks"] if c["name"] == "project_access")
    assert check["status"] == "warn"
    assert "bootstrap administrators only" in check["detail"]


@pytest.fixture
def bootstrapped_client(tmp_path: Path):
    """enforce mode, no ACL file, alice recovered via DOSSIER_BOOTSTRAP_ADMINS."""
    users_path = _users_path(tmp_path)
    gateway_a = _gateway(tmp_path, _PROJECT_A)
    registry = GatewayRegistry(known_projects=[_PROJECT_A])
    registry.add(_PROJECT_A, gateway_a)
    settings = Settings(
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
        project_access_mode="enforce",
        project_acl_path="",
        bootstrap_administrators=(_ALICE_ID,),
    )
    app = create_app(settings, registry, LocalBackend(users_path))
    with TestClient(app) as client:
        yield client
    gateway_a.close()


def test_bootstrap_admin_can_read_the_estate_end_to_end(bootstrapped_client) -> None:
    login(bootstrapped_client, "alice", "alice-password")
    dashboard = bootstrapped_client.get("/")
    assert dashboard.status_code == 200
    assert "project-alpha" in dashboard.text
    assert bootstrapped_client.get("/p/project-alpha").status_code == 200


def test_non_bootstrap_user_is_denied_end_to_end(bootstrapped_client) -> None:
    login(bootstrapped_client, "bob", "bob-password")
    dashboard = bootstrapped_client.get("/")
    assert dashboard.status_code == 200
    assert "project-alpha" not in dashboard.text
    assert bootstrapped_client.get("/p/project-alpha").status_code == 403


@pytest.fixture
def unconfigured_client(tmp_path: Path):
    """enforce mode with nothing configured — the lockout state."""
    users_path = _users_path(tmp_path)
    gateway_a = _gateway(tmp_path, _PROJECT_A)
    registry = GatewayRegistry(known_projects=[_PROJECT_A])
    registry.add(_PROJECT_A, gateway_a)
    settings = Settings(
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
        project_access_mode="enforce",
        project_acl_path="",
    )
    app = create_app(settings, registry, LocalBackend(users_path))
    with TestClient(app) as client:
        yield client
    gateway_a.close()


def test_unconfigured_enforce_denies_everything_but_stays_diagnosable(
    unconfigured_client,
) -> None:
    login(unconfigured_client, "alice", "alice-password")
    assert unconfigured_client.get("/p/project-alpha").status_code == 403
    # The app is still up and still able to explain itself.
    assert unconfigured_client.get("/livez").status_code == 200
    health = unconfigured_client.get("/healthz")
    check = next(
        c for c in health.json()["checks"] if c["name"] == "project_access"
    )
    assert check["status"] == "fail"


def test_default_settings_are_deny_by_default() -> None:
    """The dataclass default itself is secure — not just load_settings."""
    from dossier.config import Settings

    assert Settings.__dataclass_fields__["project_access_mode"].default == "enforce"
