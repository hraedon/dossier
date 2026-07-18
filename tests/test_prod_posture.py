"""Production posture: ``DOSSIER_ENV=prod`` promotes safe defaults and the
doctor escalates posture gaps from ``warn`` to ``fail`` (Plan 015 WI-1.1).

``dev`` (the default) preserves every historical default for backwards
compat; ``prod`` is opt-in. These tests pin both sides of the toggle so a
regression in either direction is caught.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from regista.testing import InMemoryRegista

from dossier.app import create_app
from dossier.auth.backends import LocalBackend
from dossier.config import Settings, load_settings
from dossier.gateway import RegistaGateway
from dossier.health import build_health
from dossier.keys import generate_keyset
from dossier.multi import GatewayRegistry

_PROJECT = "dossier_test"


# ── helpers ───────────────────────────────────────────────────────────────


def _hash_pw(pw: str) -> str:
    from dossier.auth.passwords import hash_password

    return hash_password(pw)


def _users_file(tmp_path: Path) -> Path:
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


def _settings(
    tmp_path: Path,
    *,
    env_mode: str = "dev",
    project_access_mode: str = "open",
    allowed_hosts: tuple[str, ...] = (),
    session_secret: str = "test-session-secret-not-for-prod",
    users_path: str | None = None,
    require_ssl: bool = False,
    project_acl_path: str = "",
) -> Settings:
    return Settings(
        database_url="",
        project=_PROJECT,
        hmac_key_path="",
        session_secret=session_secret,
        session_max_age_seconds=43200,
        secure_cookies=False,
        require_ssl=require_ssl,
        users_path=str(_users_file(tmp_path)) if users_path is None else users_path,
        auth_backend="local",
        principal_key_dir=str(tmp_path / "principals"),
        project_access_mode=project_access_mode,  # type: ignore[arg-type]
        project_acl_path=project_acl_path,
        env_mode=env_mode,  # type: ignore[arg-type]
        allowed_hosts=allowed_hosts,
    )


def _make_gateway(tmp_path: Path, project: str = _PROJECT) -> RegistaGateway:
    key_path = tmp_path / f"keys_{project}.json"
    generate_keyset(key_path)
    gw = RegistaGateway(
        InMemoryRegista(project=project, hmac_key_path=str(key_path)),
        project_name=project,
    )
    gw.register_workflow()
    return gw


@pytest.fixture
def empty_registry() -> GatewayRegistry:
    return GatewayRegistry(known_projects=[])


# ── config: DOSSIER_ENV toggles the safe defaults ─────────────────────────


def test_dev_default_require_ssl_off(monkeypatch):
    """dev (the default) keeps require_ssl False — backwards compat."""
    monkeypatch.delenv("DOSSIER_ENV", raising=False)
    monkeypatch.delenv("DOSSIER_REQUIRE_SSL", raising=False)
    monkeypatch.delenv("DOSSIER_PROJECT_ACCESS_MODE", raising=False)
    monkeypatch.delenv("DOSSIER_PROJECT_ACL_PATH", raising=False)
    monkeypatch.delenv("DOSSIER_ALLOWED_HOSTS", raising=False)
    settings = load_settings(strict=False)
    assert settings.env_mode == "dev"
    assert settings.require_ssl is False
    assert settings.project_access_mode == "open"
    assert settings.allowed_hosts == ()


def test_prod_defaults_require_ssl_on(monkeypatch):
    """prod promotes require_ssl to True by default."""
    monkeypatch.setenv("DOSSIER_ENV", "prod")
    monkeypatch.delenv("DOSSIER_REQUIRE_SSL", raising=False)
    settings = load_settings(strict=False)
    assert settings.env_mode == "prod"
    assert settings.require_ssl is True


def test_prod_explicit_require_ssl_override(monkeypatch):
    """An explicit DOSSIER_REQUIRE_SSL wins over the prod default."""
    monkeypatch.setenv("DOSSIER_ENV", "prod")
    monkeypatch.setenv("DOSSIER_REQUIRE_SSL", "false")
    settings = load_settings(strict=False)
    assert settings.require_ssl is False


def test_prod_defaults_access_mode_enforce_with_acl(monkeypatch, tmp_path):
    """prod + an ACL path → project_access_mode defaults to enforce."""
    acl = tmp_path / "acl.json"
    acl.write_text(
        json.dumps(
            {"version": 1, "projects": {_PROJECT: {"principals": ["alice"]}}}
        ),
        encoding="utf-8",
    )
    if os.name == "posix":
        acl.chmod(0o600)
    monkeypatch.setenv("DOSSIER_ENV", "prod")
    monkeypatch.delenv("DOSSIER_PROJECT_ACCESS_MODE", raising=False)
    monkeypatch.setenv("DOSSIER_PROJECT_ACL_PATH", str(acl))
    settings = load_settings(strict=False)
    assert settings.project_access_mode == "enforce"


def test_prod_without_acl_falls_back_to_open(monkeypatch):
    """prod + no ACL → open (so the doctor can report the posture gap as a
    fail, rather than crashing load_settings)."""
    monkeypatch.setenv("DOSSIER_ENV", "prod")
    monkeypatch.delenv("DOSSIER_PROJECT_ACCESS_MODE", raising=False)
    monkeypatch.delenv("DOSSIER_PROJECT_ACL_PATH", raising=False)
    settings = load_settings(strict=False)
    assert settings.project_access_mode == "open"


def test_prod_explicit_access_mode_wins(monkeypatch, tmp_path):
    """An explicit DOSSIER_PROJECT_ACCESS_MODE wins over the prod default."""
    acl = tmp_path / "acl.json"
    acl.write_text(
        json.dumps(
            {"version": 1, "projects": {_PROJECT: {"principals": ["alice"]}}}
        ),
        encoding="utf-8",
    )
    if os.name == "posix":
        acl.chmod(0o600)
    monkeypatch.setenv("DOSSIER_ENV", "prod")
    monkeypatch.setenv("DOSSIER_PROJECT_ACCESS_MODE", "audit")
    monkeypatch.setenv("DOSSIER_PROJECT_ACL_PATH", str(acl))
    settings = load_settings(strict=False)
    assert settings.project_access_mode == "audit"


def test_invalid_env_mode_rejected(monkeypatch):
    monkeypatch.setenv("DOSSIER_ENV", "staging")
    with pytest.raises(ValueError, match="dev' or 'prod'"):
        load_settings(strict=False)


def test_allowed_hosts_parsed(monkeypatch):
    monkeypatch.setenv("DOSSIER_ALLOWED_HOSTS", "dossier.example, ops.example ")
    settings = load_settings(strict=False)
    assert settings.allowed_hosts == ("dossier.example", "ops.example")


# ── health: prod escalates posture gaps from warn to fail ──────────────────


def test_dev_open_access_is_warn(tmp_path, empty_registry):
    settings = _settings(tmp_path, env_mode="dev", project_access_mode="open")
    health = build_health(settings, empty_registry)
    check = next(c for c in health["checks"] if c["name"] == "project_access")
    assert check["status"] == "warn"


def test_prod_open_access_is_fail(tmp_path, empty_registry):
    settings = _settings(tmp_path, env_mode="prod", project_access_mode="open")
    health = build_health(settings, empty_registry)
    check = next(c for c in health["checks"] if c["name"] == "project_access")
    assert check["status"] == "fail"


def test_dev_tls_unset_is_warn(tmp_path, monkeypatch, empty_registry):
    monkeypatch.delenv("DOSSIER_TLS_CERT_PATH", raising=False)
    monkeypatch.delenv("DOSSIER_TLS_KEY_PATH", raising=False)
    settings = _settings(tmp_path, env_mode="dev")
    health = build_health(settings, empty_registry)
    check = next(c for c in health["checks"] if c["name"] == "tls")
    assert check["status"] == "warn"


def test_prod_tls_unset_is_fail(tmp_path, monkeypatch, empty_registry):
    monkeypatch.delenv("DOSSIER_TLS_CERT_PATH", raising=False)
    monkeypatch.delenv("DOSSIER_TLS_KEY_PATH", raising=False)
    settings = _settings(tmp_path, env_mode="prod")
    health = build_health(settings, empty_registry)
    check = next(c for c in health["checks"] if c["name"] == "tls")
    assert check["status"] == "fail"


def test_session_secret_missing_is_fail_in_both_modes(tmp_path, empty_registry):
    """A missing/short session secret is fail in dev AND prod (it always was)."""
    for mode in ("dev", "prod"):
        settings = _settings(
            tmp_path, env_mode=mode, session_secret="short"
        )
        health = build_health(settings, empty_registry)
        check = next(c for c in health["checks"] if c["name"] == "session_secret")
        assert check["status"] == "fail", f"{mode}: {check}"


def test_local_users_path_missing_is_fail_in_both_modes(tmp_path, empty_registry):
    """A missing users_path for the local backend is fail in dev AND prod."""
    for mode in ("dev", "prod"):
        settings = _settings(tmp_path, env_mode=mode, users_path="")
        health = build_health(settings, empty_registry)
        check = next(c for c in health["checks"] if c["name"] == "auth_backend")
        assert check["status"] == "fail", f"{mode}: {check}"


def test_dev_allowed_hosts_unset_is_skip(tmp_path, empty_registry):
    settings = _settings(tmp_path, env_mode="dev", allowed_hosts=())
    health = build_health(settings, empty_registry)
    check = next(c for c in health["checks"] if c["name"] == "allowed_hosts")
    assert check["status"] == "skip"


def test_prod_allowed_hosts_unset_is_warn(tmp_path, empty_registry):
    settings = _settings(tmp_path, env_mode="prod", allowed_hosts=())
    health = build_health(settings, empty_registry)
    check = next(c for c in health["checks"] if c["name"] == "allowed_hosts")
    assert check["status"] == "warn"


def test_allowed_hosts_set_is_ok(tmp_path, empty_registry):
    settings = _settings(
        tmp_path, env_mode="prod", allowed_hosts=("dossier.example",)
    )
    health = build_health(settings, empty_registry)
    check = next(c for c in health["checks"] if c["name"] == "allowed_hosts")
    assert check["status"] == "ok"


def test_prod_ok_when_all_posture_satisfied(tmp_path, monkeypatch, empty_registry):
    """A fully-configured prod deploy reports ok (no false failures)."""
    monkeypatch.delenv("DOSSIER_TLS_CERT_PATH", raising=False)
    monkeypatch.delenv("DOSSIER_TLS_KEY_PATH", raising=False)
    # TLS must be evident in prod — use a real cert/key pair (self-signed).
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("cert", encoding="utf-8")
    key.write_text("key", encoding="utf-8")
    monkeypatch.setenv("DOSSIER_TLS_CERT_PATH", str(cert))
    monkeypatch.setenv("DOSSIER_TLS_KEY_PATH", str(key))
    acl = tmp_path / "acl.json"
    acl.write_text(
        json.dumps(
            {"version": 1, "projects": {_PROJECT: {"principals": ["alice"]}}}
        ),
        encoding="utf-8",
    )
    if os.name == "posix":
        acl.chmod(0o600)
    settings = Settings(
        database_url="",
        project=_PROJECT,
        hmac_key_path="",
        session_secret="x" * 32,
        session_max_age_seconds=43200,
        secure_cookies=True,
        require_ssl=True,
        users_path=str(_users_file(tmp_path)),
        auth_backend="local",
        principal_key_dir=str(tmp_path / "principals"),
        project_access_mode="enforce",
        project_acl_path=str(acl),
        env_mode="prod",
        allowed_hosts=("dossier.example",),
    )
    health = build_health(settings, empty_registry)
    fails = [c for c in health["checks"] if c["status"] == "fail"]
    assert not fails, f"unexpected fails: {fails}"
    assert health["ok"] is True


# ── TrustedHostMiddleware wiring ───────────────────────────────────────────


@pytest.fixture
def gw(tmp_path):
    g = _make_gateway(tmp_path)
    yield g
    g.close()


def _build_app(tmp_path: Path, gw: RegistaGateway, *, allowed_hosts: tuple[str, ...]) -> object:
    settings = _settings(tmp_path, allowed_hosts=allowed_hosts)
    registry = GatewayRegistry(known_projects=[_PROJECT])
    registry.add(_PROJECT, gw)
    return create_app(settings, registry, LocalBackend(_users_file(tmp_path)))


def test_trusted_host_middleware_rejects_unknown_host(tmp_path, gw):
    """When DOSSIER_ALLOWED_HOSTS is set, a request with a disallowed Host
    is rejected (400) by TrustedHostMiddleware."""
    app = _build_app(tmp_path, gw, allowed_hosts=("allowed.example",))
    with TestClient(app, base_url="http://allowed.example") as client:
        # Allowed host reaches the app.
        assert client.get("/login").status_code == 200
        # Disallowed host is rejected by the middleware before routing.
        resp = client.get("/login", headers={"host": "evil.example"})
        assert resp.status_code == 400


def test_no_trusted_host_middleware_when_unset(tmp_path, gw):
    """When DOSSIER_ALLOWED_HOSTS is unset, no TrustedHostMiddleware is wired
    — any Host header is accepted (the dev default)."""
    app = _build_app(tmp_path, gw, allowed_hosts=())
    from starlette.middleware.trustedhost import TrustedHostMiddleware

    has_thm = any(m.cls is TrustedHostMiddleware for m in app.user_middleware)  # type: ignore[attr-defined]
    assert not has_thm
    with TestClient(app) as client:
        # Any host is accepted.
        assert client.get("/login").status_code == 200
        assert (
            client.get("/login", headers={"host": "evil.example"}).status_code == 200
        )
