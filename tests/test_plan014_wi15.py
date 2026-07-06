"""Tests for Plan 014 WI-1.5 — team deployment (TLS seam, suite.env, LDAP config).

Covers the WI-1.5 deliverables that are unit-testable:
- TLS config seam: ``load_tls_config`` (None when unset, set when configured,
  partial detection) and that ``dossier serve`` wires it into uvicorn
  (``ssl_certfile``/``ssl_keyfile`` passed when set; absent when unset;
  half-set is a fail-loud exit).
- suite.env → settings flow: a suite.env file feeds ``load_settings`` and the
  loaded path is reported by ``suite_env_path`` (the doctor surface).
- doctor ``--json`` reports the new ``tls`` and ``suite_env`` checks.
- LDAP config seam: ``_ldap_config_check`` reports completeness without a bind
  (the live bind is operator-gated infra).

The live cross-machine TLS login + real LDAP bind are operator-gated and not
exercised here (they need the work network + real certs + the directory).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from dossier.config import (
    Settings,
    load_settings,
    load_suite_env,
    load_tls_config,
    suite_env_path,
)
from dossier.health import (
    _ldap_config_check,
    _suite_env_check,
    _tls_checks,
    build_health,
)
from dossier.multi import GatewayRegistry

_PROJECT = "dossier_test"
_SECRET = "test-session-secret-not-for-prod-at-least-32-chars"


def _empty_settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url="",
        project=_PROJECT,
        hmac_key_path="",
        session_secret=_SECRET,
        session_max_age_seconds=43200,
        secure_cookies=False,
        require_ssl=False,
        users_path=str(tmp_path / "users.json"),
        auth_backend="local",
        principal_key_dir=str(tmp_path / "principals"),
    )


def _empty_registry(settings: Settings) -> GatewayRegistry:
    # settings=None so list_projects() is genuinely empty (an empty known_projects
    # list falls back to {settings.project}); this keeps the health probe from
    # attempting a DB connection in a unit test.
    return GatewayRegistry(settings=None, known_projects=[])


@pytest.fixture(autouse=True)
def _reset_suite_env_loaded(monkeypatch):
    import dossier.config as cfg

    monkeypatch.setattr(cfg, "_SUITE_ENV_LOADED", False)
    monkeypatch.setattr(cfg, "_SUITE_ENV_PATH", None)
    yield


# Snapshot/restore the suite env vars these tests touch. ``load_suite_env``
# writes ``os.environ`` directly (not via monkeypatch), and ``monkeypatch.delenv``
# on an already-absent var schedules no restoration — so without this, a value
# injected from a suite.env file leaks into later modules (mirrors the
# ``_cleanup_env`` fixture in test_suite_env.py).
_TRACKED = (
    "REGISTA_DSN", "DOSSIER_DATABASE_URL", "REGISTA_KEY_PATH",
    "DOSSIER_HMAC_KEY_PATH", "DOSSIER_SESSION_SECRET", "AGENT_SUITE_CONFIG",
    "DOSSIER_TLS_CERT_PATH", "DOSSIER_TLS_KEY_PATH", "DOSSIER_AUTH_BACKEND",
    "DOSSIER_USERS_PATH", "DOSSIER_PROJECTS", "DOSSIER_PROJECT",
    "DOSSIER_LDAP_SERVER", "DOSSIER_LDAP_BASE_DN", "DOSSIER_LDAP_BIND_DN",
    "DOSSIER_LDAP_BIND_PASSWORD", "DOSSIER_LDAP_DOMAIN",
)


@pytest.fixture(autouse=True)
def _restore_suite_env():
    snapshot = {k: os.environ.get(k) for k in _TRACKED}
    yield
    for k, v in snapshot.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


# ── TLS config seam ────────────────────────────────────────────────────────


def test_load_tls_config_none_when_unset(monkeypatch):
    monkeypatch.delenv("DOSSIER_TLS_CERT_PATH", raising=False)
    monkeypatch.delenv("DOSSIER_TLS_KEY_PATH", raising=False)
    assert load_tls_config() is None


def test_load_tls_config_returns_config_when_both_set(monkeypatch):
    monkeypatch.setenv("DOSSIER_TLS_CERT_PATH", "/run/secrets/tls/cert.pem")
    monkeypatch.setenv("DOSSIER_TLS_KEY_PATH", "/run/secrets/tls/key.pem")
    tls = load_tls_config()
    assert tls is not None
    assert tls.cert_path == "/run/secrets/tls/cert.pem"
    assert tls.key_path == "/run/secrets/tls/key.pem"


def test_load_tls_config_partial_when_only_one_set(monkeypatch):
    monkeypatch.setenv("DOSSIER_TLS_CERT_PATH", "/run/secrets/tls/cert.pem")
    monkeypatch.delenv("DOSSIER_TLS_KEY_PATH", raising=False)
    tls = load_tls_config()
    assert tls is not None
    assert tls.cert_path == "/run/secrets/tls/cert.pem"
    assert tls.key_path == ""


# ── serve wires TLS into uvicorn ────────────────────────────────────────────


def _serve_env(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("REGISTA_DSN", "postgresql://dossier:dossier@localhost/dossier")
    monkeypatch.setenv("REGISTA_KEY_PATH", str(tmp_path / "keys.json"))
    monkeypatch.setenv("DOSSIER_SESSION_SECRET", "x" * 40)
    monkeypatch.setenv("DOSSIER_AUTH_BACKEND", "local")
    (tmp_path / "users.json").write_text("[]", encoding="utf-8")
    monkeypatch.setenv("DOSSIER_USERS_PATH", str(tmp_path / "users.json"))


def _patch_uvicorn_run(monkeypatch, captured: dict) -> None:
    def _fake_run(app, **kwargs):
        captured["called"] = True
        captured["kwargs"] = kwargs

    monkeypatch.setattr("uvicorn.run", _fake_run)


def test_serve_passes_ssl_kwargs_when_tls_configured(monkeypatch, tmp_path):
    _serve_env(monkeypatch, tmp_path)
    (tmp_path / "cert.pem").write_text("fake-cert", encoding="utf-8")
    (tmp_path / "key.pem").write_text("fake-key", encoding="utf-8")
    monkeypatch.setenv("DOSSIER_TLS_CERT_PATH", str(tmp_path / "cert.pem"))
    monkeypatch.setenv("DOSSIER_TLS_KEY_PATH", str(tmp_path / "key.pem"))

    captured: dict = {}
    _patch_uvicorn_run(monkeypatch, captured)

    from dossier.cli import main

    rc = main(["serve", "--host", "127.0.0.1", "--port", "8000", "--skip-provision-check"])
    assert rc == 0
    assert captured.get("called") is True
    kwargs = captured["kwargs"]
    assert kwargs["ssl_certfile"] == str(tmp_path / "cert.pem")
    assert kwargs["ssl_keyfile"] == str(tmp_path / "key.pem")
    assert kwargs["host"] == "127.0.0.1"
    assert kwargs["port"] == 8000


def test_serve_plain_http_when_tls_unset(monkeypatch, tmp_path):
    _serve_env(monkeypatch, tmp_path)
    monkeypatch.delenv("DOSSIER_TLS_CERT_PATH", raising=False)
    monkeypatch.delenv("DOSSIER_TLS_KEY_PATH", raising=False)

    captured: dict = {}
    _patch_uvicorn_run(monkeypatch, captured)

    from dossier.cli import main

    rc = main(["serve", "--host", "127.0.0.1", "--port", "8000", "--skip-provision-check"])
    assert rc == 0
    assert captured.get("called") is True
    kwargs = captured["kwargs"]
    assert "ssl_certfile" not in kwargs
    assert "ssl_keyfile" not in kwargs


def test_serve_rejects_half_set_tls(monkeypatch, tmp_path, capsys):
    _serve_env(monkeypatch, tmp_path)
    monkeypatch.setenv("DOSSIER_TLS_CERT_PATH", str(tmp_path / "cert.pem"))
    monkeypatch.delenv("DOSSIER_TLS_KEY_PATH", raising=False)

    captured: dict = {}
    _patch_uvicorn_run(monkeypatch, captured)

    from dossier.cli import main

    rc = main(["serve", "--host", "127.0.0.1", "--port", "8000", "--skip-provision-check"])
    assert rc == 2
    assert not captured.get("called")
    err = capsys.readouterr().err
    assert "DOSSIER_TLS_CERT_PATH" in err
    assert "DOSSIER_TLS_KEY_PATH" in err


# ── doctor / health checks ─────────────────────────────────────────────────


def test_tls_check_warn_when_unset(monkeypatch):
    monkeypatch.delenv("DOSSIER_TLS_CERT_PATH", raising=False)
    monkeypatch.delenv("DOSSIER_TLS_KEY_PATH", raising=False)
    [check] = _tls_checks()
    assert check["status"] == "warn"
    assert "plain HTTP" in check["detail"]


def test_tls_check_ok_when_configured_and_present(monkeypatch, tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("x")
    key.write_text("x")
    monkeypatch.setenv("DOSSIER_TLS_CERT_PATH", str(cert))
    monkeypatch.setenv("DOSSIER_TLS_KEY_PATH", str(key))
    [check] = _tls_checks()
    assert check["status"] == "ok"
    assert str(cert) in check["detail"]


def test_tls_check_fail_when_configured_but_missing(monkeypatch):
    monkeypatch.setenv("DOSSIER_TLS_CERT_PATH", "/no/such/cert.pem")
    monkeypatch.setenv("DOSSIER_TLS_KEY_PATH", "/no/such/key.pem")
    [check] = _tls_checks()
    assert check["status"] == "fail"
    assert "cert not found" in check["detail"]
    assert "key not found" in check["detail"]


def test_suite_env_check_skip_when_none(monkeypatch):
    import dossier.config as cfg

    monkeypatch.setattr(cfg, "_SUITE_ENV_PATH", None)
    check = _suite_env_check()
    assert check["status"] == "skip"
    assert "process env" in check["detail"]


def test_suite_env_check_ok_when_loaded(monkeypatch):
    import dossier.config as cfg

    monkeypatch.setattr(cfg, "_SUITE_ENV_PATH", "/etc/agent-suite/suite.env")
    check = _suite_env_check()
    assert check["status"] == "ok"
    assert "/etc/agent-suite/suite.env" in check["detail"]


def test_ldap_config_check_fail_when_incomplete(monkeypatch):
    for k in (
        "DOSSIER_LDAP_SERVER", "DOSSIER_LDAP_BASE_DN", "DOSSIER_LDAP_BIND_DN",
        "DOSSIER_LDAP_BIND_PASSWORD", "DOSSIER_LDAP_DOMAIN",
    ):
        monkeypatch.delenv(k, raising=False)
    check = _ldap_config_check()
    assert check["status"] == "fail"
    assert "DOSSIER_LDAP_SERVER" in check["detail"]


def test_ldap_config_check_ok_when_complete(monkeypatch):
    monkeypatch.setenv("DOSSIER_LDAP_SERVER", "ldaps://dc.WORK-DOMAIN:636")
    monkeypatch.setenv("DOSSIER_LDAP_BASE_DN", "DC=WORK-DOMAIN")
    monkeypatch.setenv("DOSSIER_LDAP_BIND_DN", "CN=svc-dossier,DC=WORK-DOMAIN")
    monkeypatch.setenv("DOSSIER_LDAP_BIND_PASSWORD", "env:DOSSIER_LDAP_BIND_PASSWORD")
    monkeypatch.setenv("DOSSIER_LDAP_DOMAIN", "WORK-DOMAIN")
    check = _ldap_config_check()
    assert check["status"] == "ok"
    assert "ldap configured" in check["detail"]


def test_build_health_includes_tls_and_suite_env_checks(monkeypatch, tmp_path):
    monkeypatch.delenv("DOSSIER_TLS_CERT_PATH", raising=False)
    monkeypatch.delenv("DOSSIER_TLS_KEY_PATH", raising=False)
    settings = _empty_settings(tmp_path)
    registry = _empty_registry(settings)
    health = build_health(settings, registry)
    names = [c["name"] for c in health["checks"]]
    assert "tls" in names
    assert "suite_env" in names
    tls = next(c for c in health["checks"] if c["name"] == "tls")
    assert tls["status"] == "warn"


def test_doctor_json_emits_tls_and_suite_env(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("DOSSIER_PROJECTS", "")  # no projects → regista skip, no DB contact
    monkeypatch.delenv("REGISTA_DSN", raising=False)
    monkeypatch.delenv("DOSSIER_DATABASE_URL", raising=False)
    monkeypatch.setenv("DOSSIER_SESSION_SECRET", "x" * 40)
    monkeypatch.setenv("DOSSIER_AUTH_BACKEND", "local")
    monkeypatch.setenv("DOSSIER_USERS_PATH", str(tmp_path / "users.json"))
    monkeypatch.delenv("DOSSIER_TLS_CERT_PATH", raising=False)
    monkeypatch.delenv("DOSSIER_TLS_KEY_PATH", raising=False)

    from dossier.cli import main

    main(["doctor", "--json"])
    out = capsys.readouterr().out
    health = json.loads(out)
    names = [c["name"] for c in health["checks"]]
    assert "tls" in names
    assert "suite_env" in names
    tls = next(c for c in health["checks"] if c["name"] == "tls")
    assert tls["status"] == "warn"
    # regista is unreachable without a DB (a named fail, not a 500) — the point
    # of this test is the new tls/suite_env checks, not the regista connection.


# ── suite.env → settings flow ───────────────────────────────────────────────


def test_suite_env_feeds_settings_and_reports_path(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("AGENT_SUITE_CONFIG", raising=False)
    for k in (
        "REGISTA_DSN", "DOSSIER_DATABASE_URL", "REGISTA_KEY_PATH",
        "DOSSIER_HMAC_KEY_PATH", "DOSSIER_SESSION_SECRET",
    ):
        monkeypatch.delenv(k, raising=False)

    suite = tmp_path / "suite.env"
    suite.write_text(
        "REGISTA_DSN=postgresql://from-suite/db\n"
        "REGISTA_KEY_PATH=/suite/keys.json\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("AGENT_SUITE_CONFIG", str(suite))

    load_suite_env()
    settings = load_settings(strict=False)
    assert settings.database_url == "postgresql://from-suite/db"
    assert settings.hmac_key_path == "/suite/keys.json"
    assert suite_env_path() == str(suite)


def test_suite_env_does_not_override_process_env_in_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("AGENT_SUITE_CONFIG", raising=False)
    for k in (
        "REGISTA_DSN", "DOSSIER_DATABASE_URL", "REGISTA_KEY_PATH",
        "DOSSIER_HMAC_KEY_PATH", "DOSSIER_SESSION_SECRET",
    ):
        monkeypatch.delenv(k, raising=False)

    suite = tmp_path / "suite.env"
    suite.write_text("REGISTA_DSN=postgresql://from-file/db\n", encoding="utf-8")
    monkeypatch.setenv("AGENT_SUITE_CONFIG", str(suite))
    monkeypatch.setenv("REGISTA_DSN", "postgresql://from-process/db")

    load_suite_env()
    settings = load_settings(strict=False)
    assert settings.database_url == "postgresql://from-process/db"
