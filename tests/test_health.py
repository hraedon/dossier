from __future__ import annotations

from dataclasses import replace

from dossier.config import Settings

_PROJECT = "dossier_test"


def _settings(tmp_path) -> Settings:
    return Settings(
        database_url="",
        project=_PROJECT,
        hmac_key_path="",
        session_secret="test-session-secret-not-for-prod",
        session_max_age_seconds=43200,
        secure_cookies=False,
        require_ssl=False,
        users_path=str(tmp_path / "users.json"),
        auth_backend="local",
        principal_key_dir=str(tmp_path / "principals"),
            # explicit: this fixture exercises features, not authz (WI-017)
        project_access_mode="open",
    )


def test_healthz_returns_suite_shape(app, client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["component"] == "dossier"
    assert "version" in body
    assert isinstance(body["ok"], bool)
    assert isinstance(body["degraded"], bool)
    assert "regista" in body
    assert "reachable" in body["regista"]
    assert "project" in body["regista"]
    assert "chain_ok" in body["regista"]
    assert isinstance(body["checks"], list)
    check_names = [c["name"] for c in body["checks"]]
    assert "session_secret" in check_names
    assert "auth_backend" in check_names


def test_healthz_session_secret_pass(client):
    resp = client.get("/healthz")
    body = resp.json()
    secret_check = next(c for c in body["checks"] if c["name"] == "session_secret")
    assert secret_check["status"] == "ok"


def test_healthz_auth_backend_check_present(client):
    resp = client.get("/healthz")
    body = resp.json()
    auth_check = next(c for c in body["checks"] if c["name"] == "auth_backend")
    assert auth_check["status"] in ("ok", "fail")


def test_healthz_never_replays_the_chain(app, client, monkeypatch):
    """Health is a bounded reachability probe.

    /healthz previously called gateway.integrity() — a full chain replay —
    once per configured project. On the production estate (24 projects) that
    cost ~2 GiB per request and was not released between requests, so two
    probes OOM-killed the container; agent-suite's umbrella doctor probes
    this very endpoint, so the suite's health check could kill the service
    it was checking. Chain integrity is an explicit on-demand operation.
    """
    import tempfile
    from pathlib import Path

    from dossier import health as health_mod

    calls: list[str] = []

    class _TrapGateway:
        def list_issues(self, **kwargs):
            return []

        def integrity(self):  # pragma: no cover - must never be reached
            calls.append("integrity")
            raise AssertionError("health must not replay the chain")

    class _TrapRegistry:
        def list_projects(self):
            return ["p1", "p2"]

        def get(self, project):
            return _TrapGateway()

    body = health_mod.build_health(
        _settings(Path(tempfile.mkdtemp())), _TrapRegistry()
    )
    assert calls == []
    # chain_ok is None ("not checked here"), never an implied True
    assert body["regista"]["chain_ok"] is None
    chain = next(c for c in body["checks"] if c["name"] == "chain_integrity")
    assert chain["status"] == "skip"
    assert "on-demand" in chain["detail"]


def test_health_reports_partial_principal_lifecycle_config(tmp_path):
    from dossier.health import build_health

    settings = replace(_settings(tmp_path), trust_log_project="trust-log")

    class _Registry:
        def list_projects(self):
            return []

    body = build_health(settings, _Registry())
    check = next(c for c in body["checks"] if c["name"] == "principal_lifecycle")
    assert check["status"] == "fail"
    assert "REGISTA_TRUST_GENESIS_PATH" in check["detail"]


def test_health_probes_the_separate_principal_lifecycle_gateway(tmp_path):
    from dossier.health import build_health

    genesis = tmp_path / "trust-genesis.json"
    genesis.write_text("{}", encoding="utf-8")
    settings = replace(
        _settings(tmp_path),
        trust_log_project="trust-log",
        trust_genesis_path=str(genesis),
    )

    class _Gateway:
        def has_lifecycle_ops(self):
            return True

        lifecycle_handle_key = 1

        def verify_lifecycle_trust(self):
            return None

    class _Registry:
        def list_projects(self):
            return ["work"]

        def get(self, project):
            assert project == "work"
            return _Gateway()

    body = build_health(settings, _Registry())
    check = next(c for c in body["checks"] if c["name"] == "principal_lifecycle")
    assert check["status"] == "ok"
