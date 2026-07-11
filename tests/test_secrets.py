"""Tests for dossier's suite secret-backend resolution layer (Plan 013 WI-4.1).

Mirrors agent-notes' test_secrets.py — dossier adopted the same hardened
pattern, and these tests pin the contract so a future refactor cannot regress
the security properties (silent-literal-fallback guard, ref-safe error
messages, atexit + close_all scrubbing).

Also covers the dossier-specific wiring:
- GatewayRegistry._build resolves the DSN and materializes the key-set
  manifest, and tracks the cleanup so close_all scrubs the temp file.
- _check_provisioned resolves a backend ref DSN before connecting.
- health._secrets_backend_checks flags a missing file: manifest.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from dossier import secrets as suite_secrets


def test_resolve_secret_bytes_requires_explicit_backend_ref():
    with pytest.raises(RuntimeError, match="backend ref"):
        suite_secrets.resolve_secret_bytes(
            "plaintext-secret-that-must-not-be-accepted"
        )


def test_resolve_secret_bytes_refuses_literal_provider():
    with pytest.raises(RuntimeError, match="not permitted"):
        suite_secrets.resolve_secret_bytes("literal:" + "s" * 32)


def test_resolve_secret_bytes_from_env(monkeypatch):
    monkeypatch.setenv("DOSSIER_TEST_WAKE_SECRET", "s" * 32)
    assert (
        suite_secrets.resolve_secret_bytes("env:DOSSIER_TEST_WAKE_SECRET")
        == b"s" * 32
    )


def test_resolve_secret_bytes_rejects_short_secret(monkeypatch):
    monkeypatch.setenv("DOSSIER_TEST_WAKE_SECRET", "short")
    with pytest.raises(RuntimeError, match="at least 32 bytes"):
        suite_secrets.resolve_secret_bytes("env:DOSSIER_TEST_WAKE_SECRET")

# ---------------------------------------------------------------------------
# resolve_dsn
# ---------------------------------------------------------------------------


def test_resolve_dsn_none_and_empty_passthrough():
    assert suite_secrets.resolve_dsn(None) is None
    assert suite_secrets.resolve_dsn("") == ""


def test_resolve_dsn_literal_unchanged():
    """A literal DSN has no provider prefix → returned as-is, regista untouched."""
    dsn = "postgresql://user:pass@host:5432/dossier"
    assert suite_secrets.resolve_dsn(dsn) == dsn


def test_resolve_dsn_literal_with_special_chars_in_password():
    """A password containing ``@``/``:`` must not be misread as a provider ref."""
    dsn = "postgresql://user:p@ss:word@host/db"
    assert suite_secrets.resolve_dsn(dsn) == dsn


def test_resolve_dsn_env_ref(monkeypatch):
    monkeypatch.setenv("DOSSIER_TEST_DSN", "postgresql://from-env/x")
    assert suite_secrets.resolve_dsn("env:DOSSIER_TEST_DSN") == "postgresql://from-env/x"


def test_resolve_dsn_file_ref(tmp_path):
    dsn_file = tmp_path / "dsn.txt"
    dsn_file.write_text("postgresql://from-file/x")
    assert suite_secrets.resolve_dsn(f"file:{dsn_file}") == "postgresql://from-file/x"


def test_resolve_dsn_env_missing_raises_runtime():
    with pytest.raises(RuntimeError, match="Failed to resolve DSN secret"):
        suite_secrets.resolve_dsn("env:DOSSIER_DEFINITELY_UNSET_DSN_VAR_X9Z")


def test_resolve_dsn_failure_message_is_type_only(monkeypatch):
    """A resolution failure surfaces only the exception type, never ``str(exc)``."""
    sentinel = "vault_secret_path_sentinel_x9z"
    monkeypatch.delenv(f"DOSSIER_{sentinel}", raising=False)
    with pytest.raises(RuntimeError) as exc_info:
        suite_secrets.resolve_dsn(f"env:DOSSIER_{sentinel}")
    assert sentinel not in str(exc_info.value)


# ---------------------------------------------------------------------------
# materialize_key_manifest
# ---------------------------------------------------------------------------


def test_manifest_none_and_empty():
    assert suite_secrets.materialize_key_manifest(None) == (None, None)
    assert suite_secrets.materialize_key_manifest("") == (None, None)


def test_manifest_bare_path_passes_through():
    raw = "/etc/regista/keys.json"
    path, cleanup = suite_secrets.materialize_key_manifest(raw)
    assert path == str(Path(raw))
    assert cleanup is None


def test_manifest_tilde_path_is_expanded(monkeypatch):
    monkeypatch.setenv("HOME", "/home/test")
    monkeypatch.setenv("USERPROFILE", "/home/test")
    path, cleanup = suite_secrets.materialize_key_manifest("~/.config/regista/keys.json")
    assert path == str(Path("/home/test/.config/regista/keys.json"))
    assert cleanup is None


def test_manifest_file_prefix_strips_to_plain_path(tmp_path):
    kp = tmp_path / "keys.json"
    kp.write_text('{"keys": []}')
    path, cleanup = suite_secrets.materialize_key_manifest(f"file:{kp}")
    assert path == str(kp)
    assert cleanup is None


def test_manifest_env_ref_materializes_temp_file(monkeypatch):
    manifest = json.dumps({"keys": [{"key_id": "k1", "secret": "x"}]})
    monkeypatch.setenv("DOSSIER_KEY_MANIFEST", manifest)
    path, cleanup = suite_secrets.materialize_key_manifest("env:DOSSIER_KEY_MANIFEST")

    assert path is not None
    assert cleanup is not None
    assert path != "env:DOSSIER_KEY_MANIFEST"
    assert Path(path).read_text() == manifest
    if os.name == "posix":
        mode = stat.S_IMODE(Path(path).stat().st_mode)
        assert mode == 0o600
    assert suite_secrets.materialized_temp_count() >= 1
    cleanup()
    assert not Path(path).exists()
    cleanup()  # idempotent — must not raise


def test_manifest_env_ref_unresolvable_raises(monkeypatch):
    monkeypatch.delenv("DOSSIER_MISSING_KEY_MANIFEST", raising=False)
    with pytest.raises(RuntimeError, match="Failed to resolve key-set manifest"):
        suite_secrets.materialize_key_manifest("env:DOSSIER_MISSING_KEY_MANIFEST")


def test_manifest_literal_refused():
    with pytest.raises(RuntimeError, match="literal: is not a valid key-set manifest"):
        suite_secrets.materialize_key_manifest('literal:{"keys":[]}')


def test_manifest_vault_without_sdk_fails_cleanly(monkeypatch):
    """A vault ref must fail cleanly (RuntimeError), never leak the ref text."""
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    sentinel = "secret/agent-suite/regista"
    with pytest.raises(RuntimeError) as exc_info:
        suite_secrets.materialize_key_manifest(f"vault:{sentinel}/keys")
    assert sentinel not in str(exc_info.value)


# ---------------------------------------------------------------------------
# adversarial-review regression tests (BLOCKING / MAJOR findings)
# ---------------------------------------------------------------------------


def test_resolve_dsn_vault_without_sdk_raises_not_silent(monkeypatch):
    """BLOCKING: a vault: DSN that cannot resolve must raise, never return the ref.

    Robust to whether ``hvac`` is installed: if absent, regista's silent-
    literal-fallback would return the ref unchanged (our guard catches that);
    if present but unconfigured, regista raises RegistaError (our wrapper
    converts it). Either way the ref string must NOT come back as the DSN, and
    the vault path must not be echoed in the message.
    """
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    sentinel = "agent-suite-sentinel-path"
    ref = f"vault:secret/{sentinel}/dsn"
    with pytest.raises(RuntimeError) as exc_info:
        suite_secrets.resolve_dsn(ref)
    assert sentinel not in str(exc_info.value)


def test_resolve_dsn_azure_without_sdk_raises_not_silent(monkeypatch):
    monkeypatch.delenv("AZURE_KEY_VAULT_NAME", raising=False)
    with pytest.raises(RuntimeError):
        suite_secrets.resolve_dsn("azure:regista-dsn")


def test_resolve_dsn_uppercase_prefix_resolves(monkeypatch):
    """MAJOR: ENV:VAR must resolve (prefix normalized), not silently fail."""
    monkeypatch.setenv("DOSSIER_UPPER_DSN", "postgresql://resolved/x")
    assert suite_secrets.resolve_dsn("ENV:DOSSIER_UPPER_DSN") == "postgresql://resolved/x"
    monkeypatch.setenv("DOSSIER_UPPER_DSN2", "postgresql://resolved2/x")
    assert suite_secrets.resolve_dsn("Env:DOSSIER_UPPER_DSN2") == "postgresql://resolved2/x"


def test_resolve_dsn_env_self_referential_not_flagged(monkeypatch):
    """env: must NOT trip the silent-fallback guard (always-registered provider)."""
    monkeypatch.setenv("DOSSIER_SELFREF", "env:DOSSIER_SELFREF")
    assert suite_secrets.resolve_dsn("env:DOSSIER_SELFREF") == "env:DOSSIER_SELFREF"


def test_wrapped_exception_cause_is_suppressed(monkeypatch):
    """``from None`` keeps the original (ref-echoing) exception out of __cause__."""
    monkeypatch.delenv("DOSSIER_CAUSE_LEAK_VAR", raising=False)
    with pytest.raises(RuntimeError) as exc_info:
        suite_secrets.resolve_dsn("env:DOSSIER_CAUSE_LEAK_VAR")
    assert exc_info.value.__cause__ is None


def test_manifest_uppercase_prefix_resolves(monkeypatch):
    manifest = json.dumps({"keys": []})
    monkeypatch.setenv("DOSSIER_UPPER_MANIFEST", manifest)
    path, cleanup = suite_secrets.materialize_key_manifest("ENV:DOSSIER_UPPER_MANIFEST")
    assert path is not None and cleanup is not None
    assert Path(path).read_text() == manifest
    cleanup()


def test_manifest_non_list_keys_rejected(monkeypatch):
    monkeypatch.setenv("DOSSIER_BAD_KEYS", '{"keys": "not-a-list"}')
    with pytest.raises(RuntimeError, match="must be a JSON object with a 'keys' array"):
        suite_secrets.materialize_key_manifest("env:DOSSIER_BAD_KEYS")


# ---------------------------------------------------------------------------
# atexit safety net
# ---------------------------------------------------------------------------


def test_scrub_all_cleans_registered_temps(monkeypatch):
    monkeypatch.setenv("DOSSIER_ATEXIT_MANIFEST", '{"keys":[]}')
    before = suite_secrets.materialized_temp_count()
    path, _cleanup = suite_secrets.materialize_key_manifest("env:DOSSIER_ATEXIT_MANIFEST")
    assert Path(path).exists()
    assert suite_secrets.materialized_temp_count() == before + 1
    suite_secrets._scrub_all()
    assert not Path(path).exists()
    assert suite_secrets.materialized_temp_count() == 0


def test_write_temp_manifest_scrubs_on_os_write_failure(monkeypatch):
    """MINOR (review round-2): if os.write fails, mkstemp's file is scrubbed
    so it does not persist past the failed resolution attempt."""
    import dossier.secrets as secrets_mod

    real_write = secrets_mod.os.write

    def _failing_write(fd, data):
        raise OSError("simulated disk full")

    monkeypatch.setattr(secrets_mod.os, "write", _failing_write)
    try:
        with pytest.raises(OSError):
            secrets_mod._write_temp_manifest(b'{"keys": []}')
    finally:
        secrets_mod.os.write = real_write  # type: ignore[assignment]

    # No temp file leaked into the registry (so atexit will not scrub a stray).
    # Hard to assert the exact file is gone without knowing its name, but we
    # can assert the registry count did not grow.
    assert secrets_mod.materialized_temp_count() == 0


# ---------------------------------------------------------------------------
# is_backend_ref predicate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, False),
        ("", False),
        ("postgresql://user:pass@host/db", False),
        ("/etc/regista/keys.json", False),
        ("~/.config/regista/keys.json", False),
        ("env:VAR", True),
        ("ENV:VAR", True),
        ("Vault:secret/x", True),
        ("vault:secret/x", True),
        ("azure:name", True),
        ("AZURE:name", True),
        ("file:/x", True),
        ("postgresql://host", False),
        ("akv:https://v/secrets/k", False),
    ],
)
def test_is_backend_ref(value, expected):
    assert suite_secrets.is_backend_ref(value) is expected


# ---------------------------------------------------------------------------
# GatewayRegistry wiring (Plan 013 WI-4.1)
# ---------------------------------------------------------------------------


def test_registry_close_all_scrubs_materialized_temp_manifest(monkeypatch, tmp_path):
    """A registry that builds a gateway from a backend-sourced manifest must
    scrub the temp file when closed.

    Uses a regista.Regista test-double so no Postgres is required; we only
    assert the cleanup bookkeeping, not the DB connection.
    """
    from dossier.config import Settings
    from dossier.multi import GatewayRegistry

    manifest = json.dumps({"keys": []})
    monkeypatch.setenv("DOSSIER_REGISTRY_MANIFEST", manifest)
    monkeypatch.setenv("DOSSIER_REGISTRY_DSN", "postgresql://from-backend/x")

    captured: dict[str, object] = {}

    class _FakeRegista:
        def __init__(self, dsn, project, key_path, *, require_ssl=False):
            captured["dsn"] = dsn
            captured["project"] = project
            captured["key_path"] = key_path

        def register_workflow(self, *_a, **_kw):
            return None

        def close(self):
            return None

    import regista

    monkeypatch.setattr(regista, "Regista", _FakeRegista)

    settings = Settings(
        database_url="env:DOSSIER_REGISTRY_DSN",
        project="dossier_test",
        hmac_key_path="env:DOSSIER_REGISTRY_MANIFEST",
        session_secret="x" * 40,
        session_max_age_seconds=43200,
        secure_cookies=False,
        require_ssl=False,
        users_path="",
        auth_backend="local",
        principal_key_dir="",
    )
    registry = GatewayRegistry(settings=settings, known_projects=["dossier_test"])
    gw = registry.get("dossier_test")

    assert captured["dsn"] == "postgresql://from-backend/x"
    materialized_path = captured["key_path"]
    assert materialized_path != "env:DOSSIER_REGISTRY_MANIFEST"
    assert Path(materialized_path).exists()

    registry.close_all()
    assert not Path(materialized_path).exists()
    gw.close()  # _FakeRegista.close is a no-op


def test_registry_build_failure_scrubs_temp_and_closes_pool(monkeypatch, tmp_path):
    """MAJOR (review round-2): if register_workflow raises after Regista() opened
    its connection pool, _build must close the pool AND scrub the materialized
    manifest, so a retry loop cannot accumulate connections or temp files.
    """
    from dossier.config import Settings
    from dossier.multi import GatewayRegistry

    manifest = json.dumps({"keys": []})
    monkeypatch.setenv("DOSSIER_BUILD_FAIL_MANIFEST", manifest)

    closed: list[bool] = []
    materialized_paths: list[str] = []

    class _FakeRegista:
        def __init__(self, dsn, project, key_path, *, require_ssl=False):
            materialized_paths.append(key_path)

        def register_workflow(self, *_a, **_kw):
            raise RuntimeError("simulated workflow registration failure")

        def close(self):
            closed.append(True)

    import regista

    monkeypatch.setattr(regista, "Regista", _FakeRegista)

    settings = Settings(
        database_url="postgresql://literal/x",
        project="dossier_test",
        hmac_key_path="env:DOSSIER_BUILD_FAIL_MANIFEST",
        session_secret="x" * 40,
        session_max_age_seconds=43200,
        secure_cookies=False,
        require_ssl=False,
        users_path="",
        auth_backend="local",
        principal_key_dir="",
    )
    registry = GatewayRegistry(settings=settings, known_projects=["dossier_test"])
    with pytest.raises(RuntimeError, match="simulated workflow"):
        registry.get("dossier_test")

    # The pool was closed and the temp manifest was scrubbed.
    assert closed == [True]
    assert materialized_paths, "Regista() should have been constructed"
    assert not Path(materialized_paths[0]).exists()
    # Nothing tracked for later cleanup (it was already scrubbed).
    assert registry._key_cleanups == {}


def test_registry_literal_path_no_cleanup(monkeypatch, tmp_path):
    """A literal/bare-path manifest passes through and registers no cleanup."""
    from dossier.config import Settings
    from dossier.multi import GatewayRegistry

    key_file = tmp_path / "keys.json"
    key_file.write_text('{"keys": []}')

    captured: dict[str, object] = {}

    class _FakeRegista:
        def __init__(self, dsn, project, key_path, *, require_ssl=False):
            captured["key_path"] = key_path

        def register_workflow(self, *_a, **_kw):
            return None

        def close(self):
            return None

    import regista

    monkeypatch.setattr(regista, "Regista", _FakeRegista)

    settings = Settings(
        database_url="postgresql://literal/x",
        project="dossier_test",
        hmac_key_path=str(key_file),
        session_secret="x" * 40,
        session_max_age_seconds=43200,
        secure_cookies=False,
        require_ssl=False,
        users_path="",
        auth_backend="local",
        principal_key_dir="",
    )
    registry = GatewayRegistry(settings=settings, known_projects=["dossier_test"])
    registry.get("dossier_test")
    assert captured["key_path"] == str(key_file)
    # No cleanup registered for a literal/file manifest.
    assert registry._key_cleanups == {}
    registry.close_all()


# ---------------------------------------------------------------------------
# health._secrets_backend_checks
# ---------------------------------------------------------------------------


def test_health_secrets_check_skip_for_plaintext(tmp_path):
    from dossier.config import Settings
    from dossier.health import _secrets_backend_checks

    settings = Settings(
        database_url="postgresql://literal/x",
        project="dossier_test",
        hmac_key_path=str(tmp_path / "keys.json"),
        session_secret="x" * 40,
        session_max_age_seconds=43200,
        secure_cookies=False,
        require_ssl=False,
        users_path="",
        auth_backend="local",
        principal_key_dir="",
    )
    checks = _secrets_backend_checks(settings)
    assert len(checks) == 1
    assert checks[0]["status"] == "skip"


def test_health_secrets_check_fails_for_missing_file_manifest(tmp_path):
    """MAJOR: a file: manifest that does not exist must fail, not pass silently."""
    from dossier.config import Settings
    from dossier.health import _secrets_backend_checks

    missing = tmp_path / "absent-keys.json"
    settings = Settings(
        database_url="postgresql://literal/x",
        project="dossier_test",
        hmac_key_path=f"file:{missing}",
        session_secret="x" * 40,
        session_max_age_seconds=43200,
        secure_cookies=False,
        require_ssl=False,
        users_path="",
        auth_backend="local",
        principal_key_dir="",
    )
    checks = _secrets_backend_checks(settings)
    key_check = [c for c in checks if c["name"] == "secrets_backend:REGISTA_KEY_PATH"][0]
    assert key_check["status"] == "fail"
    assert "REGISTA_KEY_PATH" in key_check["detail"]


def test_health_secrets_check_ok_for_env_refs(monkeypatch, tmp_path):
    from dossier.config import Settings
    from dossier.health import _secrets_backend_checks

    monkeypatch.setenv("DOSSIER_HEALTH_DSN", "postgresql://resolved/x")
    manifest = json.dumps({"keys": []})
    monkeypatch.setenv("DOSSIER_HEALTH_MANIFEST", manifest)

    settings = Settings(
        database_url="env:DOSSIER_HEALTH_DSN",
        project="dossier_test",
        hmac_key_path="env:DOSSIER_HEALTH_MANIFEST",
        session_secret="x" * 40,
        session_max_age_seconds=43200,
        secure_cookies=False,
        require_ssl=False,
        users_path="",
        auth_backend="local",
        principal_key_dir="",
    )
    checks = _secrets_backend_checks(settings)
    statuses = {c["name"]: c["status"] for c in checks}
    assert statuses["secrets_backend:REGISTA_DSN"] == "ok"
    assert statuses["secrets_backend:REGISTA_KEY_PATH"] == "ok"


def test_health_secrets_check_fails_for_corrupt_file_manifest(tmp_path):
    """MEDIUM: a file: manifest that exists but is not a valid key-set must
    fail the health check, not pass silently and surface later at KeySet time."""
    from dossier.config import Settings
    from dossier.health import _secrets_backend_checks

    bad = tmp_path / "bad-keys.json"
    bad.write_text("not json at all")
    settings = Settings(
        database_url="postgresql://literal/x",
        project="dossier_test",
        hmac_key_path=f"file:{bad}",
        session_secret="x" * 40,
        session_max_age_seconds=43200,
        secure_cookies=False,
        require_ssl=False,
        users_path="",
        auth_backend="local",
        principal_key_dir="",
    )
    checks = _secrets_backend_checks(settings)
    key_check = [c for c in checks if c["name"] == "secrets_backend:REGISTA_KEY_PATH"][0]
    assert key_check["status"] == "fail"


# ---------------------------------------------------------------------------
# config.load_settings — principal_key_dir derivation guard
# ---------------------------------------------------------------------------


def test_config_principal_key_dir_refuses_remote_backend_ref(monkeypatch):
    """MAJOR (review #1): a remote backend ref has no parent dir; deriving
    would drop principal keys into the CWD. Must raise."""
    monkeypatch.setenv("REGISTA_DSN", "postgresql://x/x")
    monkeypatch.setenv("REGISTA_KEY_PATH", "env:DOSSIER_REMOTE_KEYS")
    monkeypatch.setenv("DOSSIER_SESSION_SECRET", "x" * 40)
    monkeypatch.delenv("DOSSIER_PRINCIPAL_KEY_DIR", raising=False)

    from dossier.config import load_settings

    with pytest.raises(RuntimeError, match="DOSSIER_PRINCIPAL_KEY_DIR must be set"):
        load_settings(strict=False)


def test_config_principal_key_dir_derives_for_file_ref(monkeypatch, tmp_path):
    """A file: ref resolves to a real path; derive principals alongside it."""
    key_file = tmp_path / "keys.json"
    key_file.write_text('{"keys": []}')
    monkeypatch.setenv("REGISTA_DSN", "postgresql://x/x")
    monkeypatch.setenv("REGISTA_KEY_PATH", f"file:{key_file}")
    monkeypatch.setenv("DOSSIER_SESSION_SECRET", "x" * 40)
    monkeypatch.delenv("DOSSIER_PRINCIPAL_KEY_DIR", raising=False)

    from dossier.config import load_settings

    settings = load_settings(strict=False)
    assert settings.principal_key_dir == str(tmp_path / "principals")


def test_config_principal_key_dir_derives_for_bare_path(monkeypatch, tmp_path):
    """A bare filesystem path still derives principals (today's default)."""
    key_file = tmp_path / "keys.json"
    key_file.write_text('{"keys": []}')
    monkeypatch.setenv("REGISTA_DSN", "postgresql://x/x")
    monkeypatch.setenv("REGISTA_KEY_PATH", str(key_file))
    monkeypatch.setenv("DOSSIER_SESSION_SECRET", "x" * 40)
    monkeypatch.delenv("DOSSIER_PRINCIPAL_KEY_DIR", raising=False)

    from dossier.config import load_settings

    settings = load_settings(strict=False)
    assert settings.principal_key_dir == str(tmp_path / "principals")


def test_config_principal_key_dir_explicit_wins_over_remote_ref(monkeypatch):
    """An explicit DOSSIER_PRINCIPAL_KEY_DIR takes precedence and does not
    raise even when hmac_key_path is a remote ref."""
    monkeypatch.setenv("REGISTA_DSN", "postgresql://x/x")
    monkeypatch.setenv("REGISTA_KEY_PATH", "env:DOSSIER_REMOTE_KEYS_2")
    monkeypatch.setenv("DOSSIER_SESSION_SECRET", "x" * 40)
    monkeypatch.setenv("DOSSIER_PRINCIPAL_KEY_DIR", "/var/lib/dossier/principals")

    from dossier.config import load_settings

    settings = load_settings(strict=False)
    assert settings.principal_key_dir == "/var/lib/dossier/principals"
