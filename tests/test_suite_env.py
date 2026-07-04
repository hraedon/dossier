from __future__ import annotations

import os

import pytest

from dossier.config import _inject_env_file, _strip_value, load_suite_env


@pytest.fixture(autouse=True)
def _reset_loaded_flag(monkeypatch):
    import dossier.config as cfg

    monkeypatch.setattr(cfg, "_SUITE_ENV_LOADED", False)
    yield


@pytest.fixture
def clean_env(monkeypatch):
    monkeypatch.delenv("AGENT_SUITE_CONFIG", raising=False)
    monkeypatch.delenv("REGISTA_DSN", raising=False)
    monkeypatch.delenv("REGISTA_KEY_PATH", raising=False)
    monkeypatch.delenv("DOSSIER_TEST_VAR", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    yield


def _tracked_keys():
    return {"REGISTA_DSN", "KEY_PATH", "FOO", "BAZ", "NEW_VAR",
            "DOSSIER_TEST_VAR", "EXISTING_VAR", "DOSSIER_LDAP_BIND_PASSWORD"}


@pytest.fixture(autouse=True)
def _cleanup_env():
    snapshot = {k: os.environ.get(k) for k in _tracked_keys()}
    yield
    for k, v in snapshot.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


# ── _strip_value tests ──────────────────────────────────────────────────────

def test_strip_value_single_quotes():
    assert _strip_value("'hello'") == "hello"


def test_strip_value_double_quotes():
    assert _strip_value('"hello"') == "hello"


def test_strip_value_no_quotes():
    assert _strip_value("hello") == "hello"


def test_strip_value_inline_comment_unquoted():
    assert _strip_value("hello  # a comment") == "hello"


def test_strip_value_quoted_preserves_hash():
    assert _strip_value('"has#hash"') == "has#hash"


def test_strip_value_empty():
    assert _strip_value("") == ""


def test_strip_value_quoted_preserves_space_hash():
    assert _strip_value('"a password # secret"') == "a password # secret"


def test_strip_value_unquoted_then_inline_comment():
    assert _strip_value("value # a comment") == "value"


def test_strip_value_quoted_then_inline_comment():
    assert _strip_value('"value" # a comment') == "value"


# ── _inject_env_file tests ──────────────────────────────────────────────────

def test_inject_env_file_basic(tmp_path):
    f = tmp_path / "suite.env"
    f.write_text('REGISTA_DSN=postgresql://localhost/db\nKEY_PATH="/tmp/key.json"\n')
    _inject_env_file(str(f))
    assert os.environ["REGISTA_DSN"] == "postgresql://localhost/db"
    assert os.environ["KEY_PATH"] == "/tmp/key.json"


def test_inject_env_file_skips_comments_and_blanks(tmp_path):
    f = tmp_path / "suite.env"
    f.write_text("# a comment\n\nexport FOO=bar\nBAZ=qux  # trailing\n")
    _inject_env_file(str(f))
    assert os.environ["FOO"] == "bar"
    assert os.environ["BAZ"] == "qux"


def test_inject_env_file_does_not_override_existing(tmp_path):
    os.environ["EXISTING_VAR"] = "from-process"
    f = tmp_path / "suite.env"
    f.write_text("EXISTING_VAR=from-file\nNEW_VAR=from-file\n")
    _inject_env_file(str(f))
    assert os.environ["EXISTING_VAR"] == "from-process"
    assert os.environ["NEW_VAR"] == "from-file"


def test_inject_env_file_blocked_keys_skipped(tmp_path):
    f = tmp_path / "suite.env"
    f.write_text("PYTHONPATH=/evil\nLD_PRELOAD=/evil.so\nDOSSIER_TEST_VAR=ok\n")
    os.environ.pop("PYTHONPATH", None)
    os.environ.pop("LD_PRELOAD", None)
    _inject_env_file(str(f))
    assert "PYTHONPATH" not in os.environ
    assert "LD_PRELOAD" not in os.environ
    assert os.environ["DOSSIER_TEST_VAR"] == "ok"


def test_inject_env_file_rejects_world_writable(tmp_path):
    f = tmp_path / "suite.env"
    f.write_text("FOO=bar\n")
    os.chmod(f, 0o666)
    with pytest.raises(PermissionError, match="world-writable|group"):
        _inject_env_file(str(f))


def test_inject_env_file_rejects_symlink(tmp_path):
    target = tmp_path / "real.env"
    target.write_text("FOO=bar\n")
    link = tmp_path / "suite.env"
    os.symlink(target, link)
    with pytest.raises(OSError):
        _inject_env_file(str(link))


def test_inject_env_file_bom_handled(tmp_path):
    f = tmp_path / "suite.env"
    f.write_bytes(b"\xef\xbb\xbfFOO=bar\n")
    _inject_env_file(str(f))
    assert os.environ["FOO"] == "bar"


def test_inject_env_file_export_with_tab(tmp_path):
    f = tmp_path / "suite.env"
    f.write_text("export\tFOO=bar\n")
    _inject_env_file(str(f))
    assert os.environ["FOO"] == "bar"


def test_inject_env_file_quoted_value_with_space_hash(tmp_path):
    f = tmp_path / "suite.env"
    f.write_text('DOSSIER_LDAP_BIND_PASSWORD="a pass # secret"\n')
    _inject_env_file(str(f))
    assert os.environ["DOSSIER_LDAP_BIND_PASSWORD"] == "a pass # secret"


# ── load_suite_env tests ────────────────────────────────────────────────────

def test_load_suite_env_from_explicit_path(clean_env, tmp_path, monkeypatch):
    f = tmp_path / "suite.env"
    f.write_text("REGISTA_DSN=postgresql://from-file/db\n")
    monkeypatch.setenv("AGENT_SUITE_CONFIG", str(f))
    load_suite_env()
    assert os.environ["REGISTA_DSN"] == "postgresql://from-file/db"


def test_load_suite_env_missing_default_is_noop(clean_env):
    load_suite_env()


def test_load_suite_env_explicit_missing_raises(clean_env, tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_SUITE_CONFIG", str(tmp_path / "nonexistent.env"))
    with pytest.raises(FileNotFoundError):
        load_suite_env()


def test_load_suite_env_does_not_override_process_env(clean_env, tmp_path, monkeypatch):
    monkeypatch.setenv("REGISTA_DSN", "from-process")
    f = tmp_path / "suite.env"
    f.write_text("REGISTA_DSN=from-file\n")
    monkeypatch.setenv("AGENT_SUITE_CONFIG", str(f))
    load_suite_env()
    assert os.environ["REGISTA_DSN"] == "from-process"


def test_load_suite_env_idempotent(clean_env, tmp_path, monkeypatch):
    f = tmp_path / "suite.env"
    f.write_text("REGISTA_DSN=first\n")
    monkeypatch.setenv("AGENT_SUITE_CONFIG", str(f))
    load_suite_env()
    os.environ.pop("REGISTA_DSN", None)
    f.write_text("REGISTA_DSN=second\n")
    load_suite_env()
    assert "REGISTA_DSN" not in os.environ
