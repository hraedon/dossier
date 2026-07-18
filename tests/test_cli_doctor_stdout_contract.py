"""Contract: ``dossier doctor --json`` stdout is a clean JSON blob.

regista is imported as a library by ``dossier.multi``; its module-level
``log = structlog.get_logger()`` defaults to a stdout ``PrintLogger`` when
``structlog.configure()`` has never been called. regista's own CLI redirects
to stderr, but that only runs when regista's CLI is the entry point — not when
dossier imports it. Without the CLI's ``_configure_structlog_stderr`` call,
regista's structlog lines (``keys.loaded``, ``regista.connected``, ...)
contaminate ``dossier doctor --json`` stdout and break the suite umbrella's
``json.loads(stdout)`` parser (Plan 004 WI-1.4 / agent-suite ``doctor.py``).

These tests prove the contract by exercising the real ``regista.Regista(...)``
construction path with a stub that emits the same kind of structlog line the
real backend emits, then asserting stdout parses as JSON regardless of exit
code (the suite umbrella parses JSON regardless of exit code — a component may
exit 1 because ``ok: false`` while still emitting valid JSON with check
detail).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import structlog

from dossier.cli import main
from dossier.keys import generate_keyset


@pytest.fixture(autouse=True)
def _reset_structlog():
    """Ensure structlog starts at defaults so the test proves ``main()``
    configures it (not a leftover configuration from a prior test).

    Without this, a prior ``main()`` call could leave structlog configured to
    stderr and mask a regression where the configure call is removed.
    """
    structlog.reset_defaults()
    yield
    structlog.reset_defaults()


class _StubRegista:
    """Stand-in for ``regista.Regista`` that emits the structlog line the real
    backend emits during construction, then fails.

    The real regista emits ``regista.connected`` (and several ``keys.*`` /
    ``replay.*`` lines) during ``Regista()`` construction and
    ``register_workflow()``. When structlog is unconfigured (the default for a
    library import), those go to stdout. This stub emits one such line so the
    test proves the CLI's structlog-to-stderr configuration keeps stdout clean.

    Raising after the emission lets the doctor complete and print valid JSON
    (with a ``regista: fail`` check) without needing a live Postgres — exactly
    the suite-umbrella contract: parseable JSON regardless of exit code.
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        structlog.get_logger().info(
            "regista.connected", project="dossier_test", regista_version="stub"
        )
        raise RuntimeError("stub: no postgres in CI")


def _set_cli_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Configure the process env so ``load_settings(strict=False)`` resolves
    without a live backend, and ``_build`` reaches ``regista.Regista(...)``.

    A literal DSN passes ``resolve_dsn`` unchanged; a real keyset file passes
    ``materialize_key_manifest`` (bare path → ``None`` cleanup).
    """
    key_path = tmp_path / "keys.json"
    generate_keyset(key_path)
    users_path = tmp_path / "users.json"
    users_path.write_text("[]", encoding="utf-8")

    monkeypatch.setenv("REGISTA_DSN", "postgresql://stub:stub@localhost/stub")
    monkeypatch.setenv("REGISTA_KEY_PATH", str(key_path))
    monkeypatch.setenv("DOSSIER_PROJECTS", "dossier_test")
    monkeypatch.setenv(
        "DOSSIER_SESSION_SECRET", "test-session-secret-not-for-prod-32-chars"
    )
    monkeypatch.setenv("DOSSIER_AUTH_BACKEND", "local")
    monkeypatch.setenv("DOSSIER_USERS_PATH", str(users_path))


def test_doctor_json_stdout_is_clean_json(monkeypatch, tmp_path, capsys):
    """``dossier doctor --json`` stdout parses as JSON even when regista emits
    structlog during construction (Plan 004 WI-1.4).

    This exercises the real ``regista.Regista(...)`` construction path
    (``GatewayRegistry._build``) via a stub that emits the structlog line
    the real backend emits. Without ``_configure_structlog_stderr`` in
    ``main()``, that line lands on stdout and ``json.loads`` fails.
    """
    _set_cli_env(monkeypatch, tmp_path)
    monkeypatch.setattr("regista.Regista", _StubRegista)

    exit_code = main(["doctor", "--json"])
    captured = capsys.readouterr()

    # The doctor may exit 1 (regista fail from the stub); the contract is that
    # stdout is still parseable JSON with check detail — never structlog lines.
    data = json.loads(captured.out)
    assert data["component"] == "dossier"
    assert isinstance(data["checks"], list)
    assert isinstance(data["ok"], bool)
    # The stub's structlog emission must land on stderr, not stdout.
    assert "regista.connected" in captured.err
    # Exit code reflects the regista fail (the stub raises); the suite umbrella
    # parses JSON regardless of exit code.
    assert exit_code == 1


def test_doctor_json_first_line_is_open_brace(monkeypatch, tmp_path, capsys):
    """The first byte of ``dossier doctor --json`` stdout is ``{`` — the
    suite umbrella's parser (agent-suite ``doctor.py``) reads stdout as a
    single JSON document, so no preamble may precede the blob.
    """
    _set_cli_env(monkeypatch, tmp_path)
    monkeypatch.setattr("regista.Regista", _StubRegista)

    main(["doctor", "--json"])
    captured = capsys.readouterr()

    assert captured.out[:1] == "{", (
        f"stdout must start with '{{', got: {captured.out[:40]!r}"
    )
    # And it must round-trip as JSON.
    json.loads(captured.out)
