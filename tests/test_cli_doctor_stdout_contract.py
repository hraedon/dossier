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

import io
import json
import urllib.error
from pathlib import Path

import pytest
import structlog

from dossier.cli import _read_running_health, main
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


class _HealthResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload
        self.closed = False

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")

    def close(self) -> None:
        self.closed = True


def test_doctor_prefers_running_service_health(monkeypatch):
    payload: dict[str, object] = {
        "component": "dossier",
        "version": "test",
        "ok": True,
        "checks": [],
    }
    response = _HealthResponse(payload)
    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: response)

    assert _read_running_health() == payload
    assert response.closed is True


def _report_payload(summary: object, status: str | None) -> dict[str, object]:
    payload: dict[str, object] = {
        "component": "dossier",
        "version": "synthetic",
        "environment": "test",
        "ok": summary,
        "degraded": False,
        "regista": {"reachable": True, "project": "synthetic", "chain_ok": None},
        "checks": [] if status is None else [
            {"name": "synthetic", "status": status, "detail": None},
        ],
    }
    if summary == "missing-summary":
        payload.pop("ok")
    return payload


def _run_report_only_doctor(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
    *,
    json_output: bool,
    http_503: bool = False,
) -> int:
    """Exercise real main/argparse/reporting without settings or external I/O."""
    monkeypatch.setattr("dossier.config.load_suite_env", lambda: None)

    def forbidden_settings(*args: object, **kwargs: object) -> None:
        pytest.fail("a parsed running-service report must not read settings or use a backend")

    monkeypatch.setattr("dossier.config.load_settings", forbidden_settings)
    monkeypatch.setenv("DOSSIER_BASE_URL", "http://dossier.example.test")
    response = _HealthResponse(payload)
    error_body = io.BytesIO(json.dumps(payload).encode("utf-8"))
    calls: list[str] = []

    def report_response(url: str, *, timeout: float) -> _HealthResponse:
        assert url == "http://dossier.example.test/healthz"
        assert timeout == 1.0
        calls.append(url)
        if http_503:
            raise urllib.error.HTTPError(url, 503, "synthetic unhealthy", {}, error_body)
        return response

    monkeypatch.setattr("urllib.request.urlopen", report_response)
    result = main(["doctor", "--json"] if json_output else ["doctor"])
    assert len(calls) == 1
    if http_503:
        assert error_body.closed
    else:
        assert response.closed
        error_body.close()
    return result


@pytest.mark.parametrize("json_output", [False, True])
@pytest.mark.parametrize(("summary", "status", "expected"), [
    (False, None, 1), (False, "ok", 1), (False, "warn", 1), (False, "skip", 1),
    (False, "fail", 1), (True, "fail", 1),
    (True, None, 0), (True, "ok", 0), (True, "warn", 0), (True, "skip", 0),
    (None, None, 0), (0, None, 0), ("false", None, 0), ("missing-summary", None, 0),
])
def test_doctor_exit_honors_false_summary_without_rewriting_report(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    summary: object, status: str | None, expected: int, json_output: bool,
) -> None:
    payload = _report_payload(summary, status)
    expected_json = json.dumps(payload, indent=2) + "\n"

    assert _run_report_only_doctor(monkeypatch, payload, json_output=json_output) == expected

    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.dumps(payload, indent=2) + "\n" == expected_json
    if json_output:
        assert captured.out == expected_json
    else:
        expected_text = (
            "dossier synthetic — component health\n"
            "  environment: test\n"
            "  regista: reachable=True project=synthetic chain_ok=None\n"
        )
        if status is not None:
            expected_text += f"  synthetic: {status}\n"
        assert captured.out == expected_text


@pytest.mark.parametrize("json_output", [False, True])
@pytest.mark.parametrize(("summary", "status", "expected"), [
    (False, None, 1), (True, "fail", 1), (True, None, 0),
])
def test_doctor_consumes_mocked_503_report_without_changing_http_policy(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    summary: bool, status: str | None, expected: int, json_output: bool,
) -> None:
    payload = _report_payload(summary, status)

    assert _run_report_only_doctor(
        monkeypatch, payload, json_output=json_output, http_503=True,
    ) == expected

    captured = capsys.readouterr()
    assert captured.err == ""
    if json_output:
        assert captured.out == json.dumps(payload, indent=2) + "\n"
    else:
        assert captured.out.startswith("dossier synthetic — component health\n")


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

    # Pin suite-env resolution to an empty file so ``main()`` never reads the
    # developer's real ``~/.config/agent-suite/suite.env``. ``load_suite_env``
    # writes ``os.environ`` directly (not via monkeypatch), so a real file
    # would leak untracked keys (e.g. DOSSIER_PROJECT_ACL_PATH) into every
    # test that runs after this one.
    suite_env = tmp_path / "suite.env"
    suite_env.write_text("", encoding="utf-8")
    monkeypatch.setenv("AGENT_SUITE_CONFIG", str(suite_env))

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
