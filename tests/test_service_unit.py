"""The dossier systemd unit: existence, absolute ExecStart, verified install.

agent-suite WI-044: ``install-linux.md`` §7 told operators to run
``systemctl enable --now dossier`` and claimed the bootstrap installed the unit.
No ``dossier.service`` existed in any repo, wheel, or install path — the Plan 020
Linux qualification hand-wrote one to make reboot recovery testable. WI-045:
every unit the suite *did* generate failed ``203/EXEC`` because its ``ExecStart``
was a bare command name and systemd resolves those only against its own fixed
search path, never the invoking user's PATH.

These tests assert the properties those two defects violated: the unit exists and
ships in the repo, its ``ExecStart`` is absolute, and ``install-service`` reports
success only when systemd agrees the unit is runnable and running.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path, PurePosixPath

import pytest

from dossier import cli
from dossier.service import (
    ENVIRONMENT_FILES,
    REFERENCE_BIN_DIR,
    UNIT_NAME,
    ResolvedCommand,
    ServiceStatus,
    check_exec_start_runnable,
    generate_unit,
    install_service,
    remove_service,
    resolve_command,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
REFERENCE_UNIT = REPO_ROOT / "deploy" / "systemd" / f"{UNIT_NAME}.service"


def _completed(stdout: str = "", returncode: int = 0, stderr: str = ""):  # type: ignore[no-untyped-def]
    return subprocess.CompletedProcess(args=(), returncode=returncode, stdout=stdout, stderr=stderr)


class StubRunner:
    def __init__(self, outputs: dict[tuple[str, ...], object] | None = None) -> None:
        self._outputs = outputs or {}
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, cmd: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        self.calls.append(cmd)
        for prefix, out in self._outputs.items():
            if cmd[: len(prefix)] == prefix:
                assert isinstance(out, subprocess.CompletedProcess)
                return out
        return _completed()


def _fake_bin_dir(tmp_path: Path, *, executable: bool = True) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    exe = bindir / "dossier"
    exe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    exe.chmod(0o755 if executable else 0o644)
    return bindir


class SequenceRunner(StubRunner):
    """Like StubRunner, but `systemctl is-active` can answer differently over time.

    Needed because verification reads the state twice with a settle in between:
    a `Type=exec` service reports `active` the moment its executable starts and
    only reveals a startup death on the second read.
    """

    def __init__(
        self,
        outputs: dict[tuple[str, ...], object],
        *,
        active_states: list[str],
    ) -> None:
        super().__init__(outputs)
        self._states = list(active_states)

    def __call__(self, cmd: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        self.calls.append(cmd)
        if cmd[:2] == ("systemctl", "is-active"):
            state = self._states.pop(0) if self._states else "active"
            return _completed(stdout=state, returncode=0 if state == "active" else 3)
        for prefix, out in self._outputs.items():
            if cmd[: len(prefix)] == prefix:
                assert isinstance(out, subprocess.CompletedProcess)
                return out
        return _completed()


def _verifying_runner(
    bindir: Path,
    *,
    state: str = "active",
    states: list[str] | None = None,
    reported_exec_path: str | None = None,
    n_restarts: str = "0",
) -> SequenceRunner:
    exec_path = reported_exec_path or str(bindir / "dossier")
    return SequenceRunner(
        {
            ("systemctl", "show", f"{UNIT_NAME}.service", "--property=ExecStart"): _completed(
                stdout=f"{{ path={exec_path} ; argv[]=dossier serve ; ignore_errors=no }}"
            ),
            ("systemctl", "show", f"{UNIT_NAME}.service", "--property=NRestarts"): _completed(
                stdout=n_restarts
            ),
            ("systemctl", "daemon-reload"): _completed(),
            ("systemctl", "enable"): _completed(),
        },
        active_states=states if states is not None else [state, state],
    )


def _no_sleep(seconds: float) -> None:
    """Verification must be testable without spending its settle window."""
    return None


def _no_which(executable: str) -> str | None:
    return None


def _exec_start(unit_text: str) -> str:
    return next(
        line for line in unit_text.splitlines() if line.startswith("ExecStart=")
    ).removeprefix("ExecStart=")


# ---------------------------------------------------------------------------
# The unit exists at all (WI-044)
# ---------------------------------------------------------------------------


def test_reference_unit_is_shipped_in_the_repo() -> None:
    """install-linux.md §7 promises a `dossier` unit; it has to exist somewhere."""
    assert REFERENCE_UNIT.is_file(), (
        f"{REFERENCE_UNIT} is missing — the documented `systemctl enable --now dossier` "
        f"has nothing to enable"
    )


def test_reference_unit_matches_the_generator() -> None:
    """The shipped copy is a rendering of the generator, not a hand-edited file.

    A hand-maintained copy drifts, and a drifted unit is how an operator ends up
    installing something the code has never produced.
    """
    assert REFERENCE_UNIT.read_text(encoding="utf-8") == generate_unit()


def test_reference_unit_execstart_is_absolute_and_uses_the_documented_prefix() -> None:
    # PurePosixPath / as_posix: the unit is a POSIX artifact whatever the host,
    # so its properties are asserted under POSIX path semantics.
    program = shlex.split(_exec_start(REFERENCE_UNIT.read_text(encoding="utf-8")))[0]
    assert PurePosixPath(program).is_absolute(), (
        f"ExecStart={program!r} is not absolute (203/EXEC)"
    )
    assert PurePosixPath(program).parent == PurePosixPath(REFERENCE_BIN_DIR.as_posix())


def test_reference_bin_dir_is_on_systemd_fixed_search_path() -> None:
    """The documented prefix must be somewhere systemd itself would look.

    /usr/local/bin is on systemd's fixed ExecStart path; ~/.local/bin is not.
    That asymmetry is WI-045 in one line.
    """
    assert REFERENCE_BIN_DIR.as_posix() in (
        "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin",
    )


def test_generated_unit_execstart_is_always_absolute() -> None:
    """Both renderings — reference and install-time — must be absolute."""
    for resolved in (None, ResolvedCommand("/opt/dossier/bin/dossier", "serve")):
        program = shlex.split(_exec_start(generate_unit(resolved)))[0]
        assert PurePosixPath(program).is_absolute()


def test_generated_unit_reads_config_from_files_not_inline() -> None:
    """No secrets or work-domain values baked into the unit."""
    unit = generate_unit()
    for path in ENVIRONMENT_FILES:
        assert f"EnvironmentFile=-{path}" in unit
    assert "REGISTA_DSN=" not in unit
    assert "DOSSIER_SESSION_SECRET" not in unit


def test_generated_unit_binds_loopback_by_default() -> None:
    """Installing a service must not widen the host's exposure as a side effect."""
    assert "--host 127.0.0.1" in generate_unit()


def test_generated_unit_restarts_and_is_enabled_at_boot() -> None:
    """The qualification's reboot-recovery item needs both of these."""
    unit = generate_unit()
    assert "Restart=on-failure" in unit
    assert "WantedBy=multi-user.target" in unit


# ---------------------------------------------------------------------------
# Resolution and refusal (WI-045)
# ---------------------------------------------------------------------------


def test_resolve_command_returns_an_absolute_path_from_the_search_dir(tmp_path: Path) -> None:
    bindir = _fake_bin_dir(tmp_path)
    resolved = resolve_command("dossier serve --port 8000", which=_no_which,
                               search_dirs=(bindir,))
    assert resolved is not None
    assert resolved.exec_path == str(bindir / "dossier")
    assert resolved.arguments == "serve --port 8000"


def test_resolve_command_refuses_rather_than_returning_a_bare_name() -> None:
    """agent-suite WI-038 moves per-box CLIs to a system PATH, which would make a
    bare name work — a per-user install is still entitled to a loud refusal."""
    assert resolve_command("dossier serve", which=_no_which, search_dirs=()) is None


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="exec-bit semantics are POSIX; the systemd install path never runs on Windows",
)
def test_check_exec_start_runnable_rejects_bare_missing_and_non_executable(
    tmp_path: Path,
) -> None:
    assert "not absolute" in (check_exec_start_runnable(ResolvedCommand("dossier")) or "")
    assert "does not exist" in (
        check_exec_start_runnable(ResolvedCommand(str(tmp_path / "nope"))) or ""
    )
    plain = tmp_path / "plain"
    plain.write_text("x", encoding="utf-8")
    assert "not an executable file" in (
        check_exec_start_runnable(ResolvedCommand(str(plain))) or ""
    )
    runnable = tmp_path / "run"
    runnable.write_text("#!/bin/sh\n", encoding="utf-8")
    runnable.chmod(0o755)
    assert check_exec_start_runnable(ResolvedCommand(str(runnable))) is None


def test_install_refuses_to_write_a_unit_it_cannot_resolve(tmp_path: Path) -> None:
    """No unit is better than one that reports success and fails at first start."""
    unit_dir = tmp_path / "systemd"
    unit_dir.mkdir()
    result = install_service(
        unit_dir=unit_dir, runner=StubRunner(), which=_no_which, search_dirs=()
    )
    assert result.status is ServiceStatus.FAILED
    assert "203/EXEC" in result.detail
    assert list(unit_dir.iterdir()) == []


# ---------------------------------------------------------------------------
# Install verifies rather than observes
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="drives a systemd install from host tmp dirs; the POSIX-quoting "
    "(shlex) round-trip mangles Windows paths — POSIX-only by design",
)
def test_install_writes_enables_and_verifies(tmp_path: Path) -> None:
    unit_dir = tmp_path / "systemd"
    unit_dir.mkdir()
    bindir = _fake_bin_dir(tmp_path)
    runner = _verifying_runner(bindir)
    result = install_service(
        unit_dir=unit_dir, runner=runner, which=_no_which, search_dirs=(bindir,)
    )
    assert result.status is ServiceStatus.INSTALLED, result.detail
    assert result.verified == [
        "exec_start_runnable", "systemd_execstart_runnable", "service_active_after_settle"
    ]
    written = (unit_dir / f"{UNIT_NAME}.service").read_text()
    assert shlex.split(_exec_start(written))[0] == str(bindir / "dossier")
    assert ("systemctl", "enable", "--now", f"{UNIT_NAME}.service") in runner.calls


def test_install_fails_when_systemd_parses_a_different_execstart(tmp_path: Path) -> None:
    """Verification reads systemd's parse, not the string we just wrote."""
    unit_dir = tmp_path / "systemd"
    unit_dir.mkdir()
    bindir = _fake_bin_dir(tmp_path)
    result = install_service(
        unit_dir=unit_dir,
        runner=_verifying_runner(bindir, reported_exec_path="dossier"),
        sleeper=_no_sleep,
        which=_no_which,
        search_dirs=(bindir,),
    )
    assert result.status is ServiceStatus.FAILED
    assert "not verified" in result.detail


def test_install_fails_when_the_service_did_not_come_up(tmp_path: Path) -> None:
    """`enable --now` exiting 0 is not evidence the service is running."""
    unit_dir = tmp_path / "systemd"
    unit_dir.mkdir()
    bindir = _fake_bin_dir(tmp_path)
    result = install_service(
        unit_dir=unit_dir,
        runner=_verifying_runner(bindir, state="failed"),
        sleeper=_no_sleep,
        which=_no_which,
        search_dirs=(bindir,),
    )
    assert result.status is ServiceStatus.FAILED
    assert "not active" in result.detail


def test_install_fails_when_the_service_starts_then_dies(tmp_path: Path) -> None:
    """A `Type=exec` unit reports `active` the moment exec succeeds.

    Measured on the Plan 020 qualification host: installing with an unassignable
    `--host` returned `active` and exit 0 while the process was already on its way
    to flapping. A single `is-active` read observes that it started; only the
    second read, after a settle, verifies it is staying up.
    """
    unit_dir = tmp_path / "systemd"
    unit_dir.mkdir()
    bindir = _fake_bin_dir(tmp_path)
    result = install_service(
        unit_dir=unit_dir,
        runner=_verifying_runner(bindir, states=["active", "activating"]),
        which=_no_which,
        search_dirs=(bindir,),
        sleeper=_no_sleep,
    )
    assert result.status is ServiceStatus.FAILED
    assert "came up and then went activating" in result.detail
    assert "service_active_after_settle" not in result.verified


def test_install_fails_when_the_service_is_flapping(tmp_path: Path) -> None:
    """Still `active` on the second read, but it has restarted — not running."""
    unit_dir = tmp_path / "systemd"
    unit_dir.mkdir()
    bindir = _fake_bin_dir(tmp_path)
    result = install_service(
        unit_dir=unit_dir,
        runner=_verifying_runner(bindir, n_restarts="2"),
        which=_no_which,
        search_dirs=(bindir,),
        sleeper=_no_sleep,
    )
    assert result.status is ServiceStatus.FAILED
    assert "flapping" in result.detail


def test_install_actually_waits_before_believing_the_service_is_up(tmp_path: Path) -> None:
    """The settle is real elapsed time, not a comment."""
    unit_dir = tmp_path / "systemd"
    unit_dir.mkdir()
    bindir = _fake_bin_dir(tmp_path)
    waited: list[float] = []
    install_service(
        unit_dir=unit_dir,
        runner=_verifying_runner(bindir),
        which=_no_which,
        search_dirs=(bindir,),
        settle_seconds=2.5,
        sleeper=waited.append,
    )
    assert waited == [2.5]


def test_install_is_idempotent(tmp_path: Path) -> None:
    unit_dir = tmp_path / "systemd"
    unit_dir.mkdir()
    bindir = _fake_bin_dir(tmp_path)
    first = install_service(
        unit_dir=unit_dir, runner=_verifying_runner(bindir), sleeper=_no_sleep, which=_no_which,
        search_dirs=(bindir,),
    )
    content = (unit_dir / f"{UNIT_NAME}.service").read_text()
    second = install_service(
        unit_dir=unit_dir, runner=_verifying_runner(bindir), sleeper=_no_sleep, which=_no_which,
        search_dirs=(bindir,),
    )
    assert first.status is second.status is ServiceStatus.INSTALLED
    assert (unit_dir / f"{UNIT_NAME}.service").read_text() == content


def test_dry_run_acts_on_nothing_but_still_preflights(tmp_path: Path) -> None:
    unit_dir = tmp_path / "systemd"
    unit_dir.mkdir()
    bindir = _fake_bin_dir(tmp_path)
    runner = StubRunner()
    ok = install_service(
        unit_dir=unit_dir, dry_run=True, runner=runner, which=_no_which,
        search_dirs=(bindir,),
    )
    assert ok.status is ServiceStatus.INSTALLED
    assert ok.verified == ["exec_start_runnable"]
    assert list(unit_dir.iterdir()) == []
    assert runner.calls == []

    bad = install_service(
        unit_dir=unit_dir, dry_run=True, runner=runner, which=_no_which, search_dirs=()
    )
    assert bad.status is ServiceStatus.FAILED


def test_remove_is_idempotent(tmp_path: Path) -> None:
    unit_dir = tmp_path / "systemd"
    unit_dir.mkdir()
    (unit_dir / f"{UNIT_NAME}.service").write_text("dummy", encoding="utf-8")
    runner = StubRunner()
    assert remove_service(unit_dir=unit_dir, runner=runner).status is ServiceStatus.REMOVED
    assert not (unit_dir / f"{UNIT_NAME}.service").exists()
    assert remove_service(unit_dir=unit_dir, runner=runner).status is ServiceStatus.REMOVED


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="drives a systemd install from host tmp dirs; the POSIX-quoting "
    "(shlex) round-trip mangles Windows paths — POSIX-only by design",
)
def test_cli_install_service_dry_run_json(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    bindir = _fake_bin_dir(tmp_path)
    rc = cli.main([
        "install-service", "--dry-run", "--json",
        "--unit-dir", str(tmp_path / "systemd"),
        "--bin-dir", str(bindir),
    ])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["unit"] == UNIT_NAME
    assert payload["status"] == "installed"
    assert Path(shlex.split(payload["exec_start"])[0]).is_absolute()


def test_cli_install_service_exits_nonzero_when_it_cannot_resolve(
    tmp_path: Path, capsys, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """A refusal must be an exit code, not a cheerful message."""
    monkeypatch.setattr("dossier.service._default_which", lambda executable: None)
    monkeypatch.setattr("dossier.service.default_search_dirs", lambda: ())
    rc = cli.main([
        "install-service", "--dry-run", "--json",
        "--unit-dir", str(tmp_path / "systemd"),
    ])
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "failed"
    assert "203/EXEC" in payload["detail"]
