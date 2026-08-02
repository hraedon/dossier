"""The Linux systemd unit for dossier, generated at install time.

Why this module exists (agent-suite WI-044)
-------------------------------------------
``agent-suite/docs/install-linux.md`` §7 told operators to run ``sudo systemctl
enable --now dossier`` and claimed the bootstrap installed the unit. There was no
``dossier.service`` in any repo, in any wheel, or in any install path — the Plan
020 Linux qualification had to hand-write one to make the reboot-recovery
checklist item testable at all. dossier's only documented long-running substrates
were Docker Compose and the Windows WinSW wrapper (``deploy/winsw/``); an
artifact-only ``pip install dossier`` host had nothing.

Why it is *generated* rather than shipped as a data file
--------------------------------------------------------
The one host-specific thing in a unit is where the CLI lives. systemd resolves an
unqualified ``ExecStart`` only against its own **fixed** search path
(``/usr/local/sbin``, ``/usr/local/bin``, ``/usr/sbin``, ``/usr/bin``, …) and
never the invoking user's ``PATH``, so a static file cannot be correct on both a
system-scoped install and a ``~/.local/bin`` one. Shipping the text is precisely
what produced agent-suite WI-045, where all three suite timers failed
``203/EXEC`` and the weekly chain-integrity timer never fired on any host. So the
unit text is produced from the location the installing process can actually see,
and ``install_service`` **refuses** rather than writing a unit whose ``ExecStart``
does not exist. ``deploy/systemd/dossier.service`` is a reference rendering
against :data:`REFERENCE_BIN_DIR`, kept byte-identical to this generator by
``tests/test_service_unit.py``.

Installing is not the same as working, so ``install_service`` verifies three
separate things rather than reporting success for having written a file:

* the resolved executable is absolute, exists, and is executable — before
  anything is written;
* systemd's own parse of ``ExecStart`` names that executable — after
  ``daemon-reload``, so a malformed line cannot pass;
* the service is still ``active`` a few seconds later and has not restarted —
  after ``enable --now``.

That last one is deliberately not a single ``is-active`` read. A ``Type=exec``
service is reported ``active`` as soon as the executable *starts*; a process that
then dies (an unbindable ``--host``, missing config) is only visible once
``Restart=`` takes effect. Measured on the Plan 020 qualification host: installing
with an unassignable bind address returned ``active`` and exit 0 while the service
was already on its way to flapping. So the check settles and re-reads, and
requires ``NRestarts`` to still be zero.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Protocol

UNIT_NAME = "dossier"
SYSTEMD_UNIT_DIR = Path("/etc/systemd/system")

# The install prefix the reference copy under deploy/systemd/ is rendered
# against. It is both what agent-suite's install-linux.md §2 prescribes and one
# of the directories on systemd's own fixed ExecStart search path, so the
# reference copy works if installed verbatim on a system-scoped host.
REFERENCE_BIN_DIR = Path("/usr/local/bin")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000

# How long to let a freshly started service settle before believing it is up.
# Must exceed nothing in particular — it only has to be long enough for a process
# that dies on startup to have died. Comfortably shorter than RestartSec so a
# restart is still pending (state `activating`) rather than masked by a fresh
# `active`, and short enough not to stall an install.
SETTLE_SECONDS = 3.0

# The shared suite config, then dossier's own overrides. Both optional (`-`):
# a missing file must not make the unit unstartable, because the doctor's job is
# to say what is missing, not systemd's.
ENVIRONMENT_FILES: tuple[str, ...] = (
    "/etc/agent-suite/suite.env",
    "/etc/dossier/dossier.env",
)


class Runner(Protocol):
    """Run an OS command and return the completed process."""

    def __call__(self, cmd: tuple[str, ...]) -> subprocess.CompletedProcess[str]: ...


class Which(Protocol):
    """Resolve an executable name to an absolute path, or ``None``."""

    def __call__(self, executable: str) -> str | None: ...


# Injectable so tests do not spend the settle window.
Sleeper = Callable[[float], None]


def _default_runner(cmd: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)


def _default_which(executable: str) -> str | None:
    return shutil.which(executable)


class ServiceStatus(Enum):
    """The outcome of installing or removing the unit."""

    INSTALLED = "installed"
    REMOVED = "removed"
    FAILED = "failed"
    UNSUPPORTED_OS = "unsupported_os"


@dataclass
class ServiceResult:
    """What happened, and what was actually verified.

    ``verified`` is the evidence. An ``INSTALLED`` result with an empty
    ``verified`` would mean "a file exists on disk", which is the failure mode
    this module was written to close.
    """

    unit: str
    status: ServiceStatus
    detail: str = ""
    exec_start: str = ""
    files_written: list[str] = field(default_factory=list)
    verified: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status in (ServiceStatus.INSTALLED, ServiceStatus.REMOVED)

    def to_dict(self) -> dict[str, object]:
        return {
            "unit": self.unit,
            "status": self.status.value,
            "detail": self.detail,
            "exec_start": self.exec_start,
            "files_written": self.files_written,
            "verified": self.verified,
        }


@dataclass(frozen=True)
class ResolvedCommand:
    """A command split into an absolute executable and its arguments."""

    exec_path: str
    arguments: str = ""

    @property
    def exec_start(self) -> str:
        return f"{self.exec_path} {self.arguments}".rstrip()


def serve_arguments(*, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> str:
    """The ``dossier serve`` arguments the unit runs.

    Defaults match ``dossier serve``'s own defaults — loopback. A unit that
    silently bound ``0.0.0.0`` would widen a host's exposure as a side effect of
    installing a service; the operator states the bind address explicitly.
    """
    return f"serve --host {host} --port {port}"


def default_search_dirs() -> tuple[Path, ...]:
    """Where to look for the ``dossier`` CLI before falling back to ``PATH``.

    The directory the installing process's own interpreter lives in: for a pipx /
    venv / ``uv tool`` install that is the same ``bin/`` as its console scripts,
    and this process *is* dossier, so it knows where its own artifact is.
    """
    return (Path(sys.executable).parent,) if sys.executable else ()


def _is_executable_file(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def resolve_command(
    command: str,
    *,
    which: Which | None = None,
    search_dirs: tuple[Path, ...] | None = None,
) -> ResolvedCommand | None:
    """Resolve *command*'s executable to an absolute path, or ``None``.

    Deliberately does **not** consult ``$SUDO_USER``'s ``~/.local/bin``: making a
    root-run unit execute out of a user-writable directory is a
    privilege-escalation shape, and agent-suite WI-038 decided per-box component
    CLIs install system-scoped. A per-user install that leaves the CLI
    unresolvable gets a refusal naming it, never a unit that reports success and
    fails at first start.

    ``which=None`` resolves to :func:`_default_which` at call time (not as a
    def-time default) so a test's monkeypatch of the module attribute is seen.
    """
    words = shlex.split(command)
    name, arguments = words[0], shlex.join(words[1:])

    if Path(name).is_absolute():
        return ResolvedCommand(name, arguments)

    for directory in default_search_dirs() if search_dirs is None else search_dirs:
        candidate = directory / name
        if _is_executable_file(candidate):
            return ResolvedCommand(str(candidate), arguments)

    found = (which or _default_which)(name)
    return ResolvedCommand(found, arguments) if found else None


def reference_command(*, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> ResolvedCommand:
    """The rendering used for ``deploy/systemd/dossier.service``.

    as_posix: the systemd rendering is a POSIX artifact whatever the host;
    str() of a WindowsPath would backslash the ExecStart.
    """
    return ResolvedCommand(
        (REFERENCE_BIN_DIR / "dossier").as_posix(), serve_arguments(host=host, port=port)
    )


def check_exec_start_runnable(resolved: ResolvedCommand) -> str | None:
    """Return a failure reason, or ``None`` when the executable is runnable."""
    path = Path(resolved.exec_path)
    if not path.is_absolute():
        return (
            f"ExecStart is not absolute: {resolved.exec_path!r}. systemd resolves bare "
            f"names only against its own fixed path (/usr/local/sbin, /usr/local/bin, "
            f"/usr/sbin, /usr/bin), never the invoking user's PATH"
        )
    if not path.exists():
        return f"ExecStart does not exist: {resolved.exec_path}"
    if not _is_executable_file(path):
        return f"ExecStart is not an executable file: {resolved.exec_path}"
    return None


def generate_unit(
    resolved: ResolvedCommand | None = None,
    *,
    user: str = "root",
) -> str:
    """Render the ``dossier.service`` unit.

    ``resolved`` omitted yields the ``deploy/`` reference rendering. ``user``
    defaults to ``root`` because the suite's config (``/etc/agent-suite/suite.env``)
    and any TLS material it points at are root-owned; an operator with a
    dedicated service account should pass it, and a unit naming an account that
    does not exist would fail ``217/USER`` — the same class of defect as an
    ``ExecStart`` that does not exist.
    """
    command = (resolved or reference_command()).exec_start
    env_lines = "".join(f"EnvironmentFile=-{path}\n" for path in ENVIRONMENT_FILES)
    return (
        "[Unit]\n"
        "Description=dossier — the agent suite's human work-item face\n"
        "Documentation=https://github.com/hraedon/dossier\n"
        "Wants=network-online.target\n"
        "After=network-online.target postgresql.service\n"
        "\n"
        "[Service]\n"
        "Type=exec\n"
        f"ExecStart={command}\n"
        f"{env_lines}"
        f"User={user}\n"
        "Restart=on-failure\n"
        "RestartSec=10\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


# systemd renders `systemctl show -p ExecStart` as `{ path=/x/y ; argv[]=… }`.
_EXEC_PATH_RE = re.compile(r"(?:^|[;{\s])path=([^\s;}]+)")


def _extract_exec_path(raw: str) -> str | None:
    match = _EXEC_PATH_RE.search(raw)
    if match:
        return match.group(1)
    try:
        words = shlex.split(raw)
    except ValueError:
        return None
    return words[0] if words else None


def _unit_property(prop: str, *, runner: Runner) -> tuple[str | None, str | None]:
    """Read one systemd property of the unit. Returns ``(value, failure)``."""
    try:
        result = runner((
            "systemctl", "show", f"{UNIT_NAME}.service", f"--property={prop}", "--value",
        ))
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return None, f"could not read {prop} from systemd: {type(exc).__name__}"
    if result.returncode != 0:
        return None, f"systemctl show {prop} exited {result.returncode}"
    return result.stdout.strip(), None


def _is_active(*, runner: Runner) -> tuple[str, str | None]:
    try:
        result = runner(("systemctl", "is-active", f"{UNIT_NAME}.service"))
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return "", f"could not read service state: {type(exc).__name__}"
    return result.stdout.strip(), None


def _verify_installed(
    resolved: ResolvedCommand,
    *,
    runner: Runner,
    settle_seconds: float = SETTLE_SECONDS,
    sleeper: Sleeper = time.sleep,
) -> tuple[list[str], str | None]:
    """Ask systemd, not ourselves, whether the unit is runnable and staying up."""
    passed: list[str] = []

    raw, failure = _unit_property("ExecStart", runner=runner)
    if failure is not None:
        return passed, failure
    systemd_path = _extract_exec_path(raw or "")
    if systemd_path is None:
        return passed, "systemd reports no ExecStart for the installed unit"
    if Path(systemd_path) != Path(resolved.exec_path):
        return passed, (
            f"systemd parsed ExecStart as {systemd_path!r}, not the resolved "
            f"{resolved.exec_path!r}"
        )
    reason = check_exec_start_runnable(ResolvedCommand(systemd_path))
    if reason is not None:
        return passed, f"as parsed by systemd, {reason}"
    passed.append("systemd_execstart_runnable")

    state, failure = _is_active(runner=runner)
    if failure is not None:
        return passed, failure
    if state != "active":
        return passed, f"{UNIT_NAME}.service is {state or 'unknown'}, not active"

    # `active` here only means the executable started. Let it settle and re-read:
    # a process that dies on startup shows up as `activating` (restart pending)
    # or `failed`, and a flapping one shows up in NRestarts.
    sleeper(settle_seconds)

    state, failure = _is_active(runner=runner)
    if failure is not None:
        return passed, failure
    if state != "active":
        return passed, (
            f"{UNIT_NAME}.service came up and then went {state or 'unknown'} within "
            f"{settle_seconds:g}s — it started but is not staying up"
        )

    restarts, failure = _unit_property("NRestarts", runner=runner)
    if failure is not None:
        return passed, failure
    if restarts and restarts not in ("0", ""):
        return passed, (
            f"{UNIT_NAME}.service restarted {restarts} time(s) within {settle_seconds:g}s "
            f"of install — it is flapping, not running"
        )
    passed.append("service_active_after_settle")

    return passed, None


def install_service(
    *,
    unit_dir: Path = SYSTEMD_UNIT_DIR,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    user: str = "root",
    dry_run: bool = False,
    runner: Runner = _default_runner,
    which: Which | None = None,
    search_dirs: tuple[Path, ...] | None = None,
    settle_seconds: float = SETTLE_SECONDS,
    sleeper: Sleeper = time.sleep,
) -> ServiceResult:
    """Write, enable, start, and verify ``dossier.service``.

    Idempotent: re-running rewrites the same unit and re-verifies. Returns
    ``FAILED`` (writing nothing) when the CLI cannot be resolved to an absolute
    executable, and ``FAILED`` (unit left in place for inspection) when systemd
    does not agree it is runnable and running.
    """
    command = f"dossier {serve_arguments(host=host, port=port)}"
    resolved = resolve_command(command, which=which, search_dirs=search_dirs)
    if resolved is None:
        return ServiceResult(
            unit=UNIT_NAME,
            status=ServiceStatus.FAILED,
            detail=(
                "cannot resolve 'dossier' to an absolute path — refusing to write a unit "
                "that would fail 203/EXEC. Install the CLI on a system PATH "
                "(agent-suite docs/install-linux.md §2) or pass --bin-dir; systemd will "
                "not search the invoking user's PATH"
            ),
        )

    reason = check_exec_start_runnable(resolved)
    if reason is not None:
        return ServiceResult(
            unit=UNIT_NAME,
            status=ServiceStatus.FAILED,
            detail=reason,
            exec_start=resolved.exec_start,
        )
    verified = ["exec_start_runnable"]

    unit_path = unit_dir / f"{UNIT_NAME}.service"
    content = generate_unit(resolved, user=user)

    if dry_run:
        return ServiceResult(
            unit=UNIT_NAME,
            status=ServiceStatus.INSTALLED,
            detail="dry-run: unit would be written (not acted)",
            exec_start=resolved.exec_start,
            files_written=[str(unit_path)],
            verified=verified,
        )

    try:
        unit_path.parent.mkdir(parents=True, exist_ok=True)
        unit_path.write_text(content, encoding="utf-8")
    except OSError as exc:
        return ServiceResult(
            unit=UNIT_NAME,
            status=ServiceStatus.FAILED,
            detail=f"failed to write {unit_path}: {exc}",
            exec_start=resolved.exec_start,
            verified=verified,
        )

    for cmd in (
        ("systemctl", "daemon-reload"),
        ("systemctl", "enable", "--now", f"{UNIT_NAME}.service"),
    ):
        try:
            result = runner(cmd)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            return ServiceResult(
                unit=UNIT_NAME,
                status=ServiceStatus.FAILED,
                detail=f"systemctl error: {exc}",
                exec_start=resolved.exec_start,
                files_written=[str(unit_path)],
                verified=verified,
            )
        if result.returncode != 0:
            return ServiceResult(
                unit=UNIT_NAME,
                status=ServiceStatus.FAILED,
                detail=f"{' '.join(cmd)} failed: {result.stderr.strip()[:200]}",
                exec_start=resolved.exec_start,
                files_written=[str(unit_path)],
                verified=verified,
            )

    post, failure = _verify_installed(
        resolved, runner=runner, settle_seconds=settle_seconds, sleeper=sleeper
    )
    verified.extend(post)
    if failure is not None:
        return ServiceResult(
            unit=UNIT_NAME,
            status=ServiceStatus.FAILED,
            detail=f"unit written but not verified: {failure}",
            exec_start=resolved.exec_start,
            files_written=[str(unit_path)],
            verified=verified,
        )

    return ServiceResult(
        unit=UNIT_NAME,
        status=ServiceStatus.INSTALLED,
        detail="installed and verified",
        exec_start=resolved.exec_start,
        files_written=[str(unit_path)],
        verified=verified,
    )


def remove_service(
    *,
    unit_dir: Path = SYSTEMD_UNIT_DIR,
    dry_run: bool = False,
    runner: Runner = _default_runner,
) -> ServiceResult:
    """Disable, stop, and delete ``dossier.service``. Idempotent."""
    unit_path = unit_dir / f"{UNIT_NAME}.service"
    if dry_run:
        return ServiceResult(
            unit=UNIT_NAME,
            status=ServiceStatus.REMOVED,
            detail="dry-run: unit would be removed (not acted)",
            files_written=[str(unit_path)],
        )
    for cmd in (
        ("systemctl", "disable", "--now", f"{UNIT_NAME}.service"),
    ):
        try:
            runner(cmd)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
    try:
        unit_path.unlink(missing_ok=True)
    except OSError as exc:
        return ServiceResult(
            unit=UNIT_NAME,
            status=ServiceStatus.FAILED,
            detail=f"failed to remove {unit_path}: {exc}",
        )
    try:
        runner(("systemctl", "daemon-reload"))
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return ServiceResult(unit=UNIT_NAME, status=ServiceStatus.REMOVED, detail="removed")


def format_result(result: ServiceResult, action: str) -> str:
    """Human-readable summary for ``dossier install-service`` / ``--uninstall``."""
    lines = [f"dossier {action}", f"  {result.unit:<12} {result.status.value:<12} {result.detail}"]
    if result.exec_start:
        lines.append(f"    ExecStart={result.exec_start}")
    if result.verified:
        lines.append(f"    verified: {', '.join(result.verified)}")
    for path in result.files_written:
        lines.append(f"    {path}")
    return "\n".join(lines)
