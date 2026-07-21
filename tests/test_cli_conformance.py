"""dossier's CLI run through the CLI contract v1 conformance kit (Plan 018 WI-2).

The kit is the centrally versioned package ``agent_suite.conformance``, consumed
pinned as ``agent-suite-conformance==1.0.0`` from PyPI (Plan 019 B1) via the
``[dev]`` extra — never copied, never imported by runtime code.

Scope note (Plan 019 B3 / WI-023): dossier's only ``--json`` verb is ``doctor``,
which is a health *reporter* — it emits a valid health document on stdout and
exits 1 when the box is merely unconfigured (regista unreachable, no session
secret), which is neither a clean exit-0 success nor an operational-error
envelope. dossier therefore has **no hermetic exit-0 JSON success path** (every
other verb mutates or is human-text), so a ``SuccessCase`` is honestly omitted
rather than faked. What is asserted:

- **§2/§3** via an ``ErrorCase``: a misconfigured ``AGENT_SUITE_CONFIG`` makes
  ``load_suite_env`` raise before argparse; the top-level boundary converts it
  to a ``CONFIG_NOT_FOUND`` envelope on stdout with exit 1 (not 2, not a
  traceback).
- **§2** via a ``UsageCase``: an unknown verb exits 2.
- **§4** via a ``BrokenPipeCase``: closing ``doctor --json``'s stdout early
  produces no traceback.
"""

from __future__ import annotations

import os
import sys
import tempfile

import pytest

conformance = pytest.importorskip("agent_suite.conformance")

BrokenPipeCase = conformance.BrokenPipeCase
ErrorCase = conformance.ErrorCase
UsageCase = conformance.UsageCase
run_broken_pipe_case = conformance.run_broken_pipe_case
run_error_case = conformance.run_error_case
run_usage_case = conformance.run_usage_case

_CLI = (sys.executable, "-m", "dossier.cli")

# An existing but empty suite-env file: `load_suite_env` finds it and injects
# nothing, so the broken-pipe probe runs hermetically (no real store) instead of
# loading the operator's ~/.config/agent-suite/suite.env.
_EMPTY_SUITE_ENV = os.path.join(
    tempfile.mkdtemp(prefix="dossier-conformance-"), "empty-suite.env"
)
open(_EMPTY_SUITE_ENV, "w").close()

# A suite-env path that does not exist: an explicit-but-missing AGENT_SUITE_CONFIG
# is a documented operational failure (config.load_suite_env raises).
_MISSING_SUITE_ENV = "/nonexistent/dossier-conformance/suite.env"


ERROR_CASES = [
    ErrorCase(
        name="bad-suite-config",
        argv=(*_CLI, "doctor", "--json"),
        expect_code="CONFIG_NOT_FOUND",
        env={"AGENT_SUITE_CONFIG": _MISSING_SUITE_ENV},
    ),
]

USAGE_CASES = [
    UsageCase(name="unknown-verb", argv=(*_CLI, "bogusverb")),
]

BROKEN_PIPE_CASES = [
    BrokenPipeCase(
        name="doctor-broken-pipe",
        argv=(*_CLI, "doctor", "--json"),
        env={"AGENT_SUITE_CONFIG": _EMPTY_SUITE_ENV},
    ),
]


@pytest.mark.parametrize("case", ERROR_CASES, ids=lambda c: c.name)
def test_error_conformance(case: "ErrorCase") -> None:
    assert run_error_case(case) == []


@pytest.mark.parametrize("case", USAGE_CASES, ids=lambda c: c.name)
def test_usage_conformance(case: "UsageCase") -> None:
    assert run_usage_case(case) == []


@pytest.mark.parametrize("case", BROKEN_PIPE_CASES, ids=lambda c: c.name)
def test_broken_pipe_conformance(case: "BrokenPipeCase") -> None:
    assert run_broken_pipe_case(case) == []
