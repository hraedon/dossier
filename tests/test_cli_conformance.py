"""dossier's CLI run through the CLI contract v1 conformance kit (Plan 018 WI-2).

The kit is the centrally versioned package ``agent_suite.conformance``, consumed
pinned as ``agent-suite-conformance==1.1.0`` (Plan 019 B1) via the ``[dev]``
extra — never copied, never imported by runtime code.

Scope note (Plan 019 B3 / WI-023): dossier's only ``--json`` verb is ``doctor``,
which is a health *reporter* — it emits a valid health document on stdout and
exits 1 when the box is merely unconfigured (regista unreachable, no session
secret), which is neither a clean exit-0 success nor an operational-error
envelope. dossier therefore has **no hermetic exit-0 JSON success path** (every
other verb mutates or is human-text), so a ``SuccessCase`` is honestly omitted
rather than faked, and the ``success=`` dimension is deliberately not passed to
``assert_cases_declared``. What is asserted:

- **§2/§3** via an ``ErrorCase``: a misconfigured ``AGENT_SUITE_CONFIG`` makes
  ``load_suite_env`` raise before argparse; the top-level boundary converts it
  to a ``CONFIG_NOT_FOUND`` envelope on stdout with exit 1 (not 2, not a
  traceback).
- **§2** via a ``UsageCase``: an unknown verb exits 2.
- **§4** via a ``BrokenPipeCase``: closing ``doctor --json``'s stdout early
  produces no traceback.

WI-026 meta-guard (defense in depth, kit 1.1.0):

1. ``assert_cases_declared`` (shipped by the 1.1.0 kit) is called once at module
   top, after the kit import. It raises ``ConformanceGateError`` at collection
   time if any *declared* dimension is empty — catching the "module loaded but a
   refactor emptied a dimension" class. Only the dimensions dossier honestly
   declares (error / usage / broken_pipe) are guarded; a no-arg call is refused
   by the kit, so this line protects at least one dimension by construction.
2. The complementary "whole module skipped" class (``importorskip`` firing
   against a missing/wrong kit module, so line 1 is never reached) is caught by
   ``tests/test_conformance_meta_guard.py``.

``importorskip`` stays the module-import primitive: a dev who skipped the
``[dev]`` extra gets a clean skip, not a hard collection error. In CI the kit is
a mandatory pinned dep, and layer 2 turns "CI ran with the kit absent" from a
silent skip into a red build.
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
assert_cases_declared = conformance.assert_cases_declared
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

# WI-026 layer 1: fail collection loudly if any declared contract dimension
# empties. A zero-case dimension enforces nothing and — because this module is
# the kit-importing surface — would be indistinguishable from a pass in green
# CI. Only the dimensions dossier honestly declares are guarded; ``success`` is
# omitted because dossier has no hermetic exit-0 JSON path (see module docstring).
# The whole-module-skip class is covered by test_conformance_meta_guard.py.
assert_cases_declared(
    minimum=1,
    error=ERROR_CASES,
    usage=USAGE_CASES,
    broken_pipe=BROKEN_PIPE_CASES,
)


@pytest.mark.parametrize("case", ERROR_CASES, ids=lambda c: c.name)
def test_error_conformance(case: ErrorCase) -> None:
    assert run_error_case(case) == []


@pytest.mark.parametrize("case", USAGE_CASES, ids=lambda c: c.name)
def test_usage_conformance(case: UsageCase) -> None:
    assert run_usage_case(case) == []


@pytest.mark.parametrize("case", BROKEN_PIPE_CASES, ids=lambda c: c.name)
def test_broken_pipe_conformance(case: BrokenPipeCase) -> None:
    assert run_broken_pipe_case(case) == []
