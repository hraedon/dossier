"""Built-wheel conformance lane (CLI contract §7): prove the gate holds against
the *installed* dossier, not the editable source checkout.

The kit runs in two lanes: source checkout (per-PR, ``test_cli_conformance.py``)
and a built wheel installed into a clean venv (this file). Editable-source
coverage is not sufficient — a packaging mistake (a missing module, a broken
console-script entry point, an undeclared dependency) can leave the wheel broken
while local tests still pass. This lane catches that class.

The lane is hermetic and self-contained:

1. Build dossier's wheel (``uv build --wheel``) from this checkout.
2. Create a clean venv with ``--without-pip`` (an empty, isolated environment —
   nothing leaks in from the source venv).
3. Install the pinned ``agent-suite-conformance==1.1.0`` kit (from PyPI),
   dossier's built wheel WITH its resolved runtime dependencies, and pytest into
   that venv — every artifact from the registry or the built wheel, never the
   source tree.
4. Run ``test_cli_conformance.py`` inside the clean venv via ``-m
   dossier.cli`` and require — through the same ``require_gate_ran`` meta-guard
   used by ``test_conformance_meta_guard.py`` — that at least one case PASSED
   and none SKIPPED. An all-skip run means the installed ``dossier`` package was
   not importable (a wheel/packaging defect), which is exactly the regression
   this lane exists to catch.

The conformance test invokes ``python -m dossier.cli``; because it is run with
``cwd`` set to a scratch dir (not the repo root) and ``PYTHONPATH`` stripped,
``dossier`` resolves to the wheel installed in the clean venv, never the source
tree. The kit is likewise imported from the clean venv. The source checkout is
thus absent from both ``sys.path`` roots that matter.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import venv
from pathlib import Path

import pytest

# Reuse the meta-guard's pure verifier so the wheel lane asserts the same
# "ran, not skipped" contract (and inherits its non-tautological deny cases).
# ``tests/`` has no ``__init__.py``, so pytest's prepend import mode puts it on
# ``sys.path`` and the sibling module imports flat. Importing it also runs its
# module-top ``importorskip("agent_suite.conformance")`` — so this lane skips
# cleanly in a kit-less checkout, exactly as it must (the lane needs the kit).
meta_guard = pytest.importorskip("test_conformance_meta_guard")
require_gate_ran = meta_guard.require_gate_ran

REPO_ROOT = Path(__file__).resolve().parents[1]
CONF_TEST = REPO_ROOT / "tests" / "test_cli_conformance.py"
# The pinned kit version the lane installs from PyPI into the clean venv. Must
# match the [dev] extra in pyproject.toml.
KIT_PIN = "agent-suite-conformance==1.1.0"


def _uv_bin() -> str:
    """Resolve the uv binary (the family's installer); skip if absent.

    uv is on PATH in the dev environment and in CI (astral-sh/setup-uv). The lane
    uses uv to build the wheel and to install into the pip-less clean venv, so it
    is a hard requirement — a clean skip (not an error) keeps a minimal local
    checkout green.
    """
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv not found on PATH (required for the built-wheel lane)")
    return uv


def _build_wheel(tmp_path: Path) -> Path:
    """Build dossier's wheel (no deps) into ``tmp_path``/wheels; return its path.

    Uses ``uv build`` (uv is a dev tool in this family and is what CI uses);
    ``find_uv_bin`` resolves the uv binary portably.
    """
    wheel_dir = tmp_path / "wheels"
    wheel_dir.mkdir()
    uv = _uv_bin()
    subprocess.run(
        [uv, "build", "--wheel", "--out-dir", str(wheel_dir), str(REPO_ROOT)],
        check=True,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    wheels = list(wheel_dir.glob("dossier_hraedon-*.whl"))
    assert wheels, "no dossier_hraedon wheel was built"
    return wheels[0]


def _make_clean_venv(tmp_path: Path) -> Path:
    """Create an empty venv (no pip) and return its python executable path.

    ``--without-pip`` guarantees the environment starts with nothing but the
    stdlib — no packages leak from the source venv, so the lane proves the wheel
    + its declared deps are sufficient on their own.
    """
    venv_dir = tmp_path / "clean-venv"
    venv.EnvBuilder(with_pip=False, clear=True).create(venv_dir)
    bindir = "Scripts" if os.name == "nt" else "bin"
    exe = "python.exe" if os.name == "nt" else "python"
    python = venv_dir / bindir / exe
    assert python.is_file(), f"clean venv python not found at {python}"
    return python


@pytest.mark.slow
def test_wheel_conformance_against_installed_entry_points(tmp_path: Path) -> None:
    """Conformance cases pass against the built wheel in a clean venv, with the
    source checkout absent — the release-tag lane of CLI contract §7."""
    wheel = _build_wheel(tmp_path)
    python = _make_clean_venv(tmp_path)
    uv = _uv_bin()

    # uv installs into the clean venv by pointing UV_PYTHON at its interpreter;
    # the venv was created --without-pip, so uv (not pip) is the installer.
    install_env = {**os.environ, "UV_PYTHON": str(python), "VIRTUAL_ENV": str(python.parents[1])}

    # 1. The pinned conformance kit (1.1.0, from PyPI) — the gate under test.
    #    --no-deps: the kit is stdlib-only.
    subprocess.run(
        [uv, "pip", "install", "--python", str(python), "--no-deps", KIT_PIN],
        check=True, capture_output=True, text=True, env=install_env,
    )
    # 2. dossier's wheel WITH its resolved runtime deps (proves the wheel's
    #    metadata is sufficient for dependency resolution in a clean env).
    subprocess.run(
        [uv, "pip", "install", "--python", str(python), str(wheel)],
        check=True, capture_output=True, text=True, env=install_env,
    )
    # 3. pytest, to run the conformance module inside the clean venv.
    subprocess.run(
        [uv, "pip", "install", "--python", str(python), "pytest"],
        check=True, capture_output=True, text=True, env=install_env,
    )

    # Sanity: the installed package resolves from the wheel, and the kit's 1.1.0
    # meta-guard helper is importable in the clean venv (the shipped symbols the
    # conformance module dogfoods).
    probe = subprocess.run(
        [
            str(python), "-c",
            "import dossier, agent_suite.conformance as c;"
            "assert hasattr(c, 'assert_cases_declared'), c.KIT_VERSION;"
            "print(dossier.__file__); print(c.KIT_VERSION)",
        ],
        check=True, capture_output=True, text=True,
    )
    installed_dossier, kit_version = probe.stdout.splitlines()[-2:]
    assert "site-packages" in installed_dossier, (
        f"dossier resolved outside site-packages (source leak?): {installed_dossier}"
    )
    assert kit_version == "1.1.0", f"clean venv kit is {kit_version}, expected 1.1.0"

    # Run the conformance module in the clean venv against the INSTALLED wheel.
    #
    # Two isolation measures, both load-bearing:
    # - cwd is a scratch dir (not the repo root) and PYTHONPATH is stripped, so
    #   ``import dossier`` / ``-m dossier.cli`` resolve to the wheel installed in
    #   the clean venv, never the source tree on sys.path[0].
    # - the conformance module is COPIED into the scratch dir and run from there.
    #   Running it in-place under ``tests/`` would make pytest load the repo's
    #   ``tests/conftest.py``, which imports the FastAPI test client, httpx, and
    #   app fixtures the CLI gate does not use and the minimal clean venv does
    #   not have. The module is self-contained (it builds its own temp fixtures
    #   and drives ``-m dossier.cli``), so the copy is faithful.
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    isolated_test = run_dir / "test_cli_conformance.py"
    isolated_test.write_text(CONF_TEST.read_text(encoding="utf-8"), encoding="utf-8")

    env = {**os.environ, "NO_COLOR": "1", "PY_COLORS": "0"}
    env.pop("FORCE_COLOR", None)
    env.pop("PYTHONPATH", None)  # never inherit the source venv's path
    proc = subprocess.run(
        [
            str(python), "-m", "pytest", str(isolated_test),
            "-q", "-p", "no:cacheprovider", "--no-header", "--color=no",
        ],
        cwd=str(run_dir),
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    output = proc.stdout + proc.stderr

    # The gate must run cleanly AND pass at least one case — the meta-guard's two
    # independent signals. An all-skip run (installed dossier unimportable) fails
    # here, which is the regression this lane guards.
    counts = require_gate_ran(output, exit_code=proc.returncode, minimum_passed=1)
    assert counts["skipped"] == 0, (
        f"conformance cases skipped against the wheel install — the installed "
        f"dossier package is likely broken:\n{output}"
    )
