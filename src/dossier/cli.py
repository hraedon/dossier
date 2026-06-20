"""dossier CLI entry point.

Charter stage: the real commands (serve, workflow lint/register, admin) arrive in
plans/001. This stub keeps the console-script wired and buildable.
"""

from __future__ import annotations

import sys

from . import __version__


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args and args[0] in {"-V", "--version", "version"}:
        print(f"dossier {__version__}")
        return 0
    print(
        f"dossier {__version__} — charter stage.\n"
        "No runtime yet. See plans/001-mvp.md for the build order; "
        "the backend is regista (docs/provenance-model.md is the contract)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
