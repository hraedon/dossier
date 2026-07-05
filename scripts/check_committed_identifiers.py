"""Mechanical gate against committing work-domain identifiers.

Two complementary checks:

1. Always-on (no configuration): no tracked file may live under ``samples/``.
   ``.gitignore`` is advisory — ``git add -f`` bypasses it — so this guard makes
   an accidental force-add of a real identifier-bearing data file fail CI. The
   ``samples/`` directory holds real environment data (hostnames, service
   accounts, principal handles) that must never be committed (AGENTS.md).

2. Secret-driven: when ``DOSSIER_FORBIDDEN_IDENTIFIERS`` is set (a
   whitespace-separated list of real identifiers — hostnames, emails, service
   accounts, principal handles, personal names), every tracked text file
   outside ``samples/`` is scanned for those identifiers. This catches real
   names that leaked into docs, tests, or reflections. It is a no-op (exit 0)
   until the secret is configured, so it never blocks a fresh clone or a fork
   without the secret.

Run locally: python scripts/check_committed_identifiers.py
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path

MIN_IDENTIFIER_LENGTH = 4
_BINARY_SNIFF_LEN = 8192
_SKIP_DIRS = frozenset({"samples", ".venv"})
# Root-level gitignored data dirs that must never contain a tracked file. The
# guard matches the first path component so a legitimate nested code dir named
# ``samples`` (e.g. ``tests/samples/``) is not a false positive.
_GUARDED_DIRS = frozenset({"samples", "secrets"})
# Files that legitimately reference identifiers as patterns or examples.
_EXCLUDE_FILES = frozenset({
    "docs/publication-review.md",
    "scripts/check_committed_identifiers.py",
    "scripts/audit_history_identifiers.py",
    "scripts/filter-repo-replacements.txt",
    ".github/workflows/ci.yml",
})


@dataclass(frozen=True)
class Violation:
    identifier: str
    path: Path
    line_number: int
    line: str


def _filter_identifiers(identifiers: frozenset[str]) -> frozenset[str]:
    return frozenset(
        token.lower()
        for token in (i.strip() for i in identifiers)
        if len(token) >= MIN_IDENTIFIER_LENGTH
    )


def parse_identifier_set(raw: str) -> frozenset[str]:
    tokens: set[str] = set()
    for line in raw.splitlines() or [raw]:
        content = line.split("#", 1)[0].strip()
        if content:
            tokens.update(content.split())
    return _filter_identifiers(frozenset(tokens))


def scan_text(text: str, identifiers: frozenset[str]) -> Iterator[Violation]:
    identifiers = _filter_identifiers(identifiers)
    if not identifiers:
        return
    for line_number, line in enumerate(text.splitlines(), start=1):
        lower = line.lower()
        for identifier in identifiers:
            start = 0
            while True:
                offset = lower.find(identifier, start)
                if offset == -1:
                    break
                yield Violation(
                    identifier=identifier,
                    path=Path("."),
                    line_number=line_number,
                    line=line,
                )
                start = offset + len(identifier)


def _sniff_encoding(chunk: bytes) -> str | None:
    if chunk.startswith(b"\xff\xfe"):
        return "utf-16-le"
    if chunk.startswith(b"\xfe\xff"):
        return "utf-16-be"
    if chunk.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    return None


def _is_binary(chunk: bytes) -> bool:
    if _sniff_encoding(chunk) is not None:
        return False
    return b"\x00" in chunk


def scan_files(identifiers: frozenset[str], paths: list[Path]) -> list[Violation]:
    violations: list[Violation] = []
    for path in paths:
        try:
            with path.open("rb") as f:
                chunk = f.read(_BINARY_SNIFF_LEN)
        except OSError:
            continue
        if _is_binary(chunk):
            continue
        encoding = _sniff_encoding(chunk) or "utf-8"
        try:
            text = path.read_text(encoding=encoding, errors="replace")
        except OSError:
            continue
        for violation in scan_text(text, identifiers):
            violations.append(replace(violation, path=path))
    return violations


def _paths_from_git(args: list[str]) -> list[Path]:
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        check=True,
    )
    paths: list[Path] = []
    for raw in result.stdout.split("\0"):
        if not raw:
            continue
        paths.append(Path(raw))
    return paths


def collect_tracked_paths() -> list[Path]:
    return _paths_from_git(["git", "ls-files", "-z"])


def collect_staged_paths() -> list[Path]:
    return _paths_from_git(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"]
    )


def print_report(violations: list[Violation]) -> None:
    violations.sort(key=lambda v: (str(v.path), v.line_number, v.identifier))
    print("Committed identifier violations detected:", file=sys.stderr)
    for v in violations:
        print(f"  {v.path}:{v.line_number}: {v.identifier!r}", file=sys.stderr)
        print(f"      {v.line.rstrip()}", file=sys.stderr)
    print(f"\nTotal: {len(violations)} violation(s)", file=sys.stderr)


def leaked_tracked_files(paths: list[Path], guarded: frozenset[str]) -> list[Path]:
    return [p for p in paths if p.parts and p.parts[0] in guarded]


def _should_scan(path: Path) -> bool:
    rel = path.as_posix()
    if rel in _EXCLUDE_FILES:
        return False
    if any(part in _SKIP_DIRS for part in path.parts):
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Gate that prevents committing forbidden domain identifiers.",
    )
    parser.add_argument(
        "--staged",
        action="store_true",
        help="Scan only staged files (for the pre-commit hook) instead of the "
        "full tracked tree (the CI default).",
    )
    args = parser.parse_args(argv)

    paths = collect_staged_paths() if args.staged else collect_tracked_paths()

    leaked = leaked_tracked_files(paths, _GUARDED_DIRS)
    if leaked:
        print("Tracked files under a gitignored data directory detected:", file=sys.stderr)
        for p in sorted(leaked, key=str):
            print(f"  {p}", file=sys.stderr)
        print(
            "\nThese paths are gitignored by convention (samples/ holds real "
            "identifier-bearing data — hostnames, service accounts, principal "
            "handles). Remove them from the index: git rm --cached -r <path>.",
            file=sys.stderr,
        )
        return 1

    raw = os.environ.get("DOSSIER_FORBIDDEN_IDENTIFIERS", "")
    if not raw.strip():
        denylist_path = Path(__file__).resolve().parent.parent / ".identifiers-denylist.local"
        if denylist_path.exists():
            raw = denylist_path.read_text()
    if not raw.strip():
        print(
            "DOSSIER_FORBIDDEN_IDENTIFIERS is empty or unset; skipping identifier gate.",
            file=sys.stderr,
        )
        return 0

    identifiers = parse_identifier_set(raw)
    if not identifiers:
        print(
            "DOSSIER_FORBIDDEN_IDENTIFIERS contained no usable identifiers (minimum "
            f"length is {MIN_IDENTIFIER_LENGTH} characters); skipping gate.",
            file=sys.stderr,
        )
        return 0

    scan_paths = [p for p in paths if _should_scan(p)]
    violations = scan_files(identifiers, scan_paths)
    if violations:
        print_report(violations)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
