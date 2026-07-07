from __future__ import annotations

import errno
import os
from pathlib import Path

__all__ = ["open_no_follow"]

_NO_FOLLOW = getattr(os, "O_NOFOLLOW", 0)


def open_no_follow(
    path: str | os.PathLike[str],
    flags: int,
    mode: int | None = None,
) -> int:
    """Open *path* rejecting symlinks.

    Mirrors the security intent of ``O_NOFOLLOW`` (reject symlink-based
    redirection attacks) while remaining importable on Windows, where the
    flag is absent.

    POSIX: ``O_NOFOLLOW`` is ORed into *flags*, so the symlink rejection is
    atomic and enforced by the kernel — there is no regression versus a
    bare ``os.open(..., os.O_NOFOLLOW)`` call. The ``Path.is_symlink()``
    pre-check below is unreachable in practice on POSIX for a true symlink
    (the kernel rejects first), but is harmless and keeps the code path
    uniform.

    Windows: ``O_NOFOLLOW`` is absent, so the ``Path.is_symlink()`` pre-check
    is the active guard. It is a best-effort guard with a TOCTOU window: an
    attacker with write access to the parent directory could swap the path
    between the check and the ``os.open`` call. Stronger Windows protection
    (opening reparse points via ``FILE_FLAG_OPEN_REPARSE_POINT``) is a
    future enhancement (Plan 003 WI-1.1), tracked separately.

    When *flags* includes :data:`os.O_CREAT`, *mode* must be passed
    explicitly — a default of ``0o777`` would silently create
    world-accessible files in a key-custody context. Without ``O_CREAT``,
    *mode* is ignored by the platform and left at the ``0o777`` stdlib
    default (masked by the umask) when not supplied.
    """
    if flags & os.O_CREAT and mode is None:
        raise TypeError("mode is required when O_CREAT is set")
    if Path(path).is_symlink():
        raise OSError(errno.ELOOP, f"Refusing to open symlink: {os.fspath(path)}")
    return os.open(path, flags | _NO_FOLLOW, mode if mode is not None else 0o777)
