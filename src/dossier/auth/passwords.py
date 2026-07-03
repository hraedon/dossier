from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import logging
import os

_SCHEME = "scrypt"
_R = 8
_P = 1
_DKLEN = 32
_SALT_BYTES = 16
_OWASP_MIN_N = 131072
_MAX_VERIFY_N = 1 << 20

_logger = logging.getLogger("dossier.auth.passwords")


def _get_n() -> int:
    raw = os.environ.get("DOSSIER_PASSWORD_SCRYPT_N", "131072")
    try:
        n = int(raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            f"DOSSIER_PASSWORD_SCRYPT_N must be an integer, got {raw!r}"
        ) from exc
    if n < 2:
        raise RuntimeError(f"DOSSIER_PASSWORD_SCRYPT_N must be >= 2, got {n}")
    if n & (n - 1) != 0:
        raise RuntimeError(
            f"DOSSIER_PASSWORD_SCRYPT_N must be a power of 2, got {n}"
        )
    if n < _OWASP_MIN_N:
        _logger.warning(
            "DOSSIER_PASSWORD_SCRYPT_N=%d is below OWASP minimum %d — "
            "acceptable for tests but unsafe for production",
            n, _OWASP_MIN_N,
        )
    return n


def _scrypt_maxmem(n: int) -> int:
    """Calculate the required maxmem for scrypt (Plan 016 spike fix).

    scrypt requires 128 * N * r bytes of memory. Windows Python 3.14's
    OpenSSL fails with "memory limit exceeded" when maxmem is left at the
    default (0 = unlimited), so we pass an explicit value with generous
    headroom to work on all platforms.
    """
    return 128 * n * _R * 2


def hash_password(plain: str) -> str:
    """Hash a plaintext password with scrypt and a per-password random salt.

    Returns a self-describing string ``scrypt$<n>$<salt_b64>$<hash_b64>``.
    Raises ``ValueError`` if ``plain`` is empty.
    """
    if not plain:
        raise ValueError("password must not be empty")
    salt = os.urandom(_SALT_BYTES)
    n = _get_n()
    digest = hashlib.scrypt(
        plain.encode("utf-8"),
        salt=salt,
        n=n,
        r=_R,
        p=_P,
        dklen=_DKLEN,
        maxmem=_scrypt_maxmem(n),
    )
    return f"{_SCHEME}${n}${_b64(salt)}${_b64(digest)}"


def verify_password(plain: str, stored: str) -> bool:
    """Verify ``plain`` against a ``hash_password``-produced ``stored`` string.

    Constant-time via :func:`hmac.compare_digest`. Returns ``False`` for an
    empty password, an unknown scheme, or a malformed stored string — never
    raises for ordinary mismatches.
    """
    if not plain:
        return False
    parts = stored.split("$")
    if len(parts) != 4 or parts[0] != _SCHEME:
        return False
    try:
        n = int(parts[1])
        salt = _b64decode(parts[2])
        expected = _b64decode(parts[3])
    except (ValueError, binascii.Error):
        return False
    if n <= 0:
        return False
    if n > _MAX_VERIFY_N:
        return False
    digest = hashlib.scrypt(
        plain.encode("utf-8"),
        salt=salt,
        n=n,
        r=_R,
        p=_P,
        dklen=len(expected),
        maxmem=_scrypt_maxmem(n),
    )
    return hmac.compare_digest(digest, expected)


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64decode(s: str) -> bytes:
    return base64.b64decode(s, validate=True)
