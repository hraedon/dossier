from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os

_SCHEME = "scrypt"
_N = 16384
_R = 8
_P = 1
_DKLEN = 32
_SALT_BYTES = 16


def hash_password(plain: str) -> str:
    """Hash a plaintext password with scrypt and a per-password random salt.

    Returns a self-describing string ``scrypt$<n>$<salt_b64>$<hash_b64>``.
    Raises ``ValueError`` if ``plain`` is empty.
    """
    if not plain:
        raise ValueError("password must not be empty")
    salt = os.urandom(_SALT_BYTES)
    digest = hashlib.scrypt(
        plain.encode("utf-8"),
        salt=salt,
        n=_N,
        r=_R,
        p=_P,
        dklen=_DKLEN,
    )
    return f"{_SCHEME}${_N}${_b64(salt)}${_b64(digest)}"


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
    digest = hashlib.scrypt(
        plain.encode("utf-8"),
        salt=salt,
        n=n,
        r=_R,
        p=_P,
        dklen=len(expected),
    )
    return hmac.compare_digest(digest, expected)


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64decode(s: str) -> bytes:
    return base64.b64decode(s, validate=True)
