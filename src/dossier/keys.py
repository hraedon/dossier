from __future__ import annotations

import base64
import json
import logging
import os
import re
import secrets
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("dossier.keys")

_ED25519_PUBLIC_KEY_LEN = 32
_ED25519_PRIVATE_KEY_LEN = 32
_PRINCIPAL_ID_RE = re.compile(r"^[a-zA-Z0-9._-]+$")
_PRINCIPAL_ID_MAX_LEN = 256


def _validate_principal_id(principal_id: str) -> None:
    if not principal_id:
        raise ValueError("principal_id is required")
    if len(principal_id) > _PRINCIPAL_ID_MAX_LEN:
        raise ValueError(
            f"principal_id must be at most {_PRINCIPAL_ID_MAX_LEN} characters"
        )
    if not _PRINCIPAL_ID_RE.match(principal_id):
        raise ValueError(
            "principal_id must be alphanumeric, dot, hyphen, or underscore only"
        )


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Generate a real Ed25519 keypair.

    Returns ``(private_key, public_key)`` — each 32 raw bytes.

    Uses PyNaCl (same library regista uses for Ed25519 signing/verification).
    The public key is a valid Ed25519 verification key that regista's
    ``Ed25519Scheme.verify`` can verify signatures against.

    Raises :class:`RuntimeError` if PyNaCl is not installed.
    """
    try:
        import nacl.signing
    except ImportError as e:
        raise RuntimeError(
            "Ed25519 key generation requires PyNaCl: pip install dossier[ed25519]"
        ) from e
    signing_key = nacl.signing.SigningKey.generate()
    private_key = bytes(signing_key)
    public_key = bytes(signing_key.verify_key)
    if len(public_key) != _ED25519_PUBLIC_KEY_LEN:
        raise RuntimeError(
            f"Generated public key is {_ED25519_PUBLIC_KEY_LEN} bytes, "
            f"expected {_ED25519_PUBLIC_KEY_LEN}"
        )
    if len(private_key) != _ED25519_PRIVATE_KEY_LEN:
        raise RuntimeError(
            f"Generated private key is {len(private_key)} bytes, "
            f"expected {_ED25519_PRIVATE_KEY_LEN}"
        )
    return private_key, public_key


class PrincipalKeyManager:
    """Manages Ed25519 keypair generation and private-key storage.

    The public key is registered with regista's principal registry (via the
    gateway). The private key is stored in a file-based key store — the v1
    secret backend until Plan 026 lands a real one (KMS/Vault).

    Private keys are written with 0600 permissions and never appear in the
    UI (Plan 015 design principle: no raw key material in the UX, ever).
    """

    def __init__(self, key_dir: Path | str | None = None) -> None:
        self._key_dir = Path(key_dir) if key_dir else None

    def generate_and_store(self, principal_id: str) -> bytes:
        """Generate a new Ed25519 keypair and store the private key.

        Returns the ``public_key`` for registration with regista. The private
        key is stored internally and never returned to the caller.
        """
        _validate_principal_id(principal_id)
        private_key, public_key = generate_ed25519_keypair()
        self._store_private_key(principal_id, private_key)
        return public_key

    def _store_private_key(self, principal_id: str, private_key: bytes) -> None:
        """Write a principal's Ed25519 private key to a file (0600 perms).

        Writes atomically via a temp file + ``os.rename`` to avoid races
        where another process reads a partially-written key. Uses
        ``O_NOFOLLOW`` to reject symlink-based redirection attacks.
        """
        if self._key_dir is None:
            raise RuntimeError(
                "No principal key directory configured — set DOSSIER_PRINCIPAL_KEY_DIR "
                "or ensure REGISTA_KEY_PATH is set so the directory can be derived"
            )
        self._key_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self._key_dir, 0o700)

        key_path = self._key_dir / f"{principal_id}_ed25519.key"

        fd = tempfile.NamedTemporaryFile(
            dir=str(self._key_dir),
            prefix=f".{principal_id}_",
            suffix=".tmp",
            delete=False,
        )
        try:
            os.chmod(fd.name, 0o600)
            fd.write(private_key)
            fd.flush()
            os.fsync(fd.fileno())
            fd.close()
            os.rename(fd.name, str(key_path))
        except Exception:
            try:
                fd.close()
            except Exception:
                pass
            try:
                os.unlink(fd.name)
            except OSError:
                pass
            raise


def generate_keyset(path: Path, *, key_id: str | None = None) -> dict[str, Any]:
    if key_id is None:
        key_id = f"dossier-{secrets.token_hex(16)}"

    secret = secrets.token_bytes(32)
    keyset = {
        "keys": [
            {
                "key_id": key_id,
                "secret": base64.b64encode(secret).decode("ascii"),
                "status": "active",
                "scheme": "hmac-sha256",
            }
        ]
    }

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = json.dumps(keyset, indent=2).encode("utf-8")

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    os.chmod(path, 0o600)

    return keyset
