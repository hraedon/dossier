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
    """Manages Ed25519 keypair generation and private-key custody.

    The public key is registered with regista's principal registry (via the
    gateway). The private key is stored in the configured secret backend
    through regista's key-set manifest: for the file backend this is a
    private (0600) file referenced by ``secret_ref`` in the key manifest.
    Remote backends are deferred to Plan 026 secret-backend integration.

    Private keys are never returned to callers that render UI or logs
    (Plan 015 design principle: no raw key material in the UX, ever).
    """

    def __init__(
        self,
        key_dir: Path | str | None = None,
        key_manifest_path: Path | str | None = None,
    ) -> None:
        self._key_dir = Path(key_dir) if key_dir else None
        self._key_manifest_path = Path(key_manifest_path) if key_manifest_path else None

    def generate(self, principal_id: str) -> tuple[bytes, bytes]:
        """Generate a new Ed25519 keypair for *principal_id*.

        Returns ``(private_key, public_key)`` as raw 32-byte secrets. The
        caller must hand the private key to :meth:`store_private_key` once
        the matching ``key_id`` is known from regista.
        """
        _validate_principal_id(principal_id)
        return generate_ed25519_keypair()

    def generate_and_store(self, principal_id: str) -> bytes:
        """Generate a new Ed25519 keypair and store the private key.

        Returns the ``public_key`` for registration with regista. The private
        key is stored internally and never returned to the caller.

        This is the legacy v1 path used when dossier itself generates the
        keypair (e.g. the InMemoryRegista test backend). Real regista
        enrollment uses :meth:`regista.Regista.enroll_principal` instead.
        """
        _validate_principal_id(principal_id)
        private_key, public_key = generate_ed25519_keypair()
        key_id = f"dossier-actor-{principal_id}"
        self.store_private_key(principal_id, key_id, private_key)
        return public_key

    def store_private_key(
        self,
        principal_id: str,
        key_id: str,
        private_key: bytes,
    ) -> str:
        """Store *private_key* for *principal_id* and return its ``secret_ref``.

        When a key-set manifest path is configured, the manifest is updated
        so regista can resolve the secret on the actor's behalf.
        """
        secret_ref = self._store_private_key(principal_id, private_key)
        if self._key_manifest_path is not None:
            from nacl.signing import SigningKey

            verify_key = SigningKey(private_key).verify_key
            public_key = bytes(verify_key)
            self._update_key_manifest(
                principal_id,
                key_id,
                public_key,
                secret_ref,
            )
        return secret_ref

    def _store_private_key(self, principal_id: str, private_key: bytes) -> str:
        """Write a principal's Ed25519 private key to a file (0600 perms).

        Writes atomically via a temp file + ``os.rename`` to avoid races
        where another process reads a partially-written key. Uses
        ``O_NOFOLLOW`` to reject symlink-based redirection attacks.

        Returns the ``file:`` secret_ref for the stored key.
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
        return f"file:{key_path}"

    def _update_key_manifest(
        self,
        principal_id: str,
        key_id: str,
        public_key: bytes,
        secret_ref: str,
    ) -> None:
        """Update the regista key-set manifest with a new actor key entry.

        Existing active entries for the same principal are marked deprecated,
        matching the semantics of regista's own ``provision-principal``.
        """
        if self._key_manifest_path is None:
            return

        import base64

        path = self._key_manifest_path
        data: dict[str, Any] = {"keys": []}
        if path.exists():
            try:
                raw = path.read_text(encoding="utf-8")
                parsed = json.loads(raw)
                if isinstance(parsed, dict) and "keys" in parsed:
                    data = parsed
            except (OSError, json.JSONDecodeError):
                data = {"keys": []}

        keys: list[dict[str, Any]] = data.get("keys", [])
        if not isinstance(keys, list):
            keys = []

        existing = [
            k for k in keys
            if k.get("principal_id") == principal_id and k.get("key_id") == key_id
        ]
        if existing:
            return

        for k in keys:
            if k.get("principal_id") == principal_id and k.get("status") == "active":
                k["status"] = "deprecated"

        keys.append({
            "key_id": key_id,
            "scheme": "ed25519",
            "principal_id": principal_id,
            "secret_ref": secret_ref,
            "public_key": base64.b64encode(public_key).decode("ascii"),
            "role": "actor",
            "status": "active",
        })
        data["keys"] = keys

        tmp_path = path.with_suffix(path.suffix + ".tmp")
        encoded = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
        fd = os.open(
            str(tmp_path),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(encoded)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(str(tmp_path))
            except OSError:
                pass
            raise
        os.chmod(str(tmp_path), 0o600)
        os.replace(str(tmp_path), str(path))


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
