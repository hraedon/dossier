from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import dossier.gateway as _gw_module

_gw_module._TESTING = True


@dataclass(frozen=True)
class PrincipalKeyEntry:
    principal_id: str
    key_id: str
    scheme: str
    public_key: bytes
    fingerprint: str
    status: str
    valid_from: datetime
    valid_to: datetime | None
    registered_by: str
    registered_at: datetime
    revoked_at: datetime | None
    revoked_reason: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "key_id": self.key_id,
            "scheme": self.scheme,
            "public_key": self.public_key.hex(),
            "fingerprint": self.fingerprint,
            "status": self.status,
            "valid_from": self.valid_from.isoformat(),
            "valid_to": self.valid_to.isoformat() if self.valid_to else None,
            "registered_by": self.registered_by,
            "registered_at": self.registered_at.isoformat(),
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revoked_reason": self.revoked_reason,
        }


def _compute_fingerprint(public_key: bytes, scheme: str) -> str:
    return f"{scheme}:sha256:{hashlib.sha256(public_key).hexdigest()}"


def _generate_key_id() -> str:
    return f"pk_{uuid.uuid4().hex[:16]}"


class InMemoryPrincipalKeyStore:
    def __init__(self) -> None:
        self._entries: list[PrincipalKeyEntry] = []

    def register(
        self,
        principal_id: str,
        public_key: bytes,
        scheme: str = "ed25519",
        *,
        key_id: str | None = None,
        registered_by: str = "system",
    ) -> dict[str, Any]:
        if not principal_id:
            raise ValueError("principal_id is required")
        if not public_key:
            raise ValueError("public_key is required")

        if key_id is None:
            key_id = _generate_key_id()

        now = datetime.now(UTC)

        for existing in self._entries:
            if existing.principal_id == principal_id and existing.key_id == key_id:
                if existing.status == "active":
                    return existing.to_dict()
                raise ValueError(
                    f"Key {key_id} already exists for principal "
                    f"{principal_id} with status {existing.status}"
                )

        new_entries: list[PrincipalKeyEntry] = []
        for existing in self._entries:
            if existing.principal_id == principal_id and existing.status == "active":
                new_entries.append(PrincipalKeyEntry(
                    principal_id=existing.principal_id,
                    key_id=existing.key_id,
                    scheme=existing.scheme,
                    public_key=existing.public_key,
                    fingerprint=existing.fingerprint,
                    status="superseded",
                    valid_from=existing.valid_from,
                    valid_to=now,
                    registered_by=existing.registered_by,
                    registered_at=existing.registered_at,
                    revoked_at=existing.revoked_at,
                    revoked_reason=existing.revoked_reason,
                ))
            else:
                new_entries.append(existing)
        self._entries = new_entries

        entry = PrincipalKeyEntry(
            principal_id=principal_id,
            key_id=key_id,
            scheme=scheme,
            public_key=public_key,
            fingerprint=_compute_fingerprint(public_key, scheme),
            status="active",
            valid_from=now,
            valid_to=None,
            registered_by=registered_by,
            registered_at=now,
            revoked_at=None,
            revoked_reason=None,
        )
        self._entries.append(entry)
        return entry.to_dict()

    def list(
        self,
        principal_id: str | None = None,
        *,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        result = self._entries
        if principal_id is not None:
            result = [e for e in result if e.principal_id == principal_id]
        if status is not None:
            result = [e for e in result if e.status == status]
        return [e.to_dict() for e in sorted(result, key=lambda e: e.registered_at, reverse=True)]

    def get_active(self, principal_id: str) -> dict[str, Any]:
        now = datetime.now(UTC)
        for entry in reversed(self._entries):
            if entry.principal_id == principal_id and entry.status == "active":
                if entry.valid_to is not None and entry.valid_to <= now:
                    continue
                return entry.to_dict()
        raise KeyError(f"No active key for principal {principal_id!r}")

    def rotate(
        self,
        principal_id: str,
        new_public_key: bytes,
        scheme: str = "ed25519",
        *,
        registered_by: str = "system",
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        new_entries: list[PrincipalKeyEntry] = []
        for existing in self._entries:
            if existing.principal_id == principal_id and existing.status == "active":
                new_entries.append(PrincipalKeyEntry(
                    principal_id=existing.principal_id,
                    key_id=existing.key_id,
                    scheme=existing.scheme,
                    public_key=existing.public_key,
                    fingerprint=existing.fingerprint,
                    status="superseded",
                    valid_from=existing.valid_from,
                    valid_to=now,
                    registered_by=existing.registered_by,
                    registered_at=existing.registered_at,
                    revoked_at=existing.revoked_at,
                    revoked_reason=existing.revoked_reason,
                ))
            else:
                new_entries.append(existing)
        self._entries = new_entries

        new_key_id = _generate_key_id()
        entry = PrincipalKeyEntry(
            principal_id=principal_id,
            key_id=new_key_id,
            scheme=scheme,
            public_key=new_public_key,
            fingerprint=_compute_fingerprint(new_public_key, scheme),
            status="active",
            valid_from=now,
            valid_to=None,
            registered_by=registered_by,
            registered_at=now,
            revoked_at=None,
            revoked_reason=None,
        )
        self._entries.append(entry)
        return entry.to_dict()

    def revoke(
        self,
        principal_id: str,
        key_id: str,
        *,
        reason: str = "unspecified",
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        for i, existing in enumerate(self._entries):
            if existing.principal_id == principal_id and existing.key_id == key_id:
                if existing.status == "revoked":
                    return existing.to_dict()
                self._entries[i] = PrincipalKeyEntry(
                    principal_id=existing.principal_id,
                    key_id=existing.key_id,
                    scheme=existing.scheme,
                    public_key=existing.public_key,
                    fingerprint=existing.fingerprint,
                    status="revoked",
                    valid_from=existing.valid_from,
                    valid_to=existing.valid_to,
                    registered_by=existing.registered_by,
                    registered_at=existing.registered_at,
                    revoked_at=now,
                    revoked_reason=reason,
                )
                return self._entries[i].to_dict()
        raise KeyError(f"Principal key not found: {principal_id}/{key_id}")

    def clear(self) -> None:
        self._entries.clear()


def inject_test_store(gateway: Any, store: InMemoryPrincipalKeyStore) -> None:
    gateway._principal_store = store
