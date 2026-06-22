from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .passwords import hash_password, verify_password


_DUMMY_HASH = hash_password("dossier-dummy-do-not-use")


@dataclass(frozen=True, slots=True)
class Principal:
    """A verified identity, backend-agnostic.

    ``stable_id`` is a durable identifier (a minted uuid for local users, an
    LDAP ``objectGUID`` for AD) that survives renames — it is what becomes the
    regista ``actor_id``. ``raw_attributes`` carries backend-specific data
    (username, groups) for authorization and display.
    """

    stable_id: str
    display_name: str
    source: str
    raw_attributes: dict = field(default_factory=dict)


class AuthBackend(Protocol):
    """The interface every directory backend implements.

    The rest of dossier never knows which directory is behind it; it sees
    ``authenticate`` → :class:`Principal` and ``fetch_groups`` for team authz
    (Plan 004).
    """

    def authenticate(self, identifier: str, password: str) -> Principal | None:
        ...

    def fetch_groups(self, principal: Principal) -> list[str]:
        ...


class LocalBackend:
    """MVP/dev backend: users in a JSON file, scrypt-hashed passwords.

    No directory infra required. ``stable_id`` is a minted uuid per user. The
    users file is a JSON array of objects with keys ``stable_id``, ``username``,
    ``display_name``, ``password`` (a ``hash_password`` string), ``groups``.
    """

    def __init__(
        self,
        users_path: str | Path | None = None,
        *,
        users_json: str | None = None,
    ) -> None:
        if users_path is None and users_json is None:
            raise ValueError("either users_path or users_json must be provided")
        self._path = Path(users_path) if users_path is not None else None
        self._users = self._load(users_json)

    def _load(self, users_json: str | None) -> dict[str, dict]:
        if users_json is not None:
            data = json.loads(users_json)
        else:
            assert self._path is not None
            with self._path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("users file must be a JSON array of user objects")
        users: dict[str, dict] = {}
        for entry in data:
            if not isinstance(entry, dict) or not all(
                k in entry for k in ("stable_id", "username", "display_name", "password")
            ):
                raise ValueError(f"malformed user entry: {entry!r}")
            users[entry["username"]] = entry
        return users

    def authenticate(self, identifier: str, password: str) -> Principal | None:
        user = self._users.get(identifier)
        if user is None:
            verify_password(password, _DUMMY_HASH)
            return None
        if not verify_password(password, user.get("password", "")):
            return None
        return Principal(
            stable_id=user["stable_id"],
            display_name=user["display_name"],
            source="local",
            raw_attributes={
                "username": user["username"],
                "groups": list(user.get("groups", [])),
            },
        )

    def fetch_groups(self, principal: Principal) -> list[str]:
        return list(principal.raw_attributes.get("groups", []))

    @staticmethod
    def add_user(
        path: str | Path,
        username: str,
        display_name: str,
        password_plain: str,
    ) -> dict:
        """Append a new local user to ``path``, returning the new user record.

        Mints a uuid ``stable_id`` and scrypt-hashes the password. Intended for
        a future ``dossier users add`` CLI command; not wired into the CLI here.
        """
        path = Path(path)
        if path.exists():
            with path.open("r", encoding="utf-8") as f:
                users = json.load(f)
            if not isinstance(users, list):
                raise ValueError("existing users file must be a JSON array")
        else:
            users = []
        new_user = {
            "stable_id": str(uuid.uuid4()),
            "username": username,
            "display_name": display_name,
            "password": hash_password(password_plain),
            "groups": [],
        }
        users.append(new_user)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(users, f, indent=2)
        return new_user
