from __future__ import annotations

import json
from pathlib import Path

import pytest

from dossier.actors import Actor
from dossier.auth.backends import LocalBackend, Principal
from dossier.auth.passwords import hash_password, verify_password
from dossier.auth.resolver import principal_to_actor


def test_password_hash_round_trip():
    stored = hash_password("correct-horse-battery-staple")
    assert stored.startswith("scrypt$")
    assert verify_password("correct-horse-battery-staple", stored)


def test_password_hash_rejects_wrong_password():
    stored = hash_password("hunter2")
    assert not verify_password("hunter3", stored)
    assert not verify_password("", stored)


def test_hash_password_rejects_empty():
    with pytest.raises(ValueError):
        hash_password("")


def test_each_hash_has_unique_salt():
    a = hash_password("same")
    b = hash_password("same")
    assert a != b
    assert verify_password("same", a)
    assert verify_password("same", b)


def test_verify_password_rejects_malformed_stored():
    assert not verify_password("x", "not-a-hash")
    assert not verify_password("x", "bcrypt$1$2$3")
    assert not verify_password("x", "scrypt$notanint$abc$def")


def _make_users_file(tmp_path: Path, *, users: list[dict] | None = None) -> Path:
    path = tmp_path / "users.json"
    path.write_text(json.dumps(users or []), encoding="utf-8")
    return path


def test_local_backend_authenticate_good_credentials(tmp_path):
    stored = hash_password("s3cret")
    path = _make_users_file(
        tmp_path,
        users=[
            {
                "stable_id": "11111111-1111-1111-1111-111111111111",
                "username": "alice",
                "display_name": "Alice",
                "password": stored,
                "groups": ["team-a"],
            }
        ],
    )
    backend = LocalBackend(path)
    principal = backend.authenticate("alice", "s3cret")
    assert principal is not None
    assert principal.stable_id == "11111111-1111-1111-1111-111111111111"
    assert principal.display_name == "Alice"
    assert principal.source == "local"
    assert principal.raw_attributes["username"] == "alice"
    assert principal.raw_attributes["groups"] == ["team-a"]


def test_local_backend_authenticate_bad_password(tmp_path):
    path = _make_users_file(
        tmp_path,
        users=[
            {
                "stable_id": "u-1",
                "username": "alice",
                "display_name": "Alice",
                "password": hash_password("s3cret"),
                "groups": [],
            }
        ],
    )
    backend = LocalBackend(path)
    assert backend.authenticate("alice", "wrong") is None


def test_local_backend_authenticate_unknown_user(tmp_path):
    path = _make_users_file(tmp_path, users=[])
    backend = LocalBackend(path)
    assert backend.authenticate("nobody", "x") is None


def test_local_backend_fetch_groups(tmp_path):
    path = _make_users_file(
        tmp_path,
        users=[
            {
                "stable_id": "u-2",
                "username": "bob",
                "display_name": "Bob",
                "password": hash_password("p"),
                "groups": ["g1", "g2"],
            }
        ],
    )
    backend = LocalBackend(path)
    principal = backend.authenticate("bob", "p")
    assert principal is not None
    assert backend.fetch_groups(principal) == ["g1", "g2"]


def test_local_backend_from_json_string():
    backend = LocalBackend(
        users_json=json.dumps(
            [
                {
                    "stable_id": "u-3",
                    "username": "carol",
                    "display_name": "Carol",
                    "password": hash_password("pw"),
                    "groups": [],
                }
            ]
        )
    )
    principal = backend.authenticate("carol", "pw")
    assert principal is not None
    assert principal.stable_id == "u-3"


def test_local_backend_requires_path_or_json():
    with pytest.raises(ValueError):
        LocalBackend()


def test_local_backend_add_user_appends_and_hashes(tmp_path):
    path = tmp_path / "users.json"
    first = LocalBackend.add_user(path, "alice", "Alice", "pw1")
    second = LocalBackend.add_user(path, "bob", "Bob", "pw2")

    assert first["username"] == "alice"
    assert first["stable_id"] != second["stable_id"]
    assert first["password"].startswith("scrypt$")

    backend = LocalBackend(path)
    alice = backend.authenticate("alice", "pw1")
    bob = backend.authenticate("bob", "pw2")
    assert alice is not None and bob is not None
    assert alice.stable_id == first["stable_id"]
    assert bob.stable_id == second["stable_id"]
    assert backend.authenticate("alice", "pw2") is None


def test_principal_to_actor_produces_human_actor():
    principal = Principal(
        stable_id="22222222-2222-2222-2222-222222222222",
        display_name="Alice",
        source="local",
        raw_attributes={"username": "alice"},
    )
    actor = principal_to_actor(principal)
    assert isinstance(actor, Actor)
    assert actor.actor_id == principal.stable_id
    assert actor.actor_kind == "human"
    assert actor.display_name == "Alice"
    assert actor.on_behalf_of is None


def test_principal_to_actor_ignores_client_shaped_input():
    principal = Principal(
        stable_id="real-id",
        display_name="Real",
        source="local",
    )
    actor = principal_to_actor(principal)
    assert actor.actor_id == "real-id"
    assert actor.actor_kind == "human"
