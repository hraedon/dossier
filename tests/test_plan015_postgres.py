"""Plan 015 wiring tests against real regista + Postgres.

These tests exercise the production code path where regista's principal-key
registry is available: enroll/rotate/revoke/idempotency. They skip cleanly when
Postgres is not reachable.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from regista import Regista
from regista.testing import drop_project_schema, InMemoryRegista

from conftest import extract_csrf as _extract_csrf, login as _login
from dossier.app import create_app
from dossier.auth.backends import LocalBackend
from dossier.auth.passwords import hash_password
from dossier.config import Settings
from dossier.gateway import RegistaGateway
from dossier.keys import generate_keyset
from dossier.multi import GatewayRegistry

_DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
_ALICE_ID = "11111111-1111-1111-1111-111111111111"


@pytest.fixture(scope="module")
def pg_client(tmp_path_factory):
    key_path = tmp_path_factory.mktemp("pg_keys") / "keys.json"
    generate_keyset(key_path)
    project = f"dossier_plan015_{uuid.uuid4().hex[:8]}"

    prev_admin_ids = os.environ.get("DOSSIER_ADMIN_IDS", "")
    os.environ["DOSSIER_ADMIN_IDS"] = _ALICE_ID

    try:
        reg = Regista.create_project(_DSN, project, hmac_key_path=str(key_path))
    except Exception as exc:
        os.environ["DOSSIER_ADMIN_IDS"] = prev_admin_ids
        pytest.skip(f"Postgres unavailable: {exc}")

    gw = RegistaGateway(reg, project_name=project)
    gw.register_workflow()
    InMemoryRegista._catalog.clear()

    tmp_path = tmp_path_factory.mktemp("pg_client")
    settings = Settings(
        database_url=_DSN,
        project=project,
        hmac_key_path=str(key_path),
        session_secret="test-session-secret-not-for-prod",
        session_max_age_seconds=43200,
        secure_cookies=False,
        require_ssl=False,
        users_path=str(_users_file(tmp_path)),
        auth_backend="local",
        principal_key_dir=str(tmp_path / "principals"),
    )
    backend = LocalBackend(_users_file(tmp_path))
    registry = GatewayRegistry(known_projects=[project])
    registry.add(project, gw)
    app = create_app(settings, registry, backend)

    try:
        with TestClient(app) as client:
            client.app.state._test_project = project
            yield client
    finally:
        InMemoryRegista._catalog.clear()
        gw.close()
        drop_project_schema(_DSN, project)
        os.environ["DOSSIER_ADMIN_IDS"] = prev_admin_ids


def _users_file(tmp_path: Path) -> Path:
    path = tmp_path / "users.json"
    path.write_text(
        json.dumps(
            [
                {
                    "stable_id": _ALICE_ID,
                    "username": "alice",
                    "display_name": "Alice",
                    "password": hash_password("s3cret"),
                    "groups": [],
                }
            ]
        ),
        encoding="utf-8",
    )
    return path


def _project(client: TestClient) -> str:
    return client.app.state._test_project


def _gw(client: TestClient) -> RegistaGateway:
    return client.app.state.registry.get(_project(client))


def test_pg_enroll_principal_emits_event_and_shows_fingerprint(pg_client):
    _login(pg_client)
    roster_page = pg_client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)

    new_principal = f"new-user-{uuid.uuid4().hex[:8]}"
    resp = pg_client.post(
        "/admin/principals/enroll",
        data={"principal_id": new_principal, "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    roster = pg_client.get("/admin/principals")
    assert roster.status_code == 200

    gw = _gw(pg_client)
    entries = gw.list_principals(principal_id=new_principal)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["fingerprint"].startswith("ed25519:sha256:")

    assert entry["fingerprint"][:32] in roster.text
    assert entry["key_id"] in roster.text
    assert entry["public_key"] not in roster.text
    assert "private" not in roster.text.lower()

    events = gw.read_principal_enrollment_events(new_principal)
    assert len(events) == 1
    assert events[0].transition == "principal_enrolled"
    payload = events[0].payload
    assert payload["principal_id"] == new_principal
    assert payload["key_id"] == entry["key_id"]
    assert payload["fingerprint"] == entry["fingerprint"]


def test_pg_rotate_supersedes_old_key(pg_client):
    _login(pg_client)
    roster_page = pg_client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)
    pg_client.post(
        "/admin/principals/enroll",
        data={"principal_id": _ALICE_ID, "csrf_token": csrf},
        follow_redirects=False,
    )

    gw = _gw(pg_client)
    old = gw.get_principal_key(_ALICE_ID)
    assert old is not None
    old_key_id = old["key_id"]

    identity_page = pg_client.get("/me/identity")
    csrf = _extract_csrf(identity_page.text)

    resp = pg_client.post(
        "/me/key/rotate",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    new = gw.get_principal_key(_ALICE_ID)
    assert new is not None
    assert new["key_id"] != old_key_id

    entries = gw.list_principals(principal_id=_ALICE_ID)
    statuses = {e["key_id"]: e["status"] for e in entries}
    assert statuses[old_key_id] == "superseded"
    assert statuses[new["key_id"]] == "active"

    private_path = Path(pg_client.app.state.settings.principal_key_dir) / f"{_ALICE_ID}_ed25519.key"
    assert private_path.exists()


def test_pg_revoke_key(pg_client):
    _login(pg_client)
    principal = f"revoke-user-{uuid.uuid4().hex[:8]}"
    roster_page = pg_client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)
    pg_client.post(
        "/admin/principals/enroll",
        data={"principal_id": principal, "csrf_token": csrf},
        follow_redirects=False,
    )

    gw = _gw(pg_client)
    active = gw.get_principal_key(principal)
    assert active is not None

    roster_page = pg_client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)
    resp = pg_client.post(
        f"/admin/principals/{principal}/revoke",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    assert gw.get_principal_key(principal) is None
    entries = gw.list_principals(principal_id=principal)
    assert any(e["status"] == "revoked" and e["key_id"] == active["key_id"] for e in entries)


def test_pg_enroll_idempotent(pg_client):
    _login(pg_client)
    principal = f"idempotent-user-{uuid.uuid4().hex[:8]}"
    roster_page = pg_client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)

    def enroll() -> None:
        pg_client.post(
            "/admin/principals/enroll",
            data={"principal_id": principal, "csrf_token": csrf},
            follow_redirects=False,
        )

    enroll()
    gw = _gw(pg_client)
    events_after_first = gw.read_principal_enrollment_events(principal)
    assert len(events_after_first) == 1
    first_key_id = events_after_first[0].payload["key_id"]

    roster_page = pg_client.get("/admin/principals")
    csrf = _extract_csrf(roster_page.text)
    enroll()

    events_after_second = gw.read_principal_enrollment_events(principal)
    assert len(events_after_second) == 1
    assert events_after_second[0].payload["key_id"] == first_key_id
