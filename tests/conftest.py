from __future__ import annotations

import os

os.environ.setdefault("DOSSIER_PASSWORD_SCRYPT_N", "16")

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from regista.testing import InMemoryRegista

from dossier.app import create_app
from dossier.auth.backends import LocalBackend
from dossier.config import Settings
from dossier.gateway import RegistaGateway
from dossier.keys import generate_keyset
from dossier.multi import GatewayRegistry

from helpers import ALICE

_CRLF_RE = re.compile(r'name="csrf_token"\s+value="([^"]+)"')

_PROJECT = "dossier_test"
_PROJECT_SLUG = "dossier-test"


def extract_csrf(html: str) -> str:
    m = _CRLF_RE.search(html)
    assert m, "csrf_token not found in HTML"
    return m.group(1)


def login(client: TestClient, username: str = "alice", password: str = "s3cret") -> str:
    page = client.get("/login")
    csrf = extract_csrf(page.text)
    resp = client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/"
    return csrf


@pytest.fixture
def gateway(tmp_path):
    key_path = tmp_path / "keys.json"
    generate_keyset(key_path)
    reg = InMemoryRegista(project=_PROJECT, hmac_key_path=str(key_path))
    gw = RegistaGateway(reg, project_name=_PROJECT)
    gw.register_workflow()
    InMemoryRegista._catalog.clear()
    yield gw
    InMemoryRegista._catalog.clear()
    gw.close()


@pytest.fixture
def make_issue(gateway):
    def _make(*, actor=ALICE, work_item_type="bug", title="Test issue", **fields):
        fields.setdefault("title", title)
        wi, _ = gateway.create_issue(
            actor=actor,
            work_item_type=work_item_type,
            custom_fields=fields or None,
        )
        return wi

    return _make


def _hash_pw(pw: str) -> str:
    from dossier.auth.passwords import hash_password

    return hash_password(pw)


def _users_file(tmp_path: Path) -> Path:
    path = tmp_path / "users.json"
    path.write_text(
        json.dumps(
            [
                {
                    "stable_id": "11111111-1111-1111-1111-111111111111",
                    "username": "alice",
                    "display_name": "Alice",
                    "password": _hash_pw("s3cret"),
                    "groups": [],
                }
            ]
        ),
        encoding="utf-8",
    )
    return path


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url="",
        project=_PROJECT,
        hmac_key_path="",
        session_secret="test-session-secret-not-for-prod",
        session_max_age_seconds=43200,
        secure_cookies=False,
        require_ssl=False,
        users_path=str(_users_file(tmp_path)),
        auth_backend="local",
        principal_key_dir=str(tmp_path / "principals"),
    )


@pytest.fixture
def app(tmp_path, gateway):
    settings = _settings(tmp_path)
    backend = LocalBackend(_users_file(tmp_path))
    registry = GatewayRegistry(known_projects=[_PROJECT])
    registry.add(_PROJECT, gateway)
    return create_app(settings, registry, backend)


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c
