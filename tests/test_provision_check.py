"""Tests for Plan 013 WI-2.2 — idempotent install/first-run.

Covers:
- _check_provisioned returns False for a non-existent project
- _check_provisioned returns True after regista provision
- _provision_error produces the actionable message
- _cmd_init fails with the actionable message when not provisioned
"""

from __future__ import annotations

import uuid

from dossier.cli import _check_provisioned, _provision_error

_DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"


def test_check_provisioned_false_for_nonexistent():
    project = f"nonexist_{uuid.uuid4().hex[:8]}"
    assert _check_provisioned(_DSN, project, require_ssl=False) is False


def test_check_provisioned_true_after_provision():
    from regista._provision import provision
    from regista.testing import drop_project_schema

    project = f"provcheck_{uuid.uuid4().hex[:8]}"
    drop_project_schema(_DSN, project)
    try:
        provision(_DSN, [project])
        assert _check_provisioned(_DSN, project, require_ssl=False) is True
    finally:
        drop_project_schema(_DSN, project)


def test_provision_error_message_is_actionable():
    msg = _provision_error("my_project")
    assert "my_project" in msg
    assert "regista provision --project my_project" in msg
    assert "provision-principal" in msg


def test_init_fails_on_unprovisioned(monkeypatch, capsys):
    monkeypatch.setenv("REGISTA_DSN", _DSN)
    monkeypatch.setenv("REGISTA_KEY_PATH", "/nonexistent/keys.json")
    monkeypatch.setenv("DOSSIER_PROJECT", f"nonexist_{uuid.uuid4().hex[:8]}")
    monkeypatch.setenv("DOSSIER_SESSION_SECRET", "a" * 40)

    from dossier.cli import main

    rc = main(["init"])
    assert rc == 1
    captured = capsys.readouterr()
    assert "regista provision" in captured.err
