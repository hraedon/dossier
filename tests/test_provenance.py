"""Tests for Plan 017 — agent-activity window (session list/detail + trail).

Fixtures mirror cairn's real event shape (agent-provenance):
- ``session_attestation`` events (entity_kind="session") with harness
  name/version, principal, scope statement.
- ``tool_call_begin``/``end``/``fail`` events bound to work items, with
  ``on_behalf_of`` carrying session_id + principal_id, and the Plan 009
  WI-1.2 digest fields (stdout_digest, stdout_digest_alg,
  stdout_bytes_total, stdout_truncated).
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from conftest import login as _login
from helpers import AGENT_R
from regista import Event

from dossier.provenance import (
    build_tool_call_trail,
    compute_verification,
    extract_principal,
    extract_session_id,
    read_session_detail,
    read_session_summaries,
)

_SESSION_ID = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
_SESSION_UUID = uuid.UUID(_SESSION_ID)
_PRINCIPAL = "human:alice"
_PRINCIPAL_DISPLAY = "Alice"
_HARNESS_NAME = "claude-code"
_HARNESS_VERSION = "2.1.200"


def _on_behalf(session_id: str = _SESSION_ID) -> dict[str, Any]:
    return {
        "principal_id": _PRINCIPAL,
        "session_id": session_id,
        "principal_display_name": _PRINCIPAL_DISPLAY,
    }


def _agent_for_session(session_id: str) -> Any:
    """Model the authenticated cairn actor carrying the trusted delegation."""
    return replace(AGENT_R, on_behalf_of=_on_behalf(session_id))


def _session_attestation_payload(session_id: str = _SESSION_ID) -> dict[str, Any]:
    return {
        "version": "1",
        "principal_id": _PRINCIPAL,
        "session_id": session_id,
        "attested_at": "2026-07-09T12:00:00Z",
        "harnesses": [{"name": _HARNESS_NAME, "version": _HARNESS_VERSION}],
        "scope_statement": "In scope: claude-code.",
        "harness_config_digests": {_HARNESS_NAME: "sha256:config123"},
    }


def _tool_call_begin_payload(
    tool: str = "Edit",
    files: list[dict[str, Any]] | None = None,
    session_id: str = _SESSION_ID,
) -> dict[str, Any]:
    return {
        "tool": tool,
        "tool_args_hash": "sha256:args123",
        "tool_args_redacted": {
            "tool": tool,
            "file_paths": [f["path"] for f in files] if files else [],
        },
        "files": files or [],
        "on_behalf_of": {"principal_id": _PRINCIPAL, "session_id": session_id},
        "harness": {"name": _HARNESS_NAME, "version": _HARNESS_VERSION},
    }


def _tool_call_end_payload(
    tool: str = "Edit",
    files: list[dict[str, Any]] | None = None,
    *,
    exit_code: int = 0,
    stdout: str = "done",
    truncated: bool = False,
    session_id: str = _SESSION_ID,
) -> dict[str, Any]:
    stdout_bytes = stdout.encode("utf-8")
    digest = hashlib.sha256(stdout_bytes).hexdigest()
    return {
        "tool": tool,
        "tool_args_hash": "sha256:args123",
        "files": files or [],
        "result_summary": {
            "exit_code": exit_code,
            "stdout_digest": digest,
            "stdout_digest_alg": "sha256",
            "stdout_bytes_total": len(stdout_bytes),
            "stdout_truncated": truncated,
        },
        "on_behalf_of": {"principal_id": _PRINCIPAL, "session_id": session_id},
        "harness": {"name": _HARNESS_NAME, "version": _HARNESS_VERSION},
    }


def _tool_call_fail_payload(
    tool: str = "Bash",
    error: str = "command failed",
    session_id: str = _SESSION_ID,
) -> dict[str, Any]:
    return {
        "tool": tool,
        "tool_args_hash": "sha256:args456",
        "files": [],
        "result_summary": {
            "exit_code": 1,
            "error": error,
        },
        "on_behalf_of": {"principal_id": _PRINCIPAL, "session_id": session_id},
        "harness": {"name": _HARNESS_NAME, "version": _HARNESS_VERSION},
    }


def _attest_session(gateway, session_id: str = _SESSION_ID) -> Event:
    return gateway.append_note_event(
        actor=_agent_for_session(session_id),
        entity_id=uuid.UUID(session_id),
        transition="session_attestation",
        payload={
            **_session_attestation_payload(session_id),
            "on_behalf_of": _on_behalf(session_id),
        },
    )


def _begin_tool_call(
    gateway,
    *,
    tool: str = "Edit",
    files: list[dict[str, Any]] | None = None,
    session_id: str = _SESSION_ID,
) -> uuid.UUID:
    wi, _ = gateway.create_issue(
        actor=_agent_for_session(session_id),
        work_item_type="bug",
        custom_fields={"title": f"Tool call: {tool}"},
    )
    gateway.append_work_item_event(
        actor=_agent_for_session(session_id),
        work_item_id=wi.work_item_id,
        transition="tool_call_begin",
        payload={
            **_tool_call_begin_payload(tool=tool, files=files, session_id=session_id),
            "on_behalf_of": _on_behalf(session_id),
        },
    )
    return wi.work_item_id


def _end_tool_call(
    gateway,
    work_item_id: uuid.UUID,
    *,
    tool: str = "Edit",
    files: list[dict[str, Any]] | None = None,
    exit_code: int = 0,
    stdout: str = "done",
    truncated: bool = False,
    session_id: str = _SESSION_ID,
) -> Event:
    return gateway.append_work_item_event(
        actor=_agent_for_session(session_id),
        work_item_id=work_item_id,
        transition="tool_call_end",
        payload={
            **_tool_call_end_payload(
                tool=tool, files=files, exit_code=exit_code,
                stdout=stdout, truncated=truncated, session_id=session_id,
            ),
            "on_behalf_of": _on_behalf(session_id),
        },
    )


def _fail_tool_call(
    gateway,
    work_item_id: uuid.UUID,
    *,
    tool: str = "Bash",
    error: str = "command failed",
    session_id: str = _SESSION_ID,
) -> Event:
    return gateway.append_work_item_event(
        actor=_agent_for_session(session_id),
        work_item_id=work_item_id,
        transition="tool_call_fail",
        payload={
            **_tool_call_fail_payload(tool=tool, error=error, session_id=session_id),
            "on_behalf_of": _on_behalf(session_id),
        },
    )


# ----------------------------------------------------------------------
# Pure-function tests
# ----------------------------------------------------------------------


def _make_event(
    *,
    transition: str = "tool_call_begin",
    work_item_id: uuid.UUID | None = None,
    payload: dict[str, Any] | None = None,
    on_behalf_of: dict[str, Any] | None = None,
    timestamp: datetime | None = None,
    event_seq: int = 0,
) -> Event:
    ev_id = uuid.uuid4()
    wid = work_item_id or uuid.uuid4()
    return Event(
        event_id=ev_id,
        work_item_id=wid,
        event_seq=event_seq,
        actor_id="agent:relay",
        actor_kind="agent",
        actor_metadata=None,
        key_id="test-key",
        workflow_name="canonical",
        workflow_version=2,
        timestamp=timestamp or datetime.now(UTC),
        transition=transition,
        payload=payload,
        payload_canonical_hash=b"",
        signature=b"",
        on_behalf_of=on_behalf_of,
    )


def test_extract_session_id_from_on_behalf_of():
    ev = _make_event(on_behalf_of={"principal_id": "p", "session_id": "sess-123"})
    assert extract_session_id(ev) == "sess-123"


def test_extract_session_id_from_payload():
    ev = _make_event(
        payload={"session_id": "sess-456"},
        on_behalf_of=None,
    )
    assert extract_session_id(ev) == "sess-456"


def test_extract_session_id_none():
    ev = _make_event(payload=None, on_behalf_of=None)
    assert extract_session_id(ev) is None


def test_extract_principal_from_on_behalf_of():
    ev = _make_event(on_behalf_of={
        "principal_id": "human:bob",
        "principal_display_name": "Bob",
    })
    pid, display = extract_principal(ev)
    assert pid == "human:bob"
    assert display == "Bob"


def test_extract_principal_from_payload():
    ev = _make_event(
        payload={"principal_id": "human:carol"},
        on_behalf_of=None,
    )
    pid, display = extract_principal(ev)
    assert pid == "human:carol"
    assert display is None


def test_build_tool_call_trail_pairs_begin_end():
    wid = uuid.uuid4()
    begin = _make_event(
        transition="tool_call_begin",
        work_item_id=wid,
        payload={"tool": "Edit", "tool_args_hash": "h1", "files": []},
        event_seq=1,
    )
    end = _make_event(
        transition="tool_call_end",
        work_item_id=wid,
        payload={"tool": "Edit", "tool_args_hash": "h1", "result_summary": {"exit_code": 0}},
        event_seq=2,
    )
    trail = build_tool_call_trail([begin, end])
    assert len(trail) == 1
    assert trail[0].tool == "Edit"
    assert trail[0].status == "completed"
    assert trail[0].exit_code == 0


def test_build_tool_call_trail_degraded_begin_without_end():
    wid = uuid.uuid4()
    begin = _make_event(
        transition="tool_call_begin",
        work_item_id=wid,
        payload={"tool": "Bash", "tool_args_hash": "h1", "files": []},
        event_seq=1,
    )
    trail = build_tool_call_trail([begin])
    assert len(trail) == 1
    assert trail[0].status == "running"


def test_build_tool_call_trail_failed():
    wid = uuid.uuid4()
    begin = _make_event(
        transition="tool_call_begin",
        work_item_id=wid,
        payload={"tool": "Bash", "tool_args_hash": "h1"},
        event_seq=1,
    )
    fail = _make_event(
        transition="tool_call_fail",
        work_item_id=wid,
        payload={"tool": "Bash", "tool_args_hash": "h1", "result_summary": {"error": "boom"}},
        event_seq=2,
    )
    trail = build_tool_call_trail([begin, fail])
    assert len(trail) == 1
    assert trail[0].status == "failed"
    assert trail[0].error == "boom"


def test_build_tool_call_trail_merges_file_digests():
    wid = uuid.uuid4()
    begin = _make_event(
        transition="tool_call_begin",
        work_item_id=wid,
        payload={"tool": "Edit", "tool_args_hash": "h1", "files": [
            {"path": "/foo.py", "pre_digest": "sha256:pre"},
        ]},
        event_seq=1,
    )
    end = _make_event(
        transition="tool_call_end",
        work_item_id=wid,
        payload={"tool": "Edit", "tool_args_hash": "h1", "files": [
            {"path": "/foo.py", "post_digest": "sha256:post"},
        ]},
        event_seq=2,
    )
    trail = build_tool_call_trail([begin, end])
    assert len(trail[0].files) == 1
    assert trail[0].files[0].pre_digest == "sha256:pre"
    assert trail[0].files[0].post_digest == "sha256:post"


def test_compute_verification_verified():
    v = compute_verification(chain_intact=True, tool_calls=[])
    assert v.status == "verified"
    assert v.chain_intact is True
    assert v.degradation_flags == []


def test_compute_verification_gap_detected():
    from dossier.provenance import ToolCallEntry
    tc = ToolCallEntry(
        work_item_id=uuid.uuid4(), tool="Bash", tool_args_hash="h",
        files=[], exit_code=None, stdout_digest=None,
        stdout_digest_alg=None, stdout_bytes_total=None,
        stdout_truncated=None, stderr_digest=None, error=None,
        begin_timestamp=datetime.now(UTC), end_timestamp=None,
        status="running", harness_name=None, harness_version=None,
    )
    v = compute_verification(chain_intact=True, tool_calls=[tc])
    assert v.status == "gap-detected"
    assert len(v.degradation_flags) == 1


def test_compute_verification_unverified():
    v = compute_verification(chain_intact=False, tool_calls=[])
    assert v.status == "unverified"
    assert v.chain_intact is False


# ----------------------------------------------------------------------
# Integration tests (gateway fixture)
# ----------------------------------------------------------------------


def test_read_session_summaries_discovers_session(gateway):
    _attest_session(gateway)
    wid = _begin_tool_call(
        gateway, tool="Edit", files=[{"path": "/foo.py", "pre_digest": "sha256:pre"}]
    )
    _end_tool_call(
        gateway, wid, tool="Edit",
        files=[{"path": "/foo.py", "post_digest": "sha256:post"}],
    )

    summaries = read_session_summaries(gateway, "dossier-test")
    assert len(summaries) == 1
    s = summaries[0]
    assert s.session_id == _SESSION_ID
    assert s.principal_id == _PRINCIPAL
    assert s.principal_display_name == _PRINCIPAL_DISPLAY
    assert s.harnesses == [{"name": _HARNESS_NAME, "version": _HARNESS_VERSION}]
    assert s.event_count == 2
    assert s.degraded is False
    assert s.chain_intact is True


def test_read_session_summaries_degraded_session(gateway):
    _attest_session(gateway)
    _begin_tool_call(gateway, tool="Bash")
    # No end event — degraded

    summaries = read_session_summaries(gateway, "dossier-test")
    assert len(summaries) == 1
    assert summaries[0].degraded is True


def test_read_session_summaries_empty(gateway):
    summaries = read_session_summaries(gateway, "dossier-test")
    assert summaries == []


def test_read_session_detail_complete(gateway):
    _attest_session(gateway)
    wid = _begin_tool_call(
        gateway, tool="Edit",
        files=[{"path": "/projects/foo/bar.py", "pre_digest": "sha256:pre123"}],
    )
    _end_tool_call(
        gateway, wid, tool="Edit",
        files=[{"path": "/projects/foo/bar.py", "post_digest": "sha256:post456"}],
        stdout="hello world",
    )

    detail = read_session_detail(gateway, _SESSION_ID, "dossier-test")
    assert detail is not None
    assert detail.summary.session_id == _SESSION_ID
    assert len(detail.tool_calls) == 1
    tc = detail.tool_calls[0]
    assert tc.tool == "Edit"
    assert tc.status == "completed"
    assert tc.exit_code == 0
    assert tc.stdout_digest == hashlib.sha256(b"hello world").hexdigest()
    assert tc.stdout_digest_alg == "sha256"
    assert tc.stdout_bytes_total == 11
    assert tc.stdout_truncated is False
    assert len(tc.files) == 1
    assert tc.files[0].path == "/projects/foo/bar.py"
    assert tc.files[0].pre_digest == "sha256:pre123"
    assert tc.files[0].post_digest == "sha256:post456"
    assert detail.verification.status == "verified"
    assert detail.attestation_event is not None


def test_read_session_detail_truncated_output(gateway):
    _attest_session(gateway)
    long_output = "x" * 3000
    wid = _begin_tool_call(gateway, tool="Bash")
    _end_tool_call(gateway, wid, tool="Bash", stdout=long_output, truncated=True)

    detail = read_session_detail(gateway, _SESSION_ID, "dossier-test")
    assert detail is not None
    tc = detail.tool_calls[0]
    assert tc.stdout_bytes_total == 3000
    assert tc.stdout_truncated is True
    assert tc.stdout_digest == hashlib.sha256(long_output.encode("utf-8")).hexdigest()


def test_read_session_detail_failed_tool_call(gateway):
    _attest_session(gateway)
    wid = _begin_tool_call(gateway, tool="Bash")
    _fail_tool_call(gateway, wid, tool="Bash", error="exit code 1")

    detail = read_session_detail(gateway, _SESSION_ID, "dossier-test")
    assert detail is not None
    tc = detail.tool_calls[0]
    assert tc.status == "failed"
    assert tc.error == "exit code 1"
    assert tc.exit_code == 1


def test_read_session_detail_degraded(gateway):
    _attest_session(gateway)
    _begin_tool_call(gateway, tool="Bash")
    # No end event

    detail = read_session_detail(gateway, _SESSION_ID, "dossier-test")
    assert detail is not None
    assert detail.summary.degraded is True
    assert detail.verification.status == "gap-detected"
    assert len(detail.verification.degradation_flags) == 1


def test_read_session_detail_not_found(gateway):
    detail = read_session_detail(gateway, "nonexistent-session-id", "dossier-test")
    assert detail is None


def test_read_session_detail_multiple_tool_calls(gateway):
    _attest_session(gateway)
    w1 = _begin_tool_call(gateway, tool="Read")
    _end_tool_call(gateway, w1, tool="Read", stdout="content")
    w2 = _begin_tool_call(gateway, tool="Edit", files=[{"path": "/a.py", "pre_digest": "p"}])
    _end_tool_call(
        gateway,
        w2,
        tool="Edit",
        files=[{"path": "/a.py", "post_digest": "q"}],
        stdout="edited",
    )
    w3 = _begin_tool_call(gateway, tool="Bash")
    _fail_tool_call(gateway, w3, tool="Bash", error="timeout")

    detail = read_session_detail(gateway, _SESSION_ID, "dossier-test")
    assert detail is not None
    assert len(detail.tool_calls) == 3
    statuses = [tc.status for tc in detail.tool_calls]
    assert "completed" in statuses
    assert "failed" in statuses


def test_multiple_sessions(gateway):
    sid2 = "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb"
    _attest_session(gateway, _SESSION_ID)
    _attest_session(gateway, sid2)

    w1 = _begin_tool_call(gateway, tool="Edit", session_id=_SESSION_ID)
    _end_tool_call(gateway, w1, tool="Edit", session_id=_SESSION_ID)

    w2 = _begin_tool_call(gateway, tool="Read", session_id=sid2)
    _end_tool_call(gateway, w2, tool="Read", session_id=sid2)

    summaries = read_session_summaries(gateway, "dossier-test")
    assert len(summaries) == 2
    session_ids = {s.session_id for s in summaries}
    assert _SESSION_ID in session_ids
    assert sid2 in session_ids


# ----------------------------------------------------------------------
# Web route tests
# ----------------------------------------------------------------------


def test_sessions_route_unauthenticated_redirects(client):
    resp = client.get("/sessions", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_sessions_route_empty(client):
    _login(client)
    resp = client.get("/sessions")
    assert resp.status_code == 200
    assert "no attested sessions" in resp.text


def test_sessions_route_shows_session(client, gateway):
    _login(client)
    _attest_session(gateway)
    wid = _begin_tool_call(gateway, tool="Edit")
    _end_tool_call(gateway, wid, tool="Edit", stdout="done")

    resp = client.get("/sessions")
    assert resp.status_code == 200
    assert _SESSION_ID[:8] in resp.text
    assert _PRINCIPAL_DISPLAY in resp.text
    assert f"{_HARNESS_NAME}@{_HARNESS_VERSION}" in resp.text
    # WI-C: the list carries the real verification verdict, not a bare
    # "intact" derived from the project-wide chain flag.
    assert "chain verified" in resp.text.lower()


def test_sessions_route_shows_degraded(client, gateway):
    _login(client)
    _attest_session(gateway)
    _begin_tool_call(gateway, tool="Bash")

    resp = client.get("/sessions")
    assert resp.status_code == 200
    assert "trail incomplete" in resp.text.lower()


def test_session_detail_route_unauthenticated_redirects(client):
    resp = client.get(
        f"/p/dossier-test/sessions/{_SESSION_ID}",
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_session_detail_route_renders_trail(client, gateway):
    _login(client)
    _attest_session(gateway)
    wid = _begin_tool_call(
        gateway, tool="Edit",
        files=[{"path": "/projects/foo/bar.py", "pre_digest": "sha256:pre123"}],
    )
    _end_tool_call(
        gateway, wid, tool="Edit",
        files=[{"path": "/projects/foo/bar.py", "post_digest": "sha256:post456"}],
        stdout="hello world",
    )

    resp = client.get(f"/p/dossier-test/sessions/{_SESSION_ID}")
    assert resp.status_code == 200
    assert _SESSION_ID in resp.text
    assert "Edit" in resp.text
    assert "/projects/foo/bar.py" in resp.text
    assert "completed" in resp.text
    assert "verified" in resp.text.lower()


def test_session_detail_route_renders_digest_fields(client, gateway):
    _login(client)
    _attest_session(gateway)
    wid = _begin_tool_call(gateway, tool="Bash")
    _end_tool_call(gateway, wid, tool="Bash", stdout="x" * 3000, truncated=True)

    resp = client.get(f"/p/dossier-test/sessions/{_SESSION_ID}")
    assert resp.status_code == 200
    assert "truncated" in resp.text.lower()
    assert "sha256" in resp.text.lower()


def test_session_detail_route_degraded_shows_gap(client, gateway):
    _login(client)
    _attest_session(gateway)
    _begin_tool_call(gateway, tool="Bash")

    resp = client.get(f"/p/dossier-test/sessions/{_SESSION_ID}")
    assert resp.status_code == 200
    assert "trail incomplete" in resp.text.lower()
    assert "degradation" in resp.text.lower()
    assert "running" in resp.text.lower()


def test_session_detail_route_failed_shows_error(client, gateway):
    _login(client)
    _attest_session(gateway)
    wid = _begin_tool_call(gateway, tool="Bash")
    _fail_tool_call(gateway, wid, tool="Bash", error="exit code 1")

    resp = client.get(f"/p/dossier-test/sessions/{_SESSION_ID}")
    assert resp.status_code == 200
    assert "failed" in resp.text.lower()
    assert "exit code 1" in resp.text


def test_session_detail_route_not_found(client, gateway):
    _login(client)
    resp = client.get("/p/dossier-test/sessions/nonexistent-id")
    assert resp.status_code == 404


def test_session_detail_route_shows_verification_status(client, gateway):
    _login(client)
    _attest_session(gateway)
    wid = _begin_tool_call(gateway, tool="Edit")
    _end_tool_call(gateway, wid, tool="Edit", stdout="ok")

    resp = client.get(f"/p/dossier-test/sessions/{_SESSION_ID}")
    assert resp.status_code == 200
    assert "verified" in resp.text.lower()
    assert "ds-verify" in resp.text


def test_session_detail_route_shows_harness(client, gateway):
    _login(client)
    _attest_session(gateway)
    wid = _begin_tool_call(gateway, tool="Edit")
    _end_tool_call(gateway, wid, tool="Edit", stdout="ok")

    resp = client.get(f"/p/dossier-test/sessions/{_SESSION_ID}")
    assert resp.status_code == 200
    assert f"{_HARNESS_NAME}@{_HARNESS_VERSION}" in resp.text


def test_session_detail_route_shows_attestation_section(client, gateway):
    _login(client)
    _attest_session(gateway)
    wid = _begin_tool_call(gateway, tool="Edit")
    _end_tool_call(gateway, wid, tool="Edit", stdout="ok")

    resp = client.get(f"/p/dossier-test/sessions/{_SESSION_ID}")
    assert resp.status_code == 200
    assert "session attestation" in resp.text.lower()
    assert "In scope: claude-code" in resp.text
    assert _PRINCIPAL_DISPLAY in resp.text
    assert "on behalf of" in resp.text.lower()


# ── WI-C: session verification UX ────────────────────────────────────────
#
# A human looking at a session must be able to see whether its provenance
# chain actually verifies — and when it does not, why. Nothing below asserts a
# hardcoded optimistic value; every verdict is driven by a real regista result.


def test_unreachable_store_is_unverifiable_not_broken(gateway, monkeypatch):
    """The distinction WI-C exists for: 'could not check' != 'chain broken'."""
    from dossier.provenance import CHAIN_UNKNOWN, read_chain_integrity

    def _boom(*args, **kwargs):
        raise ConnectionError("store unreachable")

    monkeypatch.setattr(gateway, "integrity", _boom)
    integrity = read_chain_integrity(gateway)
    assert integrity.state == CHAIN_UNKNOWN
    assert integrity.intact is False
    assert integrity.reason is not None
    assert "could not be run" in integrity.reason
    assert "not verified" in integrity.reason


def test_broken_chain_is_reported_as_broken_with_the_drift(gateway, monkeypatch):
    from dossier.provenance import CHAIN_BROKEN, read_chain_integrity

    class _Drifted:
        replayed_drift = 3

    monkeypatch.setattr(gateway, "integrity", lambda *a, **k: _Drifted())
    integrity = read_chain_integrity(gateway)
    assert integrity.state == CHAIN_BROKEN
    assert integrity.reason is not None
    assert "3 drift" in integrity.reason


def test_unverifiable_chain_never_renders_as_verified(gateway, monkeypatch):
    from dossier.provenance import UNVERIFIABLE

    _attest_session(gateway)
    wid = _begin_tool_call(gateway, tool="Edit")
    _end_tool_call(gateway, wid, tool="Edit")

    monkeypatch.setattr(
        gateway, "integrity", lambda *a, **k: (_ for _ in ()).throw(OSError("down"))
    )
    detail = read_session_detail(gateway, _SESSION_ID, "dossier-test")
    assert detail is not None
    assert detail.verification.status == UNVERIFIABLE
    assert detail.verification.chain_intact is False
    assert detail.verification.reasons  # a verdict without a reason is not honest


def test_invalid_signature_makes_the_session_unverified(gateway, monkeypatch):
    """A tampered/unverifiable signature is a failure, not a footnote."""
    from dossier.provenance import UNVERIFIED

    _attest_session(gateway)
    wid = _begin_tool_call(gateway, tool="Edit")
    _end_tool_call(gateway, wid, tool="Edit")

    monkeypatch.setattr(
        gateway,
        "verify_event",
        lambda event: {
            "verified": False,
            "signature_valid": False,
            "signer_registered": True,
        },
    )
    detail = read_session_detail(gateway, _SESSION_ID, "dossier-test")
    assert detail is not None
    assert detail.verification.status == UNVERIFIED
    assert detail.verification.signature_findings
    assert any("did not verify" in f for f in detail.verification.signature_findings)


def test_registered_v6_signer_is_attributed_without_a_downgrade(gateway):
    """A v6 fixture accepts every writer key before ordinary events are signed."""
    _attest_session(gateway)
    wid = _begin_tool_call(gateway, tool="Edit")
    _end_tool_call(gateway, wid, tool="Edit")

    detail = read_session_detail(gateway, _SESSION_ID, "dossier-test")
    assert detail is not None
    v = detail.verification
    assert v.status == "verified"
    assert v.signature_findings == []
    assert v.signatures_checked == 3
    assert v.unattributed_signatures == 0
    assert v.attribution_note is None


def test_signature_check_error_is_a_finding(gateway, monkeypatch):
    from dossier.provenance import UNVERIFIED

    _attest_session(gateway)
    wid = _begin_tool_call(gateway, tool="Edit")
    _end_tool_call(gateway, wid, tool="Edit")

    def _boom(event):
        raise RuntimeError("verifier exploded")

    monkeypatch.setattr(gateway, "verify_event", _boom)
    detail = read_session_detail(gateway, _SESSION_ID, "dossier-test")
    assert detail is not None
    assert detail.verification.status == UNVERIFIED
    assert any(
        "could not be checked" in f
        for f in detail.verification.signature_findings
    )


def test_failed_signature_outranks_an_unknown_chain(gateway):
    """A demonstrated failure is reported as failure, not as 'cannot check'."""
    from dossier.provenance import (
        CHAIN_UNKNOWN,
        UNVERIFIED,
        ChainIntegrity,
        SignatureReport,
        compute_verification,
    )

    v = compute_verification(
        ChainIntegrity(CHAIN_UNKNOWN, "store down"),
        [],
        signatures=SignatureReport(findings=["bad sig"], checked=1),
    )
    assert v.status == UNVERIFIED


def test_summaries_carry_a_verdict_without_claiming_signature_checks(gateway):
    """The list view must not imply it checked signatures when it did not."""
    _attest_session(gateway)
    wid = _begin_tool_call(gateway, tool="Edit")
    _end_tool_call(gateway, wid, tool="Edit")

    summaries = read_session_summaries(gateway, "dossier-test")
    assert len(summaries) == 1
    v = summaries[0].verification
    assert v.status == "verified"
    assert v.signatures_checked == 0
    assert v.attribution_note is None


def test_session_detail_route_renders_the_verification_panel(client, gateway):
    _login(client)
    _attest_session(gateway)
    wid = _begin_tool_call(gateway, tool="Edit")
    _end_tool_call(gateway, wid, tool="Edit")

    resp = client.get(f"/p/dossier-test/sessions/{_SESSION_ID}")
    assert resp.status_code == 200
    text = resp.text.lower()
    assert "provenance verification" in text
    assert "chain verified" in text
    assert "signatures checked" in text
    # The v6 fixture's accepted actor keys are attributable; no legacy HMAC
    # downgrade should be rendered.
    assert "public-key registry" not in text


def test_session_detail_route_renders_an_unverifiable_session(
    client, gateway, monkeypatch
):
    """A session whose chain cannot be checked says so, and says why."""
    _login(client)
    _attest_session(gateway)
    _begin_tool_call(gateway, tool="Edit")

    monkeypatch.setattr(
        gateway,
        "integrity",
        lambda *a, **k: (_ for _ in ()).throw(ConnectionError("store unreachable")),
    )
    resp = client.get(f"/p/dossier-test/sessions/{_SESSION_ID}")
    assert resp.status_code == 200
    text = resp.text.lower()
    assert "could not be verified" in text
    assert "could not be run" in text
    assert "chain verified" not in text


def test_session_detail_route_renders_a_broken_session(client, gateway, monkeypatch):
    _login(client)
    _attest_session(gateway)
    _begin_tool_call(gateway, tool="Edit")

    monkeypatch.setattr(
        gateway,
        "verify_event",
        lambda event: {
            "verified": False,
            "signature_valid": False,
            "signer_registered": True,
        },
    )
    resp = client.get(f"/p/dossier-test/sessions/{_SESSION_ID}")
    assert resp.status_code == 200
    text = resp.text.lower()
    assert "verification failed" in text
    assert "did not verify" in text
