"""Agent-activity provenance: session list + tool-call trail (Plan 017).

This module builds human-readable session and tool-call-trail data structures
from signed regista events authored by cairn (agent-provenance). Everything
shown comes from the event log — the UI never synthesizes activity from side
channels (Plan 017 principle: "render the record, don't re-derive it").

cairn attests into its own regista project:

- ``session_attestation`` events (``entity_kind="session"``) carry the
  harness name/version, principal (``on_behalf_of``), and scope statement.
- ``tool_call_begin``/``end``/``fail`` events are bound to cairn-managed work
  items, with ``on_behalf_of`` carrying ``session_id`` + ``principal_id``.
  The payload includes tool name, file digests, exit code, and the output
  digest fields from agent-provenance Plan 009 WI-1.2
  (``stdout_digest``, ``stdout_digest_alg``, ``stdout_bytes_total``,
  ``stdout_truncated``).

The ambient ``work_item_id`` binding is how work items humans track relate to
attestations. Cross-project provenance reads honor Plan 014's authorization
seam (``can_read_project``).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from regista import Event

from .gateway import RegistaGateway

_TOOL_CALL_TRANSITIONS = frozenset({
    "tool_call_begin",
    "tool_call_end",
    "tool_call_fail",
})

_TOOL_CALL_BEGIN = "tool_call_begin"
_TOOL_CALL_END = "tool_call_end"
_TOOL_CALL_FAIL = "tool_call_fail"
_SESSION_ATTESTATION = "session_attestation"

_MAX_EVENTS = 10_000


@dataclass(frozen=True)
class FileDigest:
    path: str
    pre_digest: str | None
    post_digest: str | None


@dataclass(frozen=True)
class ToolCallEntry:
    work_item_id: uuid.UUID
    tool: str
    tool_args_hash: str
    files: list[FileDigest]
    exit_code: int | None
    stdout_digest: str | None
    stdout_digest_alg: str | None
    stdout_bytes_total: int | None
    stdout_truncated: bool | None
    stderr_digest: str | None
    error: str | None
    begin_timestamp: datetime | None
    end_timestamp: datetime | None
    status: str
    harness_name: str | None
    harness_version: str | None


@dataclass(frozen=True)
class VerificationStatus:
    status: str
    chain_intact: bool
    degradation_flags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SessionSummary:
    session_id: str
    principal_id: str
    principal_display_name: str | None
    harnesses: list[dict[str, Any]]
    attested_at: datetime | None
    event_count: int
    start_time: datetime | None
    end_time: datetime | None
    degraded: bool
    project_slug: str
    chain_intact: bool


@dataclass(frozen=True)
class SessionDetail:
    summary: SessionSummary
    tool_calls: list[ToolCallEntry]
    verification: VerificationStatus
    attestation_event: Event | None


def extract_session_id(event: Event) -> str | None:
    ob = getattr(event, "on_behalf_of", None)
    if isinstance(ob, dict):
        sid = ob.get("session_id")
        if sid:
            return str(sid)
    payload = getattr(event, "payload", None)
    if isinstance(payload, dict):
        sid = payload.get("session_id")
        if sid:
            return str(sid)
    return None


def extract_principal(event: Event) -> tuple[str, str | None]:
    ob = getattr(event, "on_behalf_of", None)
    if isinstance(ob, dict):
        pid = ob.get("principal_id")
        display = ob.get("principal_display_name")
        if pid:
            return str(pid), str(display) if display else None
    payload = getattr(event, "payload", None)
    if isinstance(payload, dict):
        pid = payload.get("principal_id")
        if pid:
            return str(pid), None
    return "unknown", None


def extract_harnesses(event: Event) -> list[dict[str, Any]]:
    payload = getattr(event, "payload", None)
    if isinstance(payload, dict):
        harnesses = payload.get("harnesses")
        if isinstance(harnesses, list):
            return harnesses
    return []


def _extract_harness_from_payload(payload: dict[str, Any] | None) -> tuple[str | None, str | None]:
    if payload and isinstance(payload.get("harness"), dict):
        h = payload["harness"]
        return (
            str(h["name"]) if h.get("name") else None,
            str(h["version"]) if h.get("version") else None,
        )
    return None, None


def _parse_file_digests(files: Any) -> list[FileDigest]:
    if not isinstance(files, list):
        return []
    result: list[FileDigest] = []
    for f in files:
        if isinstance(f, dict):
            result.append(FileDigest(
                path=str(f.get("path", "")),
                pre_digest=str(f["pre_digest"]) if f.get("pre_digest") else None,
                post_digest=str(f["post_digest"]) if f.get("post_digest") else None,
            ))
    return result


def _merge_file_digests(begin_files: list[FileDigest], end_files: list[FileDigest]) -> list[FileDigest]:
    by_path: dict[str, FileDigest] = {}
    for fd in begin_files:
        by_path[fd.path] = fd
    for fd in end_files:
        existing = by_path.get(fd.path)
        if existing:
            by_path[fd.path] = FileDigest(
                path=fd.path,
                pre_digest=existing.pre_digest or fd.pre_digest,
                post_digest=fd.post_digest or existing.post_digest,
            )
        else:
            by_path[fd.path] = fd
    return list(by_path.values())


def build_tool_call_trail(events: list[Event]) -> list[ToolCallEntry]:
    """Pair begin/end events by work_item_id into an ordered trail.

    Events are grouped by ``work_item_id``. Within each group, the last
    ``tool_call_begin`` is paired with the last ``tool_call_end`` or
    ``tool_call_fail``. A begin without an end (or vice versa) is a
    degradation — the entry is included with a ``running`` / ``orphaned-end``
    status.
    """
    by_wi: dict[uuid.UUID, list[Event]] = {}
    for ev in events:
        if ev.transition not in _TOOL_CALL_TRANSITIONS:
            continue
        by_wi.setdefault(ev.work_item_id, []).append(ev)

    entries: list[ToolCallEntry] = []
    for wi_id, wi_events in by_wi.items():
        wi_events.sort(key=lambda e: e.event_seq)

        begin_ev: Event | None = None
        end_ev: Event | None = None
        for ev in wi_events:
            if ev.transition == _TOOL_CALL_BEGIN:
                begin_ev = ev
            elif ev.transition in (_TOOL_CALL_END, _TOOL_CALL_FAIL):
                end_ev = ev

        if begin_ev is None and end_ev is not None:
            begin_ev = end_ev

        base_ev = begin_ev or end_ev
        if base_ev is None:
            continue

        begin_payload = getattr(begin_ev, "payload", None) or {} if begin_ev else {}
        end_payload = getattr(end_ev, "payload", None) or {} if end_ev else {}

        begin_files = _parse_file_digests(begin_payload.get("files"))
        end_files = _parse_file_digests(end_payload.get("files"))
        files = _merge_file_digests(begin_files, end_files)

        result_summary = end_payload.get("result_summary") if end_payload else None
        rs = result_summary if isinstance(result_summary, dict) else {}

        harness_name, harness_version = _extract_harness_from_payload(
            begin_payload or end_payload
        )

        if end_ev is None:
            status = "running"
        elif end_ev.transition == _TOOL_CALL_FAIL:
            status = "failed"
        else:
            status = "completed"

        entries.append(ToolCallEntry(
            work_item_id=wi_id,
            tool=str(begin_payload.get("tool") or end_payload.get("tool") or "unknown"),
            tool_args_hash=str(begin_payload.get("tool_args_hash") or end_payload.get("tool_args_hash") or ""),
            files=files,
            exit_code=rs.get("exit_code"),
            stdout_digest=rs.get("stdout_digest"),
            stdout_digest_alg=rs.get("stdout_digest_alg"),
            stdout_bytes_total=rs.get("stdout_bytes_total"),
            stdout_truncated=rs.get("stdout_truncated"),
            stderr_digest=rs.get("stderr_digest"),
            error=rs.get("error"),
            begin_timestamp=getattr(begin_ev, "timestamp", None) if begin_ev else None,
            end_timestamp=getattr(end_ev, "timestamp", None) if end_ev else None,
            status=status,
            harness_name=harness_name,
            harness_version=harness_version,
        ))

    entries.sort(key=lambda e: e.begin_timestamp or e.end_timestamp or datetime.min)
    return entries


def compute_verification(
    chain_intact: bool,
    tool_calls: list[ToolCallEntry],
) -> VerificationStatus:
    """Compute the verification status from chain integrity + trail gaps.

    Returns one of:
    - ``verified``: chain intact, no degradation detected
    - ``gap-detected``: chain intact but trail has gaps (orphaned begins/ends)
    - ``unverified``: chain broken (replay drift detected)
    """
    flags: list[str] = []
    for tc in tool_calls:
        if tc.status == "running":
            flags.append(f"tool call {tc.tool} ({str(tc.work_item_id)[:8]}) has no end event")
        if tc.begin_timestamp is None and tc.end_timestamp is not None:
            flags.append(f"tool call {tc.tool} ({str(tc.work_item_id)[:8]}) has an end without a begin")

    if not chain_intact:
        return VerificationStatus(
            status="unverified",
            chain_intact=False,
            degradation_flags=flags,
        )
    if flags:
        return VerificationStatus(
            status="gap-detected",
            chain_intact=True,
            degradation_flags=flags,
        )
    return VerificationStatus(
        status="verified",
        chain_intact=True,
        degradation_flags=[],
    )


def _read_tool_call_events(gateway: RegistaGateway) -> list[Event]:
    events: list[Event] = []
    for transition in (_TOOL_CALL_BEGIN, _TOOL_CALL_END, _TOOL_CALL_FAIL):
        events.extend(gateway.read_events_by_transition(transition, limit=_MAX_EVENTS))
    return events


def _group_by_session(events: list[Event]) -> dict[str, list[Event]]:
    by_session: dict[str, list[Event]] = {}
    for ev in events:
        sid = extract_session_id(ev)
        if sid:
            by_session.setdefault(sid, []).append(ev)
    return by_session


def read_session_summaries(
    gateway: RegistaGateway,
    project_slug: str,
) -> list[SessionSummary]:
    """Read all attested agent sessions from a regista project.

    Discovers ``session_attestation`` events, then groups tool-call events
    by ``session_id`` (from ``on_behalf_of``) to compute event counts,
    timing, and degradation flags.
    """
    attestation_events = gateway.read_events_by_transition(
        _SESSION_ATTESTATION, limit=_MAX_EVENTS
    )
    if not attestation_events:
        return []

    tool_call_events = _read_tool_call_events(gateway)
    tc_by_session = _group_by_session(tool_call_events)

    try:
        integrity = gateway.integrity()
        chain_intact = integrity.replayed_drift == 0
    except Exception:
        chain_intact = False

    summaries: list[SessionSummary] = []
    for att_ev in attestation_events:
        sid = extract_session_id(att_ev)
        if not sid:
            continue

        principal_id, principal_display = extract_principal(att_ev)
        harnesses = extract_harnesses(att_ev)

        tc_events = tc_by_session.get(sid, [])
        tool_calls = build_tool_call_trail(tc_events)

        timestamps = [e.timestamp for e in tc_events if e.timestamp]
        start_time = min(timestamps) if timestamps else getattr(att_ev, "timestamp", None)
        end_time = max(timestamps) if timestamps else None

        degraded = any(tc.status == "running" for tc in tool_calls)

        summaries.append(SessionSummary(
            session_id=sid,
            principal_id=principal_id,
            principal_display_name=principal_display,
            harnesses=harnesses,
            attested_at=getattr(att_ev, "timestamp", None),
            event_count=len(tc_events),
            start_time=start_time,
            end_time=end_time,
            degraded=degraded,
            project_slug=project_slug,
            chain_intact=chain_intact,
        ))

    summaries.sort(key=lambda s: s.attested_at or datetime.min, reverse=True)
    return summaries


def read_session_detail(
    gateway: RegistaGateway,
    session_id: str,
    project_slug: str,
) -> SessionDetail | None:
    """Read a single session's detail: attestation + ordered tool-call trail.

    Returns ``None`` if no ``session_attestation`` event exists for
    *session_id*.
    """
    attestation_events = gateway.read_events_by_transition(
        _SESSION_ATTESTATION, limit=_MAX_EVENTS
    )
    att_ev: Event | None = None
    for ev in attestation_events:
        if extract_session_id(ev) == session_id:
            att_ev = ev
            break

    tool_call_events = _read_tool_call_events(gateway)
    tc_events = [
        ev for ev in tool_call_events
        if extract_session_id(ev) == session_id
    ]
    tool_calls = build_tool_call_trail(tc_events)

    try:
        integrity = gateway.integrity()
        chain_intact = integrity.replayed_drift == 0
    except Exception:
        chain_intact = False

    verification = compute_verification(chain_intact, tool_calls)

    if att_ev is None:
        if not tool_calls:
            return None
        principal_id, principal_display = "unknown", None
        harnesses: list[dict[str, Any]] = []
        attested_at: datetime | None = None
    else:
        principal_id, principal_display = extract_principal(att_ev)
        harnesses = extract_harnesses(att_ev)
        attested_at = getattr(att_ev, "timestamp", None)

    timestamps = [e.timestamp for e in tc_events if e.timestamp]
    start_time = min(timestamps) if timestamps else attested_at
    end_time = max(timestamps) if timestamps else None
    degraded = any(tc.status == "running" for tc in tool_calls)

    summary = SessionSummary(
        session_id=session_id,
        principal_id=principal_id,
        principal_display_name=principal_display,
        harnesses=harnesses,
        attested_at=attested_at,
        event_count=len(tc_events),
        start_time=start_time,
        end_time=end_time,
        degraded=degraded,
        project_slug=project_slug,
        chain_intact=chain_intact,
    )

    return SessionDetail(
        summary=summary,
        tool_calls=tool_calls,
        verification=verification,
        attestation_event=att_ev,
    )
