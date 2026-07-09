"""Working views: review queue, my work, activity feed (Plan 018 Phase 1).

All views derive from the regista event log — no side-channel state. A queue
view is a query, not a table. Every read honors the Plan 014 authz seam
(``can_read_project``) at the call site in ``app.py``.

Design notes:
- The review queue surfaces items ``in_review``, ``in_human_review``, and
  ``deferred`` (awaiting re-entry), with assurance level from Plan 014
  WI-1.4 and the gate they're blocked on. Strict-gate items awaiting a
  human accept sort first.
- My work distinguishes "I did this" (human actor) from "my agent did this
  on my behalf" (agent actor with ``on_behalf_of`` → me) by inspecting
  the event log.
- The activity feed is a reverse-chronological list of transitions across
  permitted projects, filterable by project, actor kind, and transition.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from regista import Event, WorkItem

from .assurance import assurance_class, assurance_label, compute_assurance_level
from .gateway import RegistaGateway
from . import web

_REVIEW_STATES = frozenset({"in_review", "in_human_review"})
_QUEUE_STATES = ["in_review", "in_human_review", "deferred"]

_NON_COMMENT_TRANSITIONS = frozenset({
    "created", "start", "block", "unblock", "defer", "resume",
    "submit_for_review", "adversarial_pass", "request_changes",
    "accept", "reject", "reopen", "close_from_open",
})


@dataclass(frozen=True)
class ReviewQueueEntry:
    key: str
    title: str
    project_slug: str
    state: str
    issue_url: str
    project_url: str
    age: str
    age_hours: float
    assurance_level: str
    assurance_label: str
    assurance_css: str
    gate: str
    strict_gate: bool
    submitted_by: str
    assignee: str


@dataclass(frozen=True)
class MyWorkEntry:
    key: str
    title: str
    project_slug: str
    state: str
    issue_url: str
    project_url: str
    relation: str
    relation_label: str
    last_action: str
    last_action_time: str
    assignee: str


@dataclass(frozen=True)
class ActivityEntry:
    timestamp: datetime
    timestamp_label: str
    transition: str
    transition_label: str
    project_slug: str
    work_item_id: uuid.UUID
    issue_url: str
    display_key: str
    title: str
    actor_id: str
    actor_kind: str
    actor_display: str
    on_behalf_display: str | None
    session_id: str | None
    session_url: str | None


def _gate_for_state(state: str, assurance: str) -> str:
    if state == "in_human_review":
        return "human accept"
    if state == "in_review":
        if assurance in ("self-reviewed", "unreviewed"):
            return "adversarial review → human accept"
        return "adversarial review"
    if state == "deferred":
        return "re-entry (resume)"
    return state


def _is_strict_gate(state: str, assurance: str) -> bool:
    return state == "in_human_review" or (
        state == "in_review" and assurance in ("self-reviewed", "unreviewed")
    )


def _sort_priority(state: str, assurance: str) -> int:
    if state == "in_human_review":
        return 0
    if state == "in_review" and assurance in ("self-reviewed", "unreviewed"):
        return 1
    if state == "in_review":
        return 2
    return 3


def _age_hours(wi: WorkItem) -> float:
    ts = wi.last_event_at
    now = datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    delta = now - ts
    hours = delta.total_seconds() / 3600.0
    return hours if hours > 0.0 else 0.0


def _format_age(hours: float) -> str:
    if hours < 1:
        return f"{int(hours * 60)}m"
    if hours < 24:
        return f"{hours:.1f}h"
    days = hours / 24
    return f"{days:.1f}d"


def _last_transition_event(events: list[Event]) -> Event | None:
    for ev in reversed(events):
        if ev.transition and ev.transition in _NON_COMMENT_TRANSITIONS:
            return ev
    return None


def _matches_principal(event: Event, actor_id: str) -> bool:
    ob = getattr(event, "on_behalf_of", None)
    if not isinstance(ob, dict):
        return False
    pid = ob.get("principal_id")
    if pid is None:
        return False
    pid_str = str(pid)
    if pid_str == actor_id:
        return True
    if ":" in pid_str and pid_str.rsplit(":", 1)[-1] == actor_id:
        return True
    return False


def read_review_queue(
    gateway: RegistaGateway,
    project_slug: str,
) -> list[ReviewQueueEntry]:
    """Build the review-queue entries for a single project.

    Returns items in ``in_review``, ``in_human_review``, and ``deferred``
    states, sorted so strict-gate items awaiting a human accept come first,
    then by age (oldest first within each group).
    """
    page = gateway.list_issues(current_states=_QUEUE_STATES, page_size=500)
    entries: list[ReviewQueueEntry] = []

    for wi in page.items:
        events = gateway.history(wi.work_item_id)
        assurance = compute_assurance_level(events)

        last_ev = _last_transition_event(events)
        submitted_by = web.actor_display(last_ev) if last_ev else "—"

        age_h = _age_hours(wi)

        entries.append(ReviewQueueEntry(
            key=web.display_key(wi),
            title=web.issue_title(wi),
            project_slug=project_slug,
            state=wi.current_state,
            issue_url=f"/p/{project_slug}/issues/{wi.work_item_id}",
            project_url=f"/p/{project_slug}",
            age=_format_age(age_h),
            age_hours=age_h,
            assurance_level=assurance,
            assurance_label=assurance_label(assurance),
            assurance_css=assurance_class(assurance),
            gate=_gate_for_state(wi.current_state, assurance),
            strict_gate=_is_strict_gate(wi.current_state, assurance),
            submitted_by=submitted_by,
            assignee=web.issue_field(wi, "assignee", ""),
        ))

    entries.sort(key=lambda e: (_sort_priority(e.state, e.assurance_level), -e.age_hours))
    return entries


def read_my_work(
    gateway: RegistaGateway,
    project_slug: str,
    actor_id: str,
) -> list[MyWorkEntry]:
    """Build the my-work entries for a single project.

    An item qualifies if the principal:
    - created it (``created`` event actor_id matches),
    - is assigned to it (``assignee`` custom field matches), or
    - had an agent act on their behalf (last transition event's
      ``on_behalf_of.principal_id`` matches).

    The ``relation`` field distinguishes "I did this" from "my agent did
    this on my behalf".
    """
    page = gateway.list_issues(page_size=500)
    entries: list[MyWorkEntry] = []

    for wi in page.items:
        events = gateway.history(wi.work_item_id)
        if not events:
            continue

        creator_id: str | None = None
        for ev in events:
            if ev.transition == "created":
                creator_id = ev.actor_id
                break

        created_by_me = creator_id == actor_id
        assignee = web.issue_field(wi, "assignee", "")
        assigned_to_me = bool(assignee) and assignee == actor_id

        last_ev = _last_transition_event(events)
        agent_on_behalf = last_ev is not None and _matches_principal(last_ev, actor_id)

        if not (created_by_me or assigned_to_me or agent_on_behalf):
            continue

        if agent_on_behalf and last_ev is not None:
            relation = "agent-on-behalf"
            relation_label = "my agent (on my behalf)"
        elif created_by_me and assigned_to_me:
            relation = "created-assigned"
            relation_label = "created by me, assigned to me"
        elif created_by_me:
            relation = "created"
            relation_label = "created by me"
        else:
            relation = "assigned"
            relation_label = "assigned to me"

        last_action = "—"
        last_action_time = "—"
        if last_ev is not None:
            last_action = web.transition_label(last_ev.transition or "")
            last_action_time = web.format_timestamp(last_ev.timestamp)

        entries.append(MyWorkEntry(
            key=web.display_key(wi),
            title=web.issue_title(wi),
            project_slug=project_slug,
            state=wi.current_state,
            issue_url=f"/p/{project_slug}/issues/{wi.work_item_id}",
            project_url=f"/p/{project_slug}",
            relation=relation,
            relation_label=relation_label,
            last_action=last_action,
            last_action_time=last_action_time,
            assignee=assignee,
        ))

    entries.sort(key=lambda e: e.state)
    return entries


def read_activity_feed(
    gateway: RegistaGateway,
    project_slug: str,
    *,
    limit: int = 100,
    actor_kind_filter: str | None = None,
    transition_filter: str | None = None,
) -> list[ActivityEntry]:
    """Read recent transition events for the activity feed.

    Returns entries in descending time order. Filters by *actor_kind_filter*
    (human/agent) and *transition_filter* are applied client-side after the
    read because regista's ``read_events`` does not support actor_kind
    filtering directly.
    """
    events = gateway.read_recent_events(limit=limit * 3)

    wi_cache: dict[uuid.UUID, WorkItem] = {}

    def _get_wi(wid: uuid.UUID) -> WorkItem | None:
        if wid not in wi_cache:
            wi_cache[wid] = gateway.get_issue(wid)
        return wi_cache[wid]

    entries: list[ActivityEntry] = []
    for ev in events:
        if ev.transition is None or ev.transition == "comment":
            continue

        if actor_kind_filter and ev.actor_kind != actor_kind_filter:
            continue
        if transition_filter and ev.transition != transition_filter:
            continue

        wi = _get_wi(ev.work_item_id)
        if wi is None:
            continue

        ob_display = web.on_behalf_display(ev)

        session_id: str | None = None
        session_url: str | None = None
        ob = getattr(ev, "on_behalf_of", None)
        if isinstance(ob, dict):
            sid = ob.get("session_id")
            if sid:
                session_id = str(sid)
                session_url = f"/p/{project_slug}/sessions/{session_id}"

        entries.append(ActivityEntry(
            timestamp=ev.timestamp,
            timestamp_label=web.format_timestamp(ev.timestamp),
            transition=ev.transition,
            transition_label=web.transition_label(ev.transition),
            project_slug=project_slug,
            work_item_id=ev.work_item_id,
            issue_url=f"/p/{project_slug}/issues/{ev.work_item_id}",
            display_key=web.display_key(wi),
            title=web.issue_title(wi),
            actor_id=ev.actor_id,
            actor_kind=ev.actor_kind,
            actor_display=web.actor_display(ev),
            on_behalf_display=ob_display,
            session_id=session_id,
            session_url=session_url,
        ))

    entries.sort(key=lambda e: e.timestamp, reverse=True)
    return entries[:limit]


def build_digest(
    gateways: list[tuple[str, RegistaGateway]],
    actor_id: str,
) -> dict[str, Any]:
    """Build a per-principal digest (Plan 018 WI-2.2).

    Gathers: review-queue count, my-work count, and agent-session count.
    The caller renders this into a deliverable format; dossier does not
    send email — the webhook sink handles delivery.

    Returns a dict with ``review_items``, ``my_work_items``, ``session_count``,
    and ``is_empty``. An empty day (no items in any category) sets
    ``is_empty=True`` so the caller sends nothing.
    """
    review_items: list[dict[str, Any]] = []
    my_work_items: list[dict[str, Any]] = []
    session_count = 0

    for slug, gw in gateways:
        queue = read_review_queue(gw, slug)
        for q_entry in queue:
            review_items.append({
                "key": q_entry.key,
                "title": q_entry.title,
                "project_slug": q_entry.project_slug,
                "gate": q_entry.gate,
                "assurance": q_entry.assurance_label,
                "url": q_entry.issue_url,
            })

        mine = read_my_work(gw, slug, actor_id)
        for m_entry in mine:
            my_work_items.append({
                "key": m_entry.key,
                "title": m_entry.title,
                "project_slug": m_entry.project_slug,
                "state": m_entry.state,
                "relation": m_entry.relation_label,
                "url": m_entry.issue_url,
            })

        try:
            from .provenance import read_session_summaries
            sessions = read_session_summaries(gw, slug)
            session_count += len(sessions)
        except Exception:
            pass

    return {
        "review_items": review_items,
        "my_work_items": my_work_items,
        "session_count": session_count,
        "is_empty": not review_items and not my_work_items and session_count == 0,
    }
