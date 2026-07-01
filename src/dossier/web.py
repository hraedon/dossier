from __future__ import annotations

from datetime import datetime
from typing import Any

from regista import Event, WorkItem

from .actors import Actor

_TRANSITION_LABELS: dict[str, str] = {
    "created": "created",
    "start": "started",
    "block": "blocked",
    "unblock": "unblocked",
    "defer": "deferred",
    "resume": "resumed",
    "submit_for_review": "submitted for review",
    "adversarial_pass": "adversarial review passed",
    "request_changes": "requested changes",
    "accept": "accepted",
    "reject": "rejected (send back)",
    "reopen": "reopened",
    "close_from_open": "closed",
    "comment": "commented",
}

_BUTTON_LABELS: dict[str, str] = {
    "start": "Start work",
    "block": "Block",
    "unblock": "Unblock",
    "defer": "Defer",
    "resume": "Resume",
    "submit_for_review": "Submit for review",
    "adversarial_pass": "Adversarial review passed",
    "request_changes": "Request changes",
    "accept": "Accept",
    "reject": "Rejected (send back)",
    "reopen": "Reopen",
    "close_from_open": "Close (won't fix)",
}

_REVIEW_VERDICTS = frozenset({"adversarial_pass", "request_changes", "accept", "reject"})


def transition_tuple(tdef: Any) -> tuple[str, str, bool]:
    """Return ``(name, button_label, needs_note)`` for a ``TransitionDef``.

    ``needs_note`` is True for the review-verdict transitions
    (``adversarial_pass``, ``request_changes``, ``accept``, ``reject``) and
    False otherwise. The label falls back to the transition name.
    """
    name = tdef.name
    label = _BUTTON_LABELS.get(name, name)
    needs_note = name in _REVIEW_VERDICTS
    return name, label, needs_note


def transition_label(transition: str) -> str:
    return _TRANSITION_LABELS.get(transition, transition)


def actor_display(event: Event) -> str:
    meta = getattr(event, "actor_metadata", None)
    if isinstance(meta, dict) and meta.get("display_name"):
        return str(meta["display_name"])
    return str(getattr(event, "actor_id", "unknown"))


def on_behalf_display(event: Event) -> str | None:
    delegation = getattr(event, "on_behalf_of", None)
    if not isinstance(delegation, dict):
        return None
    name = delegation.get("principal_display_name")
    if name:
        return str(name)
    pid = delegation.get("principal_id")
    return str(pid) if pid else None


def event_verdict(event: Event) -> str | None:
    payload = getattr(event, "payload", None)
    if not isinstance(payload, dict):
        return None
    transition = getattr(event, "transition", "")
    if transition in _REVIEW_VERDICTS:
        note = payload.get("review_note")
        if note:
            return str(note)
    if transition == "comment":
        body = payload.get("body")
        if body:
            return str(body)
    return None


def is_same_lineage_acknowledged(event: Event) -> bool:
    """True iff this review-verdict event carried an explicit
    ``same_lineage_acknowledged`` flag — surfaced in the verified-history view so
    a same-lineage adversarial review is never mistaken for an independent one
    (G3 legibility)."""
    payload = getattr(event, "payload", None)
    return isinstance(payload, dict) and payload.get("same_lineage_acknowledged") is True


def format_timestamp(ts: datetime | None) -> str:
    if ts is None:
        return ""
    try:
        return ts.strftime("%Y-%m-%d %H:%M")
    except AttributeError:
        return str(ts)


def status_pill_class(state: str) -> str:
    return {
        "done": "ds-pill--ok",
        "in_progress": "ds-pill--info",
        "blocked": "ds-pill--warn",
        "deferred": "ds-pill--muted",
        "in_review": "ds-pill--warn",
        "in_human_review": "ds-pill--warn",
        "open": "ds-pill--muted",
    }.get(state, "ds-pill--muted")


def issue_title(issue: WorkItem) -> str:
    cf = getattr(issue, "custom_fields", None)
    if isinstance(cf, dict):
        return str(cf.get("title", "untitled"))
    return "untitled"


def issue_field(issue: WorkItem, name: str, default: str = "") -> str:
    cf = getattr(issue, "custom_fields", None)
    if isinstance(cf, dict):
        val = cf.get(name)
        return str(val) if val is not None else default
    return default


def display_key(issue: WorkItem) -> str:
    """Return the human-friendly ``<PREFIX>-<N>`` key (e.g. ``DOSSIER-3``).

    Falls back to a truncated work-item UUID if no ``display_key`` custom field
    is present (e.g. items created before WI-006, or breadcrumb-type items
    from agent-notes that predate the field).
    """
    key = issue_field(issue, "display_key", "")
    if key:
        return key
    wid = getattr(issue, "work_item_id", None)
    if wid is not None:
        return str(wid)[:8]
    return "—"


def last_event_time(issue: WorkItem) -> str:
    ts = getattr(issue, "last_event_at", None)
    return format_timestamp(ts)


def kind_badge(actor: Actor) -> str:
    return str(actor.actor_kind)
