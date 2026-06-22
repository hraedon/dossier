from __future__ import annotations

from .actors import Actor

_TRANSITION_LABELS: dict[str, str] = {
    "created": "created",
    "start": "started",
    "block": "blocked",
    "unblock": "unblocked",
    "submit_for_review": "submitted for review",
    "request_changes": "requested changes",
    "accept": "accepted",
    "reopen": "reopened",
    "close_from_open": "closed",
    "comment": "commented",
}

_TRANSITIONS_FROM: dict[str, list[tuple[str, str, bool]]] = {
    "open": [
        ("start", "Start work", False),
        ("close_from_open", "Close (won't fix)", False),
    ],
    "in_progress": [
        ("block", "Block", False),
        ("submit_for_review", "Submit for review", False),
    ],
    "blocked": [
        ("unblock", "Unblock", False),
    ],
    "in_review": [
        ("request_changes", "Request changes", True),
        ("accept", "Accept", True),
    ],
    "done": [
        ("reopen", "Reopen", False),
    ],
}


def transitions_from(state: str) -> list[tuple[str, str, bool]]:
    """Return ``(transition_name, button_label, needs_note)`` for ``state``.

    This mirrors the workflow YAML's declared transitions; regista still
    enforces them. Kept in sync by hand.
    """
    return list(_TRANSITIONS_FROM.get(state, []))


def transition_label(transition: str) -> str:
    return _TRANSITION_LABELS.get(transition, transition)


def actor_display(event) -> str:
    meta = getattr(event, "actor_metadata", None)
    if isinstance(meta, dict) and meta.get("display_name"):
        return str(meta["display_name"])
    return str(getattr(event, "actor_id", "unknown"))


def on_behalf_display(event) -> str | None:
    delegation = getattr(event, "on_behalf_of", None)
    if not isinstance(delegation, dict):
        return None
    name = delegation.get("principal_display_name")
    if name:
        return str(name)
    pid = delegation.get("principal_id")
    return str(pid) if pid else None


def event_verdict(event) -> str | None:
    payload = getattr(event, "payload", None)
    if not isinstance(payload, dict):
        return None
    transition = getattr(event, "transition", "")
    if transition in {"accept", "request_changes"}:
        note = payload.get("review_note")
        if note:
            return str(note)
    if transition == "comment":
        body = payload.get("body")
        if body:
            return str(body)
    return None


def format_timestamp(ts) -> str:
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
        "in_review": "ds-pill--warn",
        "open": "ds-pill--muted",
    }.get(state, "ds-pill--muted")


def issue_title(issue) -> str:
    cf = getattr(issue, "custom_fields", None)
    if isinstance(cf, dict):
        return str(cf.get("title", "untitled"))
    return "untitled"


def issue_field(issue, name: str, default: str = "") -> str:
    cf = getattr(issue, "custom_fields", None)
    if isinstance(cf, dict):
        val = cf.get(name)
        return str(val) if val is not None else default
    return default


def last_event_time(issue) -> str:
    ts = getattr(issue, "last_event_at", None)
    return format_timestamp(ts)


def kind_badge(actor: Actor) -> str:
    return str(actor.actor_kind)
