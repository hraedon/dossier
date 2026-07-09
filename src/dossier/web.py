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


def link_target_url(link: Any, current_project_slug: str) -> str:
    """Build a navigable URL for a link's target work item.

    Intra-project links stay within the current project's URL space.
    Cross-project links (``target_project`` set) route to the other
    project's schema (hyphens in slugs, per :func:`multi.project_to_slug`).
    """
    target_project = getattr(link, "target_project", None)
    to_id = getattr(link, "to_work_item_id", "")
    if target_project:
        slug = target_project.replace("_", "-")
    else:
        slug = current_project_slug
    return f"/p/{slug}/issues/{to_id}"


def link_target_label(link: Any, issues_by_id: dict[str, Any] | None = None) -> str:
    """A human-readable label for a link target.

    If the target work item is in the same project and present in
    *issues_by_id*, use its display key + title; otherwise fall back to
    a truncated UUID or the target project name.
    """
    target_project = getattr(link, "target_project", None)
    to_id = getattr(link, "to_work_item_id", None)
    if target_project:
        return f"{target_project.replace('_', '-')} / {str(to_id)[:8]}"
    if issues_by_id and to_id in issues_by_id:
        issue = issues_by_id[to_id]
        return f"{display_key(issue)} — {issue_title(issue)}"
    return str(to_id)[:8] if to_id else "—"


def is_cross_project_link(link: Any) -> bool:
    return getattr(link, "target_project", None) is not None


def owner_display(entry: Any) -> str:
    """Return the owner's actor_id, or 'unassigned' if no owner set."""
    owner = getattr(entry, "owner_actor_id", None) if entry else None
    return str(owner) if owner else "unassigned"


def project_display_name(entry: Any, fallback: str) -> str:
    """Return display_name from the catalog entry, or *fallback*."""
    name = getattr(entry, "display_name", None) if entry else None
    return str(name) if name else fallback


def kind_badge(actor: Actor) -> str:
    return str(actor.actor_kind)


def state_description(state: str) -> str:
    """Plain-language description of a work-item state for non-authors (WI-2.2)."""
    return {
        "open": "not yet started",
        "in_progress": "work is underway",
        "blocked": "waiting on a dependency",
        "deferred": "deliberately set aside",
        "in_review": "awaiting review",
        "in_human_review": "awaiting human review",
        "done": "completed",
    }.get(state, state)


def harness_display(harnesses: Any) -> str:
    """Format a list of harness dicts as ``name@version`` (comma-joined)."""
    if not isinstance(harnesses, list) or not harnesses:
        return "unknown"
    parts: list[str] = []
    for h in harnesses:
        if isinstance(h, dict):
            name = h.get("name", "?")
            version = h.get("version", "?")
            parts.append(f"{name}@{version}")
    return ", ".join(parts) if parts else "unknown"


def verification_status_class(status: str) -> str:
    """CSS class for the verification-status badge (Plan 017)."""
    return {
        "verified": "ds-verify--ok",
        "gap-detected": "ds-verify--warn",
        "unverified": "ds-verify--crit",
    }.get(status, "ds-verify--muted")


def verification_status_label(status: str) -> str:
    """Human-readable label for the verification status."""
    return {
        "verified": "verified",
        "gap-detected": "gap detected",
        "unverified": "unverified",
    }.get(status, status)


def tool_call_status_class(status: str) -> str:
    return {
        "completed": "ds-pill--ok",
        "failed": "ds-pill--crit",
        "running": "ds-pill--warn",
    }.get(status, "ds-pill--muted")


def format_digest(digest: Any, alg: Any) -> str:
    """Format an output digest for display: ``alg:digest[:16]``."""
    if not digest:
        return "—"
    alg_str = str(alg) if alg else "sha256"
    digest_str = str(digest)
    short = digest_str[:16] if len(digest_str) > 16 else digest_str
    return f"{alg_str}:{short}"


def format_bytes(n: Any) -> str:
    """Format a byte count human-readably."""
    if n is None:
        return "—"
    try:
        count = int(n)
    except (ValueError, TypeError):
        return str(n)
    if count < 1024:
        return f"{count} B"
    if count < 1024 * 1024:
        return f"{count / 1024:.1f} KiB"
    return f"{count / (1024 * 1024):.1f} MiB"


def safe_path(path: Any) -> str:
    """Render an attested file path safely (no traversal/injection).

    Plan 017 WI-1.3 AC: paths are rendered safely (no traversal/injection
    via attested strings). The path is returned as-is for display (HTML
    auto-escaping handles injection); this function exists as the single
    point where path-sanitization policy can be tightened.
    """
    return str(path) if path else "—"


def session_principal_display(summary: Any) -> str:
    """Return the principal display name or ID from a SessionSummary."""
    display = getattr(summary, "principal_display_name", None)
    if display:
        return str(display)
    pid = getattr(summary, "principal_id", None)
    return str(pid) if pid else "unknown"
