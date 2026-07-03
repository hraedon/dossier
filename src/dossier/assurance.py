"""Review-assurance level computation (Plan 014 WI-1.4).

The assurance level is a pure function of the signed event log — dossier
*surfaces* it, it does not recompute it. The levels are:

- ``self-reviewed``: the review verdict shares a model lineage with the
  author's events, and no human has accepted it.
- ``independently reviewed``: a cross-lineage adversarial review passed,
  but no human has accepted it.
- ``human-accepted``: a human has explicitly accepted the work (the
  ``accept`` transition by a ``human`` actor).
- ``unreviewed``: no review verdict has been issued.

Under the strict deployment gate, a same-lineage-reviewed item that reached
``done`` must have done so via human accept — so it reads ``human-accepted``,
not ``self-reviewed``.
"""

from __future__ import annotations

from regista import Event

_REVIEW_VERDICTS = frozenset({"adversarial_pass", "request_changes", "accept", "reject"})


def compute_assurance_level(events: list[Event]) -> str:
    """Compute the review-assurance level from an item's event history.

    Returns one of: ``unreviewed``, ``self-reviewed``,
    ``independently-reviewed``, ``human-accepted``.
    """
    has_human_accept = False
    has_cross_lineage_review = False
    has_same_lineage_review = False

    author_lineages: set[str] = set()
    for event in events:
        if event.transition == "created":
            meta = getattr(event, "actor_metadata", None)
            if isinstance(meta, dict) and meta.get("model_lineage"):
                author_lineages.add(str(meta["model_lineage"]))

    for event in events:
        if event.transition not in _REVIEW_VERDICTS:
            continue

        actor_kind = getattr(event, "actor_kind", "system")
        meta = getattr(event, "actor_metadata", None)
        reviewer_lineage = None
        if isinstance(meta, dict):
            reviewer_lineage = meta.get("model_lineage")

        if event.transition == "accept" and actor_kind == "human":
            has_human_accept = True
        elif event.transition in ("adversarial_pass", "accept"):
            if reviewer_lineage and reviewer_lineage in author_lineages:
                has_same_lineage_review = True
            else:
                has_cross_lineage_review = True

    if has_human_accept:
        return "human-accepted"
    if has_cross_lineage_review:
        return "independently-reviewed"
    if has_same_lineage_review:
        return "self-reviewed"
    return "unreviewed"


def assurance_label(level: str) -> str:
    """Human-readable label for an assurance level."""
    return {
        "human-accepted": "human-accepted",
        "independently-reviewed": "independently reviewed",
        "self-reviewed": "self-reviewed (same lineage)",
        "unreviewed": "unreviewed",
    }.get(level, level)


def assurance_class(level: str) -> str:
    """CSS class suffix for the assurance badge."""
    return {
        "human-accepted": "ok",
        "independently-reviewed": "ok",
        "self-reviewed": "warn",
        "unreviewed": "muted",
    }.get(level, "muted")
