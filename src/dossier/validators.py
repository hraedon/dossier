from __future__ import annotations

from collections.abc import Iterable


_REVIEW_VERDICTS = frozenset({"accept", "request_changes"})


def derive_authors(prior_events: Iterable) -> tuple[set[str], set[str]]:
    """Return ``(author_ids, author_kinds)`` from a work-item's prior events.

    An "author" is any actor who performed a non-review transition on the item
    (creation, start, block/unblock, submit_for_review, reopen, close_from_open).
    Prior review verdicts (``accept``/``request_changes``) are excluded, so a
    reviewer who previously rejected work is not counted as an author and may
    re-review once the work is resubmitted. This is the broad, harder-to-game
    author set recommended in plans/005 (decision flagged there: the set is
    conservatively broad for the MVP).

    Delegation-aware: when an agent acted ``on_behalf_of`` a principal, the
    principal's id/kind are also recorded as authors — so a human who did work
    via an agent cannot then self-review that work. (The symmetric gap — an
    agent reviewing on behalf of an author — requires the reviewer's own
    ``on_behalf_of`` on ``ValidatorContext``, a regista-side extension tracked
    separately; not exploitable in the all-human MVP.)
    """
    author_ids: set[str] = set()
    author_kinds: set[str] = set()
    for event in prior_events:
        if getattr(event, "transition", None) in _REVIEW_VERDICTS:
            continue
        author_ids.add(event.actor_id)
        author_kinds.add(event.actor_kind)
        delegation = getattr(event, "on_behalf_of", None)
        if delegation:
            principal_id = delegation.get("principal_id")
            principal_kind = delegation.get("principal_kind")
            if principal_id:
                author_ids.add(principal_id)
            if principal_kind:
                author_kinds.add(principal_kind)
    return author_ids, author_kinds


class ReviewRejected(ValueError):
    """Raised by ``adversarial_review`` when the review violates a structural rule.

    Carries a ``reason`` and structured ``detail`` so callers (gateway/UI) can
    surface a precise message. regista wraps non-RegistaError exceptions from
    validators as ``VALIDATOR_FAILED``; the ``reason`` survives in that message.
    """

    def __init__(self, reason: str, detail: dict | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail or {}


def adversarial_review(ctx) -> None:
    """Structural review gate (plans/005). Runs in-transition via regista.

    Two rules, both enforced from the work-item's own signed event log:
      1. Separation of duties — the reviewer must differ from every author.
      2. Agent work needs a human adversary — if any author was an agent, the
         reviewer must be human (an agent may not alone accept agent work).
    """
    author_ids, author_kinds = derive_authors(ctx.prior_events)

    if ctx.actor_id in author_ids:
        raise ReviewRejected(
            "adversarial_review: the reviewer must differ from every actor who "
            "worked this item (self-review is not allowed)",
            detail={"actor_id": ctx.actor_id, "authors": sorted(author_ids)},
        )

    if "agent" in author_kinds and ctx.actor_kind != "human":
        raise ReviewRejected(
            "adversarial_review: agent-authored work requires a human reviewer",
            detail={
                "reviewer_kind": ctx.actor_kind,
                "author_kinds": sorted(author_kinds),
            },
        )
