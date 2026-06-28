from __future__ import annotations

from collections.abc import Iterable


# Review verdicts are never authorship. ``comment`` is also not authorship
# (it carries no work-state change) — a commenter must not become an author,
# else a stray comment blocks an otherwise-independent reviewer.
_REVIEW_VERDICTS = frozenset({"accept", "request_changes", "adversarial_pass", "reject"})
_NON_AUTHOR_TRANSITIONS = _REVIEW_VERDICTS | {"comment"}


def _event_lineage(event) -> str | None:
    meta = getattr(event, "actor_metadata", None)
    if isinstance(meta, dict):
        lineage = meta.get("model_lineage")
        if lineage:
            return str(lineage)
    return None


def derive_authors(prior_events: Iterable) -> tuple[set[str], set[str], set[str], bool]:
    """Return ``(author_ids, author_kinds, author_lineages, agent_author_undeclared)``
    from a work-item's prior events.

    An "author" is any actor who performed a non-review, non-comment transition
    on the item (creation, start, block/unblock, defer/resume, submit_for_review,
    reopen, close_from_open). Prior review verdicts and comments are excluded, so
    a reviewer who previously rejected work is not counted as an author and may
    re-review once the work is resubmitted (the broad, harder-to-game author
    set recommended in plans/005).

    Delegation-aware: when an agent acted ``on_behalf_of`` a principal, the
    principal's id/kind are also recorded as authors — so a human who did work
    via an agent cannot then self-review that work. A ``principal_lineage`` read
    from ``on_behalf_of`` (defensive; usually absent) is also included.

    ``author_lineages`` collects each author's declared ``model_lineage``; it is
    empty for human-only work. ``agent_author_undeclared`` is True iff some
    author event was an ``agent`` whose ``actor_metadata`` carried no
    ``model_lineage`` — the cross-lineage rule fails closed on this because it
    cannot prove the reviewer's lineage differs from that author's.
    """
    author_ids: set[str] = set()
    author_kinds: set[str] = set()
    author_lineages: set[str] = set()
    agent_author_undeclared = False
    for event in prior_events:
        if getattr(event, "transition", None) in _NON_AUTHOR_TRANSITIONS:
            continue
        author_ids.add(event.actor_id)
        author_kinds.add(event.actor_kind)
        lineage = _event_lineage(event)
        if lineage:
            author_lineages.add(lineage)
        elif event.actor_kind == "agent":
            agent_author_undeclared = True
        delegation = getattr(event, "on_behalf_of", None)
        if isinstance(delegation, dict):
            principal_id = delegation.get("principal_id")
            principal_kind = delegation.get("principal_kind")
            if principal_id:
                author_ids.add(principal_id)
            if principal_kind:
                author_kinds.add(principal_kind)
            principal_lineage = delegation.get("principal_lineage")
            if principal_lineage:
                author_lineages.add(str(principal_lineage))
    return author_ids, author_kinds, author_lineages, agent_author_undeclared


class ReviewRejected(ValueError):
    """Raised by review validators when a transition violates a structural rule.

    Carries a ``reason`` and structured ``detail`` so callers (gateway/UI) can
    surface a precise message. regista wraps non-RegistaError exceptions from
    validators as ``VALIDATOR_FAILED``; the ``reason`` survives in that message.
    """

    def __init__(self, reason: str, detail: dict | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail or {}


def _check_separation_of_duties(ctx, author_ids: set[str], gate: str) -> None:
    """Shared direct + delegation self-review check.

    Closes WI-004 via ``ctx.on_behalf_of`` (regista Plan 021): a reviewer acting
    on behalf of an author is a self-review.
    """
    if ctx.actor_id in author_ids:
        raise ReviewRejected(
            f"{gate}: the reviewer must differ from every actor who "
            "worked this item (self-review is not allowed)",
            detail={"actor_id": ctx.actor_id, "authors": sorted(author_ids)},
        )
    delegation = getattr(ctx, "on_behalf_of", None)
    if isinstance(delegation, dict):
        principal_id = delegation.get("principal_id")
        if principal_id and principal_id in author_ids:
            raise ReviewRejected(
                f"{gate}: a reviewer acting on behalf of an author is a "
                "self-review (delegated self-review is not allowed)",
                detail={
                    "actor_id": ctx.actor_id,
                    "principal_id": principal_id,
                    "authors": sorted(author_ids),
                },
            )


def _require_review_note(ctx, gate: str) -> None:
    """Every review verdict must carry a non-empty ``review_note`` (plans/005
    WI-2). The verdict event is the provenance record of what was checked / what
    was found; a silent verdict breaks G3 (legibility)."""
    note = (getattr(ctx, "payload", None) or {}).get("review_note")
    if not note or not str(note).strip():
        raise ReviewRejected(
            f"{gate}: a non-empty review note is required for every review verdict",
            detail={"transition": getattr(ctx, "transition_name", None)},
        )


def _adversarial_pass_identities(prior_events) -> set[str]:
    """Actor ids and delegation principal ids of *every* ``adversarial_pass``
    event on the item. Used by ``human_gate`` to enforce two-stage independence
    across all review cycles (not just the most recent pass): the same
    accountable person may not both challenge the work and finally accept it.

    Delegation-aware: an agent pass ``on_behalf_of`` a human principal counts
    that principal, so a human who directed an agent's adversarial review may not
    then accept the same item (closes the delegated two-stage bypass).
    """
    identities: set[str] = set()
    for event in prior_events:
        if getattr(event, "transition", None) != "adversarial_pass":
            continue
        aid = getattr(event, "actor_id", None)
        if aid:
            identities.add(aid)
        delegation = getattr(event, "on_behalf_of", None)
        if isinstance(delegation, dict):
            pid = delegation.get("principal_id")
            if pid:
                identities.add(pid)
    return identities


def adversarial_review(ctx) -> None:
    """Cross-lineage adversarial review gate (plans/005). Runs in-transition via
    regista on the ``in_review`` exits (``adversarial_pass``, ``request_changes``).

    Rules, all enforced from the work-item's own signed event log:
      1. Separation of duties (direct) — the reviewer must differ from every author.
      2. Separation of duties (delegation — closes WI-004) — a reviewer acting
         ``on_behalf_of`` an author is rejected.
      3. A non-empty ``review_note`` is required.
      4. Cross-lineage rule — if the reviewer is an agent and any author is an
         agent, the reviewer's model lineage must be *confirmed distinct* from
         the authors'. Distinctness is unconfirmed when the reviewer's lineage
         collides with an author's, when the reviewer's lineage is undeclared,
         or when an agent author's lineage is undeclared. In every unconfirmed
         case the transition is rejected unless the payload carries
         ``same_lineage_acknowledged is True`` — the "never silent" guarantee.
         A human reviewer (lineage None) is never blocked by this rule.
    """
    author_ids, author_kinds, author_lineages, agent_author_undeclared = derive_authors(
        ctx.prior_events
    )

    _check_separation_of_duties(ctx, author_ids, "adversarial_review")
    _require_review_note(ctx, "adversarial_review")

    reviewer_lineage = (getattr(ctx, "actor_metadata", None) or {}).get("model_lineage")
    reviewer_is_agent = ctx.actor_kind == "agent"
    agent_author = "agent" in author_kinds
    reviewer_collides = bool(reviewer_lineage) and reviewer_lineage in author_lineages
    reviewer_undeclared = reviewer_is_agent and not reviewer_lineage

    if reviewer_is_agent and agent_author and (
        reviewer_collides or reviewer_undeclared or agent_author_undeclared
    ):
        payload = getattr(ctx, "payload", None) or {}
        if payload.get("same_lineage_acknowledged") is not True:
            raise ReviewRejected(
                "adversarial_review: the reviewer's model lineage is not "
                "confirmed distinct from an author (shared lineage, undeclared "
                "reviewer lineage, or an undeclared agent author); same-lineage "
                "review requires an explicit same_lineage_acknowledged "
                "acknowledgment",
                detail={
                    "actor_id": ctx.actor_id,
                    "reviewer_lineage": reviewer_lineage,
                    "author_lineages": sorted(author_lineages),
                    "agent_author_undeclared": agent_author_undeclared,
                },
            )


def human_gate(ctx) -> None:
    """Human final-acceptance gate. Runs in-transition via regista on the
    ``in_human_review`` exits (``accept``, ``reject``).

    Rules:
      1. ``ctx.actor_kind == "human"`` — the final accountability step before
         ``done`` requires a human actor.
      2. Separation of duties (direct + delegation), same as adversarial_review.
      3. A non-empty ``review_note`` is required.
      4. Two-stage independence — for ``accept`` only, the accepter must differ
         from every actor who performed an ``adversarial_pass`` on this item
         (across all review cycles, and accounting for delegation principals), so
         the adversarial pass and the final acceptance cannot collapse to one
         accountable person.
    """
    if ctx.actor_kind != "human":
        raise ReviewRejected(
            "human_gate: final acceptance requires a human actor",
            detail={"actor_id": ctx.actor_id, "actor_kind": ctx.actor_kind},
        )

    author_ids, _author_kinds, _author_lineages, _undeclared = derive_authors(
        ctx.prior_events
    )
    _check_separation_of_duties(ctx, author_ids, "human_gate")
    _require_review_note(ctx, "human_gate")

    if getattr(ctx, "transition_name", None) == "accept":
        pass_ids = _adversarial_pass_identities(ctx.prior_events)
        delegation = getattr(ctx, "on_behalf_of", None)
        acceptor_principal = (
            delegation.get("principal_id") if isinstance(delegation, dict) else None
        )
        if ctx.actor_id in pass_ids or (acceptor_principal and acceptor_principal in pass_ids):
            raise ReviewRejected(
                "human_gate: the final accepter must differ from every actor who "
                "performed an adversarial pass on this item (two-stage independence "
                "across review cycles and delegation)",
                detail={
                    "actor_id": ctx.actor_id,
                    "adversarial_pass_identities": sorted(pass_ids),
                },
            )
