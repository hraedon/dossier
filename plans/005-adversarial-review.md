# Plan 005 — Adversarial review as a structural gate

**Status:** Implemented 2026-06-26 (`adversarial_review` + `human_gate` validators
landed in regista as built-ins, wired into the canonical workflow; dossier review
flow UI + review-note capture in place; separation-of-duties and agent→human
rules tested).
**Author:** Opus 4.8
**Strategic role:** Make adversarial review a **structural property of the
workflow**, not a convention people can skip. `done` is unreachable except through
`in_review`, and the review exits are gated so a review is *independent* and
*recorded*. This is the portfolio's over-claim-catching / "grade honestly, don't
glaze" discipline (agentic-onboarding, sf2 RFC-030, the independent reviews that caught
false-negatives in adcs-lens) encoded into the state machine — and, because every
transition is a signed regista event, a work-item's dossier ends up recording *who
adversarially reviewed this and what they found*.

## What "adversarial" means here

Not a rubber stamp. The reviewer's job is to **try to falsify the work** — find the
skipped tests, the unvalidated claim, the fixture-only "it works" — and a
**rejection (`request_changes`) is a first-class, expected outcome**, not an error.
Two properties make it adversarial rather than ceremonial, and both are enforced
mechanically:

1. **Separation of duties.** The actor performing `accept` or `request_changes`
   must be a *different actor* than any author of the work. Self-review is
   impossible, not merely discouraged.
2. **Agent work gets a human adversary.** If any author actor was
   `actor_kind=agent`, the reviewing actor must be `actor_kind=human`. An agent's
   work is not accepted into `done` on another agent's say-so alone. (Agent→agent
   review is allowed as an *additional* pass, never as the sole gate.)

## The `adversarial_review` validator

A regista **sync validator** (named in the workflow on both `accept` and
`request_changes`) that gates the transition transaction. It is provenance-native:
it derives "who authored this" from the work-item's own event log, which is exactly
the trustworthy record dossier already maintains.

Inputs available to the validator: the acting actor (server-resolved, never
client-supplied — Plan 002), and the work-item's event history (prior actors and
their `actor_kind`).

Logic:
- Compute `authors` = the set of actors who performed work transitions for this
  item (at minimum `start` / `submit_for_review`; conservatively, any non-review
  transition since the last `open`).
- **Reject the transition** if `acting_actor ∈ authors` (self-review).
- **Reject** if `any(a.kind == agent for a in authors)` and
  `acting_actor.kind != human` (agent work needs a human adversary).
- Otherwise allow.

Failure is a clear, surfaced error in the UI ("you can't review your own work" /
"agent-authored work needs a human reviewer"), not a silent no-op.

## Capturing the verdict (provenance)

The review outcome is the transition event itself — `accept` or `request_changes`,
carrying the reviewer (actor), timestamp, and a **required review note** in the
event payload (what was checked / what was found). This makes the verdict part of
the signed, hash-chained dossier (guarantees G1–G3). The verified-history view
(`001` WI-7) renders review verdicts distinctly — a visible "challenged by X on
<date>: <finding>".

## Interaction with team write-scoping (Plan 004)

Review is a write, so it is team-scoped: the reviewer is normally a member of the
item's owning team but ≠ the author (separation of duties within the team). Note the
tension and the option: **independent (cross-team) review is *stronger* adversarial
review.** MVP keeps review in-team with the distinct-actor rule; a later option is
to allow/require a reviewer outside the owning team for higher-assurance items.
Flagged as a decision below.

## Work items

- **WI-1 — `adversarial_review` validator:** separation-of-duties + agent→human
  rule, deriving authors from the event log; register it with regista; wire it on
  `accept` and `request_changes`.
- **WI-2 — Required review note** in the review transition payload; surfaced in the
  UI on review.
- **WI-3 — Render verdicts in the verified-history view** (challenged/accepted,
  by whom, finding) — coordinate with `001` WI-7.
- **WI-4 — UI for the review flow:** submit-for-review, the reviewer's accept /
  request-changes actions with the note, and clear validator-failure messages.
- **WI-5 — Tests (run them, watch them fail once):** self-review rejected;
  agent-authored + agent-reviewer rejected; agent-authored + human-reviewer
  accepted; distinct human reviewer accepted; rejection routes back to
  `in_progress`. These assertions are the teeth of the whole feature — a validator
  you've never seen reject is a rumor.

## Decisions to surface to a human

- **Author set definition:** just the submitter, or every actor who touched the item
  since the last `open`? (Recommend the broader set — harder to game.)
- **Independent (cross-team) review:** in-team distinct-actor only (MVP) vs
  allow/require an out-of-team reviewer for some item types.
- **Multiple reviewers / N-eyes:** single distinct reviewer (MVP) vs requiring more
  than one for high-priority items.
- Whether `reopen` from `done` should itself require review to re-close (it does —
  it routes back through `open`/`in_progress` → `in_review`, so re-closing is
  re-reviewed by construction; confirm that's intended).

## Sequencing / relationships

Depends on Plan 002 (server-resolved actors with `actor_kind` — the validator's
trust root) and the `001` workflow/gateway. Coordinates with `004` (team scoping of
the review write) and `001` WI-7 (rendering verdicts). The validator and its tests
are the core; the UI rides on `001`'s issue view.
