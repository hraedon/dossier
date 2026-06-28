# Plan 008 — Add `deferred` as a first-class canonical state

**Status:** Delivered 2026-06-28. Workflow v4 registered; 93 tests pass.
Small workflow-contract change on the v3 canonical lifecycle. Companion to Plan
007 / agent-notes Plan 010.
**Author:** Opus 4.8
**Strategic role:** Resolve dossier Plan 007 §6.1 / agent-notes Plan 010 §5.1 —
how the breadcrumb `deferred` state maps onto the canonical lifecycle — by adding
`deferred` as a **first-class canonical state** rather than collapsing it into
`blocked` or hiding it in a custom field. This keeps the lifecycle legible, which
is dossier's whole subject signature.

---

## 1. Decision (made 2026-06-28)

`deferred` becomes a real state in the v4 workflow. Rationale: `deferred` (chose
to wait / triage-later) and `blocked` (cannot proceed, waiting on a dependency)
are **genuinely different facts**. dossier exists to make work history *legible*;
collapsing the two throws away signal the instrument is built to preserve. The
work to add a state is bounded (web.py already derives transitions from the
registered workflow, so the UI follows for free), so the value/cost tradeoff
favors the faithful representation.

## 2. Workflow change

Canonical v3 states today:
`open / in_progress / blocked / in_review / in_human_review / done`.

Added in v4: **`deferred`**.

Transitions (proposed — confirm in review):

- **into `deferred`:** from `open` and `in_progress` (`defer`). An actor parks an
  item they are choosing not to work now.
- **out of `deferred`:** to `open` (`resume`) and to `in_progress` (`start`). A
  deferred item re-enters the active flow.
- `deferred` is **non-terminal** and **carries no review gate** — it is an idle
  state, not a completion. It cannot transition directly to `done` (a deferred
  item must re-enter the flow and pass the gate like any other).

`deferred` is distinct from `blocked`: `blocked` denotes an external dependency
(and typically links to the blocker); `deferred` denotes a deliberate choice to
wait with no dependency implied.

## 3. Work items

- **WI-1 — Workflow definition.** Add `deferred` + the `defer`/`resume`/`start`
  transitions to the v3 canonical workflow definition. No validator on these
  transitions (idle state, no gate).
- **WI-2 — Projection / status enum.** Add `deferred` to the work-item status
  enum the projection and board render. Confirm web.py's workflow-derived
  transition list surfaces `defer`/`resume` on the right states with no code
  change (it derives from the registered workflow — verify, don't assume).
- **WI-3 — UI.** Ensure the board and the verified-history view render `deferred`
  legibly (a distinct chip from `blocked`); confirm the patina styling has a slot.
- **WI-4 — Tests.** `open`/`in_progress` → `deferred` → back; `deferred` cannot
  reach `done` directly; the state renders on the board and in history.

## 4. Sequencing & dependencies

Independent of regista Plan 023; touches only the dossier-owned workflow + UI. Can
land **before** agent-notes Plan 010 (010's WI-3 verb remap maps breadcrumb
`defer` onto this state, so this state must exist first). No regista core change
(adding a state to an existing workflow is a workflow-registry edit, not an
envelope change).

## 5. Risks

- **Contract change.** Adding a state is an AGENTS.md-level workflow-contract
  change — note it there and in the workflow's version/changelog so both faces and
  any tooling that enumerates states pick it up. Low blast radius (transitions are
  derived, not hardcoded) but must be announced, not silent.
