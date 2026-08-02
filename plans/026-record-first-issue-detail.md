# Plan 026 — Record-first issue detail and reading measure

**Status:** In Progress — WI-1 and WI-2 implemented 2026-07-29 on
`feat/ui-visual-pass`: issue detail reordered (pagehead -> last-event ->
description -> links -> verified history -> transitions -> comment form) via
template block order only, `.ds-record-grid` 7/5 split at >=1100px with
record-first stacking below and a print reset; `.ds-prose` gains the 68ch /
fs-md / 1.65 / `--text` reading measure, chain verdicts render as prose, and
area inputs inherit the measure. Guard test
(`test_issue_detail_renders_record_before_acting_surfaces`) codifies the DOM
order; full pytest / ruff / mypy green; vision-capable adversarial review of
dark/light/390px/print before-after pairs returned GO with no findings
(evidence: `samples/plan-026/record-first/`). Human screenshot sign-off
pending. WI-3 remains gated on patina Plan 002.
**Owner:** dossier.
**Coordinates:** Plan 024 (shell contract), patina Plan 002 (quiet-tier
contrast floor, proposed).

A work-item page is a *dossier*: the signed record is the product, and acting
on the item (transition, comment) is secondary. The current detail template
renders in the opposite order — description, links, transition controls,
comment form, and only then the verified history — so the provenance core sits
below the fold on anything with a description. The 2026-07-29 visual pass made
the chain look right; this plan makes it *primary*. Both changes are dossier-
owned composition: no patina change required, no provider/action logic moves.

## WI-1 — Record-first composition

Reorder `_history.html`'s render target so the verified chain is the first
contentful block after the pagehead, with acting surfaces after it. DOM order
is reading order (screen readers, focus sequence), so the reorder happens in
markup, not via CSS visual tricks:

- issue detail renders: pagehead -> last-event line -> description -> links ->
  **verified history** -> transitions -> comment form.
- On wide viewports (>=1100px) the record and the acting rail sit side by side
  (grid, ~7/5 split): chain primary column, transitions + comment in a
  right-hand rail. Below that width it is single-column, record first.
- The transition select, review-note visibility toggle, same-lineage
  acknowledgement, and comment form keep their exact markup (golden journeys
  and review-note tests bind to it); only their placement moves.

**Contract:** all current assertions stay green — `test_shell.py` landmarks,
`test_ui.py` semantics, golden journeys. The moving parts are template block
order + two layout rules in the ds- layer. No route, view-model, or gateway
changes.

## WI-2 — Reading measure for prose

patina's instrument density (13.5px base, tight rhythm) is right for tables
and wrong for paragraphs. Give prose a proper reading measure without touching
the instrument frame:

- `.ds-prose` (descriptions, review-note/verdict rendering): `max-width: 68ch`,
  `font-size: var(--fs-md)`, `line-height: 1.65`, color `--text` (not
  `--text-2` — body text is the payload).
- Comment and description *inputs* inherit the wider measure so what you write
  resembles what you read.
- Tables, pills, chain metadata stay at instrument density.

## WI-3 — Converge on patina's quiet tier (dependency: patina Plan 002)

The visual pass moved information-bearing microcopy from `--text-3` to
`--text-2` as a local AA workaround. Once patina Plan 002 lands and is
re-synced, review each promoted class and demote anything whose intent was
decorative back to `--text-3`, so dossier returns to the shared tier ladder
instead of carrying a private one. If patina 002 is declined, the workaround
stays and this WI is cancelled by note.

## Acceptance

- Issue detail: the chain is the first contentful section after the pagehead,
  verifiable in DOM order; two-column composition at wide widths, stacked
  record-first below.
- Reading measure applied to all prose surfaces; no table/pill regression.
- Reviewer sign-off via before/after screenshots (dark, light, 390px, print)
  as in the visual-pass round.
- pytest / ruff / mypy green; golden journeys unchanged.
