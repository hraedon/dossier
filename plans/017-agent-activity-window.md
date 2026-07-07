# Plan 017 — The agent-activity window: provenance in the human face

**Status:** Proposed 2026-07-07.
**Author:** Claude (Fable 5), from the 2026-07-07 suite v2 gaps review
**Strategic role:** The suite's value proposition is "a human can see and verify
what the agents did." Today dossier renders work items, transitions, and
comments — but the layer that records what agents *actually did* (cairn's
session and tool-call attestations: which tools ran, which files were touched,
what the outputs hashed to) is invisible to a human. It lives in a separate
regista project with no surface and no cross-link from the work items humans
read. This plan gives the human face its provenance window — the feature a
regulated reviewer opens first.

## Ground truth at time of writing

- dossier's UI surface (verified 2026-07-07): landing, per-project issue
  list/detail/new, comments, transitions, search, identity/key pages, admin
  principal roster + break-glass. No session view, no tool-call trail, no
  chain-status indicator beyond per-item history.
- cairn attests into its own regista project (`session_attestation`,
  `tool_call_begin`/`end`/`fail` bound to cairn-managed work items), with
  `on_behalf_of` carrying session + principal. Work items humans track live in
  *other* projects; the ambient work_item_id binding is how the two relate.
- regista Plan 022 shipped cross-project value-refs (gated); Plan 014 gave
  dossier the multi-project window and per-project permission milestones.
- **Dependency honesty:** cairn's capture is currently broken/unwired
  (agent-provenance Plan 009). Building this window before 009's live proof
  passes means rendering an empty or wrong record. Phase 1 here can develop
  against 009's recorded fixtures, but the plan *closes* only against real
  attestations.

## Principles

- **Render the record, don't re-derive it.** Everything shown comes from signed
  regista events; the UI never synthesizes activity from side channels.
- **Verification status is a first-class UI fact.** A human should never wonder
  "is this trail complete and intact?" — the page says so, with the same
  honesty discipline as the assurance work (Plan 014 WI-1.4 / regista 027):
  verified / unverified / gap-detected are visually distinct.
- **Respect the permission milestones.** Cross-project provenance reads honor
  Plan 014's authorization seam; the provenance window must not become a
  side door around per-project permissions when they land.

---

## Phase 1 — The session and trail views

### WI-1.1 — Session list + session detail
- A per-project (and cross-project, permission-gated) list of attested agent
  sessions: harness name/version, principal (`on_behalf_of`), start/end,
  event counts, degradation flags. Session detail renders the ordered tool-call
  trail: tool, files touched, exit code, output digest (+ bytes/truncation per
  agent-provenance Plan 009 WI-1.2), timing.
- **AC:** a session recorded by cairn's live proof (009 WI-2.2) renders
  completely; a degraded session (bridge gap) shows the degradation visibly.

### WI-1.2 — Tool-call trail on the work item
- When attestations bind to an ambient work_item_id, `issue_detail` gains an
  "agent activity" section: the tool-call trail for this item, interleaved with
  the workflow history the page already shows — the mixed human+agent record
  the convergence proof demonstrated at the store level, now legible.
- Cross-project linkage (work item in project X, attestation in the provenance
  project) uses regista's cross-project value-refs; where refs are not enabled,
  fall back to a read-through by (project, work_item_id) with the linkage
  clearly labeled as a lookup, not a signed ref.
- **AC:** the work item driven by the live proof shows its agent trail inline;
  a work item with no agent activity shows nothing (no empty scaffolding).

### WI-1.3 — Files-touched index
- The audit question a reviewer actually asks: "what touched this file?"
  A search facet over attested file paths → sessions + work items that touched
  them, with links into WI-1.1/1.2 views.
- **AC:** searching a path from the live proof returns its session and work
  item; paths are rendered safely (no traversal/injection via attested strings).

## Phase 2 — Verification made visible

### WI-2.1 — Chain-health widget
- Dashboard (and per-project header) widget: chain intact as of `<timestamp>`,
  last verify run, count of verifier findings (gaps, degradations, tamper
  signals) with drill-down. Backed by stored verifier results (a `cairn verify`
  / `regista replay` run recorded as an event or cached report — decide with
  regista; do not run a full chain walk per page load).
- **AC:** after a verify run, the widget reflects it; injecting the tamper
  fixture from agent-suite's negative test flips the widget to a red state
  naming the failure.

### WI-2.2 — Verified-history stamp on the trail views
- WI-1.1/1.2 views carry the verification stamp: whether the rendered span of
  chain was covered by the last verify, and the assurance vocabulary already
  shipped (asserted vs verified lineage) extended to attestations.
- **AC:** a trail rendered from a span past the last verify shows "unverified
  since <ts>" rather than implying more than the store proves.

---

## Sequencing

Develop Phase 1 against agent-provenance Plan 009's recorded fixtures in
parallel with 009; close WI-1.1/1.2 only against the live proof. Phase 2 rides
on the verifier-report decision with regista and can land second. Plan 018
(working views + notifications) builds on this plan's pages but does not block
on it.
