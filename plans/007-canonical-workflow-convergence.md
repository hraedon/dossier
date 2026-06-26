# Plan 007 — Canonical workflow convergence: one lifecycle, lease as a separate axis

**Status:** Proposed 2026-06-26. Cross-repo (dossier + agent-notes); spawns an
agent-notes implementation plan. Builds on dossier Plan 006 (convergence, whose
P1–P3 are delivered) and the dossier v3 review-gate workflow landed this session.
Not started.
**Author:** glm-5.2 (session)
**Strategic role:** Make dossier and agent-notes two **faces of one work-item
universe** — the same regista work-items, driven through one canonical lifecycle
workflow, with agent-notes' lease semantics preserved as a separate regista axis.
This is the concrete "ingest every other project's work-items and standardize"
step: every source's items become the same regista work-items, so a single item
shows a mixed human+agent verified chain.

## 1. Decision (made this session, with rationale)

**Compose, not replace.** Per the axis separation (Opus):

- **Lifecycle** = domain state ("what state is this work in"). Human-legible.
  The shared layer. → **the dossier v3 canonical workflow.**
- **Lease** = concurrency control + liveness ("who holds it right now, are they
  alive"). Mostly machine-facing. → **regista's native claims primitive**, which
  is already orthogonal to workflow state and which agent-notes already uses
  (`acquire_claim` / `release_claim` / `heartbeat_claim`).
- **Review gate** = the dossier checkpoint. → **bolts onto the lifecycle**
  (`in_review` → `in_human_review` → `done`).

"Replace" is not simplification here — it deletes a coordination primitive
(lease) and, worse, discards attribution-grade facts (claim/heartbeat/release
intervals are exactly the mixed-chain provenance dossier wants to record).
Compose is also cheap: the lease axis is already a regista mechanism, not net-new
machinery. **regista Plan 004 (`extends:` YAML inheritance) is explicitly NOT the
tool here** — it deduplicates workflow *files*, not runtime axes; the compose is
achieved by using two orthogonal regista primitives (workflow + claims), not by
YAML inheritance.

## 2. Ground truth at time of writing

- **dossier v3 workflow** landed this session: states
  `open / in_progress / blocked / in_review / in_human_review / done`; two-stage
  review gate (`adversarial_review` validator on the `in_review` exits,
  `human_gate` on the `in_human_review` exits); cross-lineage rule +
  `same_lineage_acknowledged`; `human_gate` requires a human accepter distinct
  from every adversarial-pass identity (delegation-aware, all cycles). web.py
  derives transitions from the registered workflow (custom-workflow ready).
- **regista claims primitive** exists: `acquire_claim` / `heartbeat_claim` /
  `release_claim` — a lease layer separate from workflow state.
- **agent-notes Plan 009 (dossier 006 P1–P3) delivered** (2026-06-23):
  write-through to regista, never-fail outbox, reconcile, enforcement hooks. It
  routes claim/release/heartbeat to regista claims. Its lifecycle workflow is the
  **"breadcrumb" workflow**: `open / claimed / deferred / closed` +
  `amend_*` self-transitions. **This is the workflow that must converge.**
- **regista Plan 021** merged (this session): `ValidatorContext.on_behalf_of`,
  enabling delegated self-review rejection.
- Both faces currently target regista, but **with different workflows** — so they
  are not yet the same universe.

## 3. The target

```
agent-notes (CLI/skills/lease) ─┐
                               ├──► regista (one project, one canonical
   harness hooks ───────────────┘     lifecycle workflow + native claims)
                                              ▲
dossier (web/lifecycle/review-gate) ──────────┘
```

- **One regista project, one canonical lifecycle workflow** (dossier v3) for the
  shared universe. A breadcrumb a human files and an issue an agent works are
  the *same* work-item.
- **Lease = regista claims**, never a lifecycle state. agent-notes' breadcrumb
  `claimed` **state** is retired in favor of a regista **claim** (a lease held by
  an actor, with heartbeat liveness). "Is someone working this right now?" is
  answered by the claims layer + the projection, not by `current_state`.
- **The mixed chain is real**: a work-item's verified history shows agent
  remediation (lifecycle transitions), lease holds (claim/heartbeat/release as
  attributed events), a cross-lineage adversarial pass, and a human accept — one
  signed, hash-chained record.

## 4. State mapping — breadcrumb → canonical

agent-notes' breadcrumb lifecycle must map onto the canonical workflow. Proposed:

| breadcrumb | canonical | notes |
|---|---|---|
| `open` | `open` | direct |
| `claimed` | *(not a state)* | becomes a regista **claim**; lifecycle stays `open`/`in_progress` |
| `in-progress agent work` | `in_progress` | agent `start`s; this is the remediation phase |
| `deferred` | `blocked` *(or custom field)* | **decision** — see §7 |
| `closed` | `done` | direct (but `done` requires the review gate — see §7) |
| `amend_*` | non-state `amend` event | like `comment`: an attributed event that does not change state |

## 5. Work items

- **WI-1 — Adopt the canonical workflow in agent-notes.** Point agent-notes at
  the shared regista project; register/use the dossier v3 workflow; retire the
  breadcrumb workflow for new writes (kept read-only). Agent actors must declare
  `model_lineage` (now required by the cross-lineage rule).
- **WI-2 — Lease as claims, not state.** Ensure claim/release/heartbeat go to
  regista claims exclusively; remove breadcrumb `claimed` as a lifecycle state;
  the agent-notes projection derives "currently leased by X" from claims.
- **WI-3 — Transition vocabulary alignment.** Map agent-notes verbs (start,
  submit, close, defer, amend) onto the canonical transitions; the outbox signs
  the same payloads dossier uses (incl. `review_note`, `same_lineage_acknowledged`).
- **WI-4 — Migration:** breadcrumb items → canonical workflow, one-way,
  idempotent (via `source_identifier`), old store read-only until trust is
  established. Re-validate the chain (`replay()==0`) post-migration.
- **WI-5 — dossier renders the mixed chain.** The verified-history view already
  renders the full event log; confirm lease events (claim/heartbeat/release) and
  `amend` events render legibly alongside lifecycle + review events.
- **WI-6 — Tests:** an item filed by an agent (agent-notes path) appears in
  dossier's board; a human transitions it through the gate in dossier; the chain
  verifies and shows both actors; a lease held by the agent is visible.

## 6. Decisions to surface to a human

1. **`deferred` mapping.** breadcrumb `deferred` → canonical `blocked`, or a
   `deferred`/`triage` custom field, or a new canonical state? (Adding a state is
   a workflow-contract change — AGENTS.md.)
2. **Does agent-authored work that reaches `done` require the full review gate?**
   The canonical workflow makes `done` reachable only through
   `in_review → in_human_review → accept`. agent-notes' `close_*` breadcrumb
   transitions closed without review. **Recommend: yes — agent work must pass the
   gate; this is the whole provenance point.** But this changes agent-notes'
   close semantics and must be confirmed.
3. **One shared project vs project-per-source.** Convergence implies one project.
   If isolation is ever wanted later, regista's schema-per-project still allows a
   federation of projects behind dossier views.
4. **`model_lineage` source of truth.** Where does an agent's lineage come from
   in agent-notes — config, the harness, the actor credential? Must be
   trustworthy (the cross-lineage rule depends on it).

## 7. Sequencing / dependencies

Depends on: dossier v3 workflow (done), regista 021 (done), agent-notes 009
P1–P3 (done). No new regista core work required — claims already exist.

1. WI-1 + WI-2 (point agent-notes at the canonical workflow; lease→claims) — the
   shape change.
2. WI-3 + WI-4 (vocab alignment + migration) — the data change.
3. WI-5 + WI-6 (render + test the mixed chain) — the payoff/demo.

## 8. Risks

- **Migration fidelity** across two workflow vocabularies (breadcrumb →
  canonical); one-way, verified, old store read-only.
- **Lease/state conflation in agent-notes** — the breadcrumb `claimed` state has
  likely leaked into projection logic; demoting it to a claim is a careful
  refactor, not a rename.
- **Gate friction for agents** — if every agent close now needs a human accept,
  agent workflows that auto-close must be reworked (decision §6.2).
- **Lineage trust** — the cross-lineage guarantee is only as honest as the
  declared `model_lineage`; a spoofed/omitted lineage is the trust boundary to
  watch (the validator fails closed, but accurate declaration is an obligation).
