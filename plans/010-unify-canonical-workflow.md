# Plan 010 — Unify the canonical workflow (one definition both faces register)

**Status:** Proposed 2026-06-29; §4 decisions ratified 2026-06-29 (user). Cross-repo
(regista + dossier + agent-notes). Not started — ready for WI-1.
**Author:** Opus 4.8
**Strategic role:** Close the convergence gap found when trying to prove the
end-to-end north star ("one work-item, mixed human+agent verified chain, driven
through one lifecycle by both faces"). Plans 006/007/008/023 + agent-notes Plan
010 converged the lifecycle *shape* and moved the review *validators* into regista
as built-ins — but the workflow *definition itself is still duplicated and
divergent per face*. This plan makes the canonical workflow a **single shared
artifact** both faces register verbatim, so a single work-item really is governed
by one workflow and can carry both agent and human actions.

---

## 1. The gap (what the end-to-end check surfaced)

dossier and agent-notes each register their **own** workflow into regista. They
share the state lattice and transition shape, but differ where it counts:

| | dossier face | agent-notes face |
|---|---|---|
| workflow `name` | `dossier` | `breadcrumb` |
| `version` | 4 | 2 |
| `roles` | `member`, `system` | `agent`, `human`, `system` |
| accept gate (`human_gate`) | `require_human: true` (**strict**) | `require_human: false` (**relaxed**) |
| work-item types | `bug`, `task` | `breadcrumb` |

Consequences (why the north star is not achievable as built):

- **Two named workflows in one project = two item universes.** Each face creates
  items under *its own* workflow; an agent-notes item and a dossier item are
  never the *same* item. regista keys workflows by name.
- **Disjoint roles where it matters.** dossier's workflow has no `agent` role, so
  an agent could not act on a dossier-governed item even if it were shared. (Note
  `actor_kind` — human/agent/system — *is* shared; the divergence is the workflow
  `role` vocabulary: dossier maps humans to role `member`, agent-notes to `human`.)
- **Conflicting gate policy.** The same item cannot be both strict and relaxed.
- **regista ships no canonical workflow.** Plan 023 moved the *validators*
  (`adversarial_review`, `human_gate`) into regista as built-ins, but the
  *workflow definition* stayed duplicated in each face.

**Why unit suites are green anyway:** each face tests *its own* workflow in
isolation. Nothing asserts a *shared* workflow across faces — the cross-face
integration gap is invisible to either suite alone. WI-4 below closes that.

## 2. Decision — Approach A (canonical workflow shipped from regista)

Considered:

- **A. regista ships one canonical workflow; both faces register it verbatim.**
  Single source of truth, no drift by construction, natural sequel to Plan 023
  (validators already live in regista), matches Model A (regista = authoritative
  store). **Chosen.**
- **B. Promote agent-notes' `breadcrumb` workflow as canonical; dossier adopts
  it.** Less work (breadcrumb is already near-canonical), but creates face↔face
  ownership coupling; faces should be peers over regista, not depend on each
  other. Rejected as the *home*, but its content is the best starting point (see
  §3).
- **C. No unification; dossier drives any workflow generically.** Lightest, leans
  on the "render any workflow" goal, but weakens the "one work-item universe"
  guarantee and still needs the role/gate reconciliation. Rejected.
- **D. `extends:` composition / E. vendored shared package.** Both still leave two
  named workflows or reintroduce drift. Rejected (D was already ruled out in Plan
  007 §1).

## 3. The target — one canonical workflow

A single workflow definition, **shipped from regista** and registered *verbatim*
(idempotently) by both faces. Start from agent-notes' `breadcrumb.workflow.yaml`
(already the fullest canonical lattice: all states, the two-stage gate, the
`amend` self-transitions, relaxed-default gate) and generalize:

- **name:** a neutral canonical name (e.g. `canonical`) — **not** `dossier` or
  `breadcrumb`. (See §4 decision 1.)
- **roles:** the union covering both faces. Recommended `{human, agent, system}`
  (drop `member`; dossier maps authenticated users to role `human`). This mirrors
  `actor_kind`, and distinguishing `agent` from `human` in `allowed_roles`
  matters for the cross-lineage gate. (See §4 decision 2.)
- **work-item types:** the union — `breadcrumb`, `bug`, `task` (+ room to add).
  Each face creates its own types under the one workflow.
- **states / transitions:** the canonical v4 lattice (open / in_progress /
  blocked / deferred / in_review / in_human_review / done), unchanged.
- **gate policy:** **relaxed by default** (homelab decision, agent-notes Plan 010
  §0a), `strict` registerable for a workplace deployment. One policy per
  registration — both faces must agree per project.

## 4. Decisions (ratified 2026-06-29)

1. **Canonical workflow name = `canonical`** (neutral; not `dossier`/`breadcrumb`).
   Accept the resulting agent-notes item migration (see §7 / WI-2).
2. **Role vocabulary = `{human, agent, system}`** (drop `member`; mirrors
   `actor_kind`, and the cross-lineage gate needs to distinguish agent from
   human). dossier maps authenticated users to role `human` (today: `member`).
3. **Ships from regista as a packaged YAML + accessor** —
   `regista.canonical_workflow_yaml()`. Faces register those exact bytes; no
   hand-copying.
4. **New canonical `version`** (supersedes dossier v4 / breadcrumb v2). Existing
   items keep their historical `workflow_version` (leave; do not re-point).

## 5. Work items

- **WI-1 (regista) — ship the canonical workflow.** Package one canonical
  workflow YAML + an accessor/helper so consumers register the *same* bytes.
  Wires the Plan-023 built-in validators by name. Tests: lint + a round-trip
  register. Spawns a regista plan (the Plan-023 sequel).
- **WI-2 (agent-notes) — register the canonical workflow.** Replace
  `packaged_workflow_yaml()` (`breadcrumb.workflow.yaml`) with the regista
  canonical; reconcile role vocabulary in `core/actor.py`; keep the `breadcrumb`
  work-item *type* + its custom fields. Migrate existing items if the name/version
  changes (decision 1/4).
- **WI-3 (dossier) — register the canonical workflow.** Drop the separate
  `dossier.workflow.yaml`; register regista's canonical; map authenticated users
  to role `human` (from `member`); keep `bug`/`task` types. web.py already derives
  transitions from the registered workflow, so the UI follows.
- **WI-4 (cross-face integration test) — the regression guard.** A test (home
  TBD — likely a small shared harness or dossier integration suite) that points
  *both* faces at one regista project and asserts: (a) both register the *same*
  workflow name+version without conflict; (b) an agent-created item can be driven
  to `done` with a human accept (or relaxed self-accept after a cross-lineage
  pass) — i.e. **one item, one mixed agent+human chain**. This is the test whose
  absence hid the gap.

## 6. Validation (the original end-to-end proof)

After WI-1..4, run the live proof that motivated this plan: ephemeral Postgres,
one shared regista project + hmac key, register the canonical workflow once,
`AGENT_NOTES_REGISTA_WRITES=1`; agent-notes files+works an item (agent face),
dossier accepts it (human face), and dossier's **verified-history view** renders
the single mixed human+agent chain. Then (separately, real-infra follow-up)
provision the dedicated dossier Postgres and re-confirm.

## 7. Risks & sequencing

- **Data migration.** If the canonical name/version differs from `breadcrumb`/
  `dossier`, existing items' `workflow`/`workflow_version` need handling
  (decision 1/4). Keeping the name `breadcrumb` minimizes this but muddies naming.
- **Gate-policy single-valuedness.** A project registers *one* gate policy; a
  deployment that wants strict-for-humans / relaxed-for-agents is out of scope
  (the dual-mode validator already covers the relaxed-with-cross-lineage case).
- **Sequencing:** WI-1 (regista) first and released; WI-2/WI-3 adopt it; WI-4
  lands with WI-2/WI-3 so the guard exists before this is called done. CI for
  agent-notes/dossier already installs regista from git@main, so the new
  canonical accessor is available to their CI as soon as WI-1 merges.
