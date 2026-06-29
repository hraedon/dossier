# Plan 012 — Project ownership

**Status:** Proposed 2026-06-29. Not started — for team execution.
**Author:** Opus 4.8
**Strategic role:** Give every regista project (schema) an accountable **owner**
— the responsible human for that body of work — recorded authoritatively and
surfaced in the human face. This is the *project-level* counterpart to Plan 004's
*work-item-level* team ownership: 004 decides who may write an item within a
project; 012 decides who owns the project itself (and, later, who may administer
it — archive, rename, manage its team mappings).

## Ground truth at time of writing

- A regista **project is a Postgres schema** (`_connection.py`, search_path-scoped).
  There is **no central catalog** and **no owner field**: `create_project(dsn,
  project, hmac_key_path, …)` (`__init__.py`) takes no owner and records no
  registry row. Projects are discovered today only by listing schemas.
- `actor_roles` is a **per-schema** table holding `(actor_id, role)`, where `role`
  is a **workflow** role consumed by the transition gate
  (`check_actor_role_authorized`). The canonical workflow's `allowed_roles` are
  `{human, agent, system}` — these are *transition* roles, not administrative ones.
- **Plan 011 (multi-project fronting) already needs this.** Its WI on project
  discovery flags an open question verbatim: "list schemas from the regista DB (or
  a registry) so new projects appear without redeploy. **Confirm the source of
  truth for which projects exist.**" A project catalog *is* that source of truth.
- The production store is one `regista` DB on postgres-host with ~16 per-project
  schemas (`reference-production-regista-store`).

## The central decision: where ownership lives

Three candidates were weighed; this plan **recommends Option B** and surfaces the
fork for a human to ratify.

- **Option A — an `"owner"` entry in the project's `actor_roles`.** Cheapest (no
  schema change), but **conflates two role taxonomies**: `actor_roles` feeds the
  workflow transition gate with `{human, agent, system}`; "owner" is an
  administrative role, not a transition role. Muddying that table risks the gate.
  *Rejected* for that conflation.
- **Option B — a `projects` catalog in a shared schema (recommended).** A small
  registry: `(schema_name PK, display_name, owner_actor_id, created_by,
  created_at)`. **Kills two birds:** it makes ownership authoritative *and* answers
  Plan 011's "source of truth for which projects exist." Keeps the administrative
  taxonomy cleanly separate from workflow roles. Cost: it is **cross-project state
  in a shared (public) schema**, which softens regista's §3 isolation tenet — the
  same softening Plan 022 already accepted for cross-project value-refs, so there
  is precedent and a review path. This is a **regista-side decision and change.**
- **Option C — a dossier-owned `projects` table.** dossier is the admin surface, so
  this is tempting, but it puts authoritative ownership *outside* the converged
  store — the agent face (agent-notes) would not see it, breaking the
  one-authoritative-store model (dossier Plan 006 / `reference-production-regista-store`).
  *Rejected* on convergence grounds; ownership is provenance-relevant and belongs
  in regista.

## Principles this plan must hold

- **Ownership is authoritative, so it lives in regista**, not in a face. Both faces
  (dossier human, agent-notes agent) read the same registry.
- **Keep administrative roles distinct from workflow roles.** Do not overload
  `actor_roles`; the transition gate must keep its `{human, agent, system}`
  semantics untouched.
- **Owner is `actor_id`, keyed on the same durable id as everything else** (the
  `Principal.stable_id` → `objectGUID`/uuid/`oid` chain). Ownership survives
  directory churn for the same reason attribution does (002 G1, 003).
- **MVP is descriptive, not yet enforcing.** Record + surface the owner first;
  enforcing "owner-only" admin actions is a later, separable work item so the
  feature lands without first settling the full admin-action surface.

## Design

**Catalog (regista).** Add a `projects` table in a shared schema with
`schema_name` (PK), `display_name`, `owner_actor_id` (nullable until assigned),
`created_by`, `created_at`. `create_project(...)` gains optional `owner` /
`display_name` and writes the row; existing callers keep working (owner nullable).
New API: `register_project_metadata` / `set_project_owner` / `list_projects` /
`get_project`. `list_projects` becomes the discovery source Plan 011 WI consumes.

**Backfill.** A one-shot to populate the catalog from the ~16 existing schemas
(owner left null → "unassigned", surfaced for triage). Mirrors the migration
discipline already used for the 865-item move.

**Surface (dossier).** Show the owner on the cross-project landing (Plan 011 `/`)
and per-project header; an "unassigned owner" affordance prompts assignment. An
admin can set/change the owner (a write that, in MVP, any authenticated human may
perform; gated to current-owner/admin in the enforcement WI).

**Agent face (agent-notes).** Read-only consumption — `list_projects` for routing
/ display. No write path needed for ownership from the agent side in MVP.

## Work items

- **WI-1 — `projects` catalog (regista).** Table + migration in the shared schema;
  `register_project_metadata` / `set_project_owner` / `list_projects` /
  `get_project`. **Regista-side; gated on ratifying Option B and the §3 softening.**
- **WI-2 — `create_project` writes the row.** Optional `owner` / `display_name`
  params; backward-compatible (owner nullable). Existing tests unchanged.
- **WI-3 — Backfill the catalog** from existing schemas; owner null = unassigned.
- **WI-4 — dossier surfaces ownership** on the landing + project header; unassigned
  affordance; set/change-owner form (unenforced in MVP).
- **WI-5 — Plan 011 discovery uses `list_projects`** as the source of truth (closes
  that open question; coordinate so 011 and 012 don't build two registries).
- **WI-6 — (later, separable) Owner-only admin enforcement.** Gate project-admin
  actions (archive/rename/manage team mappings) to the owner; define the admin
  action surface here, not in MVP.
- **WI-7 — Tests.** Catalog CRUD; `create_project` backward-compat; backfill
  idempotence; dossier owner display + unassigned path; `list_projects` discovery.

## Decisions to surface to a human

1. **Ratify Option B** (regista `projects` catalog) and the **§3 isolation
   softening** for a shared-schema registry — adversarial-review gated, as Plan 022
   was.
2. **Single owner vs small owner set** per project (recommend single `owner_actor_id`
   for MVP; a set is a later generalization).
3. **What ownership *enforces*** beyond legibility, and when (WI-6) — keep MVP
   descriptive.
4. **Catalog vs schema-list as discovery truth** — coordinate with Plan 011 so
   there is exactly one registry.

## Sequencing / relationships

- **Regista-side first** (WI-1/2): the catalog is a regista change and a §3
  decision; nothing in dossier can surface ownership until it exists.
- **Strong synergy with Plan 011** — the catalog is also 011's project-discovery
  source of truth; build them together to avoid two registries.
- **Distinct from Plan 004** — 004 is team write-scope *within* a project; 012 is
  ownership *of* a project. They compose (an owner is not automatically a team) and
  do not block each other.
- **Independent of Plan 003/Entra** — ownership keys on `actor_id`, which any auth
  backend already produces.
