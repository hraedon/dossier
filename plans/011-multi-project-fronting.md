# Plan 011 — Multi-project fronting (dossier as the human SoT across all projects)

**Status:** WI-1..6 implemented 2026-07-01 (GLM-5.2). WI-7 (deploy) is infra.
**Author:** Opus 4.8
**Strategic role:** The converged store is one regista project (schema) **per
software-project** (see [[reference-production-regista-store]] / dossier Plan 010,
agent-notes Plan 011). The agent face (agent-notes CLI) now routes per-project and
is live. dossier is still **single-project** (`DOSSIER_PROJECT`), so it can only
front one schema. This plan makes dossier the **human window onto all projects'
work-items** — the human counterpart to the agent SoT — so a person sees and
drives the same per-project regista items the agents do, with cross-project
references rendered.

This is NOT tonight's MVP (tonight = agent SoT). It is the next milestone so the
human face lands on the same migrated data.

## Context / what's already true

- 16 per-project regista schemas exist on the production `regista` DB, each
  with the **canonical** workflow registered and migrated data (865+ items).
- dossier already registers the canonical workflow and maps human actors to role
  `human` (Plan 010). Its `RegistaGateway` is bound to ONE `Regista`/schema at
  construction; `web.py` derives transitions from the registered workflow.
- Slug↔schema mapping is hyphens→underscores (`agent_notes.core.face_factory.
  regista_project_name` mirrors it; dossier should have its own copy of the same
  rule, not a cross-import).

## Decisions to ratify

1. **Project in the URL** — routes become `/p/<project>/…` (issues list, item
   detail, transitions). A bare `/` is the cross-project landing.
2. **Per-project gateway cache** — mirror agent-notes Plan 011: a
   `dict[str, RegistaGateway]` keyed by schema name, built lazily. The current
   project comes from the request path, not a global env.
3. **Cross-project landing view** — aggregate open items across all schemas.
   Start with a fan-out query (N schemas, N small queries) behind a cached
   project list; optimize later if needed. No cross-schema JOINs (regista §3).
4. **Cross-project references** — render regista value-references
   (`target_project` links) as navigable links to the other project's item.
5. **Project discovery** — list schemas from the regista DB (or a registry) so
   new projects appear without redeploy. Confirm the source of truth for "which
   projects exist."
6. **Auth scoping** — which projects a user may see/act on (teams, Plan 004).
   MVP: any authenticated human sees all; tighten later.

## Work items

- **WI-1 — per-project gateway routing.** `RegistaGateway` cache keyed by schema;
  resolve the project from the request; `regista_project_name()` helper in dossier.
- **WI-2 — project-scoped routes + nav.** `/p/<project>/…` for list/detail/
  transition; project switcher in the header.
- **WI-3 — cross-project landing.** `/` aggregates open items across projects
  (fan-out + cached project list). Counts per project.
- **WI-4 — cross-project reference rendering.** Show inbound/outbound
  value-references as links across projects.
- **WI-5 — verified-history view across projects.** Ensure the subject-signature
  view works for any project's item (it already derives from workflow_version).
- **WI-6 — tests.** Two-project fixture; routing, isolation (no leakage), landing
  aggregation, cross-project link rendering.
- **WI-7 — deploy.** Point dossier at the `regista` DB (the multi-schema store),
  not a single `DOSSIER_PROJECT`; stand up the web service (its own infra step).
  **Superseded 2026-07-11 by [Plan 023](023-central-service-deployment.md)**
  (central k8s service deployment); tracked there as WI-2/WI-3.

## Out of scope / later

- Heavy aggregation optimization (materialized cross-project index) — only if
  fan-out is too slow.
- Fine-grained per-project authz beyond MVP.
- Writing NEW projects' schemas on demand from the UI (agents/CLI create them).
