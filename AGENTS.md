# AGENTS.md

Conventions for agents (and humans) working on dossier.

## What this project is

A thin human-facing web front-end (FastAPI + Jinja + patina) over
[regista](https://github.com/hraedon/regista). It is a **tracker that is also a
provenance instrument**. dossier owns the UI, auth, and a workflow definition —
**not** the work-state schema, the state machine, or the event log. Those are
regista's.

## Hard rules (the family conventions, adapted)

- **All work-state changes go through regista as signed events.** This is the
  dossier analog of "no logic in the truth path that bypasses the engine." There
  is no side-channel write to work-item state — every create, transition,
  reassignment, and comment is a regista event. If you're tempted to add a local
  table that mirrors work-item state, stop: regista's projection is the source of
  truth; dossier may *cache reads* but never *own writes*.
- **Actor binding is load-bearing — no anonymous or spoofed writes.** Every
  mutation carries a real actor: a human resolved from the authenticated session
  (`actor_kind=human`), or an agent (`actor_kind=agent`) with `on_behalf_of` set.
  The provenance is only as good as this binding; treat it as security-critical.
- **Respect regista's validated transitions and role gating.** Don't reimplement
  the workflow in dossier. The allowed transitions and who may make them are
  declared in `src/dossier/workflows/dossier.workflow.yaml` and enforced by
  regista. dossier surfaces them; it does not decide them.
- **Provenance posture: built-ins on, the rest deferred but un-blocked.** HMAC-
  SHA256 signing + per-work-item hash chain are on. Ed25519, RFC-3161 timestamping,
  and witness co-signing are regista config — leave the seams open, don't wire them
  into the MVP.
- **No work-domain identifiers in committed files.** Real project/issue/account
  data never lands in the repo. Use generic examples and fixtures; any local DB and
  any `samples/` are gitignored and never committed.

## Layout

```
src/dossier/                 the FastAPI app (app factory, routes, templates, auth)
docs/provenance-model.md     design spine: work model + provenance guarantees (the contract)
docs/publication-review.md   sanitization review; gates any push
plans/                       numbered plans, status line at top
```

## Backend dependency

regista is a sibling library (`/projects/regista`). For dev, install it editable
(`uv pip install -e ../regista`) or pin a version. dossier targets regista
`0.4.0`'s workflow schema and facade API; the workflow YAML declares its
`regista_version`. regista needs Postgres 15+; its in-memory backend is for tests
only, never for a real multi-user instance.

## Workflow

The canonical lifecycle is declared in regista's `canonical.workflow.yaml`
(shipped from regista, registered verbatim by dossier — Plan 010). Currently
**v2** (v2 added the optional `display_key` custom field; v1 had no custom
fields on `bug`/`task`). States: `open / in_progress / blocked / deferred /
in_review / in_human_review / done`. `done` is reachable **only** through the
two-stage review (`in_review → in_human_review → done`), except the pre-work
triage close (`close_from_open`). `deferred` (Plan 008) is a non-terminal idle
state distinct from `blocked` — it denotes a deliberate choice to wait with no
dependency, carries no review gate, and cannot reach `done` directly. Adding or
removing a state is a contract change: bump the workflow `version`, note it in
the YAML changelog comment, and announce it here.

## UI

Adopt the patina design system (vendored tokens + IBM Plex Mono, dark-default,
per-tool accent). dossier is part of the "instrument panel" family look; pick an
accent and a subject signature (the verified-chain view is the natural one). No
SPA — server-rendered Jinja, like cert-watch and gpo-lens.

## Decisions to surface to a human

The workflow definition (states/transitions/roles — it's the contract every
work-item is created against); the auth/identity model; **anything touching the
signing or provenance configuration**; the public API shape; releases; and the
decision to front shared (agent-touched) work-items rather than dossier's own
project.
