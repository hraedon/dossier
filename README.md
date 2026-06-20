# dossier

The lightest human-facing **work-item tracker** that earns its keep as a
**provenance instrument**. A small team logs, assigns, and tracks issues through a
web UI; underneath, every change is a signed, hash-chained event with a real actor
(human *or* agent) attached. Each work-item accumulates a *dossier* — a tamper-
evident, human-readable record of everything that happened to it and who did it.

It is not a clean-room Jira clone. It is a thin UI + auth + workflow over
[regista](https://github.com/hraedon/regista), which already provides the
durable state, validated transitions, event history, and signing.

## Why it exists

Two real needs converge:

1. **A team tracker that doesn't depend on production infra.** The existing Jira
   is moving to the cloud; we want a self-hosted, dedicated-infra tracker the team
   controls, in the lightest form that's actually usable.
2. **Getting provenance off the ground.** In a regulated setting, agent tooling is
   blocked by audit/provenance gaps. dossier is where humans and agents act on the
   same work-items and *every* action is provably attributed and verifiable — the
   concrete artifact the provenance argument has been missing.

The bet: these aren't two projects. The identity/auth a tracker needs *is* the
root of provenance, and the activity log a tracker needs *is* the verified event
chain. Build the tracker honestly and you get the provenance for free.

## What it is (architecturally)

- **Backend: regista.** dossier owns no schema for work state. Work-items, states,
  transitions, custom fields, links, actors, claims, and the event log all live in
  regista (Postgres, schema-per-project). dossier declares a **workflow** (`src/
  dossier/workflows/dossier.workflow.yaml`) and consumes regista's facade API.
- **Front end: a server-rendered FastAPI web app** (Jinja + the
  [patina](https://github.com/hraedon/patina) design system), in the cert-watch /
  gpo-lens family style. No SPA.
- **Identity: real actors.** Humans authenticate (LDAP-pluggable, like cert-watch)
  and act as `actor_kind=human`; agents act as `actor_kind=agent` with
  `on_behalf_of` for delegation. This binding is the provenance foundation.
- **Provenance: regista's built-ins.** HMAC-SHA256 signing + per-work-item event
  hash chain are on from day one. Ed25519, RFC-3161 timestamping, and witness
  co-signing are config seams regista already exposes — deferred, not redesigned.

## Scope

**In (MVP):** projects → issues (`bug` / `task`); fixed workflow
(`open → in_progress → blocked → done`); create / view / edit / reassign /
transition; per-project list/board filtered by status and assignee; comments; and
the **verified history view** (the legible event chain with an integrity check).
An HTTP API underneath the UI so an agent client can later use the same backend.

**Out (MVP):** sprints, epics, custom workflows, custom fields beyond the few
declared, labels/components, email/notifications, cross-issue links, time tracking,
attachments, roles beyond "logged in," full-text search.

**Non-goals:** replacing regista's role as source of truth; becoming feature-parity
with Jira; depending on any production/cloud infrastructure.

## Boundary vs. siblings

- **regista** — the substrate. dossier is a *consumer* and a step toward regista's
  own stated endgame (the "federated pane-of-glass UI"). dossier adds no state
  regista doesn't own.
- **agent-notes** — the *agent* front-end onto regista work-items. dossier is the
  *human* front-end. Long-term they may front the same work-items (a single item
  showing a mixed human+agent chain — the killer provenance demo). The MVP fronts
  its **own** regista project; convergence is a deliberate later step, not drift.
- **agent-provenance** — the deeper attestation stack (DSSE/in-toto at run→PR
  grain). dossier rides regista's *built-in* provenance now and gives
  agent-provenance a real surface to grow against later.

## Status

Charter stage. Design spine in `docs/provenance-model.md`; draft regista workflow
in `src/dossier/workflows/dossier.workflow.yaml`; MVP plan in `plans/001-mvp.md`.
Needs a dedicated regista/Postgres instance. Private until a written sanitization
review (`docs/publication-review.md`).
