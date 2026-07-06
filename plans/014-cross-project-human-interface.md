# Plan 014 — The cross-project human interface (team-accessible, all projects)

**Status:** In Progress 2026-07-06 — Phase 1 (WI-1.1 through WI-2.2) implemented;
WI-1.5 (team deploy) implemented (TLS seam + reproducible compose + doctor
tls/ldap/suite_env checks); the live cross-machine TLS login is operator-gated
validation (real LDAP + real certs + the work network), like the public flip.
**Author:** Claude (Fable 5), from the 2026-07-02 agent-suite deployment review
**Strategic role:** Make dossier the interface a team member logs into and reads
the *whole estate's* work through — every project's work-items, their signed
history, and who did what — in one human-readable web UI. Plan 011 built the
multi-project *fronting* (per-project routes + a cross-project landing); Plan 012
designs the project *catalog/ownership*. This plan carries those to the actual
deliverable: **a deployed, legible, team-accessible cross-project window that is
sufficient as *the* human face of the suite.** Per the deployment decision, **v1
has no per-project permissions** — any authenticated team member can read any
project — and per-project permissions are an **explicitly scheduled** later
milestone (v1.1 seam, v1.5 enforcement — §Milestones), not an open-ended "someday."

## Ground truth at time of writing

- **Multi-project fronting is built** (Plan 011, WI-1..6, 2026-07-01): `/p/<project>/`
  routes, a per-project `RegistaGateway` cache, a **cross-project landing (`/`)**
  that fans out across schemas, and cross-project reference rendering. WI-7 (deploy)
  is infra — it lands via suite Plan 013.
- **Project discovery is the open dependency:** Plan 011 flags "confirm the source
  of truth for which projects exist"; Plan 012 (project catalog/ownership, proposed,
  not started) is that source. Until it lands, discovery is "list schemas."
- dossier authenticates via LDAP (its `DOSSIER_LDAP_*` surface) and maps humans to
  the canonical workflow role `human`; the three guarantees (attribution, integrity,
  legibility) are its reason for being.
- The production store has ~16 per-project schemas on one `regista` DB; agents
  already write to them via agent-notes. dossier fronting the *same* items is the
  mixed human+agent chain the north star promised.
- Per-actor Ed25519 signing is now v1 (regista Plan 026) — so the verified-history
  view can show *cryptographically verified* signers, not just claimed actors.

## Principles this plan must hold

- **Legibility is the product.** This is the human face; a team member who is not
  the author must be able to *read* what happened and who did it without decoding
  the schema. G3 (verified history = a legible record) is the acceptance bar, not a
  nice-to-have.
- **Read-broad in v1, permission-ready in structure.** v1 grants every
  authenticated team member read across all projects. But the code is written so the
  permission check is a **single, named seam** (one authorization function returning
  "allowed" unconditionally in v1) — so v1.1/v1.5 flip enforcement on without a
  rewrite. No scattered ad-hoc checks to retrofit later.
- **Compose-not-replace.** dossier still owns no work-state; it renders regista.
  Cross-project views are fan-out reads, never cross-schema JOINs (regista §3
  isolation).
- **Sensitive at rest / in transit.** A cross-project window is a broad view of the
  estate's work; it is served authenticated, over TLS, with the same at-rest
  discipline as the rest of the suite.

---

## Phase 1 — The cross-project window, deployable

### WI-1.1 — Project discovery + the authorization seam
- Wire project discovery to a **single source of truth** (Plan 012's catalog if
  landed; otherwise a schema-list adapter behind the same interface, so swapping to
  the catalog is transparent). Introduce **one** authorization seam —
  `can_read_project(user, project) -> bool` — called everywhere a project is listed
  or entered, returning `True` for any authenticated user in v1. **This is the
  explicit hook the per-project-permissions milestone (v1.1/v1.5) flips.**
- **AC:** new projects appear without a redeploy (discovery is dynamic); every
  project-listing and project-entering path routes through `can_read_project`
  (verified by a test that greps for direct access bypassing the seam); v1 returns
  allow-all and says so in one place.

### WI-1.2 — The cross-project dashboard (the landing a team member reads)
- Elevate the `/` landing from a fan-out list into the **readable estate view**: open
  work-items across all discoverable projects, grouped/filterable by project, status,
  assignee, and recency; each row legible (title, project, state, who-last-touched)
  and linking to the item. Empty/large-estate cases handled (pagination or sane
  caps). This is what a team member sees first and is the "does dossier serve as the
  human face" test.
- **AC:** the landing renders open items across ≥3 projects from the shared store;
  filters work; a `<script>`-bearing field is escaped (the G3 legibility view must
  be XSS-safe); large-estate rendering is bounded, not a full-table dump.

### WI-1.3 — The per-item dossier / verified-history view
- The item detail shows the **legible signed history**: each event, its verified
  signing principal (per-actor Ed25519, regista Plan 026 — "signed by X, verified"),
  timestamp, and transition, rendered for a human — the tamper-evident record that is
  dossier's whole reason for being. Mixed human+agent chains render both faces of the
  work uniformly.
- **AC:** an item's full history renders with verified signers; an unverifiable or
  unregistered-signer event is shown as such (never silently rendered as trusted);
  a human+agent mixed chain displays both; the view matches what `regista verify`
  reports for that item (no divergence between the UI and the cryptographic truth).

### WI-1.4 — Surface the review-assurance level (single-model honesty)
- Show, per item, the **assurance level** and gate rationale from regista Plan 027 —
  `self-reviewed` (same lineage as author, no human accept) vs
  `independently reviewed` (cross-lineage) vs `human-accepted` — so a reader sees
  *how much* review an item actually got, not just that it reached `done`. Under the
  strict deployment gate, a same-lineage-reviewed item that reached `done` shows it
  did so via human accept. dossier **surfaces** this; it does not recompute it (the
  level is a pure function of the signed log).
- **AC:** an item's assurance level renders and matches regista Plan 027's
  computation; a self-reviewed-then-accepted item reads `human-accepted`, not
  `independently reviewed`; the display makes a self-reviewed item visibly distinct
  from an independently-reviewed one (the whole point — the reader must not confuse
  them).

### WI-1.5 — Team deployment (accessible, authenticated, TLS)
- The deployable form (suite Plan 013 WI-2.1/4.1: container on Linux/Docker, Windows
  Service on Windows) served over TLS with LDAP auth, reachable by team members on
  the work network. Reads the shared `suite.env`; resolves secrets from the backend.
- **AC:** a team member on a second machine logs in over TLS and reads the
  cross-project view; no plaintext secret on the host; the deploy is reproducible
  from the documented step.

## Phase 2 — Legibility polish (what makes it *usable*, not just present)

### WI-2.1 — Search + cross-project navigation
- Estate-wide search (by title/id/assignee across projects) and navigable
  cross-project references (Plan 011's value-ref rendering) so a person can follow
  the work where it leads without knowing schema names.
- **AC:** search returns hits across projects; a cross-project reference is a working
  link; navigation never requires typing a schema/slug.

### WI-2.2 — Read-oriented affordances for non-authors
- The view is written for a colleague catching up, not the item's author: plain-language
  state, "what changed / who did it" summaries, and the consequence of each transition
  legible without workflow knowledge. (Mirrors the family's "write for the teammate who
  stepped away" discipline.)
- **AC:** a reviewer unfamiliar with a project can, from the UI alone, state what an
  item is, its status, and who last acted — validated with a real cross-project read.

## Milestones — where per-project permissions land (explicit, per the decision)

- **v1 (this plan):** no per-project permissions. Any authenticated team member reads
  all projects. The `can_read_project` seam (WI-1.1) exists and returns allow-all.
- **v1.1:** the **permission model seam is made real but still open** — introduce the
  project↔team/role mapping data (leaning on Plan 012's catalog + ownership) and have
  `can_read_project` *consult* it while defaulting open, plus the admin UI to view
  (not yet enforce) per-project membership. This is the "explicitly part of 1.1"
  hook: the structure ships, enforcement is one flag away.
- **v1.5:** **enforcement on** — `can_read_project` denies a team member a project
  they're not mapped to; the dashboard and item views filter accordingly; project
  owners (Plan 012) manage their project's readers. This is the "explicitly part of
  1.5" deliverable.

Naming these as scheduled milestones (not deferred vagueness) is deliberate: v1
ships flat-open *knowingly*, with the enforcement path already designed and the seam
already in the code, so turning it on is a planned increment, not a retrofit.

## Sequencing & notes

- **Depends on:** Plan 011 (done), suite Plan 013 (deploy/config/secrets), regista
  Plan 026 (per-actor signing, for WI-1.3's verified signers), and — for the cleanest
  discovery + the v1.1 permission data — Plan 012 (catalog/ownership). WI-1.1's
  discovery adapter lets Phase 1 proceed before Plan 012 fully lands.
- **The single-seam discipline (WI-1.1) is the load-bearing design choice** — it is
  what makes the "v1 flat, v1.1/v1.5 enforced" path a flag flip instead of a rewrite.
  A test that fails if any code reaches a project without going through the seam is
  worth more here than in most places.
- **This plan is what makes dossier "sufficient as the human face"** the blueprint's
  §6 target names — a team member logging in and reading the whole estate's signed
  work. Everything else in dossier's roadmap (auth ownership, knowledge entity)
  composes with it but this is the one that delivers the interface.
