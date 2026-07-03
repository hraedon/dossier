# Plan 013 — Suite cohesion: the human face, deployable

**Status:** Proposed 2026-07-02
**Author:** Claude (Fable 5), from the 2026-07-02 agent-suite deployment review
**Strategic role:** dossier is the suite's human face. For the suite to deploy as
a suite, dossier must stop being configured in its own private vocabulary and
instead read the shared suite config, package as a drop-in container, and report
its health in the common shape. See `/projects/agent-suite-blueprint.md` (Phase B).
This is deployment-cohesion work; dossier's product roadmap (auth ownership,
multi-project fronting) is unaffected.

## Ground truth at time of writing

- dossier is private (`hraedon/dossier`), CI green on 3.13/3.14, built on regista
  (thin FastAPI + patina UI + auth + regista workflow; owns no work-state schema).
  Plan 011 (multi-project fronting) shipped; a `plan/auth-ownership-planning`
  branch is in flight (Plan 012 project-ownership).
- dossier already ships a `docker-compose.yml` — so it is the *closest* of the
  faces to a container deployment.
- Config uses dossier-private var names: `DOSSIER_DATABASE_URL`,
  `DOSSIER_HMAC_KEY_PATH`, `DOSSIER_PROJECT`/`DOSSIER_PROJECTS`, plus its own
  `DOSSIER_LDAP_*` auth surface. None of these read the shared suite config.
- The three guarantees (attribution, integrity, legibility) are the audit story
  the suite sells; dossier is where a human *sees* it.

## Principles this plan must hold

- **Compose-not-replace, still.** dossier remains a thin face over regista; this
  plan adds config/packaging/health surface, not work-state logic.
- **Adopt the contract, keep a bridge.** Read the canonical `REGISTA_DSN` /
  `REGISTA_KEY_PATH` (regista Plan 025 WI-1.1); keep `DOSSIER_DATABASE_URL` /
  `DOSSIER_HMAC_KEY_PATH` as back-compat aliases for one release, warned as
  deprecated. dossier-specific concerns (auth, LDAP, sessions) keep their
  `DOSSIER_*` names — only the shared-with-the-spine facts converge.
- **Sensitive at rest.** Session secrets, LDAP bind creds, and the signing key
  never land in a committed file; the container reads them from the suite config /
  secret store at runtime.

---

## Phase 1 — Adopt the suite config contract

### WI-1.1 — Read canonical `REGISTA_*` with aliased fallback
- Resolve the store DSN and signing key via the suite precedence (process env →
  `$AGENT_SUITE_CONFIG` → default), preferring `REGISTA_DSN`/`REGISTA_KEY_PATH`
  and falling back to `DOSSIER_DATABASE_URL`/`DOSSIER_HMAC_KEY_PATH` with a
  one-line deprecation warning. `DOSSIER_PROJECT`/`DOSSIER_PROJECTS` remain
  (the per-tool slug convention).
- **AC:** dossier boots reading only `suite.env` (no `DOSSIER_DATABASE_URL` set);
  the legacy var still works and warns; precedence tests cover the overlap; no
  behavior change when only legacy vars are present.

## Phase 2 — Packaging as a suite component

### WI-2.1 — Container image + pinned regista
- A published (ghcr) image built from a pinned regista SHA (not `@main`) so the
  face and the spine version are a known-good pair recorded in `SUITE.lock`. The
  existing `docker-compose.yml` becomes the *local-dev* form; the image is the
  deployable artifact. Substrate-agnostic (runs under compose or k8s per the
  operator's decision — blueprint §3.1).
- **AC:** the image starts against an external Postgres with only `suite.env`
  mounted; the regista pin is explicit and matches what `SUITE.lock` records; the
  image carries no baked secret.

### WI-2.2 — Idempotent install/first-run
- dossier's first run against a freshly `regista provision`-ed project is
  well-defined: it assumes the schema/keys exist (created by `regista provision`,
  bootstrap step 2) and fails with a clear "run `regista provision --project
  <slug>` first" message if they don't — it does not silently create its own.
- **AC:** first run against a provisioned project works; against an unprovisioned
  one it exits with the actionable message, not a stack trace.

## Phase 3 — Health contract

### WI-3.1 — `dossier doctor --json` (+ a `/healthz`)
- Conform to regista Plan 025 WI-3.1's shape: `{component:"dossier", version,
  regista:{reachable, project, chain_ok}, checks:[auth backend reachable, LDAP
  bind if configured, session secret present, …]}`. Expose the same as an HTTP
  `/healthz` for the container orchestrator.
- **AC:** `doctor --json` validates against the suite shape; `/healthz` returns
  the same health; an unreachable regista or LDAP is a named `checks` failure, not
  a 500.

## Phase 4 — Cross-platform, secrets, multi-user, publication

### WI-4.1 — Resolve secrets through the backend; Windows Service packaging
- Resolve the DSN password and `REGISTA_KEY_PATH` via `regista.secrets.resolve`
  (Plan 025 WI-1.2) so dossier reads from Vault/AKV/Windows, never a plaintext
  file. Ship, alongside the container image (WI-2.1), a **Windows Service** install
  (the uvicorn app under a service wrapper) for Windows hosts — blueprint substrate
  decision (Linux/Docker/Windows, no k8s).
- **AC:** dossier boots with the signing key sourced from each backend (per-backend
  gated tests); the Windows Service install runs the app and survives a host
  reboot; no plaintext secret on disk in either path.

### WI-4.2 — One identity source + per-user config (the multi-user keystone)
- dossier is the reference for the suite's identity binding (blueprint §2.6): its
  existing `DOSSIER_LDAP_*` auth becomes the documented one-workplace-identity
  source that stamps each write's `principal_id`. Honor per-user config layering so
  multiple humans share one dossier/regista with distinct attributed identities.
- **AC:** two different authenticated users' writes carry distinct `principal_id`s
  against the same shared project; the identity binding is documented as the source
  the other faces adopt; per-user config overlay resolves correctly.

### WI-4.3 — Publication gate (sanitize before flipping public)
- Before dossier flips public (blueprint §3): filter-repo scrub for work-domain
  identifiers/secrets, add the CI identifier-gate, and complete a
  `docs/publication-review.md` checklist — the discipline the AD-lens tools used.
  Note: a prior GitGuardian alert on `session_secret="test-session-secret-not-for-prod"`
  is a known false positive (a test constant), not a leak.
- **AC:** history is clean of work-domain identifiers (verified); the identifier
  gate is green; the publication checklist is complete before the flip.

## Sequencing & notes

- Depends on regista Plan 025 WI-1.1 (config), WI-1.2 (secrets), WI-2.1
  (`provision` + service role).
- dossier is the *reference* for the other face's adoption — it already has a
  container and multi-project fronting, so land its config adoption first and let
  agent-notes mirror the pattern.
- The in-flight auth-ownership work (Plan 012) is orthogonal and can proceed in
  parallel; if it changes auth env names, keep them in the `DOSSIER_*` namespace
  (auth is dossier's own concern, not a shared-spine fact).
