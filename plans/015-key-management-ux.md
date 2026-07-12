# Plan 015 — Key-management UX (the human face of per-actor signing)

**Status:** In Progress — Phase 1 (WI-1.1 through WI-2.3) is a functional
prototype over real regista principal ops; the 2026-07-12 amendment below adds
the public custody, approval, effective-use, and Windows hardening required for
the supported v1 path.
**Author:** Claude (Fable 5), from the 2026-07-02 suite-gaps review
**Strategic role:** Per-actor Ed25519 signing (regista Plan 026) makes every write
cryptographically attributable — but keys are useless if a team can't *see and
manage* them. This plan gives the human face the key-lifecycle UX: a user sees
their own key status and requests rotation; an admin enrolls new principals,
revokes a leaver, and runs break-glass — all **without any human ever touching raw
key material.** The design principle that makes this deployable in a regulated
shop: humans authenticate (LDAP), and the private key lives in the secret backend
where a face signs on the authenticated human's behalf; the UX surfaces
*fingerprints, status, and lifecycle actions*, never secrets.

## Ground truth at time of writing

- dossier is the human face (LDAP auth, canonical workflow, the verified-history
  view). Plan 014 makes it cross-project + team-accessible.
- regista Plan 026 provides the mechanics: principal→public-key registry, per-actor
  signing, rotation/revocation, and (WI-3.3) enrollment / escrow / break-glass. A
  human's private key lives in the secret backend; **the human never handles it.**
- Multi-user (blueprint §2.6): each human has a `principal_id` from the workplace
  identity source; agents are principals too, provisioned by bootstrap.
- No UX exists for any of this — key lifecycle is CLI-only (`regista
  enroll-principal` / rotate / revoke). For a team, a CLI-only key story is a
  non-starter; the human face must carry it.

## Principles this plan must hold

- **No raw key material in the UX, ever.** The user sees a **public-key
  fingerprint**, status, dates, and buttons that trigger backend-mediated actions.
  A private key is never displayed, downloaded, or transmitted to the browser.
- **Least astonishment for non-experts.** A team member should understand "this is
  my signing identity; it's healthy; it renews on date X" without knowing what
  Ed25519 is. The UX explains consequences in plain language (the family's
  legibility rule).
- **Every lifecycle action is an attributed, signed event.** Rotation, revocation,
  enrollment, and break-glass all write signed regista events (Plan 026), and the
  UX shows that audit trail — the key history is itself part of the tamper-evident
  record.
- **Admin actions are gated and loud.** Revoking a principal or invoking
  break-glass is an elevated action behind the admin role, dual-controlled where
  Plan 026 requires it, and prominently recorded. The UX never lets a sensitive
  action happen quietly.

## 2026-07-12 v1 hardening amendment

The implemented Phase 1/2 routes are a functional prototype, not yet the
supported full-v1 custody boundary. In particular, importing
`regista._custody.store_private_key` inside the dossier process means generated
private bytes exist in the web process address space even though dossier never
receives or returns them as an application value. The stronger phrase “private
key never enters dossier's memory” is therefore a target for the provider
boundary below, not a current guarantee.

Full v1 uses the public principal-lifecycle provider from regista Plan 031.
Dossier owns authentication, authorization, preview, step-up, approval, and
status. Regista owns lifecycle validation and signed events. A custody provider
or signed Windows helper owns private-key generation and storage. The browser
receives public metadata and receipts only.

The current routes also fan enrollment/rotation/revocation across readable
projects and may partially succeed. Full v1 replaces this implicit fan-out with
an explicit operation listing every target project and a durable per-project
result. “My signing identity” becomes a project-by-project matrix rather than
stopping at the first active key.

---

## Phase 1 — The user's own key (self-service)

### WI-1.1 — "My signing identity" view
- An authenticated user sees their principal: public-key **fingerprint**, created /
  expires / rotation-due dates, current status (`active` / `rotation-due` /
  `revoked`), and a plain-language "what this is" explanation. Sourced from the
  Plan 026 registry; read-only display of public data only.
- **AC:** the view renders a user's key status from the registry; no private key
  material is present in the page or any API it calls (asserted by a test); an
  expired/rotation-due key is clearly flagged with what to do.

### WI-1.2 — Request rotation (self-service, backend-mediated)
- A "rotate my key" action that triggers regista's rotation (Plan 026 WI-3.1) via
  the backend: new keypair issued, old windowed out, a signed rotation event
  written. The user sees the new fingerprint and a confirmation; they handle no key
  material. Rate-limited / confirmed to prevent accidental churn.
- **AC:** rotation completes through the UI with the user never seeing a private
  key; a signed rotation event appears in the key history; the old key still
  verifies the user's pre-rotation events (the UI shows continuity, not a break).

### WI-1.3 — My signing history
- The user sees the events *they* signed (the per-actor attribution from Plan 026
  WI-2.2) — a legible "here's what my identity has done" record, reinforcing that
  attribution is real and reviewable.
- **AC:** the view lists the user's verified-signed events across projects they can
  read (respecting Plan 014's `can_read_project` seam); each is linked to its item;
  the list matches what `regista verify` attributes to that principal.

## Phase 2 — Admin (enrollment, revocation, break-glass)

### WI-2.1 — Principal roster + enrollment
- An admin view listing all principals (humans *and* agents) with key status, and an
  **enroll** action for a new principal (calls `regista enroll-principal`, Plan 026
  WI-3.3) — the onboarding step when a person joins or an agent is added. New
  humans are typically enrolled automatically from the identity source; the UI is
  the manual/visibility path.
- **AC:** the roster shows every principal's key status; enrolling a new principal
  issues+registers+signs via the backend and appears in the roster; agent
  principals are visible alongside humans.

### WI-2.2 — Revocation (the leaver path)
- An admin **revoke** action (Plan 026 WI-3.1): marks a principal's key revoked,
  flags post-revocation events for review, and — the leaver story — is the action
  triggered when a person is deprovisioned from the identity source. Revocation
  never invalidates the principal's correctly-signed *past* events (the audit record
  is append-only); the UI makes that distinction explicit so an admin isn't afraid
  it erases history.
- **AC:** revoke marks the key and writes a signed revocation event; the revoked
  principal can no longer sign new events; their historical events still verify and
  the UI says so; revoke is behind the admin role.

### WI-2.3 — Break-glass (emergency, dual-control, loud)
- A break-glass path (Plan 026 WI-3.3) for acting/signing when the normal identity
  source is unavailable: dual-control (two admins), a required reason, and a
  prominent, distinctly-styled record in the UI *and* a distinctly-flagged signed
  event. The UX treats break-glass as the alarm it is — never a convenience path.
- **AC:** break-glass requires two-admin confirmation + a reason; produces a
  flagged signed event visible in the key history and the item's dossier; the UI
  surfaces recent break-glass uses prominently (they should be rare and noticed).

## Sequencing & notes

- **Depends on regista Plan 026** (all the mechanics) and composes with Plan 014
  (auth, the `can_read_project` seam, the verified-history view). Phase 1 (self-
  service) can land before Phase 2 (admin) — a user seeing their own key is useful
  immediately and lower-risk than admin actions.
- **This is the "story + UX for users" the key lifecycle needed:** the operational
  *policy* (rotation cadence, leaver process timing, escrow custody) is the
  agent-suite runbook (Plan 001 WI-4.x); this plan is the *interface* that policy
  is enacted through. The two are complementary — runbook says "rotate every N
  days / revoke within H hours of departure"; this UI is where it happens and is
  seen to have happened.
- **The no-raw-key-material rule is the load-bearing design choice** — it is what
  makes per-actor signing usable by a non-cryptographer team and safe in a
  regulated setting. A test that fails if any key-management API can return private
  material is worth more here than almost anywhere.

## Phase 3 — Supported public lifecycle provider

### WI-3.1 — Replace private imports

Consume only regista Plan 031's versioned public operations for describe,
prepare, prove possession, commit, effective status, and reconcile. Remove
dossier imports of `regista._custody`, `regista._provision`, and direct manifest
mutation from production paths.

**AC:** an architecture test fails on any dossier production import from a
regista private module; provider contract fixtures cover every returned status
and error.

### WI-3.2 — Custody modes

Support three explicit modes:

- remote organizational custody (AKV/HSM or a narrow signing service);
- Windows local custody through Agent Suite Setup, generating in the target
  user's DPAPI context and returning public key + proof of possession;
- file custody for development/recovery, marked non-team and unsupported for the
  normal workplace profile.

The UI explains who can sign, where the key is usable, and what happens if the
host/backend is unavailable. It never claims non-repudiation against a
compromised signing service unless the custody authorization actually provides
that property.

### WI-3.3 — Project-scoped operation and reconciliation

Enrollment, rotation, and revocation show an exact target-project set. The
operation record holds a per-project state (`pending`, `prepared`, `committed`,
`effective`, `failed`, `repair required`) and supports idempotent retry.

**AC:** inject failure after one project commits; dossier shows the partial state,
does not summarize success, and safely converges on retry without issuing an
extra active key.

## Phase 4 — Workplace identity and protected approval

### WI-4.1 — Entra-bound human enrollment

Human enrollment selects a validated Entra identity and binds the immutable
`tid`/`oid`-derived principal identifier. Names and email addresses are display
only. Manual free-form IDs remain available only for explicitly typed agent or
service identities and require a reason.

### WI-4.2 — Step-up and immutable action digest

Enrollment outside policy, rotation, revocation, custody changes, and
break-glass bind approval to an exact digest containing actor, subject,
projects, key/custody metadata, reason, expiry, and policy version. Protected
operations require recent Plan 020 step-up.

### WI-4.3 — Genuine dual control

Replace the break-glass confirmer text field with a pending approval. A second
administrator signs in separately, performs step-up, reviews the frozen action,
and approves its digest. The initiator cannot approve, change, or execute it
after approval without invalidating that approval.

**AC:** typing another admin ID, replaying an approval, changing scope after
approval, using the same Entra identity in two sessions, and approving after
expiry all fail.

## Phase 5 — Effective-use and offboarding closure

### WI-5.1 — Prove effective signing

Registration is not “done” until the intended dossier or Windows harness client
proves it can sign a challenge with the new key and regista verifies possession.
Rotation retains old verification material and reports unreconciled clients.

### WI-5.2 — Composed offboarding

Revocation coordinates future signing denial with dossier sessions/access,
delegations, ACB capability grants, agent-wake routes, and harness overlays while
preserving historical verification. Each component returns an independent
receipt; partial offboarding is a visible repair state.

### WI-5.3 — Qualification

Qualify self-enrollment, sponsored enrollment, rotation, revocation, key loss,
backend outage, partial project failure, concurrent requests, disabled Entra
user, Windows DPAPI locality, AKV permission denial, break-glass, historical
verification, and support-bundle/page-source secret scans.
