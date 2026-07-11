# Plan 022 — Safe web administration for the suite's human face

**Status:** Proposed 2026-07-11.  
**Author:** GPT-5.6 Sol.  
**Depends:** Plans 014, 015, 019, 020, 021; agent-suite composition contracts;
regista generic signed entities and policy packs.  
**Strategic role:** Make practically configurable product policy manageable from
the web while preserving secret custody, deployment reproducibility, separation
of duties, rollback, and the suite's “thin orchestration, no bespoke control
plane” boundary.

## 1. Product decision

Add a versioned administration workspace that can inventory effective
configuration, draft/validate/diff/approve safe changes, apply runtime policy,
and produce signed deployment bundles for settings that require agent-suite or an
operator.

“Configure everything” does **not** mean a browser shell, arbitrary environment
editor, secret-value form, database console, service manager, or remote fleet
control plane. Every field has a schema, owner, sensitivity, apply mechanism,
restart/degradation semantics, and evidence contract.

## 2. Configuration classes

### Class A — Web-manageable runtime policy

Manage as signed, versioned desired state with direct supported APIs:

- projects: display metadata, ownership, archival posture, policy-pack binding;
- project access grants, explicit authenticated-public status, and admin grants;
- notification event policy, target mappings, preferences, quiet hours, digest
  cadence, and privacy-safe template selection;
- reviewer/approval roles, separation-of-duties, step-up requirements, case types,
  evidence scope/retention/notice policy;
- UI defaults, time zone, pagination, terminology/help, accessibility preferences;
- supported harness/capture posture display and ordinary evidence retention where
  the owning component exposes a contract;
- claims-ledger/control mappings and scheduled verification policy when available.

### Class B — Web-staged deployment configuration

Draft and approve in the web, but apply through a signed bundle consumed by
`agent-suite` or a narrow local helper:

- enabled suite profile/components/harness adapters;
- component endpoints, project registry, notification worker/scheduler units;
- OIDC/LDAP non-secret metadata and provider selection;
- secret **references**, escrow/blob backend identifiers, backup/retention
  schedule, verifier cadence, and supported integration configuration;
- settings requiring service restart, migration, or cross-component lock update.

The web reports “approved, awaiting operator apply,” then imports an authenticated
apply receipt and effective-state probe. It does not report success because a
file was downloaded.

### Class C — Bootstrap-owned, read-only posture

Display redacted source/status and remediation guidance, but do not edit:

- database DSN/credentials, schema/service roles, and initial project creation;
- session-signing secret and first/root administrator;
- TLS private key/certificate binding and listen address/port;
- secret-backend root authentication, escrow master keys, private signing keys;
- filesystem/service-account identity, executable paths, and OS service manager;
- disaster-recovery root material and break-glass bootstrap.

Changing these remains an explicit deployment operation because a broken web
change could remove the only path capable of repairing itself.

### Class D — Permanently prohibited

- raw secret/private-key entry, display, download, copy, or browser round trip;
- arbitrary env vars, command lines, SQL, Python, templates, URLs without a typed
  integration schema, or filesystem paths outside allowlisted field contracts;
- disabling audit/access controls through an unreviewed “advanced” toggle;
- silent bulk edits, wildcard target principals, or model-generated apply actions;
- editing historical events/effective revisions in place.

## 3. Configuration architecture

```text
web draft -> schema + semantic validation -> deterministic diff/risk
         -> independent approval + optional step-up
         -> signed desired revision
              | runtime-safe apply -> owning component API -> receipt/probe
              | deployment apply   -> signed bundle -> agent-suite/operator
         -> effective-state report + drift -> signed apply result
```

The canonical record is a generic signed configuration revision in regista, not
a dossier-owned settings database. Secret refs are opaque typed values. Effective
state is a projection from component reports and apply receipts. Historical
revisions remain immutable.

Each field records:

- schema/version and owning component;
- desired value or redacted ref, source, and scope;
- sensitivity/risk class and required approver roles;
- runtime/restart/migration/irreversible semantics;
- validation and preflight results;
- author, approvers, step-up evidence, timestamps, and reason;
- prior/new revision digests, apply receipt, effective probe, and rollback link.

## 4. Work plan

### Phase 0 — Inventory and contracts

#### WI-0.1 — Configuration registry

Inventory every current environment variable, config file, CLI option, policy,
secret ref, scheduled unit, and component integration. Assign Class A–D, owner,
schema, default, sensitivity, apply mechanism, restart need, doctor evidence, and
web eligibility. CI fails when a new setting lacks registry metadata.

#### WI-0.2 — Signed revision schema

Define draft, proposed, approved, applying, effective, drifted, failed,
superseded, and rolled-back states with optimistic concurrency and immutable
revision digests. Unknown fields/versions fail closed.

#### WI-0.3 — Provider protocol

Each owning component exposes deterministic `describe`, `validate`, `plan`,
`apply` (only where safe), `effective`, and `rollback` capabilities. Dossier
renders/composes; it does not reimplement secret, scheduler, auth, provenance, or
deployment logic.

### Phase 1 — Read-only administration inventory

#### WI-1.1 — Effective configuration dashboard

Show desired/effective/source/drift/restart/health for all registered settings,
redacting sensitive refs appropriately. Distinguish absent, inherited, defaulted,
unreachable, unsupported, and unknown—not just configured/unconfigured.

#### WI-1.2 — Explain and export

Every field has purpose, consequence, owning component, docs, and change path.
Export a secret-free effective report and machine-readable registry for review.

**AC:** a support bundle or page source contains no DSN password, secret value,
private key, token, auth header, or hidden form field carrying one.

### Phase 2 — Draft, validate, approve

#### WI-2.1 — Typed editors

Build server-rendered editors from reviewed schemas, with domain validation,
cross-field semantics, previews, accessible errors, and no generic key/value
escape hatch. Validate redirect origins, URLs/SSRF boundaries, identifier formats,
retention/cadence, target allowlists, and secret-ref schemes.

#### WI-2.2 — Deterministic diff and impact

Show exact old/new values (redacted as needed), affected projects/components,
restart/migration/lockout risk, policy/claim impact, and positive/negative
preflight results. Models may explain a diff but cannot decide validity or risk.

#### WI-2.3 — Approval and step-up

Low-risk personal preferences may self-apply. Project policy requires owner/admin
authority. Auth, ACL, evidence access/retention, secrets refs, signing/key policy,
and deployment changes require distinct approver(s) and Plan 020 step-up. Approval
binds the exact revision digest; edits invalidate it.

### Phase 3 — Safe runtime apply

#### WI-3.1 — Runtime providers

Apply Class A revisions through owning component contracts with idempotency,
compare-and-swap, receipt, and effective probe. Partial multi-component applies
enter a named degraded state with compensation/roll-forward guidance; they are
never summarized as success.

#### WI-3.2 — Lockout prevention

Auth/ACL/admin changes run a policy simulation against the current actor, at least
one independent repair principal, current projects, and protected operations.
Use staged activation with a short rollback window and a bootstrap-owned recovery
path. No revision may remove every administrator or every repair route.

#### WI-3.3 — Rollback

Rollback creates a new signed revision to a previously validated value; it never
deletes history. Irreversible/migration settings expose roll-forward or restore
procedures instead of a fake rollback button.

### Phase 4 — Deployment bundle and apply receipts

#### WI-4.1 — Agent-suite handoff

Produce a signed, secret-free desired-config bundle with pinned schema/component
versions and exact planned operations. The operator runs an agent-suite dry-run
and apply outside the web process; a future helper must expose only allowlisted
operations and a dedicated least-privilege identity—never a shell.

#### WI-4.2 — Receipt and drift loop

Import signed apply receipts, restart/migration results, component doctor output,
and effective config digests. Highlight approved-but-unapplied, partially applied,
drifted, unsupported, and stale states. Reconciliation proposes work; it does not
silently overwrite operators.

### Phase 5 — Administration UX and operations

- searchable settings by job/component/risk rather than raw env-var names;
- pending approvals, scheduled changes, maintenance windows, and rollback queue;
- configuration audit history linked to incidents/work/evidence;
- accessible WCAG 2.2 AA editor/diff/approval journeys under Plan 021;
- backup/restore and migration of signed desired revisions;
- doctor checks for provider availability, stuck applies, drift, expiring refs,
  orphan drafts, missing repair principal, and unacknowledged failures;
- rate limits, CSRF, CSP, no-store responses, request-size bounds, and adversarial
  tests for mass assignment, parameter pollution, stale forms, confused deputy,
  SSRF, XSS, secret reflection, approval replay, and concurrent apply.

## 5. Initial configuration coverage target

The first supported release should cover:

1. project metadata/ownership and Plan 014 ACL policy;
2. Plan 019 notification policy, targets, preferences, and digest cadence;
3. Plan 020 non-secret identity metadata and step-up mappings;
4. Plan 021 case/approval/retention/notice policy (not content access itself);
5. Plan 015 key lifecycle policy and roster actions;
6. capture/evidence posture display, with deployment apply delegated;
7. schedule/doctor/backup posture display and signed agent-suite handoff.

Only after these providers pass qualification should the registry expand. Coverage
is measured by explicit registry entries, not a claim that every environment
variable has a form.

## 6. Completion gate

An authorized operator can understand effective configuration, safely change the
initial coverage set through draft/diff/approval/apply, recover from a rejected or
partial change, and independently verify who approved and what became effective.
No browser/web process handles secret values or arbitrary host authority; a
compromised ordinary dossier process cannot mutate bootstrap roots or turn the UI
into a fleet control plane.
