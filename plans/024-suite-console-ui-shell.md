# Plan 024 — Suite console and replaceable UI shell

**Status:** In Progress — Phase 0 implemented 2026-07-12: reference shell,
closed typed shell view models, semantic template macros, six-area production
navigation, compatibility Work navigation, responsive/focus foundation, and
rendered accessibility tests. Provider-backed areas remain.  
**Owner:** dossier.  
**Coordinates:** agent-suite Plan 013; dossier Plans 009, 015, and 017–023;
regista Plan 031.  
**Strategic role:** Make dossier the single coherent human surface for the full
suite while separating semantic UI contracts from a replaceable visual pass.

## 1. Decision

Dossier is promoted from a work tracker with adjacent administration pages to
the shared suite console. It renders component-owned truth through versioned
providers and delegates acting operations to those providers. It does not gain
a generic shell, SQL console, service-manager identity, secret-value editor, or
component-specific shadow databases.

The implementation begins from a deliberately replaceable shell. Phase 0 fixes:

- information architecture and route ownership;
- semantic landmarks, heading hierarchy, focus order, and keyboard behavior;
- roles, page states, status vocabulary, freshness, and provenance;
- provider/view-model boundaries;
- responsive content priority;
- stable test selectors and accessibility names.

It does **not** freeze final branding, component layout, typography, colors,
animation, illustration, or density. A later UI pass may replace every CSS rule
and template composition while preserving route/view-model/accessibility tests.

## 2. Primary navigation

| Area | Core pages | Owning providers |
|---|---|---|
| Work | dashboard, my work, review, projects, search | regista/dossier |
| Knowledge | browse, search, note detail, links, index posture | agent-notes/regista |
| Activity | sessions, tool calls, files, coverage, degradation | cairn/regista |
| Evidence | integrity, cases, exports, disclosures, verification | cairn/regista |
| Operations | estate, releases, protection, delivery, drift, capacity | agent-suite/components |
| Administration | projects, access, identities, keys, policies, integrations, changes | owning providers |

The user menu owns my identity, signing history, notification preferences,
accessibility preferences, session information, and sign-out.

Navigation visibility may be role-aware for clarity. Routes and providers must
independently authorize every read and action.

## 3. Shared page contract

Every page view model supplies:

- `area`, `title`, optional `description`, and breadcrumbs;
- authenticated actor and available areas;
- authorization decision and project/scope context;
- data source, observed time, proof/effective revision, and freshness state;
- overall status plus named findings;
- primary/secondary actions with risk and required authority;
- empty, loading, unavailable, unsupported, stale, partial, and error states;
- help/runbook link and stable correlation ID for support;
- pagination/filter state where relevant.

Templates do not inspect component internals or infer security state from the
presence of fields. Providers normalize component results into closed view-model
types; unknown enum values fail closed into an explicit `unknown` state.

## 4. Interaction rules

- Server-rendered HTML is the baseline. Progressive enhancement may improve
  filters, polling, and dialogs; core journeys work without client JavaScript.
- GET is read-only. Acting forms use POST, CSRF, optimistic concurrency, and an
  idempotency key.
- High-risk actions use a review page, not an inline confirmation dialog.
- Preview/plan and apply are distinct. Approval binds the exact action digest.
- Partial multi-provider results render per target; no green aggregate hides a
  failed target.
- Tables have a usable narrow-screen alternate representation.
- Status is expressed with icon/text and accessible names, never color alone.
- Destructive, irreversible, migration, and root-authority operations name
  consequences and recovery before execution.
- Secrets/private keys never appear in HTML, JSON, hidden inputs, browser logs,
  URLs, exports, analytics, or support bundles.

## 5. Visual skeleton

The reference under `design/ui-shell/` demonstrates:

- persistent primary navigation and a compact mobile fallback;
- role/freshness context in the header;
- a role-aware home with action queue and estate status;
- summary cards that do not hide warning/failure counts;
- a filterable list/table shape;
- explicit stale, partial, unknown, and unavailable examples;
- a side panel pattern for context/help, not secret-bearing actions;
- tokenized CSS that can be discarded without changing markup semantics.

The prototype contains synthetic placeholder data and no production template
imports. It is a behavioral reference, not a second application.

## 6. Provider seams

### Work provider

Existing dossier/regista gateway, extended with race-safe queues, assurance, and
canonical search/link models.

### Knowledge provider

Agent-notes exposes exact signed knowledge browse/search/detail/link and index
health contracts. Dossier never queries agent-notes private tables directly.
The localhost `agent-notes-web` viewer becomes development-only after parity.

### Activity/evidence provider

Cairn exposes session/tool/file summaries, coverage/degradation, verifier spans,
export planning, and report receipts. Dossier does not recompute cryptographic
verdicts in templates.

### Operations provider

Agent-suite composes component describe/doctor/lock/protection/drift/capacity
reports. Acting deployment operations are staged as signed bundles for the
Windows Setup surface rather than executed by the dossier web identity.

### Identity/key provider

Regista Plan 031 exposes public-key lifecycle operations; custody remains behind
a provider/local-helper boundary. Dossier Plan 015 owns the human journey.

### Capability and delivery providers

ACB exposes inventory/plan/effective/receipt without secrets. Agent-wake exposes
routing/delivery/dead-letter health and narrowly authorized retry. Dossier owns
human policy and preferences, not delivery implementation.

## 7. Work plan

### Phase 0 — Shell and contracts

#### WI-0.1 — Reference prototype

Land and review `design/ui-shell/` with collaborator, reviewer, operator, and
auditor walkthroughs. Record decisions in this plan; do not polish visual detail
before route/view-model agreement.

#### WI-0.2 — Typed shell view models

Add closed dataclasses/enums for navigation, freshness, status, findings,
actions, page metadata, and provider availability. Use exhaustive dispatch and
contract fixtures shared with agent-suite.

#### WI-0.3 — Template decomposition

Replace the flat `base.html` navigation with semantic shell templates/macros and
retain current routes behind compatibility links. Add skip-link, focus-visible,
active-area, user menu, flash/status region, and narrow-screen behavior.

### Phase 1 — Work and knowledge

- migrate current dashboard/review/my-work/feed/search into the shell;
- implement provider-backed knowledge browse/search/detail/link pages;
- cross-link work, knowledge, sessions, files, and evidence;
- make the standalone agent-notes viewer development-only after parity;
- add saved filters only after authorization-safe query contracts exist.

**Exit:** a Windows browser user completes work and knowledge journeys from one
URL with no component CLI or second web viewer.

### Phase 2 — Activity and evidence

- finish session/tool/file views and work-item interleaving;
- render coverage, degradation, verification span, and proof freshness;
- add file-centric investigation;
- add case-bound scope, protected disclosure, export, and offline handoff;
- make static report and print/PDF journeys first-class.

### Phase 3 — Identity, notifications, and administration

- land Entra/step-up;
- land Plan 015 supported key lifecycle;
- add notification preferences, digest preview/history, and delivery failures;
- add project/access/policy surfaces;
- implement configuration inventory, draft/diff/approval, signed deployment
  bundle, apply receipt, and drift.

### Phase 4 — Operations

- estate/profile inventory and component health;
- release/lock/proof freshness;
- backup/restore verification and scheduled protection;
- delivery/hook backlog and dead letters;
- key/anchor/certificate expiry;
- capacity/retention/archive posture;
- actionable runbook links and sanitized support export.

### Phase 5 — UI replacement pass and qualification

Invite a visual redesign only after the semantic shell and critical journeys are
stable. The replacement must pass the same route, view-model, accessibility,
authorization, screenshot/print, and golden-journey tests. No provider or action
logic may move into templates or browser JavaScript during the pass.

Qualification includes WCAG 2.2 AA, keyboard, screen reader, 200% zoom, high
contrast, reduced motion, 320 CSS-pixel viewport, print/PDF, slow network,
provider outage, long identifiers, large tables, and malicious attested strings.

## 8. Completion gate

- The six areas cover every applicable agent-suite v1 human journey.
- Dossier is the sole normal team web surface.
- Every displayed state names source and freshness.
- Every action names owner, scope, risk, required authority, and result.
- Authorization and provider operations are tested below the template layer.
- Critical journeys work without JavaScript and on supported Windows browsers.
- Replacing all visual CSS/templates does not require changing provider logic.
- No secret/private key or arbitrary host authority crosses the browser boundary.
