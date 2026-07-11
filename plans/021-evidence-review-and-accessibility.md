# Plan 021 — Case-bound evidence review and accessible reviewer experience

**Status:** Proposed 2026-07-11.  
**Author:** GPT-5.6 Sol.  
**Depends:** Plan 017, agent-suite Plan 011, agent-provenance capture contracts,
Plan 014 project authorization, Plan 020 step-up for protected disclosure.  
**Strategic role:** Turn activity/provenance views into an investigation-quality
review workspace while making the entire human face demonstrably usable by
reviewers with different abilities and levels of technical context.

## 1. Product boundary

Dossier is the human workflow and review surface. It may show ordinary signed
session/tool metadata through its normal process. It must not become the process
that normally holds transcript escrow unwrap authority.

Sealed content from agent-suite Plan 011 is viewed only after a signed,
case-bound, dual-controlled disclosure grant. Decryption occurs in an isolated
service/credential boundary and produces a narrowly scoped case view; ordinary
dossier routes, search, caches, templates, support bundles, and administrators
cannot retrieve it.

The workspace supports evidence review, not routine employee browsing,
productivity analysis, sentiment scoring, or person-wide discovery.

## 2. Reviewer journeys

1. Understand an ordinary work item and its human/agent history without knowing
   event schemas.
2. Follow a session → tool → file → work → review chain while seeing coverage and
   verification limits.
3. Open a named incident/audit case, explain why ordinary evidence is insufficient,
   request exact sealed records/fields, and obtain independent approval.
4. Review only authorized content, annotate context, select minimum-necessary
   extracts, and export an independently verifiable packet.
5. Complete all journeys by keyboard and common assistive technology without
   losing integrity, authorization, or assurance information.

## 3. Work plan

### Phase 0 — Information architecture and research

#### WI-0.1 — Evidence vocabulary

Standardize visible terms for asserted, signed, verified, coverage gap, content
absent, sealed, held, expired, destroyed, disclosure-authorized, and unavailable.
Status cannot rely on color or icons alone.

#### WI-0.2 — Reviewer task study

Run structured walkthroughs with at least an operator, ordinary collaborator,
security/privacy reviewer, and a technically non-specialist reviewer. Record task
completion, interpretation mistakes, missing context, and minimum evidence needed;
do not record production transcripts for the study.

### Phase 1 — Investigation-quality ordinary evidence

#### WI-1.1 — Session and work timeline convergence

Finish Plan 017's session/tool/file views against live provenance fixtures. Offer
chronological and grouped projections over the same signed records, stable links,
filter state in URLs, bounded pagination, and explicit unsupported/degraded spans.

#### WI-1.2 — Verification and coverage drill-down

Show the last verifier run, covered event range, findings, adapter/version,
content-availability dimension, and why a summary verdict was assigned. Never run
an unbounded replay on page load.

#### WI-1.3 — Evidence comparison

Compare two attempts/sessions by tool classes, files, result status, coverage,
configuration, and linked reviews. Comparison is deterministic over fields; model
summaries are optional projections with source links.

### Phase 2 — Case and disclosure workflow

#### WI-2.1 — Case request and scope builder

Create a signed case with purpose, external reference, question, projects,
sessions/records/fields, time bounds, expected data class, why ordinary evidence
is insufficient, notice posture, retention/hold request, and expiry. Reject
person-wide or unbounded scopes.

#### WI-2.2 — Independent approval and step-up

Render metadata-only approval, exact scope digest, policy-required distinct roles,
conflict/separation-of-duties checks, Plan 020 step-up, expiry, revocation, and
scope-change invalidation. Approvers cannot preview sealed content.

#### WI-2.3 — Isolated review surface

Front the separately deployed disclosure service through a visibly distinct case
surface. Enforce grant on every record/view, prohibit browser persistence and
general navigation, use strict response/cache/content security headers, and emit
signed view/failure/export events. No global transcript search or embeddings.

#### WI-2.4 — Extract and evidence packet

Let reviewers select exact excerpts/fields, add contextual annotations without
altering evidence, and export a case manifest with authorization scope, content
commitments, omissions/destruction, verifier material, recipient, and handling
marking. Prefer extracts to bulk transcripts.

#### WI-2.5 — Notice, correction, and access history

Surface capture posture, policy/retention, access events, delayed-notice reason,
and affected-participant context/correction statements according to policy. This
is product capability, not a universal legal conclusion.

### Phase 3 — Accessibility and comprehensibility qualification

Target WCAG 2.2 Level AA for the supported page set. W3C defines conformance for
complete pages and recommends WCAG 2.2 as the current target:

- https://www.w3.org/TR/WCAG22/
- https://www.w3.org/WAI/standards-guidelines/wcag/

#### WI-3.1 — Semantic and keyboard baseline

Use headings/landmarks, real tables/lists/buttons, accessible names/descriptions,
skip links, visible/unobscured focus, logical order, keyboard-operable dialogs,
error summaries, status announcements, adequate target size, and no drag-only
operation. Preserve server-rendered/no-JavaScript core journeys.

#### WI-3.2 — Visual and cognitive access

Meet contrast and zoom/reflow targets; support reduced motion and forced colors;
avoid color-only meaning; provide plain-language state/consequence text,
consistent help, redundant-entry avoidance, and accessible authentication.

#### WI-3.3 — Automated and manual matrix

Run automated accessibility checks in CI, HTML validation, keyboard-only manual
journeys, screen reader checks on at least Windows and one non-Windows stack,
200%/400% zoom, narrow viewport, forced colors/high contrast, and reduced motion.
Automated success never substitutes for manual/assistive-technology evidence.

#### WI-3.4 — Reviewer comprehension qualification

Give representative reviewers golden questions: who authorized an action, what
happened, what remains unverified, why content is sealed/unavailable, who accessed
it, and what an export proves. Record anonymized task outcomes and remediate
systematic misinterpretation before claiming reviewer usability.

### Phase 4 — Operations and adversarial proof

- Qualify authorization on direct URL, search, comparison, export, browser back,
  cached response, stale/revoked grant, concurrent scope change, project ACL
  change, and case expiry.
- Prove normal dossier/web/DB/blob administrators cannot decrypt sealed evidence.
- Prove page source, logs, traces, errors, analytics, and accessibility trees do
  not expose unauthorized content.
- Publish a dated accessibility conformance report naming supported pages,
  technologies, test environments, known exceptions, and remediation owners; do
  not claim blanket compliance from an automated score.

## 4. Completion gate

An authorized reviewer can answer the golden evidence questions, complete a
case-bound disclosure/export, and independently verify the packet. An
unauthorized manager, ordinary web process, or stale grant cannot retrieve
content. Supported reviewer journeys meet the documented WCAG 2.2 AA target and
pass the manual task/assistive-technology matrix with named residual limitations.

