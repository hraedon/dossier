# Plan 019 — Durable human notifications and scheduled digests

**Status:** Proposed 2026-07-11.  
**Author:** GPT-5.6 Sol.  
**Depends:** Plan 018, agent-wake Plan 005, regista hook-lease contract.  
**Strategic role:** Make review and operational notifications reliable enough to
be part of the workflow rather than a best-effort side effect of an HTTP request.
Complete Plan 018's digest story without adding a dossier-owned work database or
turning dossier into a mail service.

## 1. Problem and decision

Dossier now emits authenticated, idempotent agent-wake envelopes, but emission
happens after a signed transition in the web process. A crash between transition
commit and webhook POST can lose the notification; a transient wake outage can
lose it after one attempt. The workflow remains correct, but a strict review gate
can stall silently.

The durable design is:

1. the signed regista transition remains the source event;
2. regista's transactionally populated hook queue is the durable trigger;
3. a separately runnable dossier notification worker claims leased hooks and
   derives a deterministic notification intent;
4. agent-wake owns channel delivery, retries, and human routing;
5. intent and terminal delivery state are recorded as signed evidence without
   making delivery success part of work-state truth;
6. duplicates are expected and harmless through stable idempotency keys.

The web request never rolls back a valid work transition because email or a
webhook is unavailable.

## 2. Guarantees and non-guarantees

The subsystem guarantees at-least-once dispatch intent after a committed source
event, bounded retry, deterministic recipient selection, durable dead-letter
visibility, and replay-safe idempotency.

It does not claim exactly-once human receipt, that a person read the message, or
that an external mail/chat provider retained it. Those require channel receipts
with their own stated semantics.

## 3. Notification intent contract

An intent contains only:

- source event, project, work item, and transition identifiers;
- event class and policy version;
- target principal, derived reason, priority, and delivery class;
- deep-link route, not embedded sensitive work content by default;
- stable idempotency key: digest of source event ID, event class, target, and
  policy version;
- created/eligible/expiry times and retry/dead-letter status;
- optional digest-bucket identifier.

Titles, comments, prompts, tool bodies, and PHI-like content are excluded from
notifications unless a reviewed policy explicitly selects a field. The default
message says an action is required and links to the authorization-gated dossier
page.

Recipient selection is deterministic and versioned. An unresolved recipient is
a named finding, never a fallback to the actor, project owner, or broadcast list.

## 4. Work plan

### Phase 0 — Contract and migration

#### WI-0.1 — Event-to-intent policy

Define the versioned mapping for `awaiting_your_accept`, `review_requested`,
`item_returned`, `chain_verify_failed`, key lifecycle, access-case approval, and
configuration approval. Specify recipient inputs, privacy-safe content, urgency,
expiry, and immediate-versus-digest behavior.

**AC:** fixtures cover every event class, missing recipients, changed assignment,
self-review exclusion, project ACL denial, duplicate source events, and unknown
policy versions.

#### WI-0.2 — Remove request-path delivery authority

Keep the current direct emitter behind a compatibility flag for one release, but
make durable hook processing the supported production path. Never run both paths
without a shared idempotency key.

**AC:** migration mode produces one downstream delivery for one transition; the
old path can be disabled without changing work-state behavior.

### Phase 1 — Durable immediate delivery

#### WI-1.1 — Leased hook consumer

Add `dossier notifications worker` using regista's claim/complete/fail lease
contract. It must tolerate restart, lease expiry, poison events, duplicate claim,
and per-project outage. Run it as a separate systemd/Windows/container process,
not a background thread hidden in the web server.

**AC:** killing the worker after claim and before completion causes safe redelivery;
two workers cannot create divergent intent; poison events dead-letter with a
sanitized reason.

#### WI-1.2 — Signed intent and delivery evidence

Record intent creation, dispatch attempt, accepted-by-wake, dead-letter, expiry,
and operator requeue as generic signed entities/events. Exclude those event types
from their own notification trigger filter.

**AC:** replay reconstructs the same terminal state; forged success, recursive
notification, and mutation of recipient/scope are detected.

#### WI-1.3 — Wake dispatch and receipts

Send the existing authenticated v0 envelope with the stable intent ID. Treat
agent-wake's authenticated acceptance as dispatch acceptance—not human receipt.
Consume stronger channel receipts later when wake exposes them.

**AC:** wake outage retries; HTTP rejection is classified; a duplicate accepted
event is not delivered twice by a conforming channel; target allowlist rejection
cannot be reclassified as transient.

### Phase 2 — Scheduled digests

#### WI-2.1 — Per-principal digest policy

Configure enabled event classes, cadence, time zone, quiet hours, maximum items,
and immediate overrides by principal/role with organization defaults. Preferences
are policy, not an unbounded per-user query language.

**AC:** DST boundaries, missed schedule, time-zone change, quiet hours, disabled
user, empty digest, and immediate-event exclusion have deterministic tests.

#### WI-2.2 — Digest compiler and watermark

Add `dossier notifications digest --due` as an idempotent scheduled command. It
selects authorized intents since the principal's signed watermark, caps and
groups them, emits one digest intent, then advances the watermark only after wake
accepts it. Use OS scheduling through agent-suite; do not add an in-web scheduler.

**AC:** restart before/after dispatch neither loses nor permanently duplicates a
bucket; two scheduler invocations race safely; an empty period sends nothing.

#### WI-2.3 — Digest UX

Provide a preview, delivery history, failed/dead-letter queue for authorized
operators, and per-user preference surface. Every link is checked again at view
time; a digest never grants access to a project.

**AC:** revoking project access before click produces a normal 403 and the next
digest omits the project; history exposes metadata, not message bodies by default.

### Phase 3 — Operations and qualification

#### WI-3.1 — Doctor, metrics, and alerting

Report worker lease health, queue age/depth, oldest actionable intent, retry and
dead-letter counts, digest scheduler freshness, wake authentication posture, and
recipient-resolution failures. Avoid principal/project identifiers in metrics
labels.

#### WI-3.2 — Backup, restore, and upgrade

Prove queued hooks, intent history, idempotency keys, and digest watermarks survive
restore and schema upgrade. A restored old queue must not create an unbounded
notification storm; replay requires an explicit bounded operator action.

#### WI-3.3 — Live golden journey

Drive a work item through strict review, interrupt both worker and wake, restore
service, receive one actionable human notification, accept the item, and verify
the signed delivery trail.

## 5. Security and privacy gates

- No notification is broadcast because recipient resolution failed.
- No message body is copied from comments, session content, or tool output by
  default.
- Project authorization is evaluated both when compiling and when following the
  link.
- Sink secrets remain backend refs; no secret or auth header enters signed events.
- Requeue is admin-gated, attributed, bounded, and cannot change target/scope.
- Notification metadata is excluded from employee productivity analytics.

## 6. Completion gate

Plan 019 is complete when a committed review-gate event survives process and wake
outages, produces one effective human delivery through an allowed channel, and
leaves an independently replayable intent/attempt trail; scheduled digests pass
the same outage, ACL, privacy, and idempotency tests.

