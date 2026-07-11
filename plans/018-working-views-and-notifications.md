# Plan 018 — Working views and notifications: dossier as a daily surface

**Status:** In Progress — Phase 1 and WI-2.1 implemented; WI-2.2 remains.
**Author:** Claude (Fable 5), from the 2026-07-07 suite v2 gaps review
**Strategic role:** Plans 011/014 made dossier a deployable cross-project
*window*; Plan 017 adds the provenance record. What's still missing is the part
that makes a human open it every day: the views organized around *my* work —
what awaits my review, what I own, what changed since I last looked — and the
push half: today nothing tells a human that an item is waiting on their accept.
In a strict-gate deployment (regista Plan 027) the human accept is the
bottleneck by design; if nobody is told, the pipeline silently stalls. This is
the usability half of the human-visibility story.

## Ground truth at time of writing

- dossier today is pull-only and item-centric: you navigate to a project, read
  a list, open an item. No review queue, no my-work view, no activity feed, no
  notification of any kind.
- Plan 004 (teams and split views, 2026-06-20) proposed team-scoped views and
  was never started; its team model is broader than v2 needs. This plan absorbs
  its useful minimum (person-scoped views); the full team model stays parked.
- The strict gate (Plan 027 / dossier assurance work) makes same-lineage-reviewed
  items require a human accept — the exact event a human must learn about
  promptly.
- agent-wake exists as the suite's signaling component but is currently
  agent-directed (waking sessions). Human-directed delivery (email/webhook) is
  proposed as agent-wake Plan 005; this plan defines the emitting side.

## Principles

- **Views derive from the log; notifications derive from transitions.** No new
  state store; a queue view is a query, a notification is a reaction to a
  signed event.
- **Nudge, don't nag.** Default to batched digests with an immediate path for
  gate-blocking events; every notification deep-links to the exact page.
- **The emitting seam is dossier's; the delivery is wake's.** dossier decides
  *what* a human should hear about; agent-wake owns *how* it reaches them
  (Plan 005 there). Keep the boundary clean so delivery backends can vary per
  deployment.

---

## Phase 1 — The three views

### WI-1.1 — Review queue
- A cross-project "awaiting review" view scoped to the signed-in principal's
  eligible role: items `in_review` (and `deferred` awaiting re-entry) with age,
  assurance level (asserted/verified lineage — reuse the Plan 014 WI-1.4
  vocabulary), and the gate they're blocked on. Strict-gate items awaiting a
  human accept sort first.
- **AC:** an item submitted for review appears in the queue of an eligible
  reviewer within one refresh; accepting it from the linked detail page removes
  it; the queue respects per-project permissions.

### WI-1.2 — My work
- Items where the principal is the actor-in-flight: created by me, assigned to
  me (owner field from Plan 012's ownership model where present), or last
  transitioned by my agents (`on_behalf_of` → me). Grouped by state.
- **AC:** the view distinguishes "I did this" from "my agent did this on my
  behalf"; an item my agent moved to `in_review` shows up under my flag.

### WI-1.3 — Activity feed
- Cross-project reverse-chron feed of transitions (filterable by project,
  actor kind, transition), building on the Plan 014 dashboard rather than
  replacing it. Each row links to the item; agent actions link through to the
  Plan 017 trail when present.
- **AC:** the feed renders the last N transitions across permitted projects
  with stable pagination; filtering by actor kind isolates agent activity.

## Phase 2 — The push half

### WI-2.1 — Notification events (the emitting seam)
- dossier emits notification-worthy occurrences as structured events to a
  small outbound interface: `awaiting_your_accept` (strict gate),
  `review_requested`, `item_returned`, `mentioned_in_comment` (if/when
  mentions exist — otherwise omit), `chain_verify_failed` (from Plan 017
  WI-2.1's widget backend, operator-scoped). Each carries principal, project,
  item, deep link.
- Delivery is pluggable: v1 ships a webhook emitter (agent-wake's ingress is
  one valid target; a bare webhook receiver is another) — no SMTP code in
  dossier.
- **AC:** driving an item to `in_review` under the strict gate emits exactly
  one `awaiting_your_accept` to the configured sink with a working deep link;
  no sink configured = no error, a doctor `warn`.

### WI-2.2 — Digest mode
- A scheduled digest (per principal, default daily): queue counts, new items in
  my projects, my agents' session summary (count of sessions/tool calls from
  Plan 017 data). Immediate-vs-digest routing per event class, config not code.
- **AC:** with two pending reviews and one agent session, the digest names all
  three with links; an empty day sends nothing.

---

## Sequencing

Phase 1 is pure UI over existing queries and can start immediately (it does not
depend on Plan 017 or cairn). Phase 2 lands the seam first (WI-2.1), then
pairs with agent-wake Plan 005 for real delivery; until wake's delivery leg
exists, the webhook sink is validated with a test receiver. Absorbing Plan 004:
mark 004 superseded-in-part by this plan when WI-1.1/1.2 land.

## Implementation note — 2026-07-11

Phase 1 and the WI-2.1 emitting seam are present. The dossier → agent-wake
boundary is now a real authenticated contract: dossier emits a canonical v0
envelope, signs the exact body with a secret resolved from the suite backend,
binds an idempotency event ID, declares its source/service identity, and places
the human principal in `meta.target`. Unsigned generic webhooks remain available
for test receivers but report a degraded doctor posture and are explicitly not
described as agent-wake compatible. Cross-repository contract tests prove wake
accepts an allowed target and rejects an unapproved one. WI-2.2 still lacks its
scheduled delivery path, so this plan remains In Progress.
