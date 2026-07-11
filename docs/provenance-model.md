# Design Spine — Work Model & Provenance Guarantees

This is the contract every part of dossier is written against. It defines two
things and how they're the same thing: the **work model** (what a tracked item is)
and the **provenance guarantees** (what dossier promises about the record). If a
feature and this document disagree, this document wins; changing the guarantees is
a decision to surface to a human.

## 1. The work model is regista's, not dossier's

dossier introduces no new state model. It maps directly onto regista primitives:

| Tracker concept | regista primitive |
|---|---|
| Issue | work-item |
| Issue type (`bug`, `task`) | work-item-type |
| Status (`open`/`in_progress`/`blocked`/`deferred`/`in_review`/`in_human_review`/`done`) | workflow state |
| Moving an issue | validated transition (role-gated) |
| Who reported / who acted | actor (`actor_kind` = human / agent / system) |
| Assignment / "who's on it" | custom field `assignee` (MVP); regista *claims* later |
| Priority, etc. | typed custom fields (`ui_visible`) |
| Comment | event carrying comment text |
| Adversarial review verdict | `accept` / `request_changes` transition event, by an actor ≠ the author |
| Activity / history | the work-item's event log |
| Issue key (`DOSSIER-42`) | dossier-minted display key over the work-item id |

The declared workflow lives in `src/dossier/workflows/dossier.workflow.yaml` and is
the authoritative state machine. dossier renders and drives it; regista enforces
it.

## 2. The three provenance guarantees (MVP)

These are the promises the verified-history view is allowed to make. Each maps to a
regista mechanism that already exists — dossier's job is to *not break* them and to
*make them legible*.

**G1 — Attribution.** Every state-changing action is attributable to a real actor.
A human action carries the authenticated principal (`actor_kind=human`); an agent
action carries the agent (`actor_kind=agent`) and, when acting for a person,
`on_behalf_of`. There are **no anonymous writes** and no path that writes work
state outside a regista event. *Mechanism:* regista actors + signing envelope;
dossier's auth resolves the human actor and is therefore the root of the guarantee.

**G2 — Integrity (tamper-evidence).** The history of a work-item is an append-only,
hash-chained event log: each event binds to its predecessor via
`prev_event_hash = SHA-256(prev_envelope ‖ prev_signature)`. A removed or altered
event breaks the chain, and replay reports it. *Mechanism:* regista event hash
chain (v8 / migration 018) + HMAC-SHA256 signing. dossier never mutates or deletes
events; corrections are new events.

**G3 — Legibility.** A human can read the record and see, per change: what changed,
who (human/agent, on whose behalf), when, and whether the chain verifies. Provenance
nobody can read is not provenance. *Mechanism:* the verified-history view renders
the event log and surfaces an integrity status (chain intact / broken) from a
replay/verify call.

**Adversarial review is part of the record.** Because `done` is reachable only
through review (`plans/005`), every completed work-item's dossier contains a signed
verdict event: who challenged the work (an actor ≠ the author; a *human* if any
author was an agent), when, and what they found. Review is structural, not a flag,
and its outcome is provenance — "this was independently challenged, by this person,
and here's the finding" is exactly the audit claim the regulated setting needs.

### Project disclosure boundary

Provenance integrity does not imply that every authenticated person may read every
record. Dossier has one project-authorization seam covering direct routes,
cross-project dashboards/search/activity, provenance/session views, signing
history, and mutations. The compatibility posture is explicitly `open` and is a
doctor warning. `audit` evaluates a strict default-deny ACL while permitting and
logging would-be denials; `enforce` applies it. Authorization identity is derived
only from the authenticated principal: stable actor ID plus immutable LDAP group
GUIDs (or case-folded local-development group names). Group identities are
domain-separated HMAC claims in the signed client-side session, so membership
names/GUIDs are not disclosed by the cookie. Policy is a deployment input; it
never mutates regista work state or weakens regista's transition gates.

## 3. Explicitly deferred (seams left open, not redesigned)

regista already supports these; the MVP does not wire them, but nothing in dossier
may foreclose them:

- **Asymmetric signing (Ed25519)** per actor — MVP uses default HMAC-SHA256.
- **RFC-3161 trusted timestamping** of event batches.
- **Witness co-signing** (external witness receipts).
- **DSSE / in-toto attestations at run→PR grain** — this is
  [agent-provenance](https://github.com/hraedon/agent-provenance)'s deeper stack,
  not dossier's. dossier gives it a surface; it does not implement it.

## 4. The one open architectural decision

Does dossier front its **own** regista project (isolated, simple — the MVP), or the
**same** work-items agents touch via agent-notes (so one item shows a mixed
human+agent chain — the strongest demo of G1)? MVP picks its own project; the actor
model above is designed so fronting shared work-items later is a configuration and
workflow-alignment step, not a rewrite. This is the `plans/001` north star, held
deliberately out of the MVP to keep it light.
