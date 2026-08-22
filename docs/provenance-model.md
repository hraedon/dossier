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

### Review assurance is regista's too (WI-012, closed)

The review-assurance level — "was this self-reviewed, independently reviewed, or
human-accepted?" — is a **provenance judgment**, so it belongs to the engine, not
the face. dossier calls `regista.gate_rationale(events, "strict")` (regista's
public API since 0.5.3, regista Plan 027) and renders the answer. The runtime
floor is `regista-hraedon>=0.7.1,<0.8` because dossier also consumes the public
trust-log verification and lifecycle authority APIs. The exact `SUITE.lock`
version/SHA pins the published 0.7.1 release pair
until regista 0.7.1 is published.

`src/dossier/assurance.py` is the only seam. It does two things and nothing else:

1. **Maps** regista's five `AssuranceLevel` values onto dossier's four-level
   display vocabulary.
2. **Downgrades an independence claim that has no evidence behind it.** regista's
   `same_lineage()` returns `False` when a lineage is *undeclared*, so an
   undeclared review is reported as `independently_reviewed`. For a UI whose whole
   purpose is not over-claiming, that is a fail-open. dossier therefore renders
   `self-reviewed` when the reviewer declared no model lineage, or when an agent
   authored the item without declaring one — and flags the verdict `degraded` with
   the reason, shown in the UI. (This preserves WI-014's fail-safe; regista's
   *write-side* `adversarial_review` validator already refuses these reviews unless
   `same_lineage_acknowledged` is set, so the two agree on the risk.)

Rendering **less** than the engine claims is always safe; rendering more never is.
The downgrade inspects the event log only for *evidence* (was a lineage declared?);
it never derives a level of its own. If regista later reports independence with a
confidence/evidence field of its own, rule 2 collapses into rule 1.

The store-side `Regista.assurance.compute_assurance(work_item_id)` facade is the
other delegation path; dossier does not use it because it re-reads the event log
per rendered row (an N+1 against the store) and returns the level without the
lineage evidence `gate_rationale` carries. Both run the same regista function over
the same events.

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
Attribution is only *cryptographic* when the actor signs with a key only they hold —
see "Human signing identity" below for how a person's identity is bound to one, and
what happens when it is not.

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

### Human signing identity — how a person's judgement is bound to a key (WI-035)

G1 says every action is attributable to a real actor. For an agent that has always
been literally true: an agent's `actor_id` *is* its regista `principal_id`, so
regista resolves that principal's Ed25519 key and the event carries a signature only
that agent could produce. For a human it was not. Dossier signed human events under
the auth backend's `stable_id` — a minted uuid for a local user, an `objectGUID` for
LDAP — and no key is registered against those. regista's `resolve_signing_key` found
nothing bound to the acting id and fell back to `active_key()`: the **shared
store-level HMAC key** that the server and every actor use for the ledger chain.

The event still sealed into the chain, so nothing looked broken. What was missing was
the attribution: anyone holding the store key could produce that event, and `regista
verify` said so — `1 unverifiable (symmetric scheme)`. This was found during the
Plan 020 Lane C Linux qualification, on the human `accept` of a work item whose three
agent legs all signed correctly. It is a violation of the agent-suite
[bootstrap contract](https://github.com/hraedon/agent-suite/blob/main/docs/bootstrap-contract.md)
§5, which requires the mixed human+agent chain to verify *with per-actor signatures*.

**The binding.** A dossier identity records the regista `principal_id` it acts as,
and that `principal_id` becomes the `actor_id` on its signed events:

| Backend | Where the binding lives |
|---------|-------------------------|
| local   | a `principal_id` field on the user's entry in `DOSSIER_USERS_PATH` |
| ldap    | the directory attribute named by `DOSSIER_LDAP_PRINCIPAL_ID_ATTR` |

It has to be the `actor_id` and not a second field alongside it. regista binds each
key to a principal and checks the two agree — `verify_principal_binding` live, and
`_verify_event_signatures` in the offline bundle verifier, both reject an event whose
`actor_id` differs from its signing key's `principal_id` as an *actor-signer
mismatch*. An identity that signs under an id no key is registered against cannot
carry a per-actor signature at all; there is no arrangement of extra fields that
changes that. Binding also makes the human **one** actor across both faces: their CLI
already acts as `REGISTA_PRINCIPAL_ID` (see agent-suite
`docs/multi-user-onboarding.md` §3), so signing dossier events under the `stable_id`
would split one person into two actors no verifier could connect.

The binding is **never derived** — not from the username, not from the `stable_id`.
A derived binding would claim a signing identity the suite may not have provisioned,
and dossier would then either sign as somebody else or fall back to the store key.
"Unbound" is a state the system states plainly instead.

The `stable_id` survives as an **authorization alias** (`Actor.alias_actor_ids`).
ACL entries, `DOSSIER_BOOTSTRAP_ADMINS`, and owner records written against the
pre-binding id keep matching, so provisioning signing cannot lock an operator out of
their own deployment. The alias is authorization-only; it never appears in a signed
event.

**No silent downgrade.** When a human action cannot be signed per-actor,
`DOSSIER_HUMAN_SIGNING` decides:

- **`require`** (the default when `DOSSIER_ENV=prod`) — the write is **refused**
  before anything is appended. The response is a `409` whose body names the identity,
  what is missing, and the provisioning command.
- **`warn`** (the default outside prod, and a legacy migration escape hatch) — older
  backends may record the write, with the downgrade reported in four places: a
  `provenance.human_signature_downgraded` WARNING, an
  `X-Dossier-Human-Signing: downgraded` response header, a callout on the issue page,
  and the `human_signing` doctor check. A clean regista v6 epoch has no shared write
  key, so dossier logs the attempted downgrade and refuses the write instead.

Refusal is the default in production because the alternative is worse than an outage.
A refused acceptance is a visible, recoverable operational problem with a named fix.
A downgraded one is a record that *reads* as a signed human decision and is not —
and it is discovered, if ever, at audit time, long after the decision it fails to
attribute. The history view now distinguishes the two cases it used to merge: a human
event sealed with a symmetric key reads *"shared key — not attributable"*, not
*"unsigned"*.

Migration for an existing deployment is in [deploy.md](deploy.md#migrating-to-per-actor-human-signing).

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

- ~~**Asymmetric signing (Ed25519)** per actor~~ — wired. Agents and humans both
  sign with per-principal Ed25519 keys; the store HMAC key seals the ledger chain
  only. See "Human signing identity" above (WI-035).
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
