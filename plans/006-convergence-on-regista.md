# Plan 006 — Convergence on regista: one work-item universe, fault-tolerant by design

**Status:** Proposed 2026-06-22. Cross-project north-star (regista + agent-notes +
dossier). Spawns per-repo implementation plans; nothing started.
**Author:** Opus 4.8
**Strategic role:** Collapse the two parallel work-item engines in the stack onto a
single authoritative store (regista), with dossier (human/web) and agent-notes
(agent/CLI) as **faces** of one log — so humans and agents act on the *same*
work-items in one provably-attributed chain. This is the concrete substrate for
"the major components of team-based agentic development, built-in," and it is
designed from the start to survive the failure that has repeatedly broken
work-tracking in this stack: **divergence under store-unavailability.**

---

## 1. Decision and context

We are **discarding prior architectural decisions** here deliberately:

- agent-notes Plan 008 (op-CRDT substrate, "borrow but do not depend on regista")
- the 2026-06-10 judgment that a consolidated agent suite was "overbuilt"
- "md-as-source-of-truth is retired" (Plan 007) — superseded by something sharper

We are **keeping the diagnoses** those decisions produced, because they are the most
valuable thing we have. Two of them are load-bearing for this plan:

- **D1 — Unconstrained media diverge, and don't scale.** Hand-edited markdown
  breadcrumbs drift spontaneously *even in clean repos* (stale `OPEN_BREADCRUMBS.txt`
  a week behind `breadcrumbs/active/`); different agents reconcile the same item
  differently (move the file / edit frontmatter / both). sf2 is the worked example
  of md not scaling.
- **D2 — DB-canonical already failed too, and not because a DB is wrong.** It failed
  because the write path was an *optional skill the model could skip*, and because
  store-unavailability **surfaced to the agent as an error**, which triggered
  improvisation back onto md. The catastrophe is *two authorities for one state*;
  its cause is *a visible write failure*.

The conclusion is not "DB vs md." It is: **one authoritative store, the write path
made non-optional and incapable of surfacing failure, and md demoted from record to
generated view.**

## 2. Target architecture (Model A — regista authoritative)

```
agent-notes (CLI + skills) ─┐
                            ├──► regista (Postgres) ──► dossier (FastAPI/web)
   harness hooks ───────────┘        THE log              human view
```

- **regista is the single source of truth.** Events, work-items, signing
  (HMAC→Ed25519), the per-work-item hash chain, workflows. One log, one chain.
- **dossier** is the human/web face (already a regista client). **agent-notes**
  becomes the agent/CLI face — *retiring its own op_log engine* (op-CRDT, content
  blobs, separate verifier). This reverses Plan 008's authority direction on
  purpose: regista is authoritative, agent-notes no longer its own authority.
- **One work-item universe.** A breadcrumb an agent files and an issue a human
  tracks are the *same* regista work-item, so a single mixed human+agent chain is
  real rather than two chains stitched together.

What we keep from agent-notes: the CLI/skills ergonomics, pgvector **as a search
projection** (§5), and Plan 008's *one genuinely good idea* — local-append-and-
reconcile (§4), now targeting regista instead of a bespoke engine.

## 3. md demoted to a generated projection

Markdown is not banned; it is **demoted from record to read-view.** The pull toward
md is a real signal (always-available, diffable, legible, lives by the code) — so we
design *for* it without letting it carry authority:

- The human-readable `OPEN_*.md` is **generated from regista**, never hand-edited.
- It is **not committed** (regenerable; committing a churny derived file is the
  `OPEN_BREADCRUMBS.txt` noise we are killing). Canonical shared view is dossier.
- When the store is unreachable it goes stale and **says so** ("STALE — N ops
  pending sync"), so staleness is honest instead of silent.

## 4. Failure tolerance — the outbox (the make-or-break layer)

The single most important property: **the one write command never surfaces a
failure to the agent**, so the improvisation reflex (D2) never fires.

### 4.1 Mechanism

- There is **one** write command (`file` / transition / comment). Internally it
  decides: regista reachable → write through (live event, live provenance);
  unreachable → append a **signed op** to a local **outbox** and return success.
- The agent **never** sees "regista unreachable." Degradation is internal. This is
  the specific thing the old design got wrong (D2): the DB error reached the agent.
- **Reconciliation** replays the outbox into regista on reconnect (and on
  SessionStart). regista's per-work-item lock serializes replay; conflicts (the
  item moved while offline) **flag for a human and block** — they do not auto-merge
  and do not silently accumulate. (The merge-lattice sophistication of Plan 008 is
  explicitly *not* rebuilt unless reality demands it.)

### 4.2 Location — centralized, not per-repo (decided)

The outbox lives in a **centralized state dir**, keyed by project:

```
$XDG_STATE_HOME/regista/outbox/<project>/<session>.jsonl
   (default ~/.local/state/regista/outbox/, env-overridable for tests)
```

Two reasons this beats per-repo scoping:

1. **It eliminates the gitignore risk by construction instead of managing it.** The
   outbox holds signed, actor-attributed ops — precisely what must never leak into
   history. The robust guarantee of "never committed" is *put it where git cannot
   see it*, not a `.gitignore` rule we have to trust. (Cf. the acb inline-comment
   `.gitignore` bug this session, which left a Vault-path file un-ignored and a
   `git add -A` away from commit.)
2. **Multi-project cleanup is a single sweep.** `reconcile` walks one `outbox/` tree
   and replays every project's pending ops, instead of hunting scattered files
   across N repos (some read-only, moved, or deleted).

Ops are keyed to their target project via the repo-root→project longest-prefix
resolution agent-notes already implements (the "librarian"), so an agent anywhere
knows which work-item universe its ops belong to.

**If** an in-repo md projection is ever wanted for editor-locality, the command must
use **`.git/info/exclude`** (repo-local, never committed, leaves the tracked
`.gitignore` untouched) and **verify with `git check-ignore` before writing** —
refusing to write if it cannot confirm the file is ignored. Lesson from the acb bug:
do not trust the ignore rule, confirm it.

### 4.3 Acceptance criteria — "did we just rebuild agent-notes?" made checkable

The design is only honest if these are testable. The convergence is **not** complete
until all three hold:

- **AC-1 — The write path always succeeds; failure never surfaces.** No code path
  shows an agent "regista unreachable." (Test: kill the DB mid-run; the agent's
  write returns success and the op lands in the outbox.)
- **AC-2 — The outbox has no authority and is never read as state.** It is signed,
  append-only, machine-owned, write-only from the agent's view. A hand-edit fails
  signature verification and is **rejected loudly** at reconcile — it cannot become
  truth. (outbox : regista :: git index : HEAD — a staging area, not a fork.)
- **AC-3 — Reconciliation is gated; conflicts resolve, not accumulate.** An actor
  cannot take key transitions (e.g. mark work done/reconciled) with a non-empty
  outbox; conflicts block on human resolution. (Test: offline op + concurrent
  central change → reconcile surfaces a blocking conflict, not a silent overwrite.)

### 4.4 The honest limit

This closes *divergence* (two authorities) by construction. It does **not** close
*under-capture* — an agent jotting a thought in prose instead of filing a structured
item. You cannot force a model to structure every thought; hooks enforce
reconciliation and orientation, not creativity-in-the-moment. Under-capture is a
*missed note*, not a *corrupted source of truth* — a milder, recoverable failure,
addressed by prompting/culture, not architecture. Stated plainly so it is not
mistaken for a regression later.

## 5. Memory as a referenceable, non-workflow regista entity (the Confluence seam)

Breadcrumbs are work-items (lifecycle) and belong in the tracker. **Memories are
not** — they are cross-session *facts* with no lifecycle, plus semantic search.
Forcing them into a work-item/workflow is a category error (and regista correctly
has no fact concept today). But the Jira↔Confluence intent — *reference knowledge
from a work-item* — is right and is the second first-class entity dossier needs.

- **regista grows a non-workflow signed entity** ("note"/"knowledge"): it gets
  events (created/edited/superseded), signing, attribution, and links — the
  provenance half (G1 attribution, G2 integrity) — **without** a state machine.
  Specified in **regista Plan 022** (entity generalization): `note` is one
  `entity_kind`, added after the entity shape lands, needing no further envelope
  bump. Unlike the acb forwarder (Plan 002 WI-5, superseded), this core extension is
  justified by a central product goal and a first-class consumer (dossier itself).
- **References are typed links, and the link act is an attributed event.** "Actor X
  linked work-item A → note M" is a signed event on A — the Jira-Confluence backlink
  with provenance for free. Built on regista's existing links concept.
- **pgvector is a search projection, not a source of truth** — an index rebuildable
  from regista-sourced content. Same for the file-based memory (`MEMORY.md`): a
  *generated view*, which resolves the current silent dual-store drift.

Scope discipline: build the **seam** (the note entity + one reference link type +
minimal CRUD), **not Confluence** (rich docs, page trees, editor). dossier's tracker
MVP is barely landed; the knowledge base grows incrementally on the same spine.

## 6. Enforcement layer

Optional skills are skippable (D2). Non-optionality comes from **harness hooks** (the
piece Plan 007 specced and deferred):

- **SessionStart** → orient + replay outbox → regista + regenerate projection.
- **Stop / PreCompact** → reconcile; must accept "no change"; if regista is
  unreachable, leave the outbox and **loudly** report "N ops pending sync."
- Ships on **both** Claude Code and opencode over the shared CLI (opencode is
  tier-one — it is where unattended drift happens), per the agent-notes lesson.

## 7. Non-goals (what we deliberately do not build)

- The op-CRDT engine, merge lattice, cross-project kernel (Plan 008 bulk). Keep only
  local-append-and-reconcile.
- Confluence-depth knowledge base. Build the seam, not the product.
- A second authority of any kind. The outbox is a queue; pgvector and md are
  projections. Nothing but regista is a source of truth.
- Local-first/disconnected multi-writer operation as a *requirement* (it is unbuilt
  today; offline windows are short for a central team tool). The outbox tolerates
  brief outages; it is not a replica.

## 8. Sequencing (phases, each independently landable)

1. **P1 — regista as the agent face.** agent-notes CLI writes through to regista;
   breadcrumb→regista-work-item migration; retire the op_log engine. (No outbox yet:
   write-through only, fail-fast — proves the model on the happy path.)
2. **P2 — the outbox + reconcile.** Centralized outbox, signed ops, replay,
   conflict-blocks-for-human. Satisfy AC-1/2/3. **This is the gate** — without it the
   convergence is unsafe.
3. **P3 — projection + enforcement hooks.** Generated md view with staleness banner;
   SessionStart/Stop/PreCompact on both harnesses.
4. **P4 — the knowledge entity + reference seam.** Non-workflow regista note entity;
   typed work-item↔note links; pgvector + `MEMORY.md` as projections. **Depends on
   regista Plan 022** (entity generalization + typed links).

## 9. Open questions / risks

- **regista core change (P4).** The non-workflow entity touches the signing
  envelope's `work_item_id` assumption, the hash-chain linkage, and pagination —
  now specified in **regista Plan 022** (the v3→v4 envelope cycle). dossier P4 depends
  on regista Plan 022 P1 (entity shape) + P4 (typed/cross-project links) having landed.
- **Conflict policy (P2).** "Flag and block for human" is the safe start; whether a
  small set of auto-resolvable cases is worth it should wait for real conflict data.
- **Migration of existing agent-notes data** (op_log → regista events) — translation
  fidelity across two signing models; one-way, verified, with the old store kept
  read-only until trust is established.
- **Rename in flight.** agent-notes → `sheaf`/`marshal`/`loom` was predicated on it
  being the substrate *kernel*. As a regista *face* that rationale dissolves; park
  the rename until after P1.
