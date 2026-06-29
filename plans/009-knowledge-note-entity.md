# Plan 009 — Knowledge `note` entity + reference seam (dossier 006 P4)

**Status:** Proposed 2026-06-28. The implementation plan for dossier Plan 006 §5 /
P4 (the "Confluence seam"). Independent of the agent-notes conversion track — can
run in parallel. Not started.
**Author:** Opus 4.8
**Strategic role:** Give dossier its second first-class entity — a **referenceable,
non-workflow `note` (knowledge) entity** in regista — so a work-item can cite a
durable fact with provenance, and so `MEMORY.md` / pgvector become *generated
projections* of a regista-sourced truth instead of a silent parallel store. This
is the Jira↔Confluence intent (reference knowledge from a work-item), built as a
**seam, not Confluence**.

---

## 1. What this is (and is not)

- **Is:** a `note` entity kind in regista with events (created / edited /
  superseded), signing, attribution, and typed links — the provenance half (G1
  attribution, G2 integrity) **without a state machine**. Plus one typed
  work-item↔note reference link and minimal CRUD.
- **Is not:** a rich-document knowledge base (page trees, an editor, rendering).
  Build the seam; the KB grows incrementally on the same spine later (006 §5
  scope discipline).

Memories are **facts with no lifecycle** — forcing them into a work-item/workflow
is a category error (006 §5). The `note` kind is precisely the non-workflow entity
that fits them.

## 2. regista groundwork (mostly done — verify, then a thin gap)

regista Plan 022 P1 already generalized events to `(entity_kind, entity_id)`, and
the event path **skips workflow resolution for any kind that is not `work_item`**
(`_events_api.py` looks up a workflow only `if entity_kind == "work_item"`). So a
workflow-less `note` entity is already supported at the append layer — this is
022's downstream P5, additive, no envelope bump.

**The one thing to verify/add:** `validate_entity_kind` must **allow `'note'`**.
Confirm whether kinds are open or allowlisted; if allowlisted, adding `note` is a
one-line regista change (the "register the note kind" half of 022 P5). Typed
cross-project links (`target_project` / `target_entity_kind` / `content_hash`)
already exist in `_links_api.py` (022 P4) — the reference link rides those.

- **WI-0 (regista, tiny) — allow the `note` kind.** Add `note` to the accepted
  entity kinds (`validate_entity_kind`); a `note` has no workflow, so no workflow
  registration is needed. Test: append created/edited/superseded events to a
  `note` entity, no workflow required, chain verifies.

## 3. Work items (dossier)

- **WI-1 — Note CRUD over regista.** Create / edit / supersede a `note` entity via
  regista events (content is a content-addressed blob like work-item bodies, per
  006 §5). Attribution + hash-chain come from regista for free. No state machine.
- **WI-2 — Typed reference link.** One link type, work-item → note ("references").
  The link act is an **attributed event on the work-item** (signed) — the
  Jira-Confluence backlink with provenance, built on regista's existing links
  (and 022's typed/cross-project link fields, so a work-item in one project can
  reference a shared knowledge note in another via value-reference + `content_hash`
  pinning).
- **WI-3 — pgvector + `MEMORY.md` as projections.** Re-point semantic search and
  the file-based memory index so both are **generated views rebuildable from
  regista-sourced note content** — resolving the current silent dual-store drift
  (006 §5). `MEMORY.md` becomes a generated, uncommitted projection with a
  staleness banner (consistent with 006 §3's md-as-projection rule).
- **WI-4 — UI seam.** A note renders read-only in dossier; a work-item's verified-
  history view shows its outbound "references" links legibly. Minimal — no editor.
- **WI-5 — Tests.** Note create/edit/supersede chain verifies; a work-item→note
  link is a signed event on the work-item and appears in its history; pgvector and
  `MEMORY.md` rebuild from regista with no separate source of truth.

## 4. Migration of existing memories

The current `agent-notes` memory corpus (`MEMORY.md` + pgvector) is the data to
bring across. One-way, idempotent: each memory → a regista `note` entity (created
event, attributed to its origin where known), the index rebuilt from regista
afterward. Old store kept read-only until the rebuilt projection is trusted.
**Coordinate with the agent-notes conversion track** (Plan 010) only insofar as
both write to the same regista — the note migration does not block, and is not
blocked by, the work-item lifecycle conversion.

## 5. Sequencing & dependencies

- **Depends on:** regista 022 P1/P4 (done, on main) + WI-0 (allow `note` kind —
  tiny). **Independent of** regista Plan 023 and agent-notes Plan 010 — runs in
  parallel with the conversion track.
- **Order:** WI-0 (regista) → WI-1 + WI-2 (entity + link) → WI-3 (projections) →
  WI-4 (UI) → WI-5 (tests) → §4 migration.

## 6. Risks

- **Scope creep into Confluence.** The pull toward rich docs / page trees / an
  editor is real; resist it. Seam only — one note entity, one link type, minimal
  CRUD. Re-read 006 §5 if the surface starts growing.
- **Projection authority slip.** pgvector and `MEMORY.md` must stay *generated*.
  Any code path that treats them as a source of truth reintroduces the dual-store
  drift this plan exists to kill — assert "rebuildable from regista" in tests.
- **Memory migration fidelity.** Attribution for historical memories is often
  unknown; record provenance honestly (unknown origin is a real, recordable fact)
  rather than fabricating an actor.
