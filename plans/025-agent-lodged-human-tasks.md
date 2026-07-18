# Plan 025 — Agent-lodged human tasks: human dependencies as first-class work

**Status:** Proposed 2026-07-18.
**Author:** Claude (Fable 5), from the operator's request during the
windows-evidence-lab WP-1 session ("a more robust way to lodge and surface
human dependencies").
**Strategic role:** Agents routinely hit steps only a human can perform —
an elevated install, a Vault admin action, a physical-world check, a purchase,
an approval outside the strict gate. Today those dependencies live in chat
scrollback and session summaries: the agent asks in-conversation, the human
does it or forgets, and nothing durable records that work stalled on a human.
This plan makes the dependency a first-class work item: an agent files a task
*addressed to* its operator or the operator's team, dossier surfaces it the
way it already surfaces review work, notification delivery rides the Plan 018
seam, and completion flows back to the agent that lodged it. The suite already
proved every leg of this loop separately; this plan connects them.

## Ground truth at time of writing

- dossier reads an `assignee` custom field and matches it against `actor_id`
  in the my-work view (Plan 018 WI-1.2, implemented). Nothing agent-side
  *writes* that field: `agent-notes work-item file/update` expose no assignee
  or custom-field surface. The only assignment path is a human editing the
  field in dossier — backwards for this use case.
- `agent-notes work-item request <target_project>` + `work-item wait
  <project:identifier>` exist and are the agent↔agent cross-project
  dependency mechanism. They have no notion of a human audience.
- Plan 018 WI-2.1 (implemented) gives dossier an authenticated, signed,
  idempotent notification envelope with the human principal in `meta.target`;
  agent-wake's email delivery of dossier's canonical event kinds is
  interop-proven (agent-wake Plan 005, 2026-07-11). WI-2.2 (digests) and
  Plan 019 (durable notifications) are pending but not prerequisites.
- Plan 004 (teams and split views, 2026-06-20) is parked; Plan 018 absorbed
  its person-scoped minimum. Team *addressing* (assign to a group, any member
  completes) remains unbuilt. Plan 014's deployment-policy provider already
  maps principals for project ACLs and is the natural membership source.
- Every work item carries the signed canonical workflow history, so an
  agent-lodged human task automatically records who asked, whom they asked,
  when the human acted, and what unblocked — the provenance story needs no
  new machinery, only the addressing.

## Principles

1. **A human task is an ordinary work item, addressed.** No parallel entity,
   no separate state machine. The canonical workflow statuses apply; what is
   new is only the audience (`assignee` / `audience`) and the tooling on both
   ends. This keeps dossier a tracker-with-provenance, not a Jira clone.
2. **Dependencies are links, not prose.** When an agent's own item is blocked
   on a human task, that is a typed link between two work items, queryable
   from both ends — never only a sentence in a body.
3. **Addressing is data, not identity guesswork.** Agents say `operator` or
   `team:<slug>`; resolution to a concrete principal happens against
   configuration (suite config / deployment-policy provider), so no agent ever
   hardcodes an LDAP uid, and reassignment is an operator-side edit.
4. **Degrade gracefully.** With no notification sink, the task still exists
   and surfaces in pull views. With no team config, `operator` still resolves.
   Absent config is a doctor `warn`, never a filing failure.
5. **The loop closes.** A lodged dependency that a human completes must be
   observable by the agent side without a human relaying it — via `work-item
   wait`, and via wake delivery where agent-wake is configured.

## Phase 1 — The contract

### WI-1.1 — Human-task addressing contract
- Document (docs/, referenced from AGENTS.md) the canonical fields: `assignee`
  (existing; a single principal's actor id) and `audience` (new custom field;
  `team:<slug>`), their precedence (assignee wins when both present), and the
  rule that either marks the item as awaiting a human.
- Define the blocking relation: a typed link (`blocked-by` / existing link
  vocabulary if one fits) from the agent's stalled item to the human task,
  usable cross-project via the existing cross-link surface.
- **AC:** the contract doc enumerates field names, value shapes, and the
  queries dossier and agent-notes will each run; no code in this WI.

### WI-1.2 — Operator and team resolution
- A workspace-level mapping (suite config or regista-backed, following where
  Plan 012's catalog lands) from the logical addresses `operator` and
  `team:<slug>` to concrete principal ids; membership for teams sourced from
  the Plan 014 deployment-policy provider until a regista membership provider
  replaces it.
- **AC:** resolving `operator` returns the configured principal; an unknown
  team resolves to a filing-time error naming the config file; missing config
  entirely degrades to a doctor `warn` and the literal value is stored.

## Phase 2 — The agent-side surface (agent-notes)

### WI-2.1 — Filing addressed items
- `agent-notes work-item file` and `update` accept `--assignee <principal|operator>`
  and `--audience team:<slug>`, writing the contract fields; `work-item
  request` accepts the same so a cross-project human task is one command.
- **AC:** an item filed with `--assignee operator` renders in dossier's
  my-work view for the configured operator with relation "assigned to me",
  with no human edit in between.

### WI-2.2 — Lodging a dependency in one step
- `--blocks <identifier>` (or `--blocked-item`) on the same verbs creates the
  typed link from the agent's stalled item to the new human task at filing
  time.
- `work-item wait` gains `--until-status` semantics adequate to "wait until
  the human task reaches a terminal status" if its current behavior does not
  already cover it.
- **AC:** file-with-block then complete-in-dossier: `wait` returns, and both
  items' histories show the link and the unblocking transition, signed.

## Phase 3 — The dossier surface

### WI-3.1 — Human-task queue
- The my-work view (and landing counters) distinguishes agent-lodged tasks
  awaiting me: filed-by-agent + addressed-to-me(/my team) + not terminal.
  Ordering follows the existing needs-attention sort; severity maps from the
  filed item as-is.
- Team-addressed items appear for every member with a "claim"-equivalent
  affordance (assignee set on take-up), reusing the existing field — the full
  Plan 004 team model stays parked.
- **AC:** an item filed via WI-2.1 addressed to `team:ops` appears for two
  configured members; one member taking it removes it from the other's queue
  view (it remains visible in the team lens).

### WI-3.2 — Blocked-agent visibility
- An addressed item renders what it is blocking: the linked stalled items,
  their projects, and age — so a human triaging the queue sees the cost of
  leaving it.
- **AC:** the WI-2.2 pair renders the blocked item's identifier and project
  on the human task's detail view, deep-linked.

## Phase 4 — The push half and the closed loop

### WI-4.1 — `task_assigned` notification kind
- Extend Plan 018 WI-2.1's canonical event kinds with `task_assigned`
  (principal, project, item, deep link, filed-by), emitted on filing or on
  the assignee/audience fields becoming set. Digest routing (Plan 018 WI-2.2 /
  Plan 019) treats it as immediate-class by default.
- **AC:** filing via WI-2.1 with a configured sink emits exactly one signed
  `task_assigned` for the resolved principal; agent-wake delivers it under its
  Plan 005 contract without changes to that contract.

### WI-4.2 — Completion wakes the agent side
- On a human task reaching a terminal status, emit `task_completed` targeting
  the *filing agent's* wake channel where one is registered (agent-wake's
  agent-directed leg); `work-item wait` remains the harness-neutral fallback.
- **AC:** live e2e in the lab: agent files, human completes in dossier, a
  waiting session observes the completion via wake without polling; the whole
  chain verifies under the signed-history view.

## Sequencing

Phase 1 is documentation plus config and can land immediately. Phase 2 is
agent-notes work (tracked there, referenced here) and depends only on WI-1.1/
1.2. Phase 3 builds on fields Phase 2 writes but WI-3.1 can develop against
hand-set fields in parallel. Phase 4 rides seams that already exist (Plan 018
WI-2.1, agent-wake Plan 005) and should follow, not precede, the pull surface
— a notification with no queue behind it is noise. The live e2e (WI-4.2 AC)
is the plan's definition of done, per the family convention that convergence
claims require live proof.

## Explicitly out of scope

- A general human workforce-management model (capacity, scheduling, SLAs).
- Reassignment workflows beyond editing the fields in dossier.
- The full Plan 004 team model (roles, split views per team) — only
  membership-based addressing is absorbed here.
- Escalation policies; Plan 019's digest/durability work covers repetition.
