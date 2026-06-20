# Plan 004 — Teams & split views

**Status:** Proposed 2026-06-20. Builds on the group membership from
`003-ldap-integration.md`. Not started.
**Author:** Opus 4.8
**Strategic role:** Let multiple teams share one dossier instance — each working its
own queue, leads seeing across — with team membership **sourced from AD groups** so
it isn't hand-maintained. "Split views" is the UI that makes a shared instance feel
like each team's own board.

## Interpretation (stated, because "split view" is ambiguous)

I'm building to this reading; correct me if it's wrong:

- A **team** is a named grouping of members. Membership is sourced from AD groups
  (Plan 003) via a `group → team` mapping; a person's teams = their AD groups that
  map to a dossier team.
- A work-item has an **owning team** (a `team` custom field on the workflow).
- **Split view** = one screen partitioned *by team*: a default "my team's work"
  scope for members, and for leads a **side-by-side multi-team view** (panes/lanes,
  one per team) so several teams' boards are visible at once.

Two forks I'm **not** deciding unilaterally — flagged under "Decisions" with my
recommendation:
1. **Visibility = soft filter or hard access control?**
2. **Team mapping = a `team` custom field or a regista project per team?**

## Principles this plan must hold

- **Team membership is directory-sourced, not hand-managed** (fits the AD world and
  keeps one source of truth). dossier maps AD groups → teams; it does not own the
  member list.
- **Workflow changes are surfaced to a human.** Adding the `team` custom field
  changes the contract every work-item is created against (`AGENTS.md`) — it goes
  through review, not silently.
- **Team context is provenance-relevant.** Record the actor's teams/groups in
  `actor_metadata` at action time, so the dossier answers "was this person in this
  team when they acted?" — strengthening the audit story (002 G1).

## Design

**Team model & mapping.** A small config (or dossier-owned table) maps AD group
GUID/name → dossier team. At login, intersect the user's groups (003 WI-3) with the
mapping to get their teams; cache in session and `actor_metadata`.

**Work-item → team.** Add a `team` custom field (enum or string, `ui_visible`) to
`dossier.workflow.yaml`. Items without a team are "unassigned-team" (visible to all,
flagged for triage).

**Views.**
- **My work** (default landing): items in my team(s), with a one-click narrowing to
  "assigned to me."
- **Team board:** a single team's list/board grouped by status, filterable by
  assignee.
- **Split view (leads):** N team boards rendered side by side in panes (or stacked
  lanes), each independently scrollable — the literal "split." Team set is the
  viewer's teams by default; a lead with cross-team groups can pick which teams to
  pane.

**Visibility model (the soft-vs-hard fork).** Recommend **soft for MVP**: everyone
authenticated can *see* all teams' items; views *default and filter* to the viewer's
team(s). Hard access control (members can only see their teams' items) is heavier —
it implies real multi-tenant authorization and, done properly, may want a regista
project per team. Ship soft; document the hard path; don't foreclose it.

## Work items

- **WI-1 — Team model + `group → team` mapping**; resolve member-teams at login into
  session + `actor_metadata`.
- **WI-2 — `team` custom field** on the workflow (surfaced workflow change); default
  / triage handling for team-less items.
- **WI-3 — "My work" default scoped view.**
- **WI-4 — Single-team board view.**
- **WI-5 — Split view:** side-by-side multi-team panes for leads, with a team picker.
- **WI-6 — Visibility model:** implement soft filtering; write up the hard-isolation
  option (regista-project-per-team) as a decision record, not code.
- **WI-7 — Record team context in `actor_metadata`** at action time (provenance).
- **WI-8 — Tests:** mapping resolution, scoping correctness (a member sees their
  team by default), split-view rendering with multiple teams.

## Decisions to surface to a human

1. **Visibility:** soft filter (recommended MVP) vs hard access control.
2. **Team mapping:** `team` custom field (recommended MVP) vs regista-project-per-team
   (real isolation, heavier, the hard-visibility enabler).
3. Whether non-team-members can be assigned an item; what "split view" should default
   to for a single-team member (probably just their team board).

## Sequencing / relationships

Depends on Plan 003 (group data) and Plan 002 (session/actor). The `team` custom
field touches the `001` design spine's workflow, so coordinate with whoever owns the
workflow version. Pure post-MVP — the `001` MVP ships single-queue before teams.
