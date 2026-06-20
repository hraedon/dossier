# Plan 002 — Auth & identity (the actor-binding foundation)

**Status:** Proposed 2026-06-20. Expands `001-mvp.md` WI-4 into a full design. Not
started.
**Author:** Opus 4.8
**Strategic role:** Auth's deliverable is **not** a login page. It is a trustworthy
mapping from `request → authenticated principal → regista human actor`, because that
binding *is* provenance guarantee **G1** (`docs/provenance-model.md`). Every signed
event in a work-item's dossier is only as attributable as this layer. Treat it as
security-critical, not plumbing.

## Ground truth at time of writing

- No auth exists yet. `itsdangerous` is already a dependency (signed cookies).
- The regista gateway (`001` WI-3) is the single choke point where dossier writes
  events; the actor must be injected there, resolved server-side, never from client
  input.
- cert-watch has a proven auth package (sessions + CSRF + LDAP/OAuth) to adapt by
  hand — not copy.

## Principles this plan must hold

- **The actor is derived server-side from the verified session — never from
  client-supplied data.** Spoofing the actor is the one failure that silently
  destroys provenance. There must be no code path where a request body or header
  sets who acted.
- **Actor identity is stable across rename.** `actor_id` keys on a durable
  identifier (LDAP `objectGUID` / local uuid), not a display name or username, so a
  renamed person's history stays attributed to them.
- **Pluggable backends keep "lightest" honest.** A small trusted team can run on a
  local backend with zero directory infra; AD is opt-in (Plan 003).

## Design

**Session layer.** Signed session cookie (`itsdangerous`), `HttpOnly` + `Secure` +
`SameSite=Lax`; short idle lifetime with sliding renewal; explicit logout. CSRF
token required on every state-changing POST (dossier mutates regista on POST).
Server-side session record is optional for MVP; revisit if we need server-side
revoke.

**`AuthBackend` protocol.** A small interface so the rest of the app never knows
which directory is behind it:
```
authenticate(credentials) -> Principal | None      # verify identity
fetch_groups(principal)    -> list[GroupId]         # for Plan 004 teams
```
`Principal` = `{ stable_id, display_name, source, raw_attributes }`.

**Backends.**
- `LocalBackend` (MVP / dev / small trusted team): users in a config file or a
  dossier-owned table, passwords hashed (argon2/bcrypt). `stable_id` = a minted
  uuid. No directory needed.
- `LdapBackend`: Plan 003.

**Principal → regista actor (the provenance-critical step).** On successful auth,
resolve-or-create a regista actor: `actor_id = stable_id`, `actor_kind = human`,
`actor_metadata = { display_name, source, groups, resolved_at }`. Cache the actor
ref in the session. The gateway injects this actor on every mutation. Renames update
`actor_metadata.display_name` but never `actor_id`.

**Agents & delegation (design now, client later).** An agent calling the future
HTTP API authenticates with a service credential and acts as
`actor_kind = agent`, its own `actor_id`, and `on_behalf_of = <human stable_id>`
when delegated. The actor model must accommodate this from the start even though the
agent client is post-MVP — otherwise the mixed human+agent chain (001 north star)
needs a rewrite.

**Authorization (coarse for MVP).** The workflow's `member` role gates transitions;
"authenticated ⇒ member" for now. Finer per-transition authz is a future concern;
the workflow's `allowed_roles` is the seam, and Plan 004 introduces team-scoped
authorization questions.

## Work items

- **WI-1 — Session layer:** signed cookie, login/logout routes, CSRF on POST,
  cookie hardening.
- **WI-2 — `AuthBackend` protocol + `LocalBackend`** (hashed passwords, config/table
  users) so dossier runs with no directory.
- **WI-3 — Principal → regista actor resolution** (stable id, `actor_metadata`,
  gateway injection). The provenance keystone.
- **WI-4 — Agent/API auth → agent actor + `on_behalf_of`** model and token format.
- **WI-5 — Security hardening:** session lifetime/renewal, login throttling/lockout,
  TLS-termination note (IIS/HttpPlatformHandler on Windows like cert-watch, or a
  reverse proxy).
- **WI-6 — Tests, including the spoof-prevention test:** assert there is *no* path
  that sets the acting actor from client input; break it once and watch it fail.

## Decisions to surface to a human

Session lifetime and cookie policy; local-backend password storage; whether to add
server-side sessions (revocation); the agent token format; TLS termination model.

## Sequencing / relationships

Foundation for Plan 003 (LDAP is an `AuthBackend`) and Plan 004 (teams consume
`fetch_groups`). WI-1→WI-3 are the MVP-blocking core; WI-4 can trail until the agent
client is real but the actor *shape* lands now.
