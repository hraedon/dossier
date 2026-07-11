# dossier

The lightest human-facing **work-item tracker** that earns its keep as a
**provenance instrument**. A small team logs, assigns, and tracks issues through a
web UI; underneath, every change is a signed, hash-chained event with a real actor
(human *or* agent) attached. Each work-item accumulates a *dossier* — a tamper-
evident, human-readable record of everything that happened to it and who did it.

It is not a clean-room Jira clone. It is a thin UI + auth + workflow over
[regista](https://github.com/hraedon/regista), which already provides the
durable state, validated transitions, event history, and signing.

## Why it exists

Two real needs converge:

1. **A team tracker that doesn't depend on production infra.** The existing Jira
   is moving to the cloud; we want a self-hosted, dedicated-infra tracker the team
   controls, in the lightest form that's actually usable.
2. **Getting provenance off the ground.** In a regulated setting, agent tooling is
   blocked by audit/provenance gaps. dossier is where humans and agents act on the
   same work-items and *every* action is provably attributed and verifiable — the
   concrete artifact the provenance argument has been missing.

The bet: these aren't two projects. The identity/auth a tracker needs *is* the
root of provenance, and the activity log a tracker needs *is* the verified event
chain. Build the tracker honestly and you get the provenance for free.

## What it is (architecturally)

- **Backend: regista.** dossier owns no schema for work state. Work-items, states,
  transitions, custom fields, links, actors, claims, and the event log all live in
  regista (Postgres, schema-per-project). dossier registers regista's **canonical
  workflow** (shipped from regista, shared with agent-notes) and consumes regista's
  facade API.
- **Front end: a server-rendered FastAPI web app** (Jinja + the
  [patina](https://github.com/hraedon/patina) design system), in the cert-watch /
  gpo-lens family style. No SPA.
- **Identity: real actors.** Humans authenticate (LDAP-pluggable, like cert-watch)
  and act as `actor_kind=human`; agents act as `actor_kind=agent` with
  `on_behalf_of` for delegation. This binding is the provenance foundation.
- **Provenance: regista's built-ins.** HMAC-SHA256 signing + per-work-item event
  hash chain are on from day one. Ed25519, RFC-3161 timestamping, and witness
  co-signing are config seams regista already exposes — deferred, not redesigned.

## Scope

**In (MVP):** projects → issues (`bug` / `task`); fixed workflow
(`open → in_progress → blocked / deferred → in_review → in_human_review → done`,
where `done` requires the two-stage review gate or a pre-work triage close);
create / view / edit / reassign / transition; per-project list/board filtered by
status and assignee; comments; and the **verified history view** (the legible
event chain with an integrity check). An HTTP API underneath the UI so an agent
client can later use the same backend.

**Out (MVP):** sprints, epics, custom workflows, custom fields beyond the few
declared, labels/components, email/notifications, cross-issue links, time tracking,
attachments, roles beyond "logged in," full-text search.

**Non-goals:** replacing regista's role as source of truth; becoming feature-parity
with Jira; depending on any production/cloud infrastructure.

## Boundary vs. siblings

- **regista** — the substrate. dossier is a *consumer* and a step toward regista's
  own stated endgame (the "federated pane-of-glass UI"). dossier adds no state
  regista doesn't own.
- **agent-notes** — the *agent* front-end onto regista work-items. dossier is the
  *human* front-end. Long-term they may front the same work-items (a single item
  showing a mixed human+agent chain — the killer provenance demo). The MVP fronts
  its **own** regista project; convergence is a deliberate later step, not drift.
- **agent-provenance** — the deeper attestation stack (DSSE/in-toto at run→PR
  grain). dossier rides regista's *built-in* provenance now and gives
  agent-provenance a real surface to grow against later.

## Status

MVP landed. The provenance foundation is real and verified: the regista gateway
(the sole choke point — a server-resolved `Actor` is injected on every
mutation), the `adversarial_review` validator (structural separation-of-duties:
no self-review; agent-authored work needs a human reviewer), local auth (signed
session + CSRF + principal→actor), and an end-to-end test proving the signed
hash-chain verifies (`replay()==0`) against real Postgres. The server-rendered
UI is live: issue list with filters, issue detail with transitions/comments, the
verified-history view (the integrity-checked event chain), and `DOSSIER-N`
display keys (WI-006). Auth hardening (scrypt N=2^17, login throttling, CSRF)
and LDAP/AD integration (Plan 003) are implemented. mypy --strict is clean.

Not yet done: `docs/publication-review.md` (sanitization review — now written,
see above), LDAP integration tests against real AD (5 skipped tests), and the
multi-project fronting (Plan 011). The repo is private until the publication
review is ratified by a human.

## Installation

Requires **Python 3.12+**.

```bash
cd /projects/dossier
python3 -m venv .venv
source .venv/bin/activate
uv pip install -e ".[dev]"
# Install the sibling regista library editable, or pin a version:
uv pip install -e ../regista
# Or: uv pip install regista==0.4.0
```

For development Postgres, start the compose service. **Note:** this binds
`5432:5432`, the same port regista's `docker-compose.test.yml` uses, so only one
container should run at a time.

```bash
docker compose up -d postgres
```

## Configuration

dossier reads the shared **suite config** on startup: if
`$AGENT_SUITE_CONFIG` is set (or `~/.config/agent-suite/suite.env` or
`/etc/agent-suite/suite.env` exists), it is loaded and any keys not already in
the process environment are injected. Precedence: process env > suite.env >
tool default. This lets you set `REGISTA_DSN` / `REGISTA_KEY_PATH` once in
`suite.env` and have every suite component pick them up.

Copy `.env.example` to `.env` (`.env` is gitignored) and fill in real values.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `REGISTA_DSN` | yes | — | Postgres DSN passed to regista (canonical; `DOSSIER_DATABASE_URL` alias deprecated) |
| `DOSSIER_PROJECT` | no | `dossier` | regista project/schema name |
| `REGISTA_KEY_PATH` | yes | — | path to the regista HMAC keyset JSON (canonical; `DOSSIER_HMAC_KEY_PATH` alias deprecated) |
| `DOSSIER_SESSION_SECRET` | yes | — | secret for itsdangerous signed session cookies |
| `DOSSIER_SESSION_MAX_AGE_SECONDS` | no | `43200` | signed session cookie lifetime |
| `DOSSIER_SECURE_COOKIES` | no | `true` | set `false` only for local dev without TLS |
| `DOSSIER_REQUIRE_SSL` | no | `false` | pass `true` to regista to require an SSL Postgres connection |
| `DOSSIER_USERS_PATH` | to serve | — | path to the local users JSON file (LocalBackend) |
| `DOSSIER_AUTH_BACKEND` | no | `local` | auth backend selector (`local`; `ldap` is Plan 003) |
| `DOSSIER_NOTIFICATION_SINK` | no | — | webhook target; agent-wake ingress is the supported authenticated path |
| `DOSSIER_NOTIFICATION_SECRET_REF` | with agent-wake | — | HMAC secret backend ref shared with the configured wake source |
| `DOSSIER_NOTIFICATION_SOURCE` | no | `dossier` | agent-wake source name used in the signed envelope and header |
| `DOSSIER_NOTIFICATION_IDENTITY` | no | — | sender principal for agent-wake source identity gating |
| `DOSSIER_BASE_URL` | no | `http://localhost:8000` | public origin used for notification deep links |
| `DOSSIER_PROJECT_ACCESS_MODE` | no | `open` | cross-project disclosure posture: `open`, `audit`, or `enforce` |
| `DOSSIER_PROJECT_ACL_PATH` | audit/enforce | — | operator-owned project ACL JSON; symlinks and writable files are refused |

For authenticated human notifications through agent-wake, configure the same
32-byte-or-longer HMAC secret on both sides. Dossier accepts the suite secret-ref
syntax while wake uses its source secret URI:

```dotenv
DOSSIER_NOTIFICATION_SINK=http://127.0.0.1:8788/
DOSSIER_NOTIFICATION_SECRET_REF=env:DOSSIER_WAKE_SECRET
DOSSIER_NOTIFICATION_SOURCE=dossier
DOSSIER_NOTIFICATION_IDENTITY=service:dossier
DOSSIER_BASE_URL=https://dossier.example.com
```

The matching wake source must be named `dossier`, resolve the same secret, allow
`service:dossier` as a trigger identity, and explicitly allow every intended
target principal. Dossier signs the exact v0 body and sends
`X-AgentWake-Source`, `X-AgentWake-Signature`, `X-AgentWake-Event-Id`, and the
optional `X-AgentWake-Identity`. An unsigned sink remains available for a generic
test receiver, but doctor reports that posture as degraded and it is not
agent-wake compatible.

### Project access control

The compatibility default is `open`: every authenticated principal can read
every configured or discovered project, and doctor reports a warning. A team
deployment should progress through `audit` to `enforce`:

```dotenv
DOSSIER_PROJECT_ACCESS_MODE=audit
DOSSIER_PROJECT_ACL_PATH=/etc/dossier/project-acl.json
```

Start from [`project-acl.example.json`](project-acl.example.json). The policy is
strict JSON with version `1`:

- undeclared projects are denied;
- a project is readable through an explicit principal, authenticated group, or
  `public: true` grant (`public` means every authenticated dossier user, never
  anonymous access);
- administrative bypass is explicit in `administrators` and is never inferred
  from `DOSSIER_ADMIN_IDS`;
- LDAP groups are matched by immutable `guid:<objectGUID>` claims; local-test
  groups use case-folded `name:<group>` claims; dossier blinds those identities
  with a domain-separated HMAC before storing them in its signed client-side
  session cookie;
- public projects cannot also carry membership grants;
- duplicate identifiers, duplicate/unknown JSON keys, empty grants, control
  characters, oversized files, symlinks, and group/world-writable policy files
  are rejected.

`audit` loads and evaluates the same policy but permits requests while logging
would-be denials. Once those logs match the intended audience, switch to
`enforce`; direct URLs, cross-project views, activity, provenance, search,
signing history, and mutations all use the same authorization seam. Policy is
loaded once at process startup, so deploy changes atomically and restart dossier.
Doctor reparses the on-disk policy and reports invalid/unreadable configuration
as a failure.

### External PostgreSQL

You can point dossier at an existing Postgres server instead of the local
compose container.

- `REGISTA_DSN` is handed directly to regista as its `dsn`. Use a
  fully-qualified URL such as
  `postgresql://dossier:replace-me@db.example.internal:5432/dossier_owner`.
- `DOSSIER_PROJECT` becomes the Postgres schema name. One regista project lives in
  one schema within the chosen database. Multiple dossier deployments can share a
  single database as long as each uses a distinct project/schema name, or they
  can use separate databases.

#### Least-privilege database role

Create a dedicated role and database. The role needs rights to create a schema
(the project name becomes the schema) and then to create tables and indexes
inside that schema. An example setup:

```sql
CREATE ROLE dossier LOGIN PASSWORD 'replace-with-strong-password';
CREATE DATABASE dossier OWNER dossier;
-- Connect to dossier as a superuser and grant create-schema rights
\c dossier
GRANT CREATE ON DATABASE dossier TO dossier;
```

regista will create the schema on first use. After creation, the role only
needs read/write rights within its own schema; restrict further with
`GRANT USAGE, CREATE ON SCHEMA dossier TO dossier` if you pre-create the schema.

#### TLS/SSL

Use two layers:

1. Psycopg TLS: add `?sslmode=require` (or `verify-full`) to `REGISTA_DSN`
   so the client refuses plaintext.
2. regista-level enforcement: set `DOSSIER_REQUIRE_SSL=true`. When the app factory
   passes `require_ssl=True` to regista, regista checks `pg_stat_ssl` on every
   connection acquisition and raises if TLS is not active.

Server-side, enforce TLS by adding a `hostssl` line in `pg_hba.conf` for the
dossier role and reload Postgres. Plaintext `host` entries for that role should be
removed or narrowed.

#### Connection-pooling caveat

regista uses `SET LOCAL search_path` per transaction to scope each query to the
project schema. This is **incompatible with PgBouncer in transaction-pooling
mode**, because transaction-scoped state may be dispatched across different
physical backends. Use a direct Postgres connection, or run PgBouncer in
**session mode**.

### Signing keys

Generate a regista-compatible HMAC keyset before starting the app:

```bash
mkdir -p /run/secrets
.venv/bin/python -m dossier.cli keys generate --path /run/secrets/dossier-keys.json
chmod 600 /run/secrets/dossier-keys.json
```

Set `REGISTA_KEY_PATH=/run/secrets/dossier-keys.json` and keep the file on
a secrets volume. The file is created with mode `0o600` by default.

### First run

```bash
cp .env.example .env          # edit .env with real values
docker compose up -d postgres
.venv/bin/python -m dossier.cli keys generate --path /run/secrets/dossier-keys.json
.venv/bin/python -m dossier.cli init                       # create project + register workflow
.venv/bin/python -m dossier.cli users add --username alice --display-name "Alice"
.venv/bin/python -m dossier.cli serve                      # http://127.0.0.1:8000
```

`init` creates the regista project/schema and registers the `dossier` workflow
(idempotent). `users add` appends a local user (it prompts for the password).
`serve` runs the FastAPI app against the configured Postgres; the minimal auth
surface (`/healthz`, `/csrf`, `/login`, `/logout`, `/me`) is live — the full
board UI (`plans/001` WI-5) lands next.
