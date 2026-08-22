# Deploying dossier for a team (Plan 014 WI-1.5)

dossier is the suite's human face. This document is the **reproducible deploy
step** that brings it up for a team: a container served over TLS with LDAP
auth, reading the shared `suite.env`, reachable by team members on the work
network. It is the artifact for Plan 014 WI-1.5; the live cross-machine TLS
login is the operator-gated validation (real LDAP + real certs + the work
network), analogous to the public flip.

Plan 013 already delivered the container image (Dockerfile + pinned regista),
the suite config contract (`REGISTA_DSN`/`REGISTA_KEY_PATH` with `DOSSIER_*`
aliases), `doctor --json` + `/healthz`, secret-backend resolution, and the
Windows Service substrate. WI-1.5 adds the **TLS seam**, the **reproducible
TLS-ready compose**, and extends `doctor` to report TLS / LDAP / suite.env
status — the last packaging gap before a team can log in.

## What you need

- **Postgres 15+** reachable from the dossier host (or the compose's `postgres`
  service).
- **regista provision** already run for each project you front (`regista
  provision --project <slug>`). dossier assumes the spine exists and fails with
  an actionable message if it does not (Plan 013 WI-2.2).
- **An initialized estate trust log** for principal lifecycle operations. The
  trust-log project is distinct from every work project and is initialized once
  from the operator-pinned, signed genesis document plus its root seed.
- **A TLS certificate + key** (operator-provisioned). For a workplace deploy,
  this is an internal-CA or public-CA cert for the host dossier runs on. For a
  local validation, a self-signed pair is fine. **No cert is ever committed.**
- **A `suite.env`** copied from `suite.env.example` with the real DSN, key
  path, and LDAP config. `suite.env` is gitignored.
- **Docker + Compose** on a Linux host (the blueprint substrate decision:
  Linux/Docker or Windows Service — no k8s).

## The reproducible step (Linux/Docker)

From the repo root:

```bash
# 1. Configure the shared suite env (gitignored; never committed).
cp suite.env.example suite.env
$EDITOR suite.env            # set REGISTA_DSN, REGISTA_KEY_PATH, LDAP_*, etc.

# 2. Provision the TLS cert + key (gitignored; never committed).
mkdir -p certs
# place your cert.pem and key.pem in ./certs/
# e.g. self-signed for local validation:
openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/key.pem \
  -out certs/cert.pem -days 365 -subj "/CN=localhost"

# 3. Provision the spine (once per project).
#    With the compose postgres running, point regista at it:
docker compose -f deploy/docker-compose.yml up -d postgres
regista provision --project dossier        # creates the schema + service role
# place the HMAC keyset where suite.env's REGISTA_KEY_PATH points:
regista keys generate --path secrets/dossier-keys.json

# 3a. Provision the estate trust log once (root seed is operator-held; never
#     commit or place it in the work-project keyset).
regista provision --project trust-log
regista --project trust-log trust init-log \
  --genesis "$REGISTA_TRUST_GENESIS_PATH" \
  --key /run/secrets/trust-log-root-seed

# 3b. Set the process-level v6 producer identity in suite.env before starting
#     dossier. Harness + version are required; model + lineage are paired.
REGISTA_PRODUCER_HARNESS=dossier
REGISTA_PRODUCER_HARNESS_VERSION=0.1.0
# REGISTA_PRODUCER_MODEL=MODEL-NAME
# REGISTA_PRODUCER_MODEL_LINEAGE=MODEL-LINEAGE

# 4. Bring up dossier over TLS.
docker compose -f deploy/docker-compose.yml up -d --build

# 5. Reach it.
curl -k https://localhost:8443/healthz      # -k: self-signed (local only)
# In a browser: https://<host>:8443/        # log in with an LDAP credential
```

`docker compose -f deploy/docker-compose.yml` reads `suite.env` (logical config)
and mounts `certs/` + `secrets/` (the cert, keyset, and users file). dossier
serves HTTPS directly via uvicorn's `ssl_certfile`/`ssl_keyfile` (the
`DOSSIER_TLS_CERT_PATH`/`DOSSIER_TLS_KEY_PATH` env seam). The compose maps
`8443 -> 8000` so the team reaches `https://<host>:8443/`.

For an **external Postgres** (the production posture), point `REGISTA_DSN` in
`suite.env` at it and drop the `postgres` service from the compose (or keep it
only for dev). The image is substrate-agnostic: it runs under compose, behind
a reverse proxy, or as a published `ghcr.io` image against an external store.

## Linux systemd service (artifact-only substrate)

For a host installed from the wheel rather than the container — the posture
`agent-suite/docs/install-linux.md` describes — dossier installs its own systemd
unit:

```bash
sudo dossier install-service --dry-run     # report the plan; act on nothing
sudo dossier install-service               # write, enable, start, and verify
sudo dossier install-service --uninstall   # remove it
```

This writes `/etc/systemd/system/dossier.service`, runs `systemctl enable --now`,
and then **verifies** three things before reporting success: that the resolved
`ExecStart` is an absolute existing executable, that systemd's own parse of
`ExecStart` names it, and that the service is `active`. It exits non-zero if any
of those fails — writing a unit file is not the success condition. Run it again
after upgrading dossier; it is idempotent.

`agent-suite install-services` invokes this for you as part of a suite install
(agent-suite WI-044).

The unit is **generated**, not shipped as a static file, because the one
host-specific thing in it is where the CLI lives: systemd resolves an
unqualified `ExecStart` only against its own fixed search path
(`/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, …) and never the
invoking user's `PATH`, so no single file is correct on both a system-scoped
install and a `~/.local/bin` one. If the `dossier` CLI is not resolvable to an
absolute path, `install-service` **refuses** and names the problem rather than
writing a unit that would fail `203/EXEC` at first start. Install the CLI on a
system PATH (`pipx install dossier`, or a venv at `/opt` linked into
`/usr/local/bin`) or pass `--bin-dir`.

`deploy/systemd/dossier.service` is a **reference rendering** against
`/usr/local/bin` for review and manual install; `tests/test_service_unit.py`
keeps it byte-identical to the generator.

Defaults and the flags that change them:

| Flag | Default | Notes |
|---|---|---|
| `--host` | `127.0.0.1` | Matches `dossier serve`. Installing a service must not widen a host's exposure as a side effect — pass `--host 0.0.0.0` (behind TLS or a reverse proxy) deliberately. |
| `--port` | `8000` | |
| `--user` | `root` | `/etc/agent-suite/suite.env` and any TLS material it points at are root-owned. Pass a dedicated service account if you have one; the account must exist, or the unit fails `217/USER`. |
| `--unit-dir` | `/etc/systemd/system` | |

The unit reads `EnvironmentFile=-/etc/agent-suite/suite.env` (the shared suite
config) and then `-/etc/dossier/dossier.env` (dossier-specific overrides). Both
are optional, and no value is baked into the unit.

## Windows Service (alternative substrate)

For a Windows host, use the WinSW service wrapper in
[`deploy/winsw/`](../deploy/winsw/) (Plan 013 WI-4.1): `install.ps1` creates a
venv, generates the env file, and installs + starts the service. The same
`DOSSIER_TLS_*` env seam applies — set the cert/key paths in the generated
`dossier-env.cmd` so the service serves over TLS. See
[`deploy/winsw/README.md`](../deploy/winsw/README.md).

## Configuration reference

All config is env-driven (process env > `suite.env` > tool default). The
canonical spine vars are shared across the suite; dossier-specific concerns
keep their `DOSSIER_*` names.

Principal lifecycle writes are a two-chain operation: dossier's work projects
remain ordinary v6 project chains, while enrollment, rotation, and revocation
events are appended to the estate-wide trust-log project. Configure both trust
variables explicitly; dossier never falls back to the current work project.

| Variable | Purpose |
|---|---|
| `DOSSIER_ENV` | `dev` (default) or `prod` — promotes safe defaults and escalates doctor posture gaps (Plan 015 WI-1.1) |
| `DOSSIER_ALLOWED_HOSTS` | comma-separated allowed Host headers; wires `TrustedHostMiddleware` when set |
| `REGISTA_DSN` | Postgres DSN (canonical; alias `DOSSIER_DATABASE_URL`) |
| `REGISTA_KEY_PATH` | HMAC keyset path (canonical; alias `DOSSIER_HMAC_KEY_PATH`) |
| `REGISTA_TRUST_LOG_PROJECT` | distinct estate-wide trust-log schema for principal lifecycle events |
| `REGISTA_TRUST_GENESIS_PATH` | operator-pinned signed trust-genesis document for lifecycle authority |
| `REGISTA_PRODUCER_HARNESS` / `_VERSION` | required process-level v6 producer identity; set to the actual harness and release |
| `REGISTA_PRODUCER_MODEL` / `_MODEL_LINEAGE` | optional model producer metadata; set both together, or leave both unset |
| `DOSSIER_PROJECT` / `DOSSIER_PROJECTS` | regista project(s) to front |
| `DOSSIER_SESSION_SECRET` | signed-cookie secret (>= 32 bytes; never committed) |
| `DOSSIER_SECURE_COOKIES` | `true` for TLS deploys, `false` for dev |
| `DOSSIER_AUTH_BACKEND` | `local` (JSON users) or `ldap` (the workplace directory) |
| `DOSSIER_PROJECT_ACCESS_MODE` | `enforce` (the default, deny-by-default), `audit`, or `open` (explicit opt-in) |
| `DOSSIER_PROJECT_ACL_PATH` | project ACL JSON (the per-project grants for `audit`/`enforce`) |
| `DOSSIER_BOOTSTRAP_ADMINS` | administrator principals/group-claims that need no ACL file — the recovery path (see `docs/project-access.md`) |
| `DOSSIER_TLS_CERT_PATH` | TLS cert path — set both to serve HTTPS, unset for HTTP |
| `DOSSIER_TLS_KEY_PATH` | TLS key path — set both to serve HTTPS, unset for HTTP |
| `DOSSIER_BEHIND_TLS_PROXY` | `true` when an ingress/proxy terminates HTTP TLS for dossier |
| `DOSSIER_LDAP_SERVER` | comma-separated `ldaps://` URLs (multi-DC failover) |
| `DOSSIER_LDAP_BASE_DN` / `_BIND_DN` / `_BIND_PASSWORD` | search-then-bind creds |
| `DOSSIER_LDAP_DOMAIN` | appears in `Principal.source` as `ldap:<domain>` |
| `DOSSIER_LDAP_CA_CERT_FILE` | AD root CA PEM (pinning; never `validate=NONE`) |
| `DOSSIER_LDAP_PRINCIPAL_ID_ATTR` | directory attribute holding each human's regista `principal_id`; unset = LDAP identities are unbound (WI-035) |
| `DOSSIER_HUMAN_SIGNING` | `require` (refuse a human write that could only be signed with the shared store key — the default in prod) or `warn` (record it, loudly). See the migration below |

Either `REGISTA_DSN` or `REGISTA_KEY_PATH` may be a secret-backend ref
(`env:`/`file:`/`vault:`/`azure:`) so no plaintext secret sits on the host
(Plan 013 WI-4.1). A literal DSN / bare key path passes through unchanged.

## Health check

`dossier doctor --json` and `GET /healthz` report the suite-conformant shape:

```json
{
  "component": "dossier",
  "version": "0.0.1",
  "ok": true,
  "degraded": true,
  "regista": {"reachable": true, "project": "dossier", "chain_ok": null},
  "checks": [
    {"name": "tls", "status": "ok", "detail": "cert=/run/secrets/tls/cert.pem"},
    {"name": "suite_env", "status": "ok", "detail": "loaded /path/to/suite.env"},
    {"name": "auth_backend", "status": "ok", "detail": "ldap configured (bind not checked in health probe)"},
    {"name": "session_secret", "status": "ok", "detail": null},
    {"name": "principal_lifecycle", "status": "ok", "detail": "trust-log project 'trust-log' reachable for 1 work project(s)"},
    {"name": "secrets_backend", "status": "skip", "detail": "no backend refs configured (plaintext/file path)"}
  ]
}
```

The `tls` check is `warn` when TLS is off (plain HTTP — dev), `ok` when the
cert+key resolve, and `fail` when TLS is half-configured (one path set or a
file missing). The `suite_env` check reports which config file is active. The
`auth_backend` check reports LDAP config completeness (the live bind is
operator-gated and not exercised by a health probe). An unreachable regista or
LDAP is a named `fail`, never a 500.

## Production posture (`DOSSIER_ENV=prod`, Plan 015 WI-1.1)

The dev defaults are deliberately permissive so a fresh checkout runs without
ceremony: `require_ssl=false`, no TLS, no host allowlist. Project access is the
exception — it is deny-by-default in dev too (WI-017). **Set
`DOSSIER_ENV=prod` for every team deploy** to promote the safe defaults:

- `require_ssl` defaults to `true` (the operator may still override via
  `DOSSIER_REQUIRE_SSL`). Note: `require_ssl` governs the **Postgres
  connection's** SSL requirement (passed to `regista.Regista(require_ssl=...)`),
  not the HTTP listener's TLS. An operator behind a TLS-terminating proxy with
  a local plaintext database connection should set `DOSSIER_REQUIRE_SSL=false`.
  The HTTP listener's TLS is controlled independently by
  `DOSSIER_TLS_CERT_PATH` / `DOSSIER_TLS_KEY_PATH`; a proxy deployment declares
  its equivalent posture with `DOSSIER_BEHIND_TLS_PROXY=true`.
- `project_access_mode` is `enforce` unless you say otherwise, in every
  environment (WI-017). Pair it with `DOSSIER_PROJECT_ACL_PATH` so
  cross-project disclosure is default-deny against a real policy. `enforce`
  with no ACL and no `DOSSIER_BOOTSTRAP_ADMINS` denies everything: the app
  still starts (so the doctor can **report** the gap as a `fail` rather than
  crash `load_settings`), `/healthz` returns 503, and startup logs an error
  naming both variables. See `docs/project-access.md` for the migration and
  recovery path.
- `human_signing` defaults to `require` (WI-035): a human action that could
  only be signed with the shared store HMAC key is **refused** rather than
  recorded without attribution. Clean regista v6 epochs have no shared write
  key, so `warn` is only a legacy-backend compatibility mode; on v6 it logs the
  attempted downgrade and refuses too.
- The doctor escalates posture gaps from `warn` to `fail` in prod: open
  access, missing TLS, missing/short session secret, missing `users_path` for
  the local backend, and unbound human signing identities. In dev these remain
  `warn`/informational.

`DOSSIER_ALLOWED_HOSTS` wires Starlette's `TrustedHostMiddleware` (only when
set, so dev is unaffected). In prod, pin it to the host(s) the team reaches
dossier through; the doctor warns when prod lacks it. dossier is expected
behind a TLS-terminating proxy in prod — the app does not silently redirect
to HTTPS (that would break health probes), but the TLS seam must be evident.

`dev` (the default) preserves every historical default for backwards
compatibility — the promotion is opt-in via `DOSSIER_ENV=prod`.

## Migrating to per-actor human signing

Before WI-035, dossier signed human events under the auth backend's `stable_id`
(a local uuid or an LDAP `objectGUID`). No signing key is registered against those,
so regista fell back to the **shared store HMAC key** and the human leg of every
chain came out as `unverifiable (symmetric scheme)`. The rationale is in
[provenance-model.md](provenance-model.md); this is the operational path.

**Upgrading changes nothing until you bind an identity.** An unbound identity keeps
the `actor_id` it always had. On a legacy backend, `warn` reports the downgrade
while provisioning is in progress; on a clean v6 epoch the write is refused in
every posture until it is bound. So do this in order.

### 1. See where you stand

```bash
dossier doctor           # or: curl -s localhost:8000/healthz | jq '.checks[] | select(.name=="human_signing")'
```

The `human_signing` check names every local identity with no `principal_id`, and every
recorded `principal_id` with no active per-actor key. On the LDAP backend it reports
whether `DOSSIER_LDAP_PRINCIPAL_ID_ATTR` is wired (it cannot enumerate the directory —
health does not make directory calls).

### 2. Keep the deployment running while you provision

If you are already on `DOSSIER_ENV=prod`, set the escape hatch *first*, so the upgrade
cannot refuse an acceptance before anyone has a key:

```env
DOSSIER_HUMAN_SIGNING=warn
```

On a legacy backend, each fallback logs
`provenance.human_signature_downgraded` and returns
`X-Dossier-Human-Signing: downgraded`. A clean v6 epoch refuses the write after
logging the attempted downgrade, so operators must provision before accepting work.

### 3. Provision a signing key per human

```bash
agent-suite bootstrap --user alice      # enrolls the principal and writes its Ed25519 key
```

This is idempotent and will not clobber an existing key (agent-suite
`docs/multi-user-onboarding.md` §5).

### 4. Record the binding on the identity

**local backend** — add `principal_id` to the user's entry in `DOSSIER_USERS_PATH`:

```json
{
  "stable_id": "4814fec5-7b84-4f61-ae43-99a91dc76a63",
  "username": "alice",
  "display_name": "Alice",
  "password": "scrypt:...",
  "principal_id": "alice"
}
```

**ldap backend** — set `DOSSIER_LDAP_PRINCIPAL_ID_ATTR` to the attribute carrying the
principal id (often `sAMAccountName`; a dedicated attribute if logon names and
principal ids differ), and make sure it is populated for each onboarded human.

An invalid `principal_id` fails at load for the local backend and is logged and
treated as unbound for LDAP — it never silently becomes a store-key signature.

**Each bound human must re-authenticate.** The actor is resolved at login and
carried in the signed session cookie, so somebody with a live session keeps acting
under their pre-binding id until they log in again — restarting dossier does not
change that. Have them log out and back in (or shorten
`DOSSIER_SESSION_MAX_AGE_SECONDS` for the changeover window) before you expect the
doctor's verdict to match what people actually sign with.

### 5. What the binding changes, and what it does not

A bound human's `actor_id` becomes their `principal_id`. Plan for that:

- **Authorization keeps working.** The old `stable_id` is retained as an
  authorization alias, so existing `DOSSIER_PROJECT_ACL_PATH` entries,
  `DOSSIER_BOOTSTRAP_ADMINS` entries, and project-owner records that name the uuid
  still match. You can migrate them to the `principal_id` at your leisure; you do not
  have to do it in the same window.
- **History does not move.** Events already written keep the `stable_id` they were
  signed under — rewriting them is neither possible nor desirable (that is G2). A
  bound human's *past* activity therefore appears under the old id and their new
  activity under the `principal_id`. If that split matters for a given person, note the
  changeover date; it is a one-time discontinuity.
- **`assignee` fields are free text.** Items assigned to the uuid keep that value.
  Reassign them if you want the new id to match.

### 6. Turn on refusal

Once `dossier doctor` reports `human_signing: ok`, remove the escape hatch (or set
`DOSSIER_HUMAN_SIGNING=require` explicitly) and restart. From then on a human action
that cannot be signed by that human is refused with a `409` naming the fix, rather
than recorded as something nobody can be held to.

## Operator-gated validation (not delivered here)

These need the workplace infra and cannot be exercised in unit CI — the
artifact + local validation is delivered; the live validation is owner-gated:

- **Real LDAP bind** — `DOSSIER_LDAP_*` pointing at the real directory, the
  bind account, and the AD root CA. The config seam + a mocked test mode are
  delivered; the live bind is operator-gated infra.
- **Cross-machine TLS login** — a team member on a second machine on the work
  network reaching `https://<host>:8443/` and logging in with an LDAP
  credential. Needs the real cert + DNS/hosts reachability on the network.
- **Real certificate provisioning** — the cert+key pair. Self-signed is used
  for local validation; production uses a CA-signed cert.

## Multi-worker lifecycle challenges: schema 50 / DURABLE_ONE_USE required

The key-lifecycle exchange (enrollment, rotation, effective-use) requires
`ChallengeStorageScope.DURABLE_ONE_USE` for multi-worker correctness: challenges
are persisted to the database (schema ≥ 50) and rehydratable by any worker.
This is the **only supported path** for production multi-worker deployments.

**Requirement:** the `SUITE.lock` `[spine].version` must pin a regista release
that ships schema 50 and `DURABLE_ONE_USE`. If the pinned release exposes only
`PROCESS_LOCAL_FOUNDATION`, multi-worker deployment is **not supported** and
the operator must run a single worker (`--workers 1`) until the spine is
upgraded. Sticky sessions are not a supported workaround — they mask a
correctness gap and create silent failure modes on worker restart.

Doctor does not yet compare challenge storage scope with worker count. Until
that check lands, operators must verify `DURABLE_ONE_USE` during deployment;
this missing automated check remains a production-qualification gap.

## No plaintext secret on the host

- `suite.env`, `certs/`, `secrets/` are gitignored — nothing real is committed.
- The container reads config from the environment / mounted secrets; nothing
  is baked into the image.
- Remote secret backends (`vault:`/`azure:`) materialize the keyset to a 0600
  temp file scrubbed at shutdown — no persisted plaintext key (Plan 013 WI-4.1).
