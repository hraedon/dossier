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

| Variable | Purpose |
|---|---|
| `DOSSIER_ENV` | `dev` (default) or `prod` — promotes safe defaults and escalates doctor posture gaps (Plan 015 WI-1.1) |
| `DOSSIER_ALLOWED_HOSTS` | comma-separated allowed Host headers; wires `TrustedHostMiddleware` when set |
| `REGISTA_DSN` | Postgres DSN (canonical; alias `DOSSIER_DATABASE_URL`) |
| `REGISTA_KEY_PATH` | HMAC keyset path (canonical; alias `DOSSIER_HMAC_KEY_PATH`) |
| `DOSSIER_PROJECT` / `DOSSIER_PROJECTS` | regista project(s) to front |
| `DOSSIER_SESSION_SECRET` | signed-cookie secret (>= 32 bytes; never committed) |
| `DOSSIER_SECURE_COOKIES` | `true` for TLS deploys, `false` for dev |
| `DOSSIER_AUTH_BACKEND` | `local` (JSON users) or `ldap` (the workplace directory) |
| `DOSSIER_PROJECT_ACCESS_MODE` | `open` (dev default), `audit`, or `enforce` (prod default when ACL set) |
| `DOSSIER_PROJECT_ACL_PATH` | project ACL JSON (required for `audit`/`enforce`) |
| `DOSSIER_TLS_CERT_PATH` | TLS cert path — set both to serve HTTPS, unset for HTTP |
| `DOSSIER_TLS_KEY_PATH` | TLS key path — set both to serve HTTPS, unset for HTTP |
| `DOSSIER_LDAP_SERVER` | comma-separated `ldaps://` URLs (multi-DC failover) |
| `DOSSIER_LDAP_BASE_DN` / `_BIND_DN` / `_BIND_PASSWORD` | search-then-bind creds |
| `DOSSIER_LDAP_DOMAIN` | appears in `Principal.source` as `ldap:<domain>` |
| `DOSSIER_LDAP_CA_CERT_FILE` | AD root CA PEM (pinning; never `validate=NONE`) |

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
  "regista": {"reachable": true, "project": "dossier", "chain_ok": true},
  "checks": [
    {"name": "tls", "status": "ok", "detail": "cert=/run/secrets/tls/cert.pem"},
    {"name": "suite_env", "status": "ok", "detail": "loaded /path/to/suite.env"},
    {"name": "auth_backend", "status": "ok", "detail": "ldap configured (bind not checked in health probe)"},
    {"name": "session_secret", "status": "ok", "detail": null},
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

The dev defaults (the historical behavior) are deliberately permissive so a
fresh checkout runs without ceremony: `require_ssl=false`,
`project_access_mode=open`, no TLS, no host allowlist. **Set
`DOSSIER_ENV=prod` for every team deploy** to promote the safe defaults:

- `require_ssl` defaults to `true` (the operator may still override via
  `DOSSIER_REQUIRE_SSL`).
- `project_access_mode` defaults to `enforce` when `DOSSIER_PROJECT_ACL_PATH`
  is set — pair `DOSSIER_ENV=prod` with an ACL so cross-project disclosure is
  default-deny. When no ACL is set in prod, the mode falls back to `open` so
  the doctor can **report** the posture gap as a `fail` rather than crash
  `load_settings`; an explicit `DOSSIER_PROJECT_ACCESS_MODE=enforce` without
  an ACL is still a hard `RuntimeError` (you cannot enforce without a policy).
- The doctor escalates posture gaps from `warn` to `fail` in prod: open
  access, missing TLS, missing/short session secret, missing `users_path` for
  the local backend. In dev these remain `warn`/informational.

`DOSSIER_ALLOWED_HOSTS` wires Starlette's `TrustedHostMiddleware` (only when
set, so dev is unaffected). In prod, pin it to the host(s) the team reaches
dossier through; the doctor warns when prod lacks it. dossier is expected
behind a TLS-terminating proxy in prod — the app does not silently redirect
to HTTPS (that would break health probes), but the TLS seam must be evident.

`dev` (the default) preserves every historical default for backwards
compatibility — the promotion is opt-in via `DOSSIER_ENV=prod`.

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

## No plaintext secret on the host

- `suite.env`, `certs/`, `secrets/` are gitignored — nothing real is committed.
- The container reads config from the environment / mounted secrets; nothing
  is baked into the image.
- Remote secret backends (`vault:`/`azure:`) materialize the keyset to a 0600
  temp file scrubbed at shutdown — no persisted plaintext key (Plan 013 WI-4.1).
