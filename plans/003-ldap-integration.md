# Plan 003 — LDAP / Active Directory integration

**Status:** Proposed 2026-06-20; amended 2026-06-29 to add Entra-readiness
guardrails (decision: guardrails only, no OIDC code now). Implemented
2026-06-29 (all 9 work items landed; 30 mocked unit tests + 5 integration test
scaffolding). Implements an `LdapBackend` for the auth backend protocol in
`002-auth-and-identity.md`.
**Author:** Opus 4.8
**Strategic role:** Authenticate UI users against AD and source their group
membership, so identity (and later teams, Plan 004) comes from the directory the
org already runs — not a hand-managed user list. Reuses cert-watch's proven LDAP
approach and the homelab AD for real validation. **Also lands the cheap seam work
so eventual Microsoft Entra (OIDC) adoption is additive, not a refactor** — see
"Entra-readiness" below.

## Ground truth at time of writing

- `ldap3` is gated behind the `[auth-ldap]` extra (already in `pyproject.toml`).
- cert-watch authenticates against a real AD over LDAPS today (multiple DCs
  on :636) and has both a samba-container e2e and a real-AD remote
  login script — patterns to adapt.
- A least-privilege bind account exists for the homelab (service-account, Vault) and is
  sufficient for read/search during dev and integration tests.

## Principles this plan must hold

- **Key the actor on `objectGUID`, not `sAMAccountName` or DN.** `sAMAccountName`
  can be reused/renamed and a DN moves when an object changes OU; `objectGUID` is
  immutable. This is what makes provenance attribution (002 G1) survive directory
  churn. Store `sAMAccountName` / `displayName` in `actor_metadata` for legibility.
- **LDAPS with real certificate validation — pin the AD CA.** No
  `validate=NONE`. The certifi-vs-Windows-store and CA-leaf gotchas from the ADCS
  work apply: pin the AD Root / issuing CA rather than trusting the ambient bundle.
- **Least-privilege bind.** The service account reads/searches only; it never needs
  write. Bind secret comes from env/Vault, never committed.

## Design

**Authenticate = search-then-bind (the standard safe flow).**
1. Bind as the service account; search for the user by
   `sAMAccountName`/`userPrincipalName` under the configured base DN with a
   configurable filter (e.g. `(&(objectClass=user)(sAMAccountName={login}))`).
2. Re-bind as the found user DN with their supplied password to verify it.
3. On success, build the `Principal`: `stable_id = objectGUID`,
   `display_name = displayName/cn`, `source = "ldap:<domain>"`,
   `raw_attributes` = the fetched attrs.

Never bind with the user's raw login as DN, and never accept an empty password
(AD may treat an empty password bind as an anonymous success — explicitly reject).

**Group membership.** Retrieve `memberOf`; for nested groups use `tokenGroups`
(constructed attribute) or an `LDAP_MATCHING_RULE_IN_CHAIN` query, configurable.
Return group identities (prefer group `objectGUID` + name) — this is what Plan 004
maps to teams. Group fetch is read-only via the service account.

**TLS.** `ldaps://` on :636 with CA pinning. Document the cert-source gotcha so a
Windows host doesn't silently fall back to the wrong trust store. Verify connectivity
with an out-of-box check, not an in-box .NET assumption (the cert-watch lesson).

**Config.** Server URI(s) (multiple DCs, failover), base DN, bind DN + secret ref,
user filter, group strategy, attribute names, connection timeout, referral policy.
All via env/secret; a documented `.env.example` with placeholders (no real domain).

## Entra-readiness (guardrails, not OIDC — decided 2026-06-29)

LDAP is bind-style: credentials arrive at `/login`, the backend verifies them
synchronously, a `Principal` comes back. That fits the current
`authenticate(identifier, password)` Protocol and the single-step `/login` route
exactly. **Entra/OIDC does not** — it is a two-step redirect flow (`/login` →
IdP → `/auth/callback?code=…` → token exchange). The risk is not the method
signature alone; it is the *single-step credential-in-hand assumption baked into
the `/login` route* (`app.py`). The decision (2026-06-29) is to make Entra
*additive* with three near-zero-cost guardrails now, and to **defer all OIDC
code** until Entra is actually scheduled.

What already makes Entra additive and must NOT be disturbed:
- `principal_to_actor` (`auth/resolver.py`) is the single keystone — every
  backend, credential or federated, converges on `Principal → Actor`. OIDC will too.
- `Principal.stable_id` is source-agnostic (uuid / `objectGUID` / Entra `oid` all
  fit) and `Principal.source` distinguishes them. LDAP uses `objectGUID`; Entra
  will use the `oid` claim.
- Group authz reads `raw_attributes["groups"]` / `fetch_groups()`. LDAP `memberOf`
  and the Entra `groups` claim populate it identically — **so Plan 004 RBAC built
  on this is provider-neutral for free.** Do not special-case the directory there.

Explicitly **deferred** (do not build speculatively): the OIDC flow itself —
redirect, PKCE, JWKS/token validation, the `/auth/callback` route. The guardrails
below mean it slots in as a new backend family + one new route, touching neither
the LDAP nor the local credential path.

## Work items

- **WI-1 — `LdapBackend.authenticate()`** via search-then-bind; reject empty
  password / anonymous bind.
- **WI-2 — Stable-id extraction (`objectGUID`)** + `actor_metadata` population,
  feeding 002 WI-3.
- **WI-3 — Group membership retrieval** (`memberOf` + nested via `tokenGroups`),
  returning group GUID+name for Plan 004.
- **WI-4 — LDAPS + CA pinning**, reusing the ADCS root-pin lessons; no disabled
  validation.
- **WI-5 — Config & secret handling** (env/Vault; service-account bind for homelab dev
  and integration), `.env.example` with placeholders only.
- **WI-6 — Tests:** mocked-`ldap3` unit tests + a real-AD integration test against
  the real AD. **Run them and watch one fail before trusting them** — the
  cert-watch broken-on-arrival LDAP test is the cautionary tale.

### Entra-readiness guardrails (do while touching auth; no OIDC code)

- **WI-7 — Rename the Protocol `AuthBackend` → `CredentialBackend`** (it is a
  credential-in-hand contract). Reserve the name `AuthBackend` for the umbrella
  concept. This single change stops a future federated backend from being forced
  through `authenticate(id, password)`. Update `auth/backends.py`, `app.py` import,
  and the `auth/__init__.py` docstring. Pure rename — LDAP/Local behavior unchanged.
- **WI-8 — Quarantine the credential assumption to a route helper.** Extract the
  form/JSON field-reading + `backend.authenticate(...)` block in `/login`
  (`app.py`) into a small `_credential_login(request, backend) -> Principal | None`
  helper. LDAP and Local use it unchanged; a future Entra `/auth/callback` route is
  a sibling that never edits the credential path.
- **WI-9 — One-page ADR** (`docs/`) recording the two-family auth design
  (credential vs federated; both → `Principal` → `principal_to_actor`) and the
  explicit OIDC deferral, so the next agent doesn't re-derive it. Mirrors the
  team's existing habit of documenting seams (the Plan-004 `fetch_groups` comment).

## Decisions to surface to a human

The stable-id attribute (recommend `objectGUID`); nested-group strategy; bind-account
privilege and secret source; multi-DC failover behavior; how aggressively to cache
group membership (staleness vs directory load).

## Sequencing / relationships

Depends on Plan 002 (it *is* an `AuthBackend`). Produces the group data Plan 004
turns into teams. Independent of the core tracker UI — can land in parallel once 002
WI-2/WI-3 exist.
