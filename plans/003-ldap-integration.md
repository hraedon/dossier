# Plan 003 — LDAP / Active Directory integration

**Status:** Proposed 2026-06-20. Implements an `LdapBackend` for the `AuthBackend`
protocol in `002-auth-and-identity.md`. Not started.
**Author:** Opus 4.8
**Strategic role:** Authenticate UI users against AD and source their group
membership, so identity (and later teams, Plan 004) comes from the directory the
org already runs — not a hand-managed user list. Reuses cert-watch's proven LDAP
approach and the homelab AD for real validation.

## Ground truth at time of writing

- `ldap3` is gated behind the `[auth-ldap]` extra (already in `pyproject.toml`).
- cert-watch authenticates against `ad.example.com` over LDAPS today (DCs
  `mvmdc0{1,2,3}` on :636) and has both a samba-container e2e and a real-AD remote
  login script — patterns to adapt.
- A least-privilege bind account exists for the homelab (`svc-gpolens`, Vault) and is
  sufficient for read/search during dev and integration tests.

## Principles this plan must hold

- **Key the actor on `objectGUID`, not `sAMAccountName` or DN.** `sAMAccountName`
  can be reused/renamed and a DN moves when an object changes OU; `objectGUID` is
  immutable. This is what makes provenance attribution (002 G1) survive directory
  churn. Store `sAMAccountName` / `displayName` in `actor_metadata` for legibility.
- **LDAPS with real certificate validation — pin the AD CA.** No
  `validate=NONE`. The certifi-vs-Windows-store and CA-leaf gotchas from the ADCS
  work apply (`reference-adcs-certsrv-client-gotchas`): pin the Hraedon Root /
  issuing CA rather than trusting the ambient bundle.
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

## Work items

- **WI-1 — `LdapBackend.authenticate()`** via search-then-bind; reject empty
  password / anonymous bind.
- **WI-2 — Stable-id extraction (`objectGUID`)** + `actor_metadata` population,
  feeding 002 WI-3.
- **WI-3 — Group membership retrieval** (`memberOf` + nested via `tokenGroups`),
  returning group GUID+name for Plan 004.
- **WI-4 — LDAPS + CA pinning**, reusing the ADCS root-pin lessons; no disabled
  validation.
- **WI-5 — Config & secret handling** (env/Vault; `svc-gpolens` bind for homelab dev
  and integration), `.env.example` with placeholders only.
- **WI-6 — Tests:** mocked-`ldap3` unit tests + a real-AD integration test against
  `ad.example.com`. **Run them and watch one fail before trusting them** — the
  cert-watch broken-on-arrival LDAP test is the cautionary tale.

## Decisions to surface to a human

The stable-id attribute (recommend `objectGUID`); nested-group strategy; bind-account
privilege and secret source; multi-DC failover behavior; how aggressively to cache
group membership (staleness vs directory load).

## Sequencing / relationships

Depends on Plan 002 (it *is* an `AuthBackend`). Produces the group data Plan 004
turns into teams. Independent of the core tracker UI — can land in parallel once 002
WI-2/WI-3 exist.
