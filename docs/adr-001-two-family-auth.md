# ADR-001: Two-family auth design (credential vs federated)

**Date:** 2026-06-29
**Status:** Accepted
**Plans:** 002 (Auth & identity), 003 (LDAP integration)

## Context

dossier authenticates UI users via a backend Protocol. Plan 002 defined an
`AuthBackend` protocol with `authenticate(identifier, password) → Principal`,
and Plan 003 adds an `LdapBackend` implementing it. Both `LocalBackend` and
`LdapBackend` are *credential-in-hand* backends: a password arrives at `/login`
and is verified synchronously.

Microsoft Entra ID (OIDC) is a likely future adoption path for the homelab
and for any org running dossier. OIDC is *not* credential-in-hand — it is a
two-step redirect flow (`/login` → IdP → `/auth/callback?code=…` → token
exchange). The risk is not the method signature alone; it is the single-step
credential assumption baked into the `/login` route.

## Decision

**Two backend families, both converging on `Principal → Actor`:**

1. **Credential backends** (`CredentialBackend` Protocol): verify a supplied
   password against a directory or local store. `LocalBackend` and `LdapBackend`
   today. They implement `authenticate(identifier, password) → Principal`.

2. **Federated backends** (future, not built): exchange a token from an IdP for
   a `Principal`. They will *not* implement `CredentialBackend` — they have no
   password to verify. They get a new route (`/auth/callback`) and a new
   backend family.

**The keystone that makes this safe:** `principal_to_actor`
(`auth/resolver.py`) is the single point where *any* verified identity becomes
the regista `Actor`. Credential and federated backends both produce a
`Principal`; the resolver doesn't care which family produced it.

### Three guardrails landed now (Plan 003, WI-7/WI-8/WI-9)

1. **WI-7 — Rename `AuthBackend` → `CredentialBackend`.** The Protocol name now
   describes what it is: a credential-in-hand contract. `AuthBackend` is
   reserved for the umbrella concept if needed later. Pure rename; behavior
   unchanged.

2. **WI-8 — Quarantine the credential assumption to a route helper.**
   `_credential_login(request, backend) → (Principal | None, is_form_request)`
   in `app.py` isolates the form/JSON field-reading + `backend.authenticate()`
   block. A future Entra `/auth/callback` route is a sibling that never edits
   this path.

3. **WI-9 — This ADR.** Records the decision so the next agent doesn't
   re-derive it.

### What already makes Entra additive (must not be disturbed)

- `Principal.stable_id` is source-agnostic (uuid / `objectGUID` / Entra `oid`
  all fit). `Principal.source` distinguishes them.
- `principal_to_actor` is the single keystone — every backend, credential or
  federated, converges on `Principal → Actor`.
- Group authz reads `raw_attributes["groups"]` / `fetch_groups()`. LDAP
  `memberOf` and the Entra `groups` claim populate it identically — so Plan 004
  RBAC built on this is provider-neutral for free.

## Explicitly deferred

The OIDC flow itself — redirect, PKCE, JWKS/token validation, the
`/auth/callback` route — is **not built speculatively**. It slots in as a new
backend family + one new route, touching neither the LDAP nor the local
credential path.
