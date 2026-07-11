# Plan 020 — Entra/OIDC federation and step-up authentication

**Status:** Proposed 2026-07-11.  
**Author:** GPT-5.6 Sol.  
**Depends:** Plan 003, Plan 014 project authorization, Plan 015 key UX.  
**Strategic role:** Add workplace SSO without weakening dossier's stable-principal
attribution, and require recent stronger authentication for sensitive operations.

## 1. Decision and scope

Add a federated backend family alongside existing local and LDAP credential
backends. The first provider is single-tenant Microsoft Entra ID through OpenID
Connect authorization-code flow with PKCE. Both families converge on the existing
`Principal → Actor` boundary; neither rewrites workflow or provenance.

The implementation uses a maintained OIDC client/token-validation library rather
than hand-written JWT or OAuth code. Microsoft recommends authorization code with
PKCE and validation of ID-token signature and claims; authorization must use
immutable tenant/object IDs rather than mutable names or email addresses:

- https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow
- https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc
- https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation

## 2. Identity contract

- Stable principal ID is the validated tuple `entra:<tid>:<oid>`.
- `name`/preferred username/email are display-only and never authorize.
- Tenant is explicitly configured and validated; `common`/multi-tenant admission
  is not supported in v1.
- Human versus service-principal token type is validated; an app identity cannot
  enter a human session.
- Existing LDAP objectGUID identities do not silently merge with Entra identities.
  Migration requires a reviewed, signed identity-link event and collision check.
- Group authorization uses Entra group object IDs normalized to the same blinded
  dossier group-claim representation as Plan 014.

Microsoft omits group claims above token size limits and emits an overage signal.
The application must detect that state. It may either fail closed with an
actionable message or query Microsoft Graph using a separately approved,
least-privilege path; it must not treat a missing group claim as an empty,
authorized set or follow an arbitrary endpoint from token content:

- https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference

## 3. Work plan

### Phase 0 — Registration and threat model

#### WI-0.1 — App registration runbook

Document single tenant, redirect URI, supported account type, logout URI, minimal
scopes, client authentication, group/app-role claim choice, certificate/secret
custody, Conditional Access prerequisites, and separate test registration.

#### WI-0.2 — Auth threat model

Cover login CSRF, state/nonce fixation, code interception, redirect confusion,
issuer/audience/tenant substitution, JWKS rotation, token replay, guest users,
service principals, group overage, identity collision/linking, stale groups,
session theft, and step-up downgrade.

### Phase 1 — Federated sign-in

#### WI-1.1 — OIDC backend and routes

Add `/auth/entra/start` and a fixed callback route. Generate one-time state, nonce,
and PKCE verifier bound to the pre-auth session; enforce short expiry and one use;
exchange code server-side; rotate the dossier session on success.

**AC:** unsolicited callback, reused state/code, wrong nonce, wrong redirect,
expired transaction, and parallel-tab confusion fail without creating a session.

#### WI-1.2 — Token validation and key rollover

Validate signature through trusted discovery/JWKS, exact issuer, audience, tenant,
nonce, times, token type, and required identity claims. Cache metadata/keys with
bounded lifetime and safe rollover; an unavailable IdP cannot cause validation to
be skipped.

**AC:** adversarial fixtures for every claim and signing-key failure are distinct;
network/cache failure is not an allow path.

#### WI-1.3 — Principal and group resolution

Map validated `tid+oid`, display metadata, group object IDs, app roles, and overage
state into `Principal`. Graph fallback, if enabled, uses explicit Microsoft Graph
endpoints, least privilege, pagination/limits, timeout, cache freshness, and
fail-closed authorization.

#### WI-1.4 — Session lifecycle and logout

Track auth method/time, tenant, session issuance, and group-claim freshness in
server-trusted session state. Provide local logout and documented IdP logout
semantics; do not claim immediate global revocation without a real signal/check.

### Phase 2 — Identity migration and lifecycle

#### WI-2.1 — LDAP-to-Entra identity links

Provide an admin-assisted migration that proves both identities, checks historical
signer/principal collisions, records who approved the link, and preserves old
attribution. Never rewrite historical actor IDs.

#### WI-2.2 — Disable/offboard behavior

Define maximum session/group staleness, periodic reauthentication, explicit
revocation intake where available, and the relationship to Plan 015 key
revocation. Directory disablement and signing-key revocation are distinct recorded
controls.

### Phase 3 — Step-up authentication

#### WI-3.1 — Protected-operation registry

Require recent step-up for key enrollment/rotation/revocation, break-glass,
project ACL/auth changes, secret-reference changes, evidence disclosure/export,
and other Plan 022 sensitive applies. Each operation declares required auth
context, freshness, and whether two-person approval also applies.

#### WI-3.2 — Entra authentication context

Use Conditional Access authentication context/claims challenges and validate the
returned `acrs` context before continuing. Bind the successful step-up to the
exact pending action digest, principal, browser session, and short expiry:

- https://learn.microsoft.com/en-us/entra/identity-platform/developer-guide-conditional-access-authentication-context

#### WI-3.3 — Non-Entra fallback

For local/LDAP deployments, define a narrower reauthentication mechanism and be
honest that it may not prove MFA/device/risk context. High-risk features may
require Entra step-up or remain disabled rather than presenting password re-entry
as equivalent assurance.

### Phase 4 — Operations and qualification

- Doctor validates discovery, redirect/origin posture, tenant/client identifiers,
  secret/certificate resolvability, JWKS freshness, group-overage policy, and
  configured step-up contexts without printing tokens or secrets.
- Login and claims logs contain correlation IDs and verdicts, not tokens, codes,
  group lists, email addresses, or Graph bodies.
- Live qualification covers normal user, nested/large-group user, guest denial,
  disabled/offboarded user, key rollover, IdP outage, Conditional Access step-up,
  identity migration, and rollback to LDAP.

## 4. Web-configuration boundary

Plan 022 may manage display labels, enabled provider, tenant/client identifiers,
group/role mappings, session/reauth policy, and step-up operation mappings through
draft/approval. Redirect origin, TLS, client credential/certificate refs, session
signing secret, and first trusted admin remain bootstrap or secret-custody inputs.
The UI never accepts an OIDC client-secret value.

## 5. Completion gate

An Entra user signs in through validated single-tenant OIDC, maps to a stable
principal with correct project authorization, completes a context-bound step-up
for a protected operation, and leaves an attributable audit trail. Every named
token, migration, overage, outage, and downgrade attack has an executable denial
test.

