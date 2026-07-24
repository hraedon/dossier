# Project access control — deny by default

**Breaking change (dossier WI-017). Read this before upgrading a running
instance.**

Cross-project read access used to default to `open`: every authenticated
principal could read every project dossier fronted. That default is gone.
`DOSSIER_PROJECT_ACCESS_MODE` now resolves to **`enforce`** — deny-by-default —
in dev and prod alike. Flat-open still exists, but it must be *chosen*.

## What changes for a running deployment

| You had | You now get | What to do |
|---|---|---|
| `DOSSIER_PROJECT_ACCESS_MODE` unset, no ACL | `enforce` with **no policy → everything denied** | set `DOSSIER_BOOTSTRAP_ADMINS` (below), then write an ACL |
| `DOSSIER_PROJECT_ACCESS_MODE` unset, ACL set | `enforce` against your ACL | check the ACL names everyone who needs access |
| `DOSSIER_PROJECT_ACCESS_MODE=open` | `open`, unchanged | nothing — but the doctor warns (fails in prod) |
| `DOSSIER_PROJECT_ACCESS_MODE=audit`/`enforce` | unchanged | nothing |

The one-line rollback, if you need the old behaviour back while you plan the
migration:

```dotenv
DOSSIER_PROJECT_ACCESS_MODE=open
```

That is a deliberate, visible choice. It is never what you get by omission,
and the doctor reports it (`warn` in dev, `fail` in prod).

## The lockout state is diagnosable, not silent

`enforce` with **no ACL and no bootstrap administrators** denies every project
to everybody. dossier does not paper over this by reopening access — a face
that cannot tell you who may read a project must not guess. Instead:

- the app **still starts**, and `/livez`, `/healthz` and `dossier doctor` still
  work, so you can see why;
- `dossier doctor` reports `project_access` as **`fail`** with the exact
  remediation in the detail;
- `/healthz` returns 503;
- startup logs one `ERROR` on `dossier.authz` naming both env vars.

`load_settings` deliberately does **not** raise here. Raising would take the
doctor down with the app and leave you with a dead process and no diagnosis.

## Recovery: `DOSSIER_BOOTSTRAP_ADMINS`

The documented way in — and the way back in if you lock yourself out — is an
explicit administrator list that needs no ACL file:

```dotenv
DOSSIER_PROJECT_ACCESS_MODE=enforce
DOSSIER_BOOTSTRAP_ADMINS=11111111-1111-1111-1111-111111111111,name:platform-team
```

- Entries are **principal IDs** (the stable actor ID — the same value the ACL's
  `administrators.principals` takes), or **group claims** prefixed `name:`
  (case-folded local group names) or `guid:` (canonical lowercase LDAP group
  GUIDs).
- A bootstrap administrator can read every project, exactly like an ACL
  administrator. The two lists compose: bootstrap entries are *added* to the
  ACL's administrators, never substituted for them.
- Entries are validated at config load, so a typo in a security control fails
  immediately rather than at the first denied request.
- There is **no built-in or implied bootstrap identity.** If you set nothing,
  nobody gets in.

With bootstrap admins configured but no ACL, the doctor reports `warn` — you
are recovered but not migrated, and only administrators can read anything.

## Finishing the migration

1. Set `DOSSIER_BOOTSTRAP_ADMINS` so you retain access.
2. Write the ACL — start from [`../project-acl.example.json`](../project-acl.example.json).
   Undeclared projects are denied; see the README's *Project access control*
   section for the full schema and the file's permission requirements.
3. Set `DOSSIER_PROJECT_ACL_PATH`, and confirm `dossier doctor` reports
   `project_access: ok`.
4. Optionally run `DOSSIER_PROJECT_ACCESS_MODE=audit` first: the policy is
   evaluated and would-be denials are logged on `dossier.authz`, but access is
   still permitted. Watch the log until it is quiet, then switch to `enforce`.
5. Once the ACL names your administrators, `DOSSIER_BOOTSTRAP_ADMINS` can be
   removed.

## Where this is implemented

- `src/dossier/authz.py` — the policy, `can_read_project` (the single seam; it
  has no permissive default and requires the caller to state the posture), and
  `build_project_access_policy` which composes ACL + bootstrap admins.
- `src/dossier/config.py` — mode resolution and `DOSSIER_BOOTSTRAP_ADMINS`
  parsing.
- `src/dossier/health.py` — `_project_access_check`, the doctor surface.
- `tests/test_project_access.py` — enforcement, the bootstrap recovery path,
  the lockout state, and the doctor's report of each.
