# Publication Review

**Status:** Active. This document gates every push to a remote. The repo
stays private (local-only, no `git remote add origin …`) until this review
passes. After the first public push, every subsequent push re-runs the
checklist below.

## Policy

dossier is a provenance instrument — it exists *because* the data it handles
is sensitive (work-items, actor identities, audit chains). The hard rule from
`AGENTS.md` is absolute:

> **No work-domain identifiers in committed files.** Real project/issue/account
> data never lands in the repo. Use generic examples and fixtures; any local DB
> and any `samples/` are gitignored and never committed.

This means: no real usernames, no real DNs, no real server hostnames, no real
AD domain names, no real database connection strings, no real HMAC keys, no
real user display names, no real project slugs from production schemas.

## Pre-push checklist

Run every item. If any fails, **stop** and fix before pushing.

### 1. Secret scan

```bash
# Check for common secret patterns
grep -rnE '(password|secret|key|token|dsn|connection.string).*=' \
  src/ tests/ docs/ plans/ --include='*.py' --include='*.md' --include='*.yaml' \
  | grep -v 'test\|example\|placeholder\|changeme\|replace\|dummy\|sample\|TODO\|\.env\.example'
```

Verify every hit is a placeholder, a test fixture, or a variable *name* (not
a value). No real credentials should appear.

### 2. Work-domain identifier scan

```bash
# Check for real hostnames, DNs, domains
grep -rnE '(DC=|CN=|OU=|ldaps?://|@hraedon|@example\.com|mvmpostgres)' \
  src/ tests/ docs/ plans/ --include='*.py' --include='*.md' --include='*.yaml'
```

Any match must be in `.env.example` (as a placeholder), in documentation (as
a generic example), or in a test fixture (using `example.com` / `test` /
`alice` / `bob` — never real names).

### 3. .gitignore verification

Confirm these are gitignored and not tracked:

```bash
git check-ignore samples/ secrets/ .env *.db *.sqlite3 *.env.local || true
```

If any prints nothing (i.e., is NOT ignored), **stop** — add it to
`.gitignore` before pushing.

### 4. Reflection / log file scan

The `reflections/` directory contains session reflections. These are written
by agents and may reference internal infrastructure. Before pushing:

```bash
# Review every file under reflections/ for work-domain identifiers
git diff --name-only HEAD~5 -- reflections/
```

Read each changed reflection. Redact any real hostnames, database names,
user identifiers, or internal infrastructure references. The reflection
should be useful to the next agent without leaking operational details.

### 5. Test fixture review

Test fixtures (`tests/`, `conftest.py`, `helpers.py`) use generic names
(`alice`, `bob`, `carol`, `dave`, `agent-relay`, `agent-glm`). Verify no
real user identifiers or real AD group GUIDs have been introduced.

### 6. Configuration review

`.env.example` must contain only placeholders:

- `changeme`, `replace-with-*`, `example.com`, `dc1.example.com`
- No real server hostnames, no real bind DNs, no real domain names

### 7. Dependency review

Confirm `pyproject.toml` pins are safe to publish:

- No private/internal package indices
- `regista` dependency is declared as `>=0.4.0` (or a published version)
- No `git+ssh://` or `git+https://internal-host` URLs

### 8. CI workflow review

`.github/workflows/ci.yml` must not reference internal infrastructure:

- No self-hosted runners with internal tags
- No secrets that reference internal credential names
- No internal artifact registries

## What constitutes a work-domain identifier

| Category | Example (forbidden) | Placeholder (allowed) |
|---|---|---|
| Server hostnames | `postgres-host` | `localhost`, `db.example.internal` |
| AD domain | `example.com` | `example.com` |
| LDAP bind DN | `CN=svc-dossier,OU=Service Accounts,DC=example,DC=com` | `CN=svc-dossier,OU=Service Accounts,DC=example,DC=com` |
| Database DSN | `postgresql://dossier:realpass@postgres-host:5432/dossier` | `postgresql://dossier:changeme@localhost:5432/dossier` |
| HMAC key | (any real key material) | (generated at runtime, never committed) |
| User display names | Real employee names | `Alice`, `Bob`, `Carol`, `Dave` |
| Project slugs | Real production schema names | `dossier`, `dossier_test` |
| Agent identifiers | Real agent model IDs | `agent-relay`, `agent-glm`, `agent-kimi` |

## Review process

1. **Self-review:** The agent (or human) making the push runs the checklist
   above. All items must pass.
2. **Independent review:** A second reviewer (agent or human) re-runs the
   scan and reads any files the first reviewer flagged. For the first public
   push, this must be a human.
3. **Record:** Note the review in the commit message (e.g., "publication
   review passed: no work-domain identifiers, no secrets, .gitignore
   verified").

## Exceptions

None. If a file must reference a real identifier for a legitimate reason
(e.g., a bug report about a specific production schema), the identifier is
redacted in the committed version and the real value is kept in a separate,
gitignored incident file.
