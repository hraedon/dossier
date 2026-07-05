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

## CI automation

The `identifier-gate` job in `.github/workflows/ci.yml` runs on every push
and pull request. It performs three scans:

1. **Targeted scan** — blocks known real hostnames/domains/service-accounts
   (e.g. `mvmpostgres*`, `hraedon.com`, `ad.hraedon`, `svc-gpolens`,
   `windows-test-host`, `postgres-host`) from appearing in any committed file.
2. **Broad scan** — catches new LDAP/AD patterns (`DC=`, `CN=`, `ldaps://`)
   that are not paired with known-safe placeholders (`example.com`,
   `test.example`, `example.internal`).
3. **Denylist gate** — `scripts/check_committed_identifiers.py` scans all
   tracked files against a denylist provided via the `DOSSIER_FORBIDDEN_IDENTIFIERS`
   CI secret. Also enforces the always-on `samples/` guard (no tracked files
   under gitignored data directories). No-op until the secret is configured,
   so it never blocks a fresh clone or fork.

The gate must be green before merging to `main`. If it fails, fix the
identifier before proceeding — do not add exclusions unless the pattern is
a confirmed false positive.

### Local pre-commit hook

```bash
# Install the identifier-gate pre-commit hook
bash scripts/install-git-hooks.sh

# Provide a denylist (gitignored, never committed)
echo 'svc-gpolens' >> .identifiers-denylist.local
echo 'windows-test-host' >> .identifiers-denylist.local
# ... or set DOSSIER_FORBIDDEN_IDENTIFIERS in your environment
```

### History audit (dry-run, read-only)

```bash
# Audit full git history for denylist identifier leaks
python3 scripts/audit_history_identifiers.py
# Report written to docs/history-identifier-audit.md (gitignored)
```

This is the dry-run / report-only companion to the identifier gate. It scans
ALL of git history (every commit's diff content + commit messages + author/
committer identity) for denylist identifiers and reports every occurrence.

## Pre-push checklist (manual)

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
| Server hostnames | `postgres-host`, `mvmpostgres01` | `localhost`, `db.example.internal`, `suite-db` |
| Windows hostnames | `windows-test-host` | `windows-host.example.internal` |
| AD DC hostnames | `mvmdc01`, `mvmdc02`, `mvmdc03` | `dc1.example.internal`, `dc2.example.internal` |
| AD domain | `example.com` | `example.com` |
| LDAP bind DN | `CN=svc-dossier,OU=Service Accounts,DC=example,DC=com` | `CN=svc-dossier,OU=Service Accounts,DC=example,DC=com` |
| Service accounts | `svc-gpolens` | `svc-bind`, `svc-dossier` |
| Database DSN | `postgresql://dossier:realpass@postgres-host:5432/dossier` | `postgresql://dossier:changeme@localhost:5432/dossier` |
| HMAC key | (any real key material) | (generated at runtime, never committed) |
| CA CN | `Hraedon Root` | `Internal Root CA` |
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

## First-publication scrub

Before the first `git push` to a public remote, run a history scrub using
`git filter-repo` to remove any work-domain identifiers that may have been
introduced and later removed.

**Per the adcs-lens WI-010 lesson: the scrub must cover CA CN / all
identifier forms, not just hostnames.** This includes:
- Server hostnames (`mvmpostgres01`, `mvmcitest01`, `mvmdc01-03`)
- AD domain (`hraedon.com`, `ad.hraedon`)
- Service account names (`svc-gpolens`)
- CA CNs (`Hraedon Root`)
- Personal names and emails (author/committer identity)
- Test host names (`windows-test-host`, `postgres-host`)

### Pre-scrub audit (dry-run, read-only)

```bash
# 1. Run the history audit to identify all leaks
python3 scripts/audit_history_identifiers.py

# 2. Review the report
cat docs/history-identifier-audit.md

# 3. Run git filter-repo --dry-run to verify the replacements
git clone /path/to/dossier dossier-public
cd dossier-public
git filter-repo --dry-run --replace-text scripts/filter-repo-replacements.txt
# Compare .git/filter-repo/fast-export.original vs .git/filter-repo/fast-export.filtered
```

### Scrub (DESTRUCTIVE — requires human approval)

```bash
# Install git-filter-repo
pip install git-filter-repo

# Create a fresh clone for the scrub (never scrub in-place)
git clone /path/to/dossier dossier-public
cd dossier-public

# Scrub known patterns from all history
git filter-repo --replace-text scripts/filter-repo-replacements.txt

# Scrub author/committer identity (not handled by --replace-text)
# Use --mailmap or --name-callback / --email-callback to rewrite
# the author/committer name and email in ALL commits.
git filter-repo --name-callback 'return b"regista-contributors"' \
  --email-callback 'return b"regista@users.noreply.github.com"'

# Verify the scrub
git log --all -p | grep -E 'mvmpostgres|hraedon\.com|ad\.hraedon|svc-gpolens|Hraedon Root' || echo "Clean"

# Then add the remote and push
git remote add origin git@github.com:hraedon/dossier.git
git push -u origin main
```

After the first push, the CI identifier-gate prevents new identifiers from
entering. The manual checklist above remains the review process for every
subsequent push.

### Audit results (2026-07-05)

**Dossier** — 43 commits scanned, 48 leaks found across 6 identifiers:
| Identifier | Occurrences | Source |
|---|---|---|
| `hraedon.com` | 17 | author/committer email + reflection reference |
| `postgres-host` | 11 | plan 016 spike results |
| `svc-gpolens` | 9 | test integration docs + plan 003 + reflections |
| `windows-test-host` | 9 | plan 016 spike results |
| `ad.hraedon` | 1 | publication-review.md (this file, as a pattern) |
| `mvmpostgres01` | 1 | reflection reference |

**Regista** — 203 commits scanned, 1651 leaks found across 6 identifiers:
| Identifier | Occurrences | Source |
|---|---|---|
| `hraedon` (org) | 420 | author/committer identity (all commits) |
| `hraedon.com` | 406 | author/committer email (all commits) |
| Personal name | 406 | author/committer name (all commits) |
| Personal email | 406 | author/committer email (all commits) |
| `mvmpostgres01` | 8 | plans + worklog + reflections |
| `mvmcitest01` | 5 | worklog + reflections |

**Note:** `git filter-repo --replace-text` only handles file content, not
author/committer identity. For regista (already public), the author/committer
identity rewrite requires `--name-callback` / `--email-callback` and a
GitHub repo delete+recreate (per adcs-lens WI-010 lesson: force-push alone
leaves pushed refs cached on GitHub's side). This is the irreversible step
the repo owner must execute.

## Exceptions

None. If a file must reference a real identifier for a legitimate reason
(e.g., a bug report about a specific production schema), the identifier is
redacted in the committed version and the real value is kept in a separate,
gitignored incident file.
