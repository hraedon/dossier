# Plan 016 — Windows Service spike (validate the platform assumption)

**Status:** Proposed 2026-07-02
**Author:** Code review (adversarial), from the 2026-07-02 suite review
**Strategic role:** Every suite-cohesion plan assumes the components run
on Windows as a first-class target (Windows Service packaging for
dossier, Windows CLI support for agent-notes/cairn, Windows secret
resolution via DPAPI). **Nobody has tested this.** This spike validates
the assumption early — before every plan builds on it — so a failure
here reshapes the packaging approach before it's baked into six plans.

## What this is

A timeboxed validation, not a production deployment. The goal is to
answer one question: **can the suite's Python components run as Windows
Services (or native Windows processes) against a real Postgres, with
the features the plans depend on?** If the answer is "yes, with these
caveats," the plans proceed. If "no, because X," the plans get a
v2 packaging revision before implementation.

## What to test (in order)

### S1 — dossier as a Windows Service

- Install dossier on a Windows host (or Windows VM) using a service
  wrapper (`nssm` or `pywin32`'s `win32serviceutil`).
- Point it at a reachable Postgres (the homelab `postgres-host` is
  fine if VPN'd, or a local Docker Postgres on Windows).
- Start the service, confirm the web UI renders, confirm LDAP auth
  works (or degrades gracefully if no LDAP is available in the test).
- **Acceptance:** dossier starts as a service, serves HTTP, survives a
  host reboot (auto-start), and connects to Postgres. Document the
  wrapper choice and the install steps.

### S2 — pgvector on Windows

- agent-notes depends on pgvector for embeddings. Verify the
  `pgvector` extension is available on the Postgres instance dossier
  connects to (this is a server-side concern, but the *client* —
  psycopg2/psycopg3 — must connect and query vector columns from a
  Windows Python process).
- **Acceptance:** a Windows Python process can `SELECT` from a
  pgvector column and `INSERT` an embedding. If pgvector is not
  available on the test Postgres, document what's needed to add it.

### S3 — agent-notes CLI on Windows

- Install agent-notes via `pip`/`pipx` on Windows. Run
  `agent-notes breadcrumb find --path .` against the same Postgres.
- Install skills: `agent-notes install-skills --target claude` on a
  Windows Claude Code profile.
- **Acceptance:** the CLI works on Windows (path handling, env var
  resolution, Postgres connection); skills install to the Windows
  Claude Code skills directory.

### S4 — cairn hooks on Windows

- Install cairn on Windows. Wire the Claude Code hooks
  (`cairn install-harness claude`) on a Windows profile.
- Run a Claude Code session and confirm the hooks fire (check for
  attestation events in regista or cairn's degradation log).
- **Acceptance:** Claude Code hooks fire on Windows the same as on
  Linux; if there are path/shell differences, document them.

### S5 — Secret resolution on Windows (DPAPI)

- Store a test signing key using Windows DPAPI (Credential Manager
  or `CryptProtectData`).
- Confirm `regista.secrets.resolve("wincred:...")` retrieves it
  from a Python process.
- **Acceptance:** the `wincred:` provider round-trips a secret on
  Windows. If the `[windows]` extra isn't implemented yet (it isn't —
  Plan 025 WI-1.2 is proposed), validate the approach with a minimal
  prototype and feed findings back to Plan 025.

## What to do if something fails

- **S1 fails (service wrapper):** try the alternative wrapper
  (`pywin32` if `nssm` fails, or vice versa). If both fail, document
  the blocker — the plans may need to target IIS + `waitress` or a
  container-on-Windows approach instead of a raw service.
- **S2 fails (pgvector client):** this is likely a psycopg2 binary
  wheel issue on Windows, not a pgvector server issue. Try
  `psycopg[binary]` (psycopg3) which has Windows wheels. If resolved,
  note the driver requirement.
- **S3 fails (agent-notes CLI):** most likely path handling (`os.path`
  vs `pathlib` issues) or env var differences. Fix in agent-notes
  directly; this is a bug, not a design gap.
- **S4 fails (cairn hooks):** Claude Code's hook execution on Windows
  may shell differently (PowerShell vs bash). Check the hook script's
  shebang/invocation. If hooks require bash on Windows, document the
  Git-Bash/WSL dependency.
- **S5 fails (DPAPI):** the `[windows]` extra isn't implemented yet,
  so this is expected to be a prototype validation, not a pass/fail.
  If DPAPI proves problematic, the Windows path can fall back to
  `file:` with NTFS ACLs as an interim, with DPAPI as a v1.1 upgrade.

## Timebox

**One focused session (half a day).** This is validation, not
implementation. If S1–S2 pass, the platform assumption holds and the
plans proceed. If S1 fails, the packaging approach needs revision
before any component implements Windows packaging — that's the
finding that matters most.

## Sequencing

- **Do this before Phase B** (dossier Plan 013 WI-4.1, agent-notes
  Plan 017 WI-4.1). It is the cheapest way to de-risk every plan's
  Windows packaging assumption.
- Does not depend on any suite-cohesion plan landing first — it uses
  the current (pre-cohesion) components as-is.
- Results feed back into: dossier Plan 013 WI-4.1 (service packaging),
  agent-notes Plan 017 WI-4.1 (Windows support), cairn Plan 008
  WI-4.1 (Windows hooks), regista Plan 025 WI-1.2 (DPAPI provider).
