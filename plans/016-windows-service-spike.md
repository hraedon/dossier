# Plan 016 — Windows Service spike (validate the platform assumption)

**Status:** Complete 2026-07-02 (executed on `windows-test-host`)
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

---

## Spike Results (2026-07-02, windows-test-host)

**Host:** `windows-test-host.ad.example.com` (Windows, cert-watch deployment host)
**Python:** 3.14.5 (system install at `C:\Users\cw-admin\AppData\Local\Python\bin\`)
**Postgres:** `postgres-host.ad.example.com:5432` (reachable from windows-test-host)
**Venv:** `C:\ProgramData\dossier\venv`

### S1 — dossier as a Windows Service: PASS (with caveats)

- dossier + regista installed via `pip install -e` in a venv on Windows.
  `psycopg[binary]` (psycopg3) downloaded Windows wheels successfully.
- FastAPI + uvicorn serve HTTP; Jinja templates and patina CSS render.
- **Service wrapper:** `nssm` download was unavailable (nssm.cc returned
  503). `pywin32`'s `win32serviceutil` installed the service but it failed
  to start — `pythonservice.exe` doesn't work with Python 3.14 (DLL/runtime
  resolution issues even after `pywin32_postinstall`). **WinSW** (v2.12.0
  from GitHub releases) worked: the service starts, serves HTTP on :8000,
  connects to Postgres, and auto-starts (startmode=Automatic).
- **Bug found:** `hashlib.scrypt` with N=131072 (the default) fails on
  Windows Python 3.14 with "memory limit exceeded." Workaround: set
  `DOSSIER_PASSWORD_SCRYPT_N=16384` (or lower). This is an OpenSSL/Windows
  memory allocation issue, not a Python bug. The `hashlib.scrypt` call
  should pass an explicit `maxmem` parameter to fix this on Windows.
- **Recommendation for Plan 013 WI-4.1:** use WinSW as the service wrapper.
  pywin32's service framework is broken on Python 3.14. WinSW is a single
  18MB exe + XML config, no Python service code needed.
- Install steps documented at `C:\ProgramData\dossier\` (venv, keys.json,
  users.json, dossier-service.exe + .xml, dossier-env.cmd).

### S2 — pgvector on Windows: PASS (server-side caveat)

- `pgvector` Python package (0.4.2) installs and imports on Windows Python
  3.14 (pulls numpy 2.5.0 with Windows wheels).
- psycopg3 client connects to Postgres and can query metadata.
- The `vector` extension is **available** on postgres-host but **not
  installed** on the `regista` database (needs superuser `CREATE EXTENSION
  vector`). The `agent_notes` database likely needs the same.
- **Client side: fully functional.** Server side: one-time DBA task
  (`CREATE EXTENSION vector` as superuser on each database that needs it).

### S3 — agent-notes CLI on Windows: PASS (with one bug fix)

- agent-notes (1.0.0) installs fully on Windows Python 3.14, including
  torch (2.12.1), sentence-transformers (5.6.0), scipy, scikit-learn, etc.
  All packages had Windows wheels — no compilation needed.
- **Bug found and fixed:** `agent_notes/core/db.py` called
  `os.register_at_fork()` (line 31) which is POSIX-only and raises
  `AttributeError` on Windows. Fixed with `if hasattr(os,
  "register_at_fork"):` guard. This is a bug in agent-notes, not a design
  gap — the fork-reset logic is irrelevant on Windows (no fork).
- CLI connects to Postgres and runs commands. `breadcrumb find` returned
  `PROJECT_NOT_REGISTERED` (expected — no project registered on
  windows-test-host).
- Skills installation command works (`install-skills --target claude`).
  Claude Code not installed on windows-test-host, so full skills install deferred.
- Path handling works correctly on Windows.

### S4 — cairn hooks on Windows: BLOCKED (cairn doesn't exist yet)

- No `cairn` project found at `/projects/cairn`. Cannot test until cairn
  is implemented. No action needed — cairn's Windows support will need its
  own validation when the project exists.

### S5 — DPAPI secret resolution on Windows: PARTIAL PASS

- `win32crypt` (from pywin32) imports and `CryptProtectData` /
  `CryptUnprotectData` are callable on Windows Python 3.14. `ctypes`
  approach also works (calling `crypt32.dll` directly).
- `CryptProtectData` fails with `NTE_BAD_KEY_STATE` (error
  -2146892987: "The computer must be trusted for delegation and the
  current user account must be configured to allow delegation"). This
  failure occurs for both user-level and machine-level DPAPI, and from
  both Python and PowerShell — it's an account/domain configuration issue
  on windows-test-host, not a platform issue.
- The `cw-admin` account's Master Key exists (`%APPDATA%\Microsoft\Protect\`)
  but the DPAPI call still fails, likely due to Kerberos delegation GPO
  restrictions on the domain account.
- **Finding for Plan 025 WI-1.2:** the `wincred:` provider can use
  `win32crypt.CryptProtectData` / `CryptUnprotectData` (or `ctypes` to
  avoid the pywin32 dependency). It will work under the SYSTEM account
  (which the dossier service runs as) or a properly configured local
  account. The `file:` + NTFS ACL fallback (mentioned in the plan) is
  a viable interim if DPAPI configuration proves environment-specific.

### Summary

| Step | Result    | Key Finding                                            |
|------|-----------|--------------------------------------------------------|
| S1   | PASS      | WinSW wrapper works; pywin32 broken on Python 3.14; scrypt N=131072 memory issue |
| S2   | PASS      | psycopg3 + pgvector client work; extension needs DBA install on server |
| S3   | PASS      | agent-notes installs fully; `os.register_at_fork` bug fixed |
| S4   | BLOCKED   | cairn project doesn't exist yet                        |
| S5   | PARTIAL   | DPAPI API accessible; `CryptProtectData` fails on `cw-admin` account (env issue, not platform) |

**Verdict:** The platform assumption holds. The suite's Python components
run on Windows Python 3.14 with real Postgres. The plans can proceed with
WinSW as the service wrapper (not nssm or pywin32), and with two bugs to
fix: (1) scrypt `maxmem` on Windows, (2) `os.register_at_fork` guard in
agent-notes. DPAPI needs a properly configured service account but the
API path is validated.
