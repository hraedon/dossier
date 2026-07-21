from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, assert_never

import structlog

from . import __version__
from .keys import generate_keyset


def emit_error(
    code: str,
    message: str,
    *,
    use_json: bool,
    detail: str | None = None,
    retryable: bool = False,
    exit_code: int = 1,
) -> int:
    """Report an operational error per suite CLI contract v1 §3 and return the code.

    Under ``--json`` the common error envelope is the single stdout document;
    otherwise the human message goes to *stderr*. No path prints an error and
    exits 0. ``exit_code`` defaults to 1 — the operational-error slot in the
    taxonomy (0 success, 2 usage). The envelope shape is validated by
    ``agent_suite.conformance`` in the tests; it is reproduced here so runtime
    code never imports the dev-only kit.
    """
    if use_json:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": {
                        "code": code,
                        "message": message,
                        "detail": detail,
                        "retryable": retryable,
                        "partial": None,
                    },
                },
                indent=2,
            )
        )
    else:
        print(f"error: {message}", file=sys.stderr)
        if detail:
            print(f"  {detail}", file=sys.stderr)
    return exit_code


class _StderrLoggerFactory:
    """Route structlog output to stderr (Plan 004 WI-1.4).

    regista is imported as a library by ``multi.py``; its module-level
    ``log = structlog.get_logger()`` resolves to a stdout ``PrintLogger`` when
    ``structlog.configure()`` has never been called. regista's own CLI redirects
    via ``_cli._configure_structlog_stderr`` but only when its CLI runs — not
    when imported as a library. Without this call, regista's structlog lines
    (``keys.loaded``, ``regista.connected``, ...) contaminate
    ``dossier doctor --json`` stdout and break the suite umbrella's
    ``json.loads(stdout)`` parser (agent-suite ``doctor.py``).
    """

    def __call__(self, *args: object) -> structlog.PrintLogger:
        return structlog.PrintLogger(file=sys.stderr)


def _configure_structlog_stderr() -> None:
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(20),
        logger_factory=_StderrLoggerFactory(),
    )


def _cmd_keys_generate(args: argparse.Namespace) -> int:
    keyset = generate_keyset(Path(args.path), key_id=args.key_id)
    kid = keyset["keys"][0]["key_id"]
    print(f"Generated HMAC keyset: {kid} -> {args.path}")
    return 0


def _check_provisioned(database_url: str, project: str, require_ssl: bool) -> bool:
    """Check whether *project* has been provisioned (schema exists).

    Returns False only when the schema genuinely does not exist.
    Connection/auth errors are re-raised so the operator sees the real
    problem rather than a misleading "not provisioned" message.
    """
    import psycopg

    from .secrets import resolve_dsn

    dsn = resolve_dsn(database_url)
    if dsn is None:
        # An empty/unresolved DSN cannot connect — treat as not provisioned
        # rather than crashing the doctor/provision-check call.
        return False

    try:
        conn_kwargs: dict[str, Any] = {}
        if require_ssl:
            conn_kwargs["sslmode"] = "require"
        with psycopg.connect(dsn, **conn_kwargs) as conn:
            row = conn.execute(
                "SELECT 1 FROM information_schema.schemata WHERE schema_name = %s",
                [project],
            ).fetchone()
            return row is not None
    except psycopg.OperationalError as exc:
        if "does not exist" in str(exc).lower() and "schema" in str(exc).lower():
            return False
        raise


def _provision_error(project: str) -> str:
    return (
        f"Project {project!r} is not provisioned.\n"
        f"  Run: regista provision --project {project}\n"
        f"  Then: regista provision-principal --project {project} --principal <id>\n"
        f"  See: regista provision --help"
    )


def _cmd_init(args: argparse.Namespace) -> int:
    from .config import load_settings
    from .gateway import packaged_workflow_yaml

    settings = load_settings(strict=False)
    required = {
        "REGISTA_DSN (or DOSSIER_DATABASE_URL)": settings.database_url,
        "DOSSIER_PROJECT": settings.project,
        "REGISTA_KEY_PATH (or DOSSIER_HMAC_KEY_PATH)": settings.hmac_key_path,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        print(f"init requires: {', '.join(missing)}", file=sys.stderr)
        return 2

    from .secrets import materialize_key_manifest, resolve_dsn

    # Resolve once and reuse for both the provision check and the Regista
    # construction (Plan 013 WI-4.1). The resolved DSN is bound to a short-
    # lived local and consumed immediately; it may contain a plaintext
    # password, so we del it as soon as the connection holds it.
    resolved_dsn = resolve_dsn(settings.database_url)
    if resolved_dsn is None:
        print("REGISTA_DSN is empty; cannot check provisioning.", file=sys.stderr)
        return 2
    if not _check_provisioned(resolved_dsn, settings.project, settings.require_ssl):
        print(_provision_error(settings.project), file=sys.stderr)
        return 1

    from regista import Regista

    key_path, key_cleanup = materialize_key_manifest(settings.hmac_key_path)
    reg: Regista | None = None
    try:
        reg = Regista(
            resolved_dsn,
            settings.project,
            key_path,
            require_ssl=settings.require_ssl,
        )
        del resolved_dsn  # scrub the plaintext-DSN local before further work
        reg.register_workflow(packaged_workflow_yaml())
    finally:
        if reg is not None:
            reg.close()
        if key_cleanup is not None:
            key_cleanup()
    print(
        f"dossier project {settings.project!r} workflow registered.",
        file=sys.stdout,
    )
    return 0


def _cmd_users_add(args: argparse.Namespace) -> int:
    import getpass

    from .auth.backends import LocalBackend
    from .config import load_settings

    settings = load_settings(strict=False)
    path = args.path or settings.users_path
    if not path:
        print("--path or DOSSIER_USERS_PATH is required.", file=sys.stderr)
        return 2
    password = args.password
    if password is None:
        password = getpass.getpass("Password: ")
        if getpass.getpass("Confirm: ") != password:
            print("Passwords do not match.", file=sys.stderr)
            return 2
    if not password:
        print("Empty password is not allowed.", file=sys.stderr)
        return 2
    record = LocalBackend.add_user(path, args.username, args.display_name, password)
    print(f"Added user {args.username!r} ({record['stable_id']}) -> {path}")
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    from .config import load_settings
    from .health import build_health
    from .multi import GatewayRegistry

    settings = load_settings(strict=False)

    known_projects: list[str]
    projects_raw = args.projects or os.environ.get("DOSSIER_PROJECTS", settings.project)
    known_projects = [p.strip() for p in projects_raw.split(",") if p.strip()]

    registry = GatewayRegistry(settings=settings, known_projects=known_projects)
    health = build_health(settings, registry)
    registry.close_all()

    if args.json:
        print(json.dumps(health, indent=2))
    else:
        print(f"dossier {health['version']} — component health")
        regista = health["regista"]
        print(f"  regista: reachable={regista['reachable']} project={regista['project']} chain_ok={regista['chain_ok']}")
        for check in health["checks"]:
            detail = f" — {check['detail']}" if check.get("detail") else ""
            print(f"  {check['name']}: {check['status']}{detail}")

    failed = [c for c in health["checks"] if c["status"] == "fail"]
    return 1 if failed else 0


def _cmd_serve(args: argparse.Namespace) -> int:
    from .config import load_ldap_config, load_settings

    settings = load_settings(strict=True)

    from uvicorn import run as uvicorn_run

    from .app import create_app
    from .auth.backends import CredentialBackend
    from .multi import GatewayRegistry, slug_to_project

    projects_raw = os.environ.get("DOSSIER_PROJECTS", settings.project)
    raw_projects = [p.strip() for p in projects_raw.split(",") if p.strip()]

    known_projects: list[str] = []
    for p in raw_projects:
        try:
            normalized = slug_to_project(p)
            known_projects.append(normalized)
        except ValueError as exc:
            print(f"DOSSIER_PROJECTS contains invalid name {p!r}: {exc}", file=sys.stderr)
            return 2

    registry = GatewayRegistry(settings=settings, known_projects=known_projects)

    if not args.skip_provision_check:
        from .secrets import resolve_dsn

        resolved_dsn = resolve_dsn(settings.database_url)
        if resolved_dsn is None:
            print("REGISTA_DSN is empty; cannot check provisioning.", file=sys.stderr)
            registry.close_all()
            return 2
        for p in known_projects:
            if not _check_provisioned(resolved_dsn, p, settings.require_ssl):
                print(_provision_error(p), file=sys.stderr)
                registry.close_all()
                return 1
        del resolved_dsn  # scrub the plaintext-DSN local before serving

    backend: CredentialBackend
    if settings.auth_backend == "ldap":
        from .auth.backends import LdapBackend

        ldap_config = load_ldap_config(strict=True)
        backend = LdapBackend.from_config(ldap_config)
    elif settings.auth_backend == "local":
        if not settings.users_path:
            print("DOSSIER_USERS_PATH is required for the local auth backend.", file=sys.stderr)
            return 2
        from .auth.backends import LocalBackend

        backend = LocalBackend(settings.users_path)
    else:
        assert_never(settings.auth_backend)

    from .config import load_tls_config

    tls = load_tls_config()
    ssl_kwargs: dict[str, Any] = {}
    if tls is not None:
        if not tls.cert_path or not tls.key_path:
            print(
                "Both DOSSIER_TLS_CERT_PATH and DOSSIER_TLS_KEY_PATH must be set "
                "to serve over TLS — only one was provided.",
                file=sys.stderr,
            )
            registry.close_all()
            return 2
        ssl_kwargs["ssl_certfile"] = tls.cert_path
        ssl_kwargs["ssl_keyfile"] = tls.key_path
        print(f"dossier: serving over TLS (cert={tls.cert_path})", file=sys.stderr)

    app = create_app(settings, registry, backend)
    try:
        uvicorn_run(app, host=args.host, port=args.port, **ssl_kwargs)
    finally:
        registry.close_all()
    return 0


def _charter(args: argparse.Namespace) -> int:
    print(
        f"dossier {__version__} — charter stage.\n"
        "No runtime yet. See plans/001-mvp.md for the build order; "
        "the backend is regista (docs/provenance-model.md is the contract)."
    )
    return 0


def _run(argv: list[str] | None) -> int:
    from .config import load_suite_env

    load_suite_env()
    # Route regista's structlog output to stderr before any subcommand runs,
    # so ``doctor --json`` stdout stays a clean JSON blob (Plan 004 WI-1.4).
    _configure_structlog_stderr()

    args = sys.argv[1:] if argv is None else argv
    if args and args[0] in {"-V", "--version", "version"}:
        print(f"dossier {__version__}")
        return 0

    parser = argparse.ArgumentParser(prog="dossier")
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"dossier {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=False)

    keys_parser = subparsers.add_parser("keys")
    gen_subparsers = keys_parser.add_subparsers(dest="keys_command", required=True)
    gen_parser = gen_subparsers.add_parser("generate")
    gen_parser.add_argument("--path", required=True)
    gen_parser.add_argument("--key-id", default=None)
    gen_parser.set_defaults(func=_cmd_keys_generate)

    init_parser = subparsers.add_parser("init")
    init_parser.set_defaults(func=_cmd_init)

    users_parser = subparsers.add_parser("users")
    users_sub = users_parser.add_subparsers(dest="users_command", required=True)
    add_parser = users_sub.add_parser("add")
    add_parser.add_argument("--username", required=True)
    add_parser.add_argument("--display-name", required=True)
    add_parser.add_argument("--path", default=None)
    add_parser.add_argument("--password", default=None)
    add_parser.set_defaults(func=_cmd_users_add)

    serve_parser = subparsers.add_parser("serve")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.add_argument(
        "--skip-provision-check",
        action="store_true",
        help="Skip the project provision check (for local dev with InMemory backend)",
    )
    serve_parser.set_defaults(func=_cmd_serve)

    doctor_parser = subparsers.add_parser("doctor")
    doctor_parser.add_argument("--json", action="store_true", help="Output JSON in the suite health shape")
    doctor_parser.add_argument("--projects", default=None, help="Comma-separated project list (default: from env)")
    doctor_parser.set_defaults(func=_cmd_doctor)

    parsed = parser.parse_args(argv)
    func: Callable[[argparse.Namespace], int] | None = getattr(parsed, "func", None)
    if func is None:
        return _charter(parsed)
    return func(parsed)


def main(argv: list[str] | None = None) -> int:
    """Top-level entry point and last-resort error boundary (CLI contract §3/§4).

    argparse's usage errors raise ``SystemExit`` (exit 2) straight through — a
    ``BaseException``, not caught here, so the usage taxonomy is preserved. A
    misconfigured suite-env path (``FileNotFoundError`` from ``load_suite_env``)
    becomes a ``CONFIG_NOT_FOUND`` envelope; any other uncaught exception becomes
    ``INTERNAL_ERROR`` instead of a traceback (§4). A closed downstream pipe is
    swallowed the CPython way so the interpreter's final flush can't re-raise.
    """
    raw = sys.argv[1:] if argv is None else argv
    json_mode = "--json" in raw
    try:
        return _run(argv)
    except BrokenPipeError:
        # A downstream reader closed the pipe (e.g. `dossier ... | head`).
        # Redirect stdout to devnull so the final flush at exit can't raise (§4).
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except (OSError, ValueError):
            pass
        return 1
    except FileNotFoundError as exc:
        return emit_error("CONFIG_NOT_FOUND", str(exc), use_json=json_mode)
    except Exception as exc:  # last-resort boundary: never surface a traceback
        return emit_error(
            "INTERNAL_ERROR",
            f"unexpected {exc.__class__.__name__}: {exc}",
            use_json=json_mode,
        )


if __name__ == "__main__":
    raise SystemExit(main())
