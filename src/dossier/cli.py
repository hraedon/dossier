from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, assert_never

from . import __version__
from .keys import generate_keyset


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

    try:
        conn_kwargs: dict[str, Any] = {}
        if require_ssl:
            conn_kwargs["sslmode"] = "require"
        with psycopg.connect(database_url, **conn_kwargs) as conn:
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

    if not _check_provisioned(settings.database_url, settings.project, settings.require_ssl):
        print(_provision_error(settings.project), file=sys.stderr)
        return 1

    from regista import Regista

    reg = Regista(
        settings.database_url,
        settings.project,
        settings.hmac_key_path,
        require_ssl=settings.require_ssl,
    )
    try:
        reg.register_workflow(packaged_workflow_yaml())
    finally:
        reg.close()
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
    import json

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
        for p in known_projects:
            if not _check_provisioned(settings.database_url, p, settings.require_ssl):
                print(_provision_error(p), file=sys.stderr)
                registry.close_all()
                return 1

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

    app = create_app(settings, registry, backend)
    try:
        uvicorn_run(app, host=args.host, port=args.port)
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


def main(argv: list[str] | None = None) -> int:
    from .config import load_suite_env

    load_suite_env()

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


if __name__ == "__main__":
    raise SystemExit(main())
