from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, assert_never

from . import __version__
from .config import Settings
from .multi import GatewayRegistry

CheckStatus = Literal["ok", "warn", "fail", "skip"]


def build_health(
    settings: Settings,
    registry: GatewayRegistry,
) -> dict[str, Any]:
    """Build the suite-conformant health shape.

    Returns::

        {
            "component": "dossier",
            "version": "0.0.1",
            "ok": bool,
            "degraded": bool,
            "regista": {"reachable": bool, "project": str, "chain_ok": bool | None},
            "checks": [{"name": str, "status": "ok|warn|fail|skip", "detail": str | None}],
        }

    The top-level ``ok`` boolean is what the suite-doctor umbrella reads to
    classify the component; ``degraded`` marks a healthy-but-warning state.
    Check status follows regista's canonical vocabulary (``ok/warn/fail/skip``).

    An unreachable regista or missing session secret is a named ``checks``
    failure — never an exception.
    """
    checks: list[dict[str, Any]] = []

    # In prod, posture gaps that are merely ``warn`` in dev escalate to
    # ``fail`` (Plan 015 WI-1.1) — a production deploy must not silently run
    # open-access, without TLS, or without a session secret.
    prod = settings.env_mode == "prod"

    # Surface the active env mode first so the operator sees the deployment
    # posture before its consequences (H1: a silent dev default in production
    # is a named state, not silence).
    checks.append(_env_mode_check(settings))

    regista_reachable = False
    chain_ok: bool | None = None

    try:
        projects = registry.list_projects()
        if projects:
            gw = registry.get(projects[0])
            gw.list_issues(current_states=["open"], page_size=1)
            regista_reachable = True
            try:
                report = gw.integrity()
                chain_ok = not report.replayed_drift
            except Exception:
                chain_ok = False
        else:
            checks.append({
                "name": "regista",
                "status": "skip",
                "detail": "no projects configured",
            })
    except Exception as exc:
        checks.append({
            "name": "regista",
            "status": "fail",
            "detail": f"unreachable ({type(exc).__name__})",
        })

    if settings.session_secret and len(settings.session_secret) >= 32:
        checks.append({"name": "session_secret", "status": "ok", "detail": None})
    else:
        checks.append({
            "name": "session_secret",
            "status": "fail",
            "detail": "missing or shorter than 32 bytes",
        })

    if settings.auth_backend == "local":
        if settings.users_path:
            checks.append({
                "name": "auth_backend",
                "status": "ok",
                "detail": "local",
            })
        else:
            checks.append({
                "name": "auth_backend",
                "status": "fail",
                "detail": "local backend selected but DOSSIER_USERS_PATH not set",
            })
    elif settings.auth_backend == "ldap":
        checks.append(_ldap_config_check())

    checks.extend(_tls_checks(prod=prod))
    checks.append(_suite_env_check())
    checks.extend(_secrets_backend_checks(settings))
    checks.append(_notification_sink_check(settings))
    checks.append(_project_access_check(settings, prod=prod))
    checks.append(_allowed_hosts_check(settings, prod=prod))

    has_fail = any(c["status"] == "fail" for c in checks)
    has_warn = any(c["status"] == "warn" for c in checks)
    ok = not has_fail
    degraded = ok and has_warn

    return {
        "component": "dossier",
        "version": __version__,
        "ok": ok,
        "degraded": degraded,
        "regista": {
            "reachable": regista_reachable,
            "project": settings.project,
            "chain_ok": chain_ok,
        },
        "checks": checks,
    }


def has_failures(health: dict[str, Any]) -> bool:
    """Return True if any check has status 'fail'."""
    return any(c["status"] == "fail" for c in health.get("checks", []))


def _tls_checks(*, prod: bool = False) -> list[dict[str, Any]]:
    """Report TLS termination config status (Plan 014 WI-1.5).

    ``warn`` when TLS is not configured (plain HTTP — acceptable for dev,
    a posture flag for production). ``ok`` when both the cert and key paths
    resolve to readable files. ``fail`` when TLS is configured but a path is
    missing or unreadable — a half-configured TLS deploy must not silently
    fall back to plaintext. In ``prod`` (Plan 015 WI-1.1), a missing TLS
    config escalates from ``warn`` to ``fail``: production must terminate TLS
    (the operator may put dossier behind a TLS-terminating proxy, but the
    ``DOSSIER_TLS_*`` seam or the proxy must be evident).
    """
    from .config import load_tls_config

    tls = load_tls_config()
    if tls is None:
        return [{
            "name": "tls",
            "status": "fail" if prod else "warn",
            "detail": "not configured (plain HTTP — dev only)",
        }]
    problems: list[str] = []
    if not tls.cert_path:
        problems.append("DOSSIER_TLS_CERT_PATH not set")
    elif not Path(tls.cert_path).is_file():
        problems.append(f"cert not found: {tls.cert_path}")
    if not tls.key_path:
        problems.append("DOSSIER_TLS_KEY_PATH not set")
    elif not Path(tls.key_path).is_file():
        problems.append(f"key not found: {tls.key_path}")
    if problems:
        return [{"name": "tls", "status": "fail", "detail": "; ".join(problems)}]
    return [{"name": "tls", "status": "ok", "detail": f"cert={tls.cert_path}"}]


def _suite_env_check() -> dict[str, Any]:
    """Report which suite.env source is active (Plan 014 WI-1.5)."""
    from .config import suite_env_path

    path = suite_env_path()
    if path:
        return {"name": "suite_env", "status": "ok", "detail": f"loaded {path}"}
    return {
        "name": "suite_env",
        "status": "skip",
        "detail": "no suite.env found (process env only)",
    }


def _env_mode_check(settings: Settings) -> dict[str, Any]:
    """Report the active deployment posture mode (H1).

    ``DOSSIER_ENV`` defaults to ``dev`` — an operator who deploys to production
    without setting ``DOSSIER_ENV=prod`` silently gets dev defaults (open
    access, no SSL required, TLS unset is ``warn`` not ``fail``). This check
    makes the active mode visible in the doctor output so the gap is named,
    not silent. It is informational (``warn`` in dev, ``ok`` in prod) and does
    not affect the suite umbrella's ``ok`` on its own — only ``fail`` checks
    flip ``ok`` to false.
    """
    if settings.env_mode == "prod":
        return {
            "name": "env_mode",
            "status": "ok",
            "detail": "DOSSIER_ENV=prod — production posture enforced",
        }
    return {
        "name": "env_mode",
        "status": "warn",
        "detail": (
            "DOSSIER_ENV unset/dev — running with dev defaults "
            "(open access, no SSL required). "
            "Set DOSSIER_ENV=prod for team deploys."
        ),
    }


def _ldap_config_check() -> dict[str, Any]:
    """Report LDAP config completeness without performing a bind (Plan 014 WI-1.5).

    The identity source's *configuration* is checked (all required env vars
    present); the live bind is operator-gated infra and is not exercised by a
    health probe. An incomplete config is a ``fail`` so a misconfigured deploy
    is visible before a user hits a login failure.
    """
    from .config import load_ldap_config

    try:
        cfg = load_ldap_config(strict=False)
    except ValueError as exc:
        return {"name": "auth_backend", "status": "fail", "detail": f"ldap: {exc}"}
    missing: list[str] = []
    if not cfg.server_urls:
        missing.append("DOSSIER_LDAP_SERVER")
    if not cfg.base_dn:
        missing.append("DOSSIER_LDAP_BASE_DN")
    if not cfg.bind_dn:
        missing.append("DOSSIER_LDAP_BIND_DN")
    if not cfg.bind_password:
        missing.append("DOSSIER_LDAP_BIND_PASSWORD")
    if not cfg.domain:
        missing.append("DOSSIER_LDAP_DOMAIN")
    if missing:
        return {
            "name": "auth_backend",
            "status": "fail",
            "detail": f"ldap incomplete: {', '.join(missing)}",
        }
    return {
        "name": "auth_backend",
        "status": "ok",
        "detail": "ldap configured (bind not checked in health probe)",
    }


def _secrets_backend_checks(settings: Settings) -> list[dict[str, Any]]:
    """Verify configured suite secret refs resolve (Plan 013 WI-4.1).

    A plaintext/bare-path deployment (the default) has nothing to verify → a
    single ``skip`` check. When a backend ref (``env:``/``vault:``/``azure:``/
    ``file:``) is configured for the regista DSN or signing key, this contacts
    the backend once to confirm the secret is reachable and (for the manifest)
    the material parses. Failures surface the exception type only — the wrapped
    message may echo partial material, but our wrapper already strips that, so
    this is a defense-in-depth. The materialized manifest temp file is cleaned
    up here; nothing persistent is left.
    """
    from . import secrets as suite_secrets

    refs: list[tuple[str, str]] = []
    if settings.database_url and suite_secrets.is_backend_ref(settings.database_url):
        refs.append(("REGISTA_DSN", settings.database_url))
    if settings.hmac_key_path and suite_secrets.is_backend_ref(settings.hmac_key_path):
        refs.append(("REGISTA_KEY_PATH", settings.hmac_key_path))

    if not refs:
        return [{
            "name": "secrets_backend",
            "status": "skip",
            "detail": "no backend refs configured (plaintext/file path)",
        }]

    results: list[dict[str, Any]] = []
    for label, ref in refs:
        try:
            if label == "REGISTA_DSN":
                suite_secrets.resolve_dsn(ref)
            else:
                path, cleanup = suite_secrets.materialize_key_manifest(ref)
                # A bare/file: path is returned unread — confirm it exists AND
                # parses as a key-set manifest, so a missing or corrupt file is
                # a named failure, not a silent pass that surfaces later when
                # regista's KeySet reads it. Remote refs are already validated
                # structurally by materialize_key_manifest.
                if cleanup is None and path is not None:
                    data = Path(path).read_bytes()
                    suite_secrets._validate_manifest_bytes(data)
                if cleanup is not None:
                    cleanup()
            results.append({
                "name": f"secrets_backend:{label}",
                "status": "ok",
                "detail": "resolved",
            })
        except Exception as exc:
            results.append({
                "name": f"secrets_backend:{label}",
                "status": "fail",
                "detail": f"{label} ref unresolvable: {type(exc).__name__}",
            })
    return results


def _notification_sink_check(settings: Settings) -> dict[str, Any]:
    """Report notification sink configuration status (Plan 018 WI-2.1).

    ``warn`` when no sink is configured — notifications are not being
    delivered, which is acceptable for dev but a posture flag for
    production. ``ok`` when ``DOSSIER_NOTIFICATION_SINK`` is set.
    """
    from .notifications import notification_health_check

    posture = notification_health_check(
        settings.notification_sink,
        settings.notification_secret_ref,
    )
    if posture["status"] != "ok":
        return posture

    from .secrets import resolve_secret_bytes

    try:
        resolve_secret_bytes(settings.notification_secret_ref)
    except Exception as exc:
        return {
            "name": "notification_sink",
            "status": "fail",
            "detail": (
                "notification signing secret unresolvable: "
                f"{type(exc).__name__}"
            ),
        }
    return posture


def _project_access_check(
    settings: Settings, *, prod: bool = False
) -> dict[str, Any]:
    """Report the effective cross-project disclosure posture.

    In ``prod`` (Plan 015 WI-1.1), ``open`` escalates from ``warn`` to
    ``fail``: a production deploy must not let every authenticated principal
    read every project. The operator opts into prod posture via
    ``DOSSIER_ENV=prod`` and should pair it with
    ``DOSSIER_PROJECT_ACCESS_MODE=enforce`` + an ACL.
    """
    mode = settings.project_access_mode

    # ``open`` needs no ACL; ``audit`` and ``enforce`` both require a loadable
    # policy before the mode-specific status is reported.
    if mode != "open":
        from .authz import load_project_access_policy

        try:
            load_project_access_policy(
                settings.project_acl_path,
                group_claim_key=settings.session_secret.encode("utf-8"),
            )
        except Exception as exc:
            return {
                "name": "project_access",
                "status": "fail",
                "detail": f"ACL invalid or unreadable: {type(exc).__name__}",
            }

    match mode:
        case "open":
            return {
                "name": "project_access",
                "status": "fail" if prod else "warn",
                "detail": "open: every authenticated principal can read every project",
            }
        case "audit":
            return {
                "name": "project_access",
                "status": "warn",
                "detail": "audit: default-deny ACL loaded; denials not enforced",
            }
        case "enforce":
            return {
                "name": "project_access",
                "status": "ok",
                "detail": "enforce: default-deny ACL loaded",
            }
        case other:
            assert_never(other)


def _allowed_hosts_check(
    settings: Settings, *, prod: bool = False
) -> dict[str, Any]:
    """Report the TrustedHostMiddleware posture (Plan 015 WI-1.1).

    ``ok`` when ``DOSSIER_ALLOWED_HOSTS`` is set (the middleware is wired).
    ``skip`` in dev when unset (no middleware — current behavior). ``warn`` in
    prod when unset: production should pin the allowed Host header set so a
    host-header-injection cannot bypass same-origin assumptions. This is a
    ``warn`` (not ``fail``) because dossier is expected behind a
    TLS-terminating proxy that can also enforce the host allowlist — the gap
    is a posture flag, not a hard block.
    """
    if settings.allowed_hosts:
        return {
            "name": "allowed_hosts",
            "status": "ok",
            "detail": f"trusted-host allowlist: {', '.join(settings.allowed_hosts)}",
        }
    if prod:
        return {
            "name": "allowed_hosts",
            "status": "warn",
            "detail": "DOSSIER_ALLOWED_HOSTS unset in prod; pin the host allowlist",
        }
    return {
        "name": "allowed_hosts",
        "status": "skip",
        "detail": "not configured (dev — no TrustedHostMiddleware)",
    }
