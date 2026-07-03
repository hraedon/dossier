from __future__ import annotations

from typing import Any, Literal

from . import __version__
from .config import Settings
from .multi import GatewayRegistry

CheckStatus = Literal["pass", "fail", "skip"]


def build_health(
    settings: Settings,
    registry: GatewayRegistry,
) -> dict[str, Any]:
    """Build the suite-conformant health shape.

    Returns::

        {
            "component": "dossier",
            "version": "0.0.1",
            "regista": {"reachable": bool, "project": str, "chain_ok": bool | None},
            "checks": [{"name": str, "status": "pass|fail|skip", "detail": str | None}],
        }

    An unreachable regista or missing session secret is a named ``checks``
    failure — never an exception.
    """
    checks: list[dict[str, Any]] = []

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
            "detail": str(exc)[:200],
        })

    if settings.session_secret and len(settings.session_secret) >= 32:
        checks.append({"name": "session_secret", "status": "pass", "detail": None})
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
                "status": "pass",
                "detail": "local",
            })
        else:
            checks.append({
                "name": "auth_backend",
                "status": "fail",
                "detail": "local backend selected but DOSSIER_USERS_PATH not set",
            })
    elif settings.auth_backend == "ldap":
        checks.append({
            "name": "auth_backend",
            "status": "pass",
            "detail": "ldap (bind not checked in health probe)",
        })

    return {
        "component": "dossier",
        "version": __version__,
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
