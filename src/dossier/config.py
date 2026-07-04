from __future__ import annotations

import os
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

_TRUE = {"1", "true", "yes"}
_FALSE = {"0", "false", "no"}


def _resolve_env(
    canonical: str,
    legacy: str,
    *,
    default: str = "",
) -> str:
    """Prefer the canonical suite var, fall back to the legacy dossier var.

    Emits a DeprecationWarning when only the legacy var is set so operators
    know to migrate. When both are set, the canonical wins silently.
    """
    canonical_val = os.environ.get(canonical, "")
    if canonical_val.strip():
        return canonical_val
    legacy_val = os.environ.get(legacy, "")
    if legacy_val.strip():
        warnings.warn(
            f"{legacy} is deprecated; use {canonical} (the suite-wide name).",
            DeprecationWarning,
            stacklevel=3,
        )
        return legacy_val
    return default


@dataclass(frozen=True, slots=True)
class Settings:
    database_url: str
    project: str
    hmac_key_path: str
    session_secret: str
    session_max_age_seconds: int
    secure_cookies: bool
    require_ssl: bool
    users_path: str
    auth_backend: Literal["local", "ldap"]
    principal_key_dir: str


@dataclass(frozen=True, slots=True)
class LdapConfig:
    """Configuration for the ``LdapBackend`` (Plan 003).

    All values come from ``DOSSIER_LDAP_*`` environment variables. No real
    domain data is committed — ``.env.example`` carries placeholders only.
    """

    server_urls: list[str]
    base_dn: str
    bind_dn: str
    bind_password: str
    user_filter: str
    group_strategy: Literal["direct", "nested"]
    ca_cert_file: str
    connect_timeout: int
    domain: str


def _parse_bool(name: str, raw: str) -> bool:
    lowered = raw.strip().lower()
    if lowered in _TRUE:
        return True
    if lowered in _FALSE:
        return False
    raise ValueError(f"Invalid boolean for {name}: {raw!r}")


def _require(name: str, value: str) -> str:
    if value.strip() == "":
        raise RuntimeError(f"{name} is required; set the environment variable.")
    return value


def load_settings(strict: bool = True) -> Settings:
    database_url = _resolve_env("REGISTA_DSN", "DOSSIER_DATABASE_URL")
    project = os.environ.get("DOSSIER_PROJECT", "dossier")
    hmac_key_path = _resolve_env("REGISTA_KEY_PATH", "DOSSIER_HMAC_KEY_PATH")
    session_secret = os.environ.get("DOSSIER_SESSION_SECRET", "")
    session_max_age_raw = os.environ.get("DOSSIER_SESSION_MAX_AGE_SECONDS", "43200")
    secure_cookies_raw = os.environ.get("DOSSIER_SECURE_COOKIES", "true")
    require_ssl_raw = os.environ.get("DOSSIER_REQUIRE_SSL", "false")
    users_path = os.environ.get("DOSSIER_USERS_PATH", "")
    auth_backend = os.environ.get("DOSSIER_AUTH_BACKEND", "local")
    if auth_backend not in ("local", "ldap"):
        raise ValueError(
            f"DOSSIER_AUTH_BACKEND must be 'local' or 'ldap', got {auth_backend!r}"
        )

    principal_key_dir = os.environ.get("DOSSIER_PRINCIPAL_KEY_DIR", "")
    if not principal_key_dir and hmac_key_path:
        principal_key_dir = str(Path(hmac_key_path).parent / "principals")

    if strict:
        _require("REGISTA_DSN (or DOSSIER_DATABASE_URL)", database_url)
        _require("REGISTA_KEY_PATH (or DOSSIER_HMAC_KEY_PATH)", hmac_key_path)
        _require("DOSSIER_SESSION_SECRET", session_secret)
        if len(session_secret) < 32:
            raise RuntimeError(
                "DOSSIER_SESSION_SECRET must be at least 32 bytes for signed sessions"
            )

    try:
        session_max_age_seconds = int(session_max_age_raw)
    except ValueError as exc:
        raise ValueError(
            f"DOSSIER_SESSION_MAX_AGE_SECONDS must be an integer, got {session_max_age_raw!r}"
        ) from exc

    secure_cookies = _parse_bool("DOSSIER_SECURE_COOKIES", secure_cookies_raw)
    require_ssl = _parse_bool("DOSSIER_REQUIRE_SSL", require_ssl_raw)

    return Settings(
        database_url=database_url,
        project=project,
        hmac_key_path=hmac_key_path,
        session_secret=session_secret,
        session_max_age_seconds=session_max_age_seconds,
        secure_cookies=secure_cookies,
        require_ssl=require_ssl,
        users_path=users_path,
        auth_backend=cast(Literal["local", "ldap"], auth_backend),
        principal_key_dir=principal_key_dir,
    )


def load_ldap_config(strict: bool = True) -> LdapConfig:
    """Load LDAP configuration from ``DOSSIER_LDAP_*`` environment variables.

    When ``strict`` is False (used by ``dossier serve`` before the backend is
    selected), missing values are allowed — the caller decides what is required.
    """
    raw_servers = os.environ.get("DOSSIER_LDAP_SERVER", "")
    server_urls = [s.strip() for s in raw_servers.split(",") if s.strip()]
    base_dn = os.environ.get("DOSSIER_LDAP_BASE_DN", "")
    bind_dn = os.environ.get("DOSSIER_LDAP_BIND_DN", "")
    bind_password = os.environ.get("DOSSIER_LDAP_BIND_PASSWORD", "")
    user_filter = os.environ.get(
        "DOSSIER_LDAP_USER_FILTER",
        "(&(objectClass=user)(sAMAccountName={login}))",
    )
    group_strategy = os.environ.get("DOSSIER_LDAP_GROUP_STRATEGY", "direct")
    ca_cert_file = os.environ.get("DOSSIER_LDAP_CA_CERT_FILE", "")
    connect_timeout_raw = os.environ.get("DOSSIER_LDAP_CONNECT_TIMEOUT", "5") or "5"
    domain = os.environ.get("DOSSIER_LDAP_DOMAIN", "")

    if group_strategy not in ("direct", "nested"):
        raise ValueError(
            f"DOSSIER_LDAP_GROUP_STRATEGY must be 'direct' or 'nested', got {group_strategy!r}"
        )

    try:
        connect_timeout = int(connect_timeout_raw)
    except ValueError as exc:
        raise ValueError(
            f"DOSSIER_LDAP_CONNECT_TIMEOUT must be an integer, got {connect_timeout_raw!r}"
        ) from exc

    if strict:
        _require("DOSSIER_LDAP_SERVER", raw_servers)
        _require("DOSSIER_LDAP_BASE_DN", base_dn)
        _require("DOSSIER_LDAP_BIND_DN", bind_dn)
        _require("DOSSIER_LDAP_BIND_PASSWORD", bind_password)
        if not domain:
            raise RuntimeError("DOSSIER_LDAP_DOMAIN is required for the ldap backend")
        is_ldaps = any(s.lower().startswith("ldaps://") for s in server_urls)
        if not is_ldaps:
            raise RuntimeError(
                "DOSSIER_LDAP_SERVER must use ldaps:// — plaintext LDAP is not permitted"
            )
        if not ca_cert_file:
            raise RuntimeError(
                "DOSSIER_LDAP_CA_CERT_FILE is required in strict mode — "
                "cannot fall back to system trust store"
            )

    return LdapConfig(
        server_urls=server_urls,
        base_dn=base_dn,
        bind_dn=bind_dn,
        bind_password=bind_password,
        user_filter=user_filter,
        group_strategy=cast(Literal["direct", "nested"], group_strategy),
        ca_cert_file=ca_cert_file,
        connect_timeout=connect_timeout,
        domain=domain,
    )
