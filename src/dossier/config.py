from __future__ import annotations

import os
import re
import stat
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from ._platform import open_no_follow

_TRUE = {"1", "true", "yes"}
_FALSE = {"0", "false", "no"}

_EXPORT_RE = re.compile(r"^export\s+")

_BLOCKED_KEYS = frozenset({
    "PATH", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP",
    "LD_LIBRARY_PATH", "LD_PRELOAD", "DYLD_LIBRARY_PATH",
    "SHLIB_PATH", "LIBPATH",
})

_SUITE_ENV_LOADED = False
# The suite.env file that was actually loaded (None when no file was found).
# Recorded so ``doctor`` can report which config source is active (Plan 014 WI-1.5).
_SUITE_ENV_PATH: str | None = None


def suite_env_path() -> str | None:
    """Return the suite.env path that was loaded, or ``None`` if none was found.

    Set by :func:`load_suite_env`. Lets the health/doctor surface report the
    active config source without re-reading the filesystem.
    """
    return _SUITE_ENV_PATH


def load_suite_env() -> None:
    """Load the shared suite config file into ``os.environ``.

    The suite-wide config file (``suite.env``) is sourced once at startup,
    before any settings are resolved.  Only keys that are **not already set**
    in the process environment are injected, so explicit process env always
    wins (blueprint §2.1 precedence: process env > suite.env > tool default).

    Resolution order for the file path:
      1. ``$AGENT_SUITE_CONFIG`` (explicit path; an explicit-but-missing file
         is an error, not silently skipped)
      2. ``~/.config/agent-suite/suite.env`` (per-user default)
      3. ``/etc/agent-suite/suite.env`` (system-wide default)

    Missing default-path files are silently skipped — the suite file is
    optional.  The function is idempotent (guarded by a module-level flag).
    """
    global _SUITE_ENV_LOADED, _SUITE_ENV_PATH
    if _SUITE_ENV_LOADED:
        return
    _SUITE_ENV_LOADED = True
    _SUITE_ENV_PATH = None

    explicit = os.environ.get("AGENT_SUITE_CONFIG", "")
    if explicit:
        if not os.path.isfile(explicit):
            raise FileNotFoundError(
                f"AGENT_SUITE_CONFIG points to {explicit!r}, which does not exist."
            )
        _inject_env_file(explicit)
        _SUITE_ENV_PATH = explicit
        return

    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    for path in (
        f"{xdg}/agent-suite/suite.env",
        "/etc/agent-suite/suite.env",
    ):
        if os.path.isfile(path):
            _inject_env_file(path)
            _SUITE_ENV_PATH = path
            return


def _inject_env_file(path: str) -> None:
    """Parse a KEY=VALUE file and inject unset keys into ``os.environ``.

    Refuses world-writable or group-writable files and symlinks.
    """
    fd = open_no_follow(path, os.O_RDONLY)
    try:
        st = os.fstat(fd)
        if st.st_mode & stat.S_IWOTH:
            raise PermissionError(
                f"Refusing to load world-writable suite env file: {path}"
            )
        with os.fdopen(fd, encoding="utf-8-sig") as f:
            for line in f:
                _parse_env_line(line)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _parse_env_line(line: str) -> None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return
    stripped = _EXPORT_RE.sub("", stripped, count=1)
    if "=" not in stripped:
        return
    key, sep, raw_value = stripped.partition("=")
    key = key.strip()
    if not key or not sep:
        return
    if key in _BLOCKED_KEYS:
        return
    value = _strip_value(raw_value.strip())
    if key not in os.environ:
        os.environ[key] = value


def _strip_value(raw: str) -> str:
    """Strip surrounding quotes and trailing inline comments from *raw*.

    Quoted values are returned verbatim (minus the quotes); inline comments
    are only stripped from unquoted values to avoid corrupting quoted content.
    """
    if not raw:
        return raw
    if len(raw) >= 2 and raw[0] in ("'", '"'):
        close = raw.rfind(raw[0])
        if close > 0:
            return raw[1:close]
    inline_comment = raw.find(" #")
    if inline_comment != -1:
        raw = raw[:inline_comment].rstrip()
    return raw


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
    notification_sink: str = ""
    base_url: str = "http://localhost:8000"


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


@dataclass(frozen=True, slots=True)
class TlsConfig:
    """TLS termination config for the dossier web server (Plan 014 WI-1.5).

    Env-driven: when both ``DOSSIER_TLS_CERT_PATH`` and ``DOSSIER_TLS_KEY_PATH``
    are set, the uvicorn server serves over TLS; when both are unset, plain
    HTTP (dev). Setting only one is a configuration error caught at serve time.
    No certificate is ever committed — these are host paths the operator
    provisions (or a mounted secret in the container deploy). This is the seam
    the AC ("logs in over TLS") exercises; the live cross-machine validation
    is operator-gated (real certs + work network).
    """

    cert_path: str
    key_path: str


def load_tls_config() -> TlsConfig | None:
    """Load TLS config from the environment.

    Returns ``None`` when TLS is not configured (both vars unset) so the
    caller serves plain HTTP. Returns a :class:`TlsConfig` (possibly with an
    empty field) when at least one var is set; the caller validates that both
    are present before serving — a half-set pair is a fail-loud error, not a
    silent plaintext fallback.
    """
    cert = os.environ.get("DOSSIER_TLS_CERT_PATH", "")
    key = os.environ.get("DOSSIER_TLS_KEY_PATH", "")
    if not cert and not key:
        return None
    return TlsConfig(cert_path=cert, key_path=key)


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
        # Derive ``<key_dir>/principals`` only when the key path is a real
        # filesystem location. A backend ref (env:/vault:/azure:) has no
        # meaningful parent directory, and a ``file:`` ref must be stripped of
        # its prefix before Path() treats the whole string as one segment.
        # Deriving from a ref would silently drop principal keys into the
        # process CWD — a private-key leak. Refuse and ask the operator to set
        # DOSSIER_PRINCIPAL_KEY_DIR explicitly.
        from .secrets import is_backend_ref

        if is_backend_ref(hmac_key_path):
            if hmac_key_path.lower().startswith("file:"):
                principal_key_dir = str(
                    Path(hmac_key_path.split(":", 1)[1]).expanduser().parent / "principals"
                )
            else:
                raise RuntimeError(
                    "DOSSIER_PRINCIPAL_KEY_DIR must be set explicitly when "
                    "REGISTA_KEY_PATH is a remote backend ref (env:/vault:/azure:)"
                )
        else:
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
        notification_sink=os.environ.get("DOSSIER_NOTIFICATION_SINK", ""),
        base_url=os.environ.get("DOSSIER_BASE_URL", "http://localhost:8000"),
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
