from __future__ import annotations

import os
from dataclasses import dataclass

_TRUE = {"1", "true", "yes"}
_FALSE = {"0", "false", "no"}


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
    auth_backend: str


def _parse_bool(name: str, raw: str) -> bool:
    lowered = raw.strip().lower()
    if lowered in _TRUE:
        return True
    if lowered in _FALSE:
        return False
    raise ValueError(f"Invalid boolean for {name}: {raw!r}")


def _require(name: str, value: str) -> str:
    if value == "":
        raise RuntimeError(f"{name} is required; set the environment variable.")
    return value


def load_settings(strict: bool = True) -> Settings:
    database_url = os.environ.get("DOSSIER_DATABASE_URL", "")
    project = os.environ.get("DOSSIER_PROJECT", "dossier")
    hmac_key_path = os.environ.get("DOSSIER_HMAC_KEY_PATH", "")
    session_secret = os.environ.get("DOSSIER_SESSION_SECRET", "")
    session_max_age_raw = os.environ.get("DOSSIER_SESSION_MAX_AGE_SECONDS", "43200")
    secure_cookies_raw = os.environ.get("DOSSIER_SECURE_COOKIES", "true")
    require_ssl_raw = os.environ.get("DOSSIER_REQUIRE_SSL", "false")
    users_path = os.environ.get("DOSSIER_USERS_PATH", "")
    auth_backend = os.environ.get("DOSSIER_AUTH_BACKEND", "local")

    if strict:
        _require("DOSSIER_DATABASE_URL", database_url)
        _require("DOSSIER_HMAC_KEY_PATH", hmac_key_path)
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
        auth_backend=auth_backend,
    )
