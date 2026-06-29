from __future__ import annotations

import json
import logging
import ssl
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from .passwords import hash_password, verify_password

if TYPE_CHECKING:
    from ..config import LdapConfig

logger = logging.getLogger("dossier.auth.ldap")

_DUMMY_HASH = hash_password("dossier-dummy-do-not-use")


@dataclass(frozen=True, slots=True)
class Principal:
    """A verified identity, backend-agnostic.

    ``stable_id`` is a durable identifier (a minted uuid for local users, an
    LDAP ``objectGUID`` for AD) that survives renames — it is what becomes the
    regista ``actor_id``. ``raw_attributes`` carries backend-specific data
    (username, groups) for authorization and display.
    """

    stable_id: str
    display_name: str
    source: str
    raw_attributes: dict = field(default_factory=dict)


class CredentialBackend(Protocol):
    """The interface every credential-in-hand backend implements.

    This is the contract for backends that verify a supplied password against
    a directory or local store — ``LocalBackend`` and ``LdapBackend`` today.
    A future federated backend (Entra/OIDC) will *not* implement this Protocol:
    it has no password to verify, only a token to exchange. See
    ``docs/adr-001-two-family-auth.md``.

    The rest of dossier never knows which directory is behind it; it sees
    ``authenticate`` → :class:`Principal` and ``fetch_groups`` for team authz
    (Plan 004).
    """

    def authenticate(self, identifier: str, password: str) -> Principal | None: ...

    def fetch_groups(self, principal: Principal) -> list[str]: ...


class LocalBackend:
    """MVP/dev backend: users in a JSON file, scrypt-hashed passwords.

    No directory infra required. ``stable_id`` is a minted uuid per user. The
    users file is a JSON array of objects with keys ``stable_id``, ``username``,
    ``display_name``, ``password`` (a ``hash_password`` string), ``groups``.
    """

    def __init__(
        self,
        users_path: str | Path | None = None,
        *,
        users_json: str | None = None,
    ) -> None:
        if users_path is None and users_json is None:
            raise ValueError("either users_path or users_json must be provided")
        self._path = Path(users_path) if users_path is not None else None
        self._users = self._load(users_json)

    def _load(self, users_json: str | None) -> dict[str, dict]:
        if users_json is not None:
            data = json.loads(users_json)
        else:
            assert self._path is not None
            with self._path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("users file must be a JSON array of user objects")
        users: dict[str, dict] = {}
        for entry in data:
            if not isinstance(entry, dict) or not all(
                k in entry for k in ("stable_id", "username", "display_name", "password")
            ):
                raise ValueError(f"malformed user entry: {entry!r}")
            users[entry["username"]] = entry
        return users

    def authenticate(self, identifier: str, password: str) -> Principal | None:
        user = self._users.get(identifier)
        if user is None:
            verify_password(password, _DUMMY_HASH)
            return None
        if not verify_password(password, user.get("password", "")):
            return None
        return Principal(
            stable_id=user["stable_id"],
            display_name=user["display_name"],
            source="local",
            raw_attributes={
                "username": user["username"],
                "groups": list(user.get("groups", [])),
            },
        )

    def fetch_groups(self, principal: Principal) -> list[str]:
        return list(principal.raw_attributes.get("groups", []))

    @staticmethod
    def add_user(
        path: str | Path,
        username: str,
        display_name: str,
        password_plain: str,
    ) -> dict:
        """Append a new local user to ``path``, returning the new user record.

        Mints a uuid ``stable_id`` and scrypt-hashes the password. Intended for
        a future ``dossier users add`` CLI command; not wired into the CLI here.
        """
        path = Path(path)
        if path.exists():
            with path.open("r", encoding="utf-8") as f:
                users = json.load(f)
            if not isinstance(users, list):
                raise ValueError("existing users file must be a JSON array")
        else:
            users = []
        new_user = {
            "stable_id": str(uuid.uuid4()),
            "username": username,
            "display_name": display_name,
            "password": hash_password(password_plain),
            "groups": [],
        }
        users.append(new_user)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(users, f, indent=2)
        return new_user


# ── objectGUID / SID helpers ──────────────────────────────────────────────


def _guid_bytes_to_str(raw: object) -> str | None:
    """Convert an AD ``objectGUID`` from raw bytes to a canonical UUID string.

    AD stores ``objectGUID`` as a little-endian binary UUID. When ldap3 fetches
    it with ``get_info=NONE``, the value is raw ``bytes``. We convert using
    ``uuid.UUID(bytes_le=...)`` which handles the AD byte order. If ldap3 (or a
    mock) already returns a string, we normalize it through ``uuid.UUID`` so
    the same object always produces the same ``stable_id`` regardless of
    formatting (braces, case, etc.).
    """
    if raw is None:
        return None
    if isinstance(raw, str):
        try:
            return str(uuid.UUID(raw))
        except (ValueError, TypeError):
            return raw
    if isinstance(raw, (bytes, bytearray)):
        try:
            return str(uuid.UUID(bytes_le=bytes(raw)))
        except (ValueError, TypeError):
            return None
    return None


# ── LDAP / Active Directory backend ──────────────────────────────────────


class LdapBackend:
    """LDAP/AD authentication via search-then-bind (Plan 003).

    **Authenticate = search-then-bind (the standard safe flow):**

    1. Bind as the service account; search for the user by
       ``sAMAccountName`` under the configured base DN.
    2. Re-bind as the found user DN with their supplied password to verify it.
    3. On success, build the :class:`Principal` with
       ``stable_id = objectGUID``, ``source = "ldap:<domain>"``.

    **Keyed on ``objectGUID``, not ``sAMAccountName`` or DN** — ``sAMAccountName``
    can be reused/renamed and a DN moves when an object changes OU;
    ``objectGUID`` is immutable (Plan 003 principle, 002 G1).

    **LDAPS with real certificate validation — pin the AD CA.** No
    ``validate=NONE``. The ``ca_cert_file`` parameter pins the root CA; without
    it, validation falls back to the system trust store with a warning.

    **Empty passwords are explicitly rejected** — AD may treat an empty-password
    bind as an anonymous success, which would bypass credential verification.

    ``fetch_groups`` returns groups cached during ``authenticate`` — direct
    (``memberOf``) or nested (``LDAP_MATCHING_RULE_IN_CHAIN``), configurable.
    """

    _NESTED_MEMBER_OID = "1.2.840.113556.1.4.1941"

    def __init__(
        self,
        *,
        server_urls: list[str],
        base_dn: str,
        bind_dn: str,
        bind_password: str,
        domain: str,
        user_filter: str = "(&(objectClass=user)(sAMAccountName={login}))",
        group_strategy: str = "direct",
        ca_cert_file: str = "",
        connect_timeout: int = 5,
    ) -> None:
        if not server_urls:
            raise ValueError("server_urls must not be empty")
        is_ldaps = any(s.lower().startswith("ldaps://") for s in server_urls)
        if not is_ldaps:
            raise ValueError("LdapBackend requires ldaps:// — plaintext LDAP is not permitted")
        if not ca_cert_file:
            logger.warning(
                "LDAPS without ca_cert_file — validating against system trust "
                "store only; private-CA servers will fail. Pin the AD root CA "
                "for reliable validation."
            )
        self._server_urls = server_urls
        self._base_dn = base_dn
        self._bind_dn = bind_dn
        self._bind_password = bind_password
        self._domain = domain
        self._user_filter = user_filter
        self._group_strategy = group_strategy
        self._ca_cert_file = ca_cert_file
        self._connect_timeout = connect_timeout

        try:
            import ldap3  # noqa: F401
        except ImportError:
            raise RuntimeError(
                "LDAP auth requires the 'ldap3' package. "
                "Install it with: pip install dossier[auth-ldap]"
            ) from None

    @classmethod
    def from_config(cls, config: LdapConfig) -> LdapBackend:
        """Build an ``LdapBackend`` from a loaded :class:`LdapConfig`."""
        return cls(
            server_urls=config.server_urls,
            base_dn=config.base_dn,
            bind_dn=config.bind_dn,
            bind_password=config.bind_password,
            domain=config.domain,
            user_filter=config.user_filter,
            group_strategy=config.group_strategy,
            ca_cert_file=config.ca_cert_file,
            connect_timeout=config.connect_timeout,
        )

    # ── connection plumbing ───────────────────────────────────────────

    def _build_tls(self):
        import ldap3

        tls_kwargs: dict = {"validate": ssl.CERT_REQUIRED}
        if self._ca_cert_file:
            tls_kwargs["ca_certs_file"] = self._ca_cert_file
        return ldap3.Tls(**tls_kwargs)

    def _build_server_pool(self):
        import ldap3

        tls = self._build_tls()
        servers = [
            ldap3.Server(url, get_info=ldap3.NONE, tls=tls, connect_timeout=self._connect_timeout)
            for url in self._server_urls
        ]
        if len(servers) > 1:
            return ldap3.ServerPool(servers, pool_strategy=ldap3.FIRST, active=True)
        return servers[0]

    # ── credential verification ──────────────────────────────────────

    def authenticate(self, identifier: str, password: str) -> Principal | None:
        if not identifier or not password:
            return None

        try:
            import ldap3
        except ImportError:
            raise RuntimeError(
                "LDAP auth requires the 'ldap3' package. "
                "Install it with: pip install dossier[auth-ldap]"
            ) from None

        svc_conn = None
        user_conn = None
        try:
            pool = self._build_server_pool()

            # ── Step 1: bind as service account and search for the user ──
            svc_conn = ldap3.Connection(
                pool,
                user=self._bind_dn,
                password=self._bind_password,
                read_only=True,
                auto_bind=False,
            )
            if not svc_conn.bind():
                logger.warning("LDAP service account bind failed")
                return None

            search_filter = self._user_filter.replace(
                "{login}", ldap3.utils.conv.escape_filter_chars(identifier)
            )

            # Search without memberOf — group membership is only fetched after
            # the password is verified, so an attacker who knows a username
            # cannot learn group memberships or drive extra directory load.
            svc_conn.search(
                self._base_dn,
                search_filter,
                attributes=[
                    "objectGUID",
                    "displayName",
                    "cn",
                    "sAMAccountName",
                ],
            )

            if not svc_conn.entries:
                return None

            entry = svc_conn.entries[0]
            user_dn = str(entry.entry_dn)

            # ── WI-2: stable_id from objectGUID ──
            guid_raw = _attr_value(entry, "objectGUID")
            stable_id = _guid_bytes_to_str(guid_raw)
            if not stable_id:
                logger.warning(
                    "LDAP user %s has no objectGUID — cannot establish stable_id",
                    identifier,
                )
                return None

            display_name = (
                _attr_value(entry, "displayName") or _attr_value(entry, "cn") or identifier
            )

            # ── Step 2: re-bind as the found user to verify their password ──
            # ldap3's bind() returns False on bad credentials (it does not
            # raise unless raise_exceptions=True), so the result MUST be
            # checked. Ignoring it is an auth bypass.
            user_conn = ldap3.Connection(
                pool,
                user=user_dn,
                password=password,
                auto_bind=False,
            )
            bound = user_conn.bind()

            if not bound:
                return None

            # ── WI-3: group retrieval (only after password is verified) ──
            # Groups are fetched via the service account connection so the
            # user's bind is not held open longer than necessary.
            if self._group_strategy == "nested":
                groups = self._fetch_nested_groups(svc_conn, user_dn)
            else:
                svc_conn.search(
                    self._base_dn,
                    search_filter,
                    attributes=["memberOf"],
                )
                groups = _attr_values(svc_conn.entries[0], "memberOf") if svc_conn.entries else []

            return Principal(
                stable_id=stable_id,
                display_name=str(display_name),
                source=f"ldap:{self._domain}",
                raw_attributes={
                    "username": identifier,
                    "dn": user_dn,
                    "groups": list(groups),
                },
            )

        except ldap3.core.exceptions.LDAPBindError:
            return None
        except (ldap3.core.exceptions.LDAPException, OSError) as exc:
            logger.warning("LDAP auth error: %s", exc)
            return None
        finally:
            if user_conn is not None:
                try:
                    user_conn.unbind()
                except Exception:
                    pass
            if svc_conn is not None:
                try:
                    svc_conn.unbind()
                except Exception:
                    pass

    def fetch_groups(self, principal: Principal) -> list[str]:
        """Return group identities cached during ``authenticate``.

        For ``direct`` strategy these are ``memberOf`` DNs; for ``nested`` they
        are DNs from the ``LDAP_MATCHING_RULE_IN_CHAIN`` recursive search. Both
        are populated during ``authenticate`` so this is a cache read — no
        additional directory round-trip. Plan 004 maps these to teams.
        """
        return list(principal.raw_attributes.get("groups", []))

    # ── internal ──────────────────────────────────────────────────────

    def _fetch_nested_groups(self, conn, user_dn: str) -> list[str]:
        """Find all groups (including nested) via ``LDAP_MATCHING_RULE_IN_CHAIN``.

        Searches for ``(&(objectClass=group)(member:OID:=<user_dn>))`` which
        recursively resolves nested group membership in a single query. Returns
        group DNs — Plan 004 will map these (or their GUIDs) to teams.
        """
        import ldap3

        escaped_dn = ldap3.utils.conv.escape_filter_chars(user_dn)
        search_filter = f"(&(objectClass=group)(member:{self._NESTED_MEMBER_OID}:={escaped_dn}))"
        conn.search(
            self._base_dn,
            search_filter,
            attributes=["distinguishedName"],
        )
        return [str(e.entry_dn) for e in conn.entries]


# ── ldap3 attribute access helpers ────────────────────────────────────────


def _attr_value(entry, name: str):
    """Safely get a single attribute value from an ldap3 entry, or ``None``."""
    if name in entry.entry_attributes:
        val = entry[name].value
        return val
    return None


def _attr_values(entry, name: str) -> list:
    """Safely get a list of attribute values from an ldap3 entry, or ``[]``."""
    if name in entry.entry_attributes:
        return list(entry[name].values)
    return []
