from __future__ import annotations

import json
import logging
import os
import ssl
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol, assert_never

from .passwords import hash_password, verify_password

if TYPE_CHECKING:
    from ..config import LdapConfig

logger = logging.getLogger("dossier.auth.ldap")

_DUMMY_HASH: str | None = None


def validate_principal_binding(value: object) -> str:
    """Validate a recorded regista ``principal_id`` and return it normalized.

    Applies regista's own principal-id grammar so a binding that dossier accepts
    is one regista can register a key against. Raises :class:`ValueError` with a
    message naming the offending value — this runs at identity-source load time
    (users file parse / LDAP attribute read), where an operator can act on it.
    """
    from ..keys import _validate_principal_id

    if not isinstance(value, str):
        raise ValueError(
            f"principal_id must be a string, got {type(value).__name__}"
        )
    candidate = value.strip()
    _validate_principal_id(candidate)
    return candidate


def _get_dummy_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password("dossier-dummy-do-not-use")
    return _DUMMY_HASH


@dataclass(frozen=True, slots=True)
class Principal:
    """A verified identity, backend-agnostic.

    ``stable_id`` is a durable identifier (a minted uuid for local users, an
    LDAP ``objectGUID`` for AD) that survives renames. ``raw_attributes``
    carries backend-specific data (username, groups) for authorization and
    display.

    ``principal_id`` is the regista signing principal this identity is bound to
    (WI-035), or ``None`` when the operator has not recorded one. It is
    deliberately never *derived* — not from the username, not from the
    ``stable_id``. A derived binding would silently claim a signing identity the
    suite may not have provisioned, and dossier would then either sign as
    somebody else or fall back to the shared store key; both are worse than
    saying "unbound". When it is set it becomes the regista ``actor_id`` (see
    :func:`dossier.auth.resolver.principal_to_actor`).
    """

    stable_id: str
    display_name: str
    source: str
    raw_attributes: dict[str, Any] = field(default_factory=dict)
    principal_id: str | None = None


@dataclass(frozen=True, slots=True)
class GroupIdentity:
    """A group identity keyed on immutable ``guid`` (Plan 003).

    DNs break when groups are renamed/moved between OUs; ``objectGUID`` is
    immutable. ``name`` is the human-readable label (the AD ``name`` attribute
    or CN extracted from the DN). ``dn`` is retained for display and debugging.
    For local users, ``guid`` is empty and ``name`` is the identifier.
    """

    guid: str
    name: str
    dn: str


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

    def fetch_groups(self, principal: Principal) -> list[GroupIdentity]: ...


class LocalBackend:
    """MVP/dev backend: users in a JSON file, scrypt-hashed passwords.

    No directory infra required. ``stable_id`` is a minted uuid per user. The
    users file is a JSON array of objects with keys ``stable_id``, ``username``,
    ``display_name``, ``password`` (a ``hash_password`` string), ``groups``, and
    an optional ``principal_id``.

    ``principal_id`` is the regista signing principal the user acts as (WI-035).
    It is optional so an existing users file keeps loading, and it is never
    inferred from ``username`` or ``stable_id``: the value must match a principal
    that `agent-suite bootstrap --user <principal_id>` has actually provisioned a
    key for, and only the operator knows that.
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

    def _load(self, users_json: str | None) -> dict[str, dict[str, Any]]:
        if users_json is not None:
            data = json.loads(users_json)
        else:
            assert self._path is not None
            with self._path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("users file must be a JSON array of user objects")
        users: dict[str, dict[str, Any]] = {}
        for entry in data:
            if not isinstance(entry, dict) or not all(
                k in entry for k in ("stable_id", "username", "display_name", "password")
            ):
                raise ValueError(f"malformed user entry: {entry!r}")
            groups = entry.get("groups", [])
            if not isinstance(groups, list):
                raise ValueError(f"groups must be a list, got {type(groups).__name__}")
            # Validate the signing binding at load, not at sign time: a typo in
            # a principal_id would otherwise surface as "no key for this actor"
            # on someone's acceptance, which reads like a provisioning gap.
            if entry.get("principal_id") is not None:
                validate_principal_binding(entry["principal_id"])
            users[entry["username"].strip().lower()] = entry
        return users

    def authenticate(self, identifier: str, password: str) -> Principal | None:
        user = self._users.get(identifier.strip().lower())
        if user is None:
            verify_password(password, _get_dummy_hash())
            return None
        if not verify_password(password, user.get("password", "")):
            return None
        return Principal(
            stable_id=user["stable_id"],
            display_name=user["display_name"],
            source="local",
            principal_id=user.get("principal_id") or None,
            raw_attributes={
                "username": user["username"],
                "groups": [
                    GroupIdentity(guid="", name=g, dn="")
                    for g in user.get("groups", [])
                ],
            },
        )

    def fetch_groups(self, principal: Principal) -> list[GroupIdentity]:
        return list(principal.raw_attributes.get("groups", []))

    @staticmethod
    def add_user(
        path: str | Path,
        username: str,
        display_name: str,
        password_plain: str,
    ) -> dict[str, Any]:
        """Append a new local user to ``path``, returning the new user record.

        Mints a uuid ``stable_id`` and scrypt-hashes the password. Intended for
        a future ``dossier users add`` CLI command; not wired into the CLI here.
        """
        import tempfile

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
        fd, tmp_path = tempfile.mkstemp(
            dir=str(path.parent), suffix=".tmp", prefix=".users_"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(users, f, indent=2)
            os.replace(tmp_path, path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
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
        group_strategy: Literal["direct", "nested"] = "direct",
        ca_cert_file: str = "",
        connect_timeout: int = 5,
        principal_id_attr: str = "",
    ) -> None:
        if not server_urls:
            raise ValueError("server_urls must not be empty")
        is_ldaps = any(s.lower().startswith("ldaps://") for s in server_urls)
        if not is_ldaps:
            raise ValueError("LdapBackend requires ldaps:// — plaintext LDAP is not permitted")
        if group_strategy not in ("direct", "nested"):
            raise ValueError(f"group_strategy must be 'direct' or 'nested', got {group_strategy!r}")
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
        # WI-035: the directory attribute carrying the suite principal_id. Empty
        # (the default) means no LDAP identity is bound, so an upgrade cannot
        # silently re-key every user's actor_id. Commonly set to
        # ``sAMAccountName`` when logon names and principal ids are the same, or
        # to a dedicated attribute when they are not.
        self._principal_id_attr = principal_id_attr.strip()

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
            principal_id_attr=config.principal_id_attr,
        )

    # ── connection plumbing ───────────────────────────────────────────

    def _build_tls(self) -> Any:
        import ldap3

        tls_kwargs: dict[str, Any] = {"validate": ssl.CERT_REQUIRED}
        if self._ca_cert_file:
            tls_kwargs["ca_certs_file"] = self._ca_cert_file
        return ldap3.Tls(**tls_kwargs)

    def _build_server_pool(self) -> Any:
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
                    *([self._principal_id_attr] if self._principal_id_attr else []),
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
            elif self._group_strategy == "direct":
                groups = self._fetch_direct_groups(svc_conn, search_filter)
            else:
                assert_never(self._group_strategy)

            return Principal(
                stable_id=stable_id,
                display_name=str(display_name),
                source=f"ldap:{self._domain}",
                principal_id=self._read_principal_id(entry, identifier),
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

    def _read_principal_id(self, entry: Any, identifier: str) -> str | None:
        """Read the suite ``principal_id`` from the directory entry (WI-035).

        Returns ``None`` when no attribute is configured or the attribute is
        absent/empty on this user — an unbound identity, which the signing policy
        then handles. A *malformed* value is also treated as unbound rather than
        raising, because raising here would turn a directory data problem into a
        login failure; it is logged with the attribute name so the operator can
        find it, and the signing policy still refuses to sign symmetrically for
        the user under a production posture.
        """
        if not self._principal_id_attr:
            return None
        raw = _attr_value(entry, self._principal_id_attr)
        if raw is None or not str(raw).strip():
            logger.warning(
                "LDAP user %s has no %s — identity is unbound and has no "
                "per-actor signing key",
                identifier,
                self._principal_id_attr,
            )
            return None
        try:
            return validate_principal_binding(str(raw))
        except ValueError as exc:
            logger.warning(
                "LDAP user %s has an invalid %s: %s — treating the identity as "
                "unbound",
                identifier,
                self._principal_id_attr,
                exc,
            )
            return None

    def fetch_groups(self, principal: Principal) -> list[GroupIdentity]:
        """Return group identities cached during ``authenticate``.

        For ``direct`` strategy these are :class:`GroupIdentity` objects built
        from a second search on the group DNs returned by ``memberOf``; for
        ``nested`` they come from the ``LDAP_MATCHING_RULE_IN_CHAIN`` recursive
        search. Both are populated during ``authenticate`` so this is a cache
        read — no additional directory round-trip. Plan 004 maps these to teams.
        """
        return list(principal.raw_attributes.get("groups", []))

    # ── internal ──────────────────────────────────────────────────────

    def _fetch_direct_groups(self, conn: Any, search_filter: str) -> list[GroupIdentity]:
        """Fetch groups via ``memberOf`` then resolve DNs to GUIDs+names.

        AD's ``memberOf`` returns DNs, which break on rename/move. We do a
        second search on those DNs to fetch ``objectGUID``, ``name``, and
        ``distinguishedName``, building :class:`GroupIdentity` objects. If a
        group DN no longer exists, it is included with ``guid=""`` and a name
        extracted from the DN's CN component.
        """
        import ldap3

        conn.search(
            self._base_dn,
            search_filter,
            attributes=["memberOf"],
        )
        member_of_dns: list[str] = [
            str(dn) for dn in (_attr_values(conn.entries[0], "memberOf") if conn.entries else [])
        ]
        if not member_of_dns:
            return []

        dn_filters = "".join(
            f"(distinguishedName={ldap3.utils.conv.escape_filter_chars(dn)})"
            for dn in member_of_dns
        )
        group_filter = f"(&(objectClass=group)(|{dn_filters}))"
        conn.search(
            self._base_dn,
            group_filter,
            attributes=["objectGUID", "name", "distinguishedName"],
        )

        found: dict[str, GroupIdentity] = {}
        for entry in conn.entries:
            dn = str(entry.entry_dn)
            guid = _guid_bytes_to_str(_attr_value(entry, "objectGUID")) or ""
            name = _attr_value(entry, "name") or _cn_from_dn(dn)
            if not guid:
                logger.warning(
                    "LDAP group %s has no objectGUID — authz may be incomplete", dn
                )
            found[dn.lower()] = GroupIdentity(guid=guid, name=str(name), dn=dn)

        result: list[GroupIdentity] = []
        for dn in member_of_dns:
            key = dn.lower()
            if key in found:
                result.append(found[key])
            else:
                logger.warning(
                    "LDAP group %s not found in resolution search — "
                    "returning empty guid; authz may be incomplete",
                    dn,
                )
                result.append(GroupIdentity(guid="", name=_cn_from_dn(dn), dn=dn))
        return result

    def _fetch_nested_groups(self, conn: Any, user_dn: str) -> list[GroupIdentity]:
        """Find all groups (including nested) via ``LDAP_MATCHING_RULE_IN_CHAIN``.

        Searches for ``(&(objectClass=group)(member:OID:=<user_dn>))`` which
        recursively resolves nested group membership in a single query. Returns
        :class:`GroupIdentity` objects with ``objectGUID``, ``name``, and DN.
        """
        import ldap3

        escaped_dn = ldap3.utils.conv.escape_filter_chars(user_dn)
        search_filter = f"(&(objectClass=group)(member:{self._NESTED_MEMBER_OID}:={escaped_dn}))"
        conn.search(
            self._base_dn,
            search_filter,
            attributes=["objectGUID", "name", "distinguishedName"],
        )

        result: list[GroupIdentity] = []
        for entry in conn.entries:
            dn = str(entry.entry_dn)
            guid = _guid_bytes_to_str(_attr_value(entry, "objectGUID")) or ""
            name = _attr_value(entry, "name") or _cn_from_dn(dn)
            if not guid:
                logger.warning(
                    "LDAP group %s has no objectGUID — authz may be incomplete", dn
                )
            result.append(GroupIdentity(guid=guid, name=str(name), dn=dn))
        return result


# ── ldap3 attribute access helpers ────────────────────────────────────────


def _attr_value(entry: Any, name: str) -> Any:
    """Safely get a single attribute value from an ldap3 entry, or ``None``."""
    if name in entry.entry_attributes:
        val = entry[name].value
        return val
    return None


def _attr_values(entry: Any, name: str) -> list[Any]:
    """Safely get a list of attribute values from an ldap3 entry, or ``[]``."""
    if name in entry.entry_attributes:
        return list(entry[name].values)
    return []


def _cn_from_dn(dn: str) -> str:
    """Extract the CN component from a DN, falling back to the full DN."""
    from ldap3.utils.dn import parse_dn

    for attr_type, attr_value, _ in parse_dn(dn):
        if attr_type.upper() == "CN":
            return str(attr_value)
    return dn
