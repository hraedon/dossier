"""Unit tests for the LdapBackend (Plan 003, WI-6).

All ldap3 interaction is mocked — these tests verify the search-then-bind
logic, objectGUID conversion, group retrieval, and error handling without
a live directory. Real-AD tests live in ``test_ldap_integration.py``.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest

from dossier.auth.backends import GroupIdentity, LdapBackend, Principal, _guid_bytes_to_str
from dossier.config import LdapConfig, load_ldap_config


# ── mock helpers ─────────────────────────────────────────────────────────


class _MockAttribute:
    """Simulates ldap3's ``Attribute`` object."""

    def __init__(self, values: object) -> None:
        if not isinstance(values, list):
            values = [values]
        self.values = values
        self.value = values[0] if values else None


class _MockEntry:
    """Simulates an ldap3 search-result ``Entry``."""

    def __init__(self, dn: str, attributes: dict[str, object]) -> None:
        self.entry_dn = dn
        self._attrs = {name: _MockAttribute(v) for name, v in attributes.items()}

    @property
    def entry_attributes(self) -> list[str]:
        return list(self._attrs.keys())

    def __contains__(self, name: str) -> bool:
        return name in self._attrs

    def __getitem__(self, name: str) -> _MockAttribute:
        return self._attrs[name]


class _MockConnection:
    """Simulates an ldap3 ``Connection`` with configurable bind/search behavior."""

    def __init__(
        self,
        *,
        bind_result: bool = True,
        search_responses: list[list[_MockEntry]] | None = None,
        entries: list[_MockEntry] | None = None,
    ) -> None:
        self._bind_result = bind_result
        self._search_responses = search_responses or []
        self.entries = entries or []
        self._search_idx = 0
        self.search_calls: list[tuple] = []
        self.bind_call_count: int = 0

    def bind(self) -> bool:
        self.bind_call_count += 1
        return self._bind_result

    def search(self, base_dn: str, filter_str: str, attributes: list | None = None) -> None:
        self.search_calls.append((base_dn, filter_str, attributes))
        if self._search_idx < len(self._search_responses):
            self.entries = self._search_responses[self._search_idx]
            self._search_idx += 1

    def unbind(self) -> None:
        pass


_BIND_DN = "CN=svc-dossier,OU=Service Accounts,DC=test,DC=example"
_BASE_DN = "DC=test,DC=example"
_DOMAIN = "test.example"
_SERVER = "ldaps://dc1.test.example:636"
_TEST_GUID = uuid.UUID("12345678-1234-5678-1234-567812345678")
_TEST_DN = "CN=Test User,OU=Users,DC=test,DC=example"
_TEST_GROUPS = [
    "CN=team-a,OU=Groups,DC=test,DC=example",
    "CN=team-b,OU=Groups,DC=test,DC=example",
]
_TEST_GROUP_GUIDS = [
    uuid.UUID("11111111-1111-1111-1111-111111111111"),
    uuid.UUID("22222222-2222-2222-2222-222222222222"),
]


def _make_group_entries(
    groups: list[str] | None = None,
    guids: list[uuid.UUID] | None = None,
) -> list[_MockEntry]:
    if groups is None:
        groups = _TEST_GROUPS
    if guids is None:
        guids = _TEST_GROUP_GUIDS
    entries: list[_MockEntry] = []
    for dn, guid in zip(groups, guids):
        name = dn.split(",")[0].split("=", 1)[1]
        entries.append(
            _MockEntry(
                dn,
                {
                    "objectGUID": guid.bytes_le,
                    "name": name,
                    "distinguishedName": dn,
                },
            )
        )
    return entries


def _make_backend(**overrides) -> LdapBackend:
    defaults: dict = {
        "server_urls": [_SERVER],
        "base_dn": _BASE_DN,
        "bind_dn": _BIND_DN,
        "bind_password": "svc-secret",
        "domain": _DOMAIN,
    }
    defaults.update(overrides)
    return LdapBackend(**defaults)


def _make_user_entry(
    *,
    guid: uuid.UUID | None = None,
    display_name: str = "Test User",
    groups: list[str] | None = None,
    dn: str = _TEST_DN,
) -> _MockEntry:
    if guid is None:
        guid = _TEST_GUID
    if groups is None:
        groups = _TEST_GROUPS
    return _MockEntry(
        dn,
        {
            "objectGUID": guid.bytes_le,
            "displayName": display_name,
            "cn": display_name,
            "sAMAccountName": "tuser",
            "memberOf": groups,
        },
    )


def _setup_conn_mock(
    mock_conn,
    svc_conn: _MockConnection,
    user_conn: _MockConnection,
    bind_dn: str = _BIND_DN,
) -> None:
    """Configure a patched ``ldap3.Connection`` to return svc vs user mocks."""

    def _factory(*args, **kwargs):
        if kwargs.get("user") == bind_dn:
            return svc_conn
        return user_conn

    mock_conn.side_effect = _factory


# ── constructor tests ────────────────────────────────────────────────────


def test_constructor_rejects_non_ldaps():
    with pytest.raises(ValueError, match="ldaps://"):
        _make_backend(server_urls=["ldap://dc1.test.example:389"])


def test_constructor_rejects_empty_server_urls():
    with pytest.raises(ValueError, match="server_urls"):
        _make_backend(server_urls=[])


def test_constructor_warns_without_ca_cert(caplog):
    import logging

    with caplog.at_level(logging.WARNING, logger="dossier.auth.ldap"):
        _make_backend(ca_cert_file="")
    assert "ca_cert_file" in caplog.text


def test_constructor_no_warning_with_ca_cert(caplog):
    import logging

    with caplog.at_level(logging.WARNING, logger="dossier.auth.ldap"):
        _make_backend(ca_cert_file="/etc/ssl/certs/ad-root.pem")
    assert "ca_cert_file" not in caplog.text


# ── objectGUID conversion tests ──────────────────────────────────────────


def test_guid_bytes_to_str_round_trip():
    raw = _TEST_GUID.bytes_le
    result = _guid_bytes_to_str(raw)
    assert result == str(_TEST_GUID)


def test_guid_bytes_to_str_normalizes_string():
    """String GUIDs are normalized through uuid.UUID for consistent formatting."""
    assert _guid_bytes_to_str(str(_TEST_GUID)) == str(_TEST_GUID)
    assert _guid_bytes_to_str("{" + str(_TEST_GUID).upper() + "}") == str(_TEST_GUID)


def test_guid_bytes_to_str_unparseable_string_passes_through():
    assert _guid_bytes_to_str("not-a-uuid") == "not-a-uuid"


def test_guid_bytes_to_str_none():
    assert _guid_bytes_to_str(None) is None


def test_guid_bytes_to_str_invalid_bytes():
    assert _guid_bytes_to_str(b"too-short") is None


# ── authenticate: success cases ──────────────────────────────────────────


@patch("ldap3.ServerPool")
@patch("ldap3.Server")
@patch("ldap3.Tls")
@patch("ldap3.Connection")
def test_authenticate_success_direct_groups(mock_conn, _tls, _srv, _pool):
    backend = _make_backend()
    user_entry = _make_user_entry()
    group_entries = _make_group_entries()
    svc_conn = _MockConnection(
        search_responses=[[user_entry], [user_entry], group_entries]
    )
    user_conn = _MockConnection(bind_result=True)
    _setup_conn_mock(mock_conn, svc_conn, user_conn)

    principal = backend.authenticate("tuser", "password123")

    assert principal is not None
    assert principal.stable_id == str(_TEST_GUID)
    assert principal.source == "ldap:test.example"
    assert principal.display_name == "Test User"
    assert principal.raw_attributes["username"] == "tuser"
    assert principal.raw_attributes["dn"] == _TEST_DN
    groups = principal.raw_attributes["groups"]
    assert len(groups) == 2
    assert all(isinstance(g, GroupIdentity) for g in groups)
    assert groups[0].guid == str(_TEST_GROUP_GUIDS[0])
    assert groups[0].name == "team-a"
    assert groups[0].dn == _TEST_GROUPS[0]
    assert groups[1].guid == str(_TEST_GROUP_GUIDS[1])
    assert groups[1].name == "team-b"
    assert groups[1].dn == _TEST_GROUPS[1]


@patch("ldap3.ServerPool")
@patch("ldap3.Server")
@patch("ldap3.Tls")
@patch("ldap3.Connection")
def test_authenticate_success_nested_groups(mock_conn, _tls, _srv, _pool):
    backend = _make_backend(group_strategy="nested")
    user_entry = _make_user_entry(groups=[])
    nested_group_dns = [
        "CN=team-a,OU=Groups,DC=test,DC=example",
        "CN=team-b,OU=Groups,DC=test,DC=example",
        "CN=nested-team,OU=Groups,DC=test,DC=example",
    ]
    nested_group_guids = [
        _TEST_GROUP_GUIDS[0],
        _TEST_GROUP_GUIDS[1],
        uuid.UUID("33333333-3333-3333-3333-333333333333"),
    ]
    group_entries = _make_group_entries(nested_group_dns, nested_group_guids)
    svc_conn = _MockConnection(search_responses=[[user_entry], group_entries])
    user_conn = _MockConnection(bind_result=True)
    _setup_conn_mock(mock_conn, svc_conn, user_conn)

    principal = backend.authenticate("tuser", "password123")

    assert principal is not None
    groups = principal.raw_attributes["groups"]
    assert len(groups) == 3
    assert all(isinstance(g, GroupIdentity) for g in groups)
    assert groups[0].name == "team-a"
    assert groups[0].dn == nested_group_dns[0]
    assert groups[0].guid == str(nested_group_guids[0])
    assert groups[1].name == "team-b"
    assert groups[1].dn == nested_group_dns[1]
    assert groups[1].guid == str(nested_group_guids[1])
    assert groups[2].name == "nested-team"
    assert groups[2].dn == nested_group_dns[2]
    assert groups[2].guid == str(nested_group_guids[2])
    assert len(svc_conn.search_calls) == 2
    assert "1.2.840.113556.1.4.1941" in svc_conn.search_calls[1][1]


@patch("ldap3.ServerPool")
@patch("ldap3.Server")
@patch("ldap3.Tls")
@patch("ldap3.Connection")
def test_authenticate_uses_display_name_fallback(mock_conn, _tls, _srv, _pool):
    """displayName missing → falls back to cn."""
    backend = _make_backend()
    user_entry = _MockEntry(
        _TEST_DN,
        {
            "objectGUID": _TEST_GUID.bytes_le,
            "cn": "Fallback Name",
            "sAMAccountName": "tuser",
            "memberOf": [],
        },
    )
    svc_conn = _MockConnection(search_responses=[[user_entry]])
    user_conn = _MockConnection(bind_result=True)
    _setup_conn_mock(mock_conn, svc_conn, user_conn)

    principal = backend.authenticate("tuser", "pw")
    assert principal is not None
    assert principal.display_name == "Fallback Name"


# ── direct group resolution: edge cases ──────────────────────────────────


@patch("ldap3.ServerPool")
@patch("ldap3.Server")
@patch("ldap3.Tls")
@patch("ldap3.Connection")
def test_direct_group_missing_object_guid(mock_conn, _tls, _srv, _pool, caplog):
    import logging

    backend = _make_backend()
    group_dn = _TEST_GROUPS[0]
    user_entry = _make_user_entry(groups=[group_dn])
    group_entry = _MockEntry(
        group_dn,
        {
            "name": "team-a",
            "distinguishedName": group_dn,
        },
    )
    svc_conn = _MockConnection(
        search_responses=[[user_entry], [user_entry], [group_entry]]
    )
    user_conn = _MockConnection(bind_result=True)
    _setup_conn_mock(mock_conn, svc_conn, user_conn)

    with caplog.at_level(logging.WARNING, logger="dossier.auth.ldap"):
        principal = backend.authenticate("tuser", "password123")

    assert principal is not None
    groups = principal.raw_attributes["groups"]
    assert len(groups) == 1
    assert groups[0].guid == ""
    assert groups[0].name == "team-a"
    assert groups[0].dn == group_dn
    assert group_dn in caplog.text


@patch("ldap3.ServerPool")
@patch("ldap3.Server")
@patch("ldap3.Tls")
@patch("ldap3.Connection")
def test_direct_group_missing_name_falls_back_to_cn(mock_conn, _tls, _srv, _pool):
    backend = _make_backend()
    group_dn = _TEST_GROUPS[0]
    user_entry = _make_user_entry(groups=[group_dn])
    group_entry = _MockEntry(
        group_dn,
        {
            "objectGUID": _TEST_GROUP_GUIDS[0].bytes_le,
            "distinguishedName": group_dn,
        },
    )
    svc_conn = _MockConnection(
        search_responses=[[user_entry], [user_entry], [group_entry]]
    )
    user_conn = _MockConnection(bind_result=True)
    _setup_conn_mock(mock_conn, svc_conn, user_conn)

    principal = backend.authenticate("tuser", "password123")

    assert principal is not None
    groups = principal.raw_attributes["groups"]
    assert len(groups) == 1
    assert groups[0].guid == str(_TEST_GROUP_GUIDS[0])
    assert groups[0].name == "team-a"
    assert groups[0].dn == group_dn


@patch("ldap3.ServerPool")
@patch("ldap3.Server")
@patch("ldap3.Tls")
@patch("ldap3.Connection")
def test_direct_group_resolution_empty_search(mock_conn, _tls, _srv, _pool, caplog):
    import logging

    backend = _make_backend()
    user_entry = _make_user_entry()
    svc_conn = _MockConnection(
        search_responses=[[user_entry], [user_entry], []]
    )
    user_conn = _MockConnection(bind_result=True)
    _setup_conn_mock(mock_conn, svc_conn, user_conn)

    with caplog.at_level(logging.WARNING, logger="dossier.auth.ldap"):
        principal = backend.authenticate("tuser", "password123")

    assert principal is not None
    groups = principal.raw_attributes["groups"]
    assert len(groups) == 2
    assert all(g.guid == "" for g in groups)
    assert groups[0].name == "team-a"
    assert groups[0].dn == _TEST_GROUPS[0]
    assert groups[1].name == "team-b"
    assert groups[1].dn == _TEST_GROUPS[1]
    assert _TEST_GROUPS[0] in caplog.text
    assert _TEST_GROUPS[1] in caplog.text


# ── authenticate: failure cases ──────────────────────────────────────────


def test_authenticate_rejects_empty_password():
    backend = _make_backend()
    assert backend.authenticate("tuser", "") is None


def test_authenticate_rejects_empty_identifier():
    backend = _make_backend()
    assert backend.authenticate("", "password") is None


@patch("ldap3.ServerPool")
@patch("ldap3.Server")
@patch("ldap3.Tls")
@patch("ldap3.Connection")
def test_authenticate_wrong_password(mock_conn, _tls, _srv, _pool):
    backend = _make_backend()
    user_entry = _make_user_entry()
    svc_conn = _MockConnection(search_responses=[[user_entry]])
    user_conn = _MockConnection(bind_result=False)
    _setup_conn_mock(mock_conn, svc_conn, user_conn)

    assert backend.authenticate("tuser", "wrong-password") is None


@patch("ldap3.ServerPool")
@patch("ldap3.Server")
@patch("ldap3.Tls")
@patch("ldap3.Connection")
def test_authenticate_user_not_found(mock_conn, _tls, _srv, _pool):
    backend = _make_backend()
    svc_conn = _MockConnection(search_responses=[[]])
    user_conn = _MockConnection(bind_result=True)
    _setup_conn_mock(mock_conn, svc_conn, user_conn)

    assert backend.authenticate("nobody", "password") is None
    assert user_conn.bind_call_count == 0


@patch("ldap3.ServerPool")
@patch("ldap3.Server")
@patch("ldap3.Tls")
@patch("ldap3.Connection")
def test_authenticate_wrong_password_does_not_fetch_groups(mock_conn, _tls, _srv, _pool):
    """Groups must not be fetched when the password is wrong (security)."""
    backend = _make_backend()
    user_entry = _make_user_entry()
    svc_conn = _MockConnection(search_responses=[[user_entry]])
    user_conn = _MockConnection(bind_result=False)
    _setup_conn_mock(mock_conn, svc_conn, user_conn)

    assert backend.authenticate("tuser", "wrong-password") is None
    assert svc_conn.search_calls.__len__() == 1


@patch("ldap3.ServerPool")
@patch("ldap3.Server")
@patch("ldap3.Tls")
@patch("ldap3.Connection")
def test_authenticate_passes_user_dn_and_password_to_user_bind(mock_conn, _tls, _srv, _pool):
    """The user connection must receive the found DN and the supplied password."""
    backend = _make_backend()
    user_entry = _make_user_entry()
    group_entries = _make_group_entries()
    svc_conn = _MockConnection(
        search_responses=[[user_entry], [user_entry], group_entries]
    )
    user_conn = _MockConnection(bind_result=True)
    _setup_conn_mock(mock_conn, svc_conn, user_conn)

    backend.authenticate("tuser", "password123")

    assert user_conn.bind_call_count == 1
    user_call = mock_conn.call_args_list[-1]
    assert user_call.kwargs["user"] == _TEST_DN
    assert user_call.kwargs["password"] == "password123"


@patch("ldap3.ServerPool")
@patch("ldap3.Server")
@patch("ldap3.Tls")
@patch("ldap3.Connection")
def test_authenticate_service_bind_failure(mock_conn, _tls, _srv, _pool):
    backend = _make_backend()
    svc_conn = _MockConnection(bind_result=False)
    user_conn = _MockConnection(bind_result=True)
    _setup_conn_mock(mock_conn, svc_conn, user_conn)

    assert backend.authenticate("tuser", "password") is None


@patch("ldap3.ServerPool")
@patch("ldap3.Server")
@patch("ldap3.Tls")
@patch("ldap3.Connection")
def test_authenticate_no_object_guid(mock_conn, _tls, _srv, _pool):
    """User without objectGUID → cannot establish stable_id → None."""
    backend = _make_backend()
    user_entry = _MockEntry(
        _TEST_DN,
        {
            "displayName": "No GUID",
            "cn": "No GUID",
            "sAMAccountName": "noguid",
            "memberOf": [],
        },
    )
    svc_conn = _MockConnection(search_responses=[[user_entry]])
    user_conn = _MockConnection(bind_result=True)
    _setup_conn_mock(mock_conn, svc_conn, user_conn)

    assert backend.authenticate("noguid", "password") is None


@patch("ldap3.ServerPool")
@patch("ldap3.Server")
@patch("ldap3.Tls")
@patch("ldap3.Connection")
def test_authenticate_bind_exception_returns_none(mock_conn, _tls, _srv, _pool):
    import ldap3

    backend = _make_backend()
    svc_conn = _MockConnection()
    user_conn = _MockConnection(bind_result=True)
    _setup_conn_mock(mock_conn, svc_conn, user_conn)

    def _raise_bind():
        raise ldap3.core.exceptions.LDAPException("connection refused")

    svc_conn.bind = _raise_bind  # type: ignore[method-assign]

    assert backend.authenticate("tuser", "password") is None


# ── fetch_groups ─────────────────────────────────────────────────────────


def _make_test_group_identities() -> list[GroupIdentity]:
    return [
        GroupIdentity(guid=str(_TEST_GROUP_GUIDS[0]), name="team-a", dn=_TEST_GROUPS[0]),
        GroupIdentity(guid=str(_TEST_GROUP_GUIDS[1]), name="team-b", dn=_TEST_GROUPS[1]),
    ]


def test_fetch_groups_returns_cached_groups():
    test_groups = _make_test_group_identities()
    principal = Principal(
        stable_id=str(_TEST_GUID),
        display_name="Test User",
        source="ldap:test.example",
        raw_attributes={"username": "tuser", "groups": test_groups},
    )
    backend = _make_backend()
    assert backend.fetch_groups(principal) == test_groups


def test_fetch_groups_empty_when_no_groups():
    principal = Principal(
        stable_id=str(_TEST_GUID),
        display_name="Test User",
        source="ldap:test.example",
        raw_attributes={"username": "tuser", "groups": []},
    )
    backend = _make_backend()
    assert backend.fetch_groups(principal) == []


def test_fetch_groups_returns_copy():
    test_groups = _make_test_group_identities()
    principal = Principal(
        stable_id=str(_TEST_GUID),
        display_name="Test User",
        source="ldap:test.example",
        raw_attributes={"username": "tuser", "groups": test_groups},
    )
    backend = _make_backend()
    groups = backend.fetch_groups(principal)
    groups.append(GroupIdentity(guid="", name="injected", dn=""))
    assert backend.fetch_groups(principal) == test_groups


# ── from_config / config loading ─────────────────────────────────────────


def test_from_config_creates_backend():
    config = LdapConfig(
        server_urls=[_SERVER],
        base_dn=_BASE_DN,
        bind_dn=_BIND_DN,
        bind_password="svc-secret",
        user_filter="(&(objectClass=user)(sAMAccountName={login}))",
        group_strategy="direct",
        ca_cert_file="/etc/ssl/certs/ad-root.pem",
        connect_timeout=10,
        domain=_DOMAIN,
    )
    backend = LdapBackend.from_config(config)
    assert backend._server_urls == [_SERVER]
    assert backend._base_dn == _BASE_DN
    assert backend._bind_dn == _BIND_DN
    assert backend._domain == _DOMAIN
    assert backend._ca_cert_file == "/etc/ssl/certs/ad-root.pem"
    assert backend._connect_timeout == 10


def test_load_ldap_config_from_env(monkeypatch):
    monkeypatch.setenv(
        "DOSSIER_LDAP_SERVER", "ldaps://dc1.example.com:636,ldaps://dc2.example.com:636"
    )
    monkeypatch.setenv("DOSSIER_LDAP_BASE_DN", "DC=example,DC=com")
    monkeypatch.setenv("DOSSIER_LDAP_BIND_DN", "CN=svc,DC=example,DC=com")
    monkeypatch.setenv("DOSSIER_LDAP_BIND_PASSWORD", "secret")
    monkeypatch.setenv("DOSSIER_LDAP_DOMAIN", "example.com")
    monkeypatch.setenv("DOSSIER_LDAP_GROUP_STRATEGY", "nested")
    monkeypatch.setenv("DOSSIER_LDAP_CA_CERT_FILE", "/etc/ssl/certs/ad.pem")
    monkeypatch.setenv("DOSSIER_LDAP_CONNECT_TIMEOUT", "10")

    config = load_ldap_config(strict=True)
    assert config.server_urls == ["ldaps://dc1.example.com:636", "ldaps://dc2.example.com:636"]
    assert config.base_dn == "DC=example,DC=com"
    assert config.bind_dn == "CN=svc,DC=example,DC=com"
    assert config.domain == "example.com"
    assert config.group_strategy == "nested"
    assert config.ca_cert_file == "/etc/ssl/certs/ad.pem"
    assert config.connect_timeout == 10


def test_load_ldap_config_defaults(monkeypatch):
    monkeypatch.setenv("DOSSIER_LDAP_SERVER", "ldaps://dc.example.com:636")
    monkeypatch.setenv("DOSSIER_LDAP_BASE_DN", "DC=example,DC=com")
    monkeypatch.setenv("DOSSIER_LDAP_BIND_DN", "CN=svc,DC=example,DC=com")
    monkeypatch.setenv("DOSSIER_LDAP_BIND_PASSWORD", "secret")
    monkeypatch.setenv("DOSSIER_LDAP_DOMAIN", "example.com")
    monkeypatch.delenv("DOSSIER_LDAP_GROUP_STRATEGY", raising=False)
    monkeypatch.delenv("DOSSIER_LDAP_CA_CERT_FILE", raising=False)
    monkeypatch.delenv("DOSSIER_LDAP_CONNECT_TIMEOUT", raising=False)
    monkeypatch.delenv("DOSSIER_LDAP_USER_FILTER", raising=False)

    config = load_ldap_config(strict=False)
    assert config.ca_cert_file == ""
    assert config.group_strategy == "direct"
    assert config.connect_timeout == 5


def test_load_ldap_config_strict_requires_ca_cert(monkeypatch):
    monkeypatch.setenv("DOSSIER_LDAP_SERVER", "ldaps://dc.example.com:636")
    monkeypatch.setenv("DOSSIER_LDAP_BASE_DN", "DC=example,DC=com")
    monkeypatch.setenv("DOSSIER_LDAP_BIND_DN", "CN=svc,DC=example,DC=com")
    monkeypatch.setenv("DOSSIER_LDAP_BIND_PASSWORD", "secret")
    monkeypatch.setenv("DOSSIER_LDAP_DOMAIN", "example.com")
    monkeypatch.delenv("DOSSIER_LDAP_CA_CERT_FILE", raising=False)

    with pytest.raises(RuntimeError, match="DOSSIER_LDAP_CA_CERT_FILE"):
        load_ldap_config(strict=True)


def test_load_ldap_config_rejects_bad_group_strategy(monkeypatch):
    monkeypatch.setenv("DOSSIER_LDAP_GROUP_STRATEGY", "invalid")
    with pytest.raises(ValueError, match="direct.*nested"):
        load_ldap_config(strict=False)


def test_load_ldap_config_rejects_plaintext_in_strict(monkeypatch):
    monkeypatch.setenv("DOSSIER_LDAP_SERVER", "ldap://dc.example.com:389")
    monkeypatch.setenv("DOSSIER_LDAP_BASE_DN", "DC=example,DC=com")
    monkeypatch.setenv("DOSSIER_LDAP_BIND_DN", "CN=svc,DC=example,DC=com")
    monkeypatch.setenv("DOSSIER_LDAP_BIND_PASSWORD", "secret")
    monkeypatch.setenv("DOSSIER_LDAP_DOMAIN", "example.com")
    with pytest.raises(RuntimeError, match="ldaps://"):
        load_ldap_config(strict=True)


def test_load_ldap_config_non_strict_allows_empty(monkeypatch):
    monkeypatch.delenv("DOSSIER_LDAP_SERVER", raising=False)
    config = load_ldap_config(strict=False)
    assert config.server_urls == []
    assert config.base_dn == ""


# ── TLS / CA pinning ──────────────────────────────────────────────────────


@patch("ldap3.Tls")
def test_build_tls_pins_ca_cert(mock_tls):
    import ssl

    backend = _make_backend(ca_cert_file="/etc/ssl/certs/ad-root.pem")
    backend._build_tls()
    mock_tls.assert_called_once()
    _, kwargs = mock_tls.call_args
    assert kwargs["validate"] == ssl.CERT_REQUIRED
    assert kwargs["ca_certs_file"] == "/etc/ssl/certs/ad-root.pem"


@patch("ldap3.Tls")
def test_build_tls_cert_required_without_ca_cert(mock_tls):
    """Even without a CA file, validation is CERT_REQUIRED (fail-closed)."""
    import ssl

    backend = _make_backend(ca_cert_file="")
    backend._build_tls()
    mock_tls.assert_called_once()
    _, kwargs = mock_tls.call_args
    assert kwargs["validate"] == ssl.CERT_REQUIRED
    assert "ca_certs_file" not in kwargs


# ── multi-DC failover ────────────────────────────────────────────────────


@patch("ldap3.ServerPool")
@patch("ldap3.Server")
@patch("ldap3.Tls")
@patch("ldap3.Connection")
def test_multi_dc_creates_server_pool(mock_conn, _tls, mock_server, mock_pool):
    backend = _make_backend(
        server_urls=["ldaps://dc1.test.example:636", "ldaps://dc2.test.example:636"],
    )
    user_entry = _make_user_entry()
    group_entries = _make_group_entries()
    svc_conn = _MockConnection(
        search_responses=[[user_entry], [user_entry], group_entries]
    )
    user_conn = _MockConnection(bind_result=True)
    _setup_conn_mock(mock_conn, svc_conn, user_conn)

    backend.authenticate("tuser", "pw")

    assert mock_server.call_count == 2
    mock_pool.assert_called_once()
    pool_args, pool_kwargs = mock_pool.call_args
    assert len(pool_args[0]) == 2
    assert pool_kwargs["pool_strategy"] == "ldap3.FIRST" or str(
        pool_kwargs.get("pool_strategy", "")
    ).endswith("FIRST")
