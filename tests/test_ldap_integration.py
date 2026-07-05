"""Real-AD integration tests for LdapBackend (Plan 003, WI-6).

These tests connect to a real LDAP/Active Directory server and exercise the
full search-then-bind flow. They are skipped by default — set
``DOSSIER_LDAP_E2E=1`` and provide the ``DOSSIER_LDAP_*`` env vars to run.

Usage with a real AD server (requires the svc-bind credential)::

    ACB_VAULT_ENV=/home/itadmin/.claude/vault.env \\
    acb exec cred:svc-bind -- env DOSSIER_LDAP_E2E=1 \\
    DOSSIER_LDAP_SERVER=ldaps://ad.example.com:636 \\
    DOSSIER_LDAP_BASE_DN=DC=example,DC=com \\
    DOSSIER_LDAP_DOMAIN=example.com \\
    DOSSIER_LDAP_CA_CERT_FILE=/etc/ssl/certs/ad-root.pem \\
    DOSSIER_LDAP_TEST_USER=<test-user> \\
    DOSSIER_LDAP_TEST_PASSWORD=<test-password> \\
    python -m pytest tests/test_ldap_integration.py -m ldap_e2e -v

The ``cred:svc-bind`` broker injects ``DOSSIER_LDAP_BIND_DN`` and
``DOSSIER_LDAP_BIND_PASSWORD`` into the child environment — they never appear
in this file or in stdout.
"""

from __future__ import annotations

import os

import pytest

pytestmark = [pytest.mark.ldap_e2e]


@pytest.fixture(autouse=True)
def _skip_unless_enabled():
    if not os.environ.get("DOSSIER_LDAP_E2E"):
        pytest.skip("DOSSIER_LDAP_E2E not set — skipping real-AD integration tests")


@pytest.fixture
def ldap_backend():
    from dossier.auth.backends import LdapBackend

    required = [
        "DOSSIER_LDAP_SERVER",
        "DOSSIER_LDAP_BASE_DN",
        "DOSSIER_LDAP_BIND_DN",
        "DOSSIER_LDAP_BIND_PASSWORD",
        "DOSSIER_LDAP_DOMAIN",
    ]
    missing = [v for v in required if not os.environ.get(v)]
    if missing:
        pytest.skip(f"missing env vars: {', '.join(missing)}")

    return LdapBackend(
        server_urls=[s.strip() for s in os.environ["DOSSIER_LDAP_SERVER"].split(",") if s.strip()],
        base_dn=os.environ["DOSSIER_LDAP_BASE_DN"],
        bind_dn=os.environ["DOSSIER_LDAP_BIND_DN"],
        bind_password=os.environ["DOSSIER_LDAP_BIND_PASSWORD"],
        domain=os.environ["DOSSIER_LDAP_DOMAIN"],
        ca_cert_file=os.environ.get("DOSSIER_LDAP_CA_CERT_FILE", ""),
        group_strategy=os.environ.get("DOSSIER_LDAP_GROUP_STRATEGY", "direct"),
    )


class TestRealADLogin:
    """Login and rejection scenarios against a real LDAP/AD server."""

    def test_valid_login_returns_principal(self, ldap_backend):
        """A real user authenticates and gets a Principal with objectGUID."""
        user = os.environ["DOSSIER_LDAP_TEST_USER"]
        password = os.environ["DOSSIER_LDAP_TEST_PASSWORD"]

        principal = ldap_backend.authenticate(user, password)

        assert principal is not None, "expected successful authentication"
        assert principal.source.startswith("ldap:")
        assert principal.stable_id, "stable_id (objectGUID) must not be empty"
        assert principal.display_name, "display_name must not be empty"
        assert principal.raw_attributes.get("username") == user
        assert principal.raw_attributes.get("dn"), "DN must be populated"
        assert isinstance(principal.raw_attributes.get("groups", []), list)

    def test_wrong_password_returns_none(self, ldap_backend):
        """A wrong password yields None, not an exception."""
        user = os.environ["DOSSIER_LDAP_TEST_USER"]

        principal = ldap_backend.authenticate(user, "dossier-wrong-password-xyzzy")

        assert principal is None

    def test_nonexistent_user_returns_none(self, ldap_backend):
        """A user that doesn't exist yields None."""
        principal = ldap_backend.authenticate(
            "dossier-nonexistent-user-xyzzy",
            "irrelevant",
        )

        assert principal is None

    def test_empty_password_returns_none(self, ldap_backend):
        """An empty password is rejected before any bind attempt."""
        user = os.environ["DOSSIER_LDAP_TEST_USER"]

        principal = ldap_backend.authenticate(user, "")

        assert principal is None

    def test_fetch_groups_returns_list(self, ldap_backend):
        """fetch_groups returns a list (possibly empty) after authentication."""
        user = os.environ["DOSSIER_LDAP_TEST_USER"]
        password = os.environ["DOSSIER_LDAP_TEST_PASSWORD"]

        principal = ldap_backend.authenticate(user, password)
        assert principal is not None

        groups = ldap_backend.fetch_groups(principal)
        assert isinstance(groups, list)
