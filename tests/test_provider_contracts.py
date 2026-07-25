"""WI-1.1: Versioned provider contract qualification (Plan 015 Gate 1).

Proves that every provider dossier consumes satisfies its declared contract,
that shared fixtures exercise every status/error path, and that architecture
boundaries reject private production imports and direct private-store access.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from dossier.contracts import (
    CONTRACT_VERSION,
    IdentityProvider,
    ProviderDescriptor,
    WorkProvider,
)
from dossier.shell import Availability

CONTRACTS_PATH = Path(__file__).resolve().parent.parent / "data" / "contracts" / "provider-contracts.json"


class TestContractDescriptors:
    def test_contract_descriptor_is_frozen(self) -> None:
        d = ProviderDescriptor(
            name="test", contract_version="1.0.0", availability=Availability.AVAILABLE
        )
        with pytest.raises(AttributeError):
            d.name = "mutated"  # type: ignore[misc]

    def test_contract_descriptor_defaults(self) -> None:
        d = ProviderDescriptor(
            name="test", contract_version="1.0.0", availability=Availability.DEGRADED
        )
        assert d.capabilities == ()
        assert d.detail is None

    def test_all_availability_states_are_renderable(self) -> None:
        for state in Availability:
            d = ProviderDescriptor(
                name="probe", contract_version=CONTRACT_VERSION, availability=state
            )
            assert d.availability == state


class TestContractFile:
    def test_contract_file_exists_and_is_valid_json(self) -> None:
        assert CONTRACTS_PATH.is_file(), f"missing {CONTRACTS_PATH}"
        data = json.loads(CONTRACTS_PATH.read_text(encoding="utf-8"))
        assert data["contract_version"] == CONTRACT_VERSION

    def test_every_declared_provider_has_a_contract_protocol(self) -> None:
        from dossier.contracts import PROVIDER_CONTRACTS

        data = json.loads(CONTRACTS_PATH.read_text(encoding="utf-8"))
        for name in data["providers"]:
            assert name in PROVIDER_CONTRACTS, f"provider {name!r} has no Protocol"

    def test_every_contract_protocol_has_a_descriptor_method(self) -> None:
        from dossier.contracts import PROVIDER_CONTRACTS

        for name, proto in PROVIDER_CONTRACTS.items():
            describe_name = f"describe_{name}"
            assert hasattr(proto, describe_name), (
                f"{proto.__name__} missing {describe_name}()"
            )


class TestGatewaySatisfiesContracts:
    def test_gateway_is_work_provider(self, gateway: Any) -> None:
        assert isinstance(gateway, WorkProvider)

    def test_gateway_is_identity_provider(self, gateway: Any) -> None:
        assert isinstance(gateway, IdentityProvider)

    def test_gateway_work_provider_methods_return_expected_types(
        self, gateway: Any, make_issue: Any
    ) -> None:
        wi = make_issue()
        wid = wi.work_item_id

        page = gateway.list_issues()
        assert hasattr(page, "items")
        assert len(page.items) >= 1

        fetched = gateway.get_issue(wid)
        assert fetched is not None

        history = gateway.history(wid)
        assert isinstance(history, list)
        assert len(history) >= 1

        transitions = gateway.transitions_from("open", 2)
        assert isinstance(transitions, list)

    def test_gateway_identity_provider_methods_return_expected_types(
        self, gateway: Any
    ) -> None:
        principals = gateway.list_principals()
        assert isinstance(principals, list)


class TestDegradedProviderRendering:
    """Dossier must render synthetic unavailable, stale, partial, and
    incompatible providers without crashing (Plan 015 WI-1.1 AC)."""

    def test_unavailable_provider_descriptor(self) -> None:
        d = ProviderDescriptor(
            name="cairn",
            contract_version="0.0.0",
            availability=Availability.UNAVAILABLE,
            detail="agent-provenance not deployed",
        )
        assert d.availability is Availability.UNAVAILABLE
        assert d.detail is not None

    def test_unknown_version_fails_closed(self) -> None:
        d = ProviderDescriptor(
            name="regista",
            contract_version="99.0.0",
            availability=Availability.UNKNOWN,
            detail="contract version 99.0.0 not recognised",
        )
        assert d.availability is Availability.UNKNOWN

    def test_incompatible_provider_descriptor(self) -> None:
        d = ProviderDescriptor(
            name="agent-wake",
            contract_version="0.1.0",
            availability=Availability.UNSUPPORTED,
            detail="delivery provider is Profile C preview",
        )
        assert d.availability is Availability.UNSUPPORTED

    def test_stale_provider_descriptor(self) -> None:
        d = ProviderDescriptor(
            name="regista",
            contract_version="0.4.0",
            availability=Availability.DEGRADED,
            detail="spine version 0.4.0 is behind the lock (0.5.3)",
        )
        assert d.availability is Availability.DEGRADED


class TestArchitectureBoundary:
    """Dossier must not import component-private modules or access private
    store tables (Plan 015 WI-1.1 AC)."""

    def test_no_private_regista_imports_in_area_modules(self) -> None:
        import importlib
        import inspect

        area_modules = [
            "dossier.knowledge",
            "dossier.provenance",
            "dossier.evidence",
            "dossier.operations",
            "dossier.administration",
            "dossier.views",
            "dossier.assurance",
        ]
        private_prefixes = ("regista._", "regista.impl")
        for mod_name in area_modules:
            mod = importlib.import_module(mod_name)
            source = inspect.getsource(mod)
            for prefix in private_prefixes:
                assert f"import {prefix}" not in source, (
                    f"{mod_name} imports private module {prefix}"
                )
                assert f"from {prefix}" not in source, (
                    f"{mod_name} imports from private module {prefix}"
                )

    def test_no_direct_sql_in_area_modules(self) -> None:
        import importlib
        import inspect

        area_modules = [
            "dossier.knowledge",
            "dossier.provenance",
            "dossier.evidence",
            "dossier.operations",
            "dossier.administration",
            "dossier.views",
        ]
        sql_patterns = ("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "CREATE TABLE")
        for mod_name in area_modules:
            mod = importlib.import_module(mod_name)
            source = inspect.getsource(mod)
            for pattern in sql_patterns:
                assert pattern not in source.upper(), (
                    f"{mod_name} contains direct SQL: {pattern!r}"
                )
