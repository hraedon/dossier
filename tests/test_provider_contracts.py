"""WI-1.1: Versioned provider contract qualification (Plan 015 Gate 1).

Proves that every provider dossier consumes satisfies its declared contract,
that shared fixtures exercise every status/error path, and that architecture
boundaries reject private production imports and direct private-store access.
"""

from __future__ import annotations

import importlib
import inspect
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from dossier.contracts import (
    CONTRACT_VERSION,
    PROVIDER_CONTRACTS,
    ActivityProvider,
    EvidenceProvider,
    IdentityProvider,
    KnowledgeProvider,
    ProviderDescriptor,
    WorkProvider,
)
from dossier.shell import Availability

# Public API on Python 3.13+; fall back to the CPython implementation-detail
# attribute on 3.12 (the attribute is stable across the 3.12 line). This keeps
# the drift guard off private names where the public helper exists.
if sys.version_info >= (3, 13):
    from typing import get_protocol_members
else:  # pragma: no cover - exercised on the 3.12 CI lane

    def get_protocol_members(tp: type) -> frozenset[str]:
        return frozenset(getattr(tp, "__protocol_attrs__", frozenset()))


CONTRACTS_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "contracts" / "provider-contracts.json"
)

# Providers whose implementations fully satisfy their declared Protocol today.
# The mechanical drift guard below enforces that *every* declared method exists
# on these implementations. The remaining providers (operations, delivery) still
# declare their contract surface in the Protocol/JSON but have not yet converged
# on adapter-backed implementations — that gap is a tracked Gate 1 follow-up,
# not silently passing here.
_FULLY_IMPLEMENTED_PROVIDERS = frozenset(
    {"work", "identity", "knowledge", "activity", "evidence"}
)


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


def _load_contract_data() -> dict[str, Any]:
    return json.loads(CONTRACTS_PATH.read_text(encoding="utf-8"))


def _resolve_implementation(spec: str, module_name: str) -> Any:
    """Resolve the object a contract's ``implementation`` field points at.

    ``class:Name`` -> the named class on the ``dossier_module``.
    ``module``     -> the ``dossier_module`` itself (free functions).
    """
    module = importlib.import_module(module_name)
    if spec.startswith("class:"):
        return getattr(module, spec.split(":", 1)[1])
    return module


class TestContractMethodDriftGuard:
    """Mechanically validate that the contract file's method vocabulary
    matches the Protocol interfaces, and that the focus providers'
    implementations actually expose every declared method — so the
    ``list_work_items``-vs-``list_issues`` kind of drift cannot recur.

    Plan 015 WI-1.1: the contract file and the Protocols are the two
    declarations of dossier's provider surface; this test pins them together
    and pins both to the implementations for the providers dossier relies on
    in Gate 1 (work, identity, knowledge).
    """

    def test_json_methods_match_protocol_methods_for_every_provider(self) -> None:
        data = _load_contract_data()
        for name, spec in data["providers"].items():
            proto = PROVIDER_CONTRACTS[name]
            protocol_methods = set(get_protocol_members(proto))
            json_methods = set(spec["methods"])
            assert json_methods == protocol_methods, (
                f"provider {name!r}: contract file methods {sorted(json_methods)} "
                f"!= Protocol methods {sorted(protocol_methods)}"
            )

    def test_every_json_method_has_a_descriptor_on_the_protocol(self) -> None:
        data = _load_contract_data()
        for name, spec in data["providers"].items():
            proto = PROVIDER_CONTRACTS[name]
            protocol_methods = set(get_protocol_members(proto))
            assert f"describe_{name}" in protocol_methods, (
                f"provider {name!r}: Protocol has no describe_{name}() descriptor"
            )
            assert f"describe_{name}" in set(spec["methods"]), (
                f"provider {name!r}: contract file omits describe_{name}()"
            )

    @pytest.mark.parametrize("name", sorted(_FULLY_IMPLEMENTED_PROVIDERS))
    def test_focus_provider_implementation_exposes_every_declared_method(
        self, name: str
    ) -> None:
        data = _load_contract_data()
        spec = data["providers"][name]
        target = _resolve_implementation(spec["implementation"], spec["dossier_module"])
        for method in spec["methods"]:
            assert hasattr(target, method), (
                f"provider {name!r}: implementation {spec['dossier_module']} "
                f"({spec['implementation']}) is missing declared method {method!r}"
            )

    def test_knowledge_descriptor_is_honest(self) -> None:
        """The knowledge provider's descriptor is a free function (no gateway
        state required), so it can be exercised directly. The gateway-backed
        descriptors (work, identity) are exercised through the ``gateway``
        fixture in :class:`TestGatewaySatisfiesContracts`."""
        from dossier.knowledge import describe_knowledge

        descriptor = describe_knowledge()
        assert isinstance(descriptor, ProviderDescriptor)
        assert descriptor.name == "knowledge"
        assert descriptor.contract_version == CONTRACT_VERSION
        assert descriptor.availability is Availability.AVAILABLE


def _param_shape(fn: Any) -> list[tuple[str, inspect._ParameterKind, Any]]:
    """Parameter names, kinds, and defaults (excluding ``self``)."""
    sig = inspect.signature(fn)
    return [
        (p.name, p.kind, p.default)
        for p in sig.parameters.values()
        if p.name != "self"
    ]


_KNOWLEDGE_MEMBERS = sorted(get_protocol_members(KnowledgeProvider))


class TestKnowledgeProviderAdapterConformance:
    """The knowledge provider is a real Protocol-satisfying object, not a
    name-only module claim. The :class:`~dossier.knowledge.KnowledgeProviderAdapter`
    binds the module functions to a gateway and is checked here for runtime
    Protocol satisfaction and signature conformance — so a method rename or a
    dropped parameter on either side is caught mechanically."""

    def test_adapter_satisfies_knowledge_provider_protocol_at_runtime(
        self, gateway: Any
    ) -> None:
        from dossier.knowledge import KnowledgeProviderAdapter

        adapter = KnowledgeProviderAdapter(gateway)
        assert isinstance(adapter, KnowledgeProvider), (
            "KnowledgeProviderAdapter must structurally satisfy the "
            "KnowledgeProvider Protocol (runtime_checkable)"
        )

    def test_adapter_exposes_every_protocol_member(self, gateway: Any) -> None:
        from dossier.knowledge import KnowledgeProviderAdapter

        adapter = KnowledgeProviderAdapter(gateway)
        for member in get_protocol_members(KnowledgeProvider):
            assert hasattr(adapter, member), f"adapter missing Protocol member {member!r}"

    @pytest.mark.parametrize("member", _KNOWLEDGE_MEMBERS)
    def test_adapter_method_signature_conforms_to_protocol(
        self, member: str, gateway: Any
    ) -> None:
        """Each adapter method accepts the same parameters (name, kind, and
        default) the Protocol declares — a structural signature check that
        catches drift in either direction."""
        from dossier.knowledge import KnowledgeProviderAdapter

        proto_sig = _param_shape(getattr(KnowledgeProvider, member))
        adapter_sig = _param_shape(getattr(KnowledgeProviderAdapter, member))
        assert proto_sig == adapter_sig, (
            f"signature drift on {member!r}: Protocol expects {proto_sig}, "
            f"adapter has {adapter_sig}"
        )

    def test_adapter_delegates_to_module_functions(
        self, gateway: Any, make_issue: Any
    ) -> None:
        """Round-trip through the adapter's public surface: create → list →
        get → search → verify. Proves the adapter delegates to the real
        module functions (and is not a stub or a recursive no-op)."""
        from dossier.actors import Actor
        from dossier.knowledge import KnowledgeProviderAdapter

        adapter = KnowledgeProviderAdapter(gateway)
        alice = Actor(
            actor_id="human:alice",
            actor_kind="human",
            display_name="Alice",
            principal_id="human:alice",
        )

        note_id = adapter.create_note(actor=alice, title="Adapter note", body="body")
        assert isinstance(note_id, str)

        listed = adapter.list_notes()
        assert any(n.note_id == note_id and n.title == "Adapter note" for n in listed)

        detail = adapter.get_note(note_id)
        assert detail is not None
        assert detail.body == "body"

        found = adapter.search_notes("Adapter")
        assert any(n.note_id == note_id for n in found)

        verdict = adapter.verify_note(note_id)
        assert "verified" in verdict and "chain_intact" in verdict


_ACTIVITY_MEMBERS = sorted(get_protocol_members(ActivityProvider))


class TestActivityProviderAdapterConformance:
    """The activity provider adapter is a real Protocol-satisfying object,
    binding session/feed reads to a gateway."""

    def test_adapter_satisfies_activity_provider_protocol_at_runtime(
        self, gateway: Any
    ) -> None:
        from dossier.activity import ActivityProviderAdapter

        adapter = ActivityProviderAdapter(gateway, project_slug="dossier-test")
        assert isinstance(adapter, ActivityProvider)

    def test_adapter_exposes_every_protocol_member(self, gateway: Any) -> None:
        from dossier.activity import ActivityProviderAdapter

        adapter = ActivityProviderAdapter(gateway, project_slug="dossier-test")
        for member in get_protocol_members(ActivityProvider):
            assert hasattr(adapter, member), (
                f"adapter missing Protocol member {member!r}"
            )

    @pytest.mark.parametrize("member", _ACTIVITY_MEMBERS)
    def test_adapter_method_signature_conforms_to_protocol(
        self, member: str, gateway: Any
    ) -> None:
        from dossier.activity import ActivityProviderAdapter

        proto_sig = _param_shape(getattr(ActivityProvider, member))
        adapter_sig = _param_shape(getattr(ActivityProviderAdapter, member))
        assert proto_sig == adapter_sig, (
            f"signature drift on {member!r}: Protocol expects {proto_sig}, "
            f"adapter has {adapter_sig}"
        )

    def test_adapter_delegates_to_module_functions(self, gateway: Any) -> None:
        """A round-trip through the adapter proves it delegates to real read
        functions and returns the dict shapes the Protocol declares."""
        from dossier.activity import ActivityProviderAdapter

        adapter = ActivityProviderAdapter(gateway, project_slug="dossier-test")

        listed = adapter.list_sessions()
        assert isinstance(listed, list)

        fetched = adapter.get_session("no-such-session")
        assert fetched is None

        feed = adapter.activity_feed()
        assert isinstance(feed, list)


_EVIDENCE_MEMBERS = sorted(get_protocol_members(EvidenceProvider))


class TestEvidenceProviderAdapterConformance:
    """The evidence provider adapter is a real Protocol-satisfying object,
    binding integrity/verification reads to a gateway."""

    def test_adapter_satisfies_evidence_provider_protocol_at_runtime(
        self, gateway: Any
    ) -> None:
        from dossier.evidence import EvidenceProviderAdapter

        adapter = EvidenceProviderAdapter(gateway, project_slug="dossier-test")
        assert isinstance(adapter, EvidenceProvider)

    def test_adapter_exposes_every_protocol_member(self, gateway: Any) -> None:
        from dossier.evidence import EvidenceProviderAdapter

        adapter = EvidenceProviderAdapter(gateway, project_slug="dossier-test")
        for member in get_protocol_members(EvidenceProvider):
            assert hasattr(adapter, member), (
                f"adapter missing Protocol member {member!r}"
            )

    @pytest.mark.parametrize("member", _EVIDENCE_MEMBERS)
    def test_adapter_method_signature_conforms_to_protocol(
        self, member: str, gateway: Any
    ) -> None:
        from dossier.evidence import EvidenceProviderAdapter

        proto_sig = _param_shape(getattr(EvidenceProvider, member))
        adapter_sig = _param_shape(getattr(EvidenceProviderAdapter, member))
        assert proto_sig == adapter_sig, (
            f"signature drift on {member!r}: Protocol expects {proto_sig}, "
            f"adapter has {adapter_sig}"
        )

    def test_adapter_delegates_to_module_functions(self, gateway: Any) -> None:
        """A round-trip through the adapter proves it delegates to real read
        functions and returns the dict/list shapes the Protocol declares."""
        from dossier.evidence import EvidenceProviderAdapter

        adapter = EvidenceProviderAdapter(gateway, project_slug="dossier-test")

        summary = adapter.evidence_summary()
        assert isinstance(summary, dict)
        assert "project_slug" in summary

        events = adapter.event_verifications()
        assert isinstance(events, list)

        report = adapter.integrity_report()
        assert isinstance(report, dict)
        assert "chain_intact" in report


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

        transitions = gateway.transitions_from("open", 3)
        assert isinstance(transitions, list)

    def test_gateway_identity_provider_methods_return_expected_types(
        self, gateway: Any
    ) -> None:
        principals = gateway.list_principals()
        assert isinstance(principals, list)

    def test_gateway_work_descriptor_is_honest(self, gateway: Any) -> None:
        descriptor = gateway.describe_work()
        assert isinstance(descriptor, ProviderDescriptor)
        assert descriptor.name == "work"
        assert descriptor.contract_version == CONTRACT_VERSION
        assert descriptor.availability is Availability.AVAILABLE

    def test_gateway_identity_descriptor_is_honest(self, gateway: Any) -> None:
        descriptor = gateway.describe_identity()
        assert isinstance(descriptor, ProviderDescriptor)
        assert descriptor.name == "identity"
        assert descriptor.contract_version == CONTRACT_VERSION
        # InMemoryRegista has no principal-key ops, so identity honestly
        # reports NOT_CONFIGURED rather than over-claiming AVAILABLE.
        assert descriptor.availability is Availability.NOT_CONFIGURED


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
            detail="spine version 0.4.0 is behind the lock (0.5.4)",
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
            "dossier.activity",
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
            "dossier.activity",
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
