"""Versioned provider contracts for dossier's six console areas (Plan 015 WI-1.1).

Each owning component exposes a public, versioned describe/read surface.
Dossier consumes contracts; it does not import component-private modules,
query private tables, recompute cryptographic verdicts, or gain
host/service-manager authority.

Unknown contract versions and values fail closed into explicit ``unknown``
or ``unsupported`` states (shell.Availability / shell.Status).

The contracts are Protocols — structural, not nominal. A provider satisfies
a contract by shape, not by inheritance. This lets InMemoryRegista-backed
test doubles and real Postgres-backed gateways satisfy the same contract
without a shared base class.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from .shell import Availability

CONTRACT_VERSION = "1.0.0"


@dataclass(frozen=True, slots=True)
class ProviderDescriptor:
    """Self-description returned by every provider's ``describe()``."""

    name: str
    contract_version: str
    availability: Availability
    capabilities: tuple[str, ...] = ()
    detail: str | None = None


@runtime_checkable
class WorkProvider(Protocol):
    """GJ-1/GJ-2: work creation, transition, review, search."""

    def describe_work(self) -> ProviderDescriptor: ...
    def list_issues(
        self,
        *,
        current_states: list[str] | None = None,
        assignee: str | None = None,
        page_size: int = 100,
    ) -> Any: ...
    def get_issue(self, work_item_id: Any) -> Any | None: ...
    def create_issue(
        self,
        *,
        actor: Any,
        work_item_type: str,
        custom_fields: dict[str, Any] | None = None,
    ) -> tuple[Any, Any]: ...
    def transition(
        self,
        *,
        actor: Any,
        work_item_id: Any,
        transition_name: str,
        payload: dict[str, Any] | None = None,
        custom_fields: dict[str, Any] | None = None,
    ) -> Any: ...
    def comment(self, *, actor: Any, work_item_id: Any, body: str) -> Any: ...
    def history(self, work_item_id: Any) -> list[Any]: ...
    def transitions_from(
        self, state: str, workflow_version: int
    ) -> list[Any]: ...


@runtime_checkable
class KnowledgeProvider(Protocol):
    """GJ-3: signed knowledge browse, search, detail, verification.

    Return types are intentionally ``Any``-bounded (matching
    :class:`WorkProvider`): the knowledge provider returns rich, typed
    presentation objects (``NoteSummary`` / ``NoteDetail``), not bare dicts,
    so the contract declares the method surface without lying about the result
    shape. :class:`dossier.knowledge.KnowledgeProviderAdapter` is the real
    Protocol-satisfying object that binds these methods to a gateway.
    """

    def describe_knowledge(self) -> ProviderDescriptor: ...
    def create_note(
        self, *, actor: Any, title: str, body: str
    ) -> str: ...
    def list_notes(self, *, limit: int = 100) -> list[Any]: ...
    def get_note(self, note_id: str) -> Any | None: ...
    def search_notes(self, query: str, *, limit: int = 50) -> list[Any]: ...
    def verify_note(self, note_id: str) -> dict[str, Any]: ...


@runtime_checkable
class ActivityProvider(Protocol):
    """GJ-5: session/tool/file/work timelines, verification."""

    def describe_activity(self) -> ProviderDescriptor: ...
    def list_sessions(self, *, limit: int = 50) -> list[dict[str, Any]]: ...
    def get_session(self, session_id: str) -> dict[str, Any] | None: ...
    def activity_feed(self, *, limit: int = 50) -> list[dict[str, Any]]: ...


@runtime_checkable
class EvidenceProvider(Protocol):
    """GJ-8: scoped export, verification, integrity."""

    def describe_evidence(self) -> ProviderDescriptor: ...
    def evidence_summary(self) -> dict[str, Any]: ...
    def event_verifications(self, *, limit: int = 100) -> list[dict[str, Any]]: ...
    def integrity_report(self, *, work_item_id: Any = None) -> dict[str, Any]: ...


@runtime_checkable
class OperationsProvider(Protocol):
    """GJ-9: estate health, findings, backup/restore status."""

    def describe_operations(self) -> ProviderDescriptor: ...
    def estate_summary(self) -> dict[str, Any]: ...
    def operations_findings(self) -> list[dict[str, Any]]: ...


@runtime_checkable
class IdentityProvider(Protocol):
    """GJ-1/GJ-4: principal lifecycle, keys, enrollment."""

    def describe_identity(self) -> ProviderDescriptor: ...
    def list_principals(self, *, principal_id: str | None = None) -> list[dict[str, Any]]: ...
    def get_principal_key(self, principal_id: str) -> dict[str, Any] | None: ...
    def enroll_principal(
        self,
        principal_id: str,
        *,
        actor: Any = None,
        private_key_dir: str | None = None,
        secret_backend: str | None = None,
    ) -> dict[str, Any] | None: ...
    def revoke_principal(
        self, principal_id: str, key_id: str, *, reason: str = "unspecified"
    ) -> dict[str, Any] | None: ...


@runtime_checkable
class DeliveryProvider(Protocol):
    """GJ-7: notification preferences, delivery state."""

    def describe_delivery(self) -> ProviderDescriptor: ...
    def get_preferences(self, principal_id: str) -> dict[str, Any]: ...
    def save_preferences(self, principal_id: str, preferences: dict[str, Any]) -> None: ...


PROVIDER_CONTRACTS: dict[str, type] = {
    "work": WorkProvider,
    "knowledge": KnowledgeProvider,
    "activity": ActivityProvider,
    "evidence": EvidenceProvider,
    "operations": OperationsProvider,
    "identity": IdentityProvider,
    "delivery": DeliveryProvider,
}
