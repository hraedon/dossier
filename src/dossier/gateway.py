from __future__ import annotations

import hashlib
import logging
import re
import threading
import uuid
from typing import TYPE_CHECKING, Any, cast

import regista
import yaml
from regista import (
    Approval,
    ErrorCode,
    Event,
    LifecycleContractError,
    LifecycleErrorCode,
    PrincipalKind,
    PrincipalLifecycle,
    QueryPage,
    Regista,
    RegistaError,
    ReplayReport,
    RevocationRequest,
    WorkItem,
)
from regista.principal_lifecycle import CONTRACT_VERSION

from .actors import SYSTEM_ACTOR, Actor

if TYPE_CHECKING:
    from .contracts import ProviderDescriptor

logger = logging.getLogger("dossier.gateway")

_TESTING = False

# Plan 010 (WI-3): dossier registers the single canonical workflow shipped from
# regista — the same one agent-notes registers — so human and agent work share
# one work-item universe. The review-gate validators are regista built-ins
# (Plan 023), auto-available by name; dossier no longer ships its own copies.
WORKFLOW_NAME = "canonical"


def packaged_workflow_yaml() -> str:
    return str(regista.canonical_workflow_yaml())


def packaged_workflow_version() -> int:
    """The ``version`` declared in the packaged workflow YAML. Used only as a
    defensive fallback when a ``WorkItem`` lacks ``workflow_version`` (which it
    never should); the work-item's own version is authoritative.
    """
    return int(yaml.safe_load(packaged_workflow_yaml())["version"])


def _metadata(actor: Actor) -> dict[str, Any]:
    role = "system" if actor.actor_kind == "system" else "human"
    meta: dict[str, Any] = {"display_name": actor.display_name, "role": role}
    if actor.model_lineage:
        meta["model_lineage"] = actor.model_lineage
    return meta


def _manifest_path_for(hmac_key_path: str) -> str | None:
    """Resolve the key-set manifest path from an hmac_key_path.

    For a ``file:`` ref or a bare filesystem path, returns the path to write
    the key-set manifest. For a non-file backend (``env:``/``vault:``/
    ``azure:``/``literal:``/``operator:``) returns ``None`` — the key-set is
    resolved from the secret backend at sign time, not from a local manifest
    file, so writing one would create a bogus file named after the ref and
    leak the ``secret_ref``. Mirrors regista's ``_resolve_key_dir``.
    """
    if hmac_key_path.startswith("file:"):
        return hmac_key_path[5:]
    if ":" not in hmac_key_path:
        return hmac_key_path
    return None


class RegistaGateway:
    """The only place dossier mutates work-state.

    Every method takes a server-resolved :class:`Actor` and injects it into the
    regista call. There is deliberately no overload that accepts ``actor_id`` /
    ``actor_kind`` from a request body: the actor is trust-rooted in auth and
    threaded through here, which is provenance guarantee G1. Reads are also
    centralised here so dossier has one regista surface.

    ``project_name`` is used to mint human-friendly ``<PREFIX>-<N>`` display keys
    (WI-006). The prefix is the project name uppercased and sanitized to
    ``[A-Z0-9_]`` (e.g. ``dossier`` → ``DOSSIER``, ``agent-notes`` →
    ``AGENT_NOTES``).
    The sequence number is derived from the maximum existing sequence among
    all work items' ``display_key`` custom fields (a read) — dossier owns no
    counter table. The minted key is stored as a ``display_key`` custom field
    in the regista create event, so the write goes through regista, not a
    side-channel. A process-level ``threading.Lock`` serializes the
    mint-then-create operation so two concurrent creates in the same process
    cannot produce the same key (WI-011). Multi-process deployments still
    require a regista-side sequence or advisory lock for full correctness.
    """

    def __init__(self, regista: Regista, project_name: str = "dossier") -> None:
        self._reg = regista
        self._project_name = project_name
        self._mint_lock = threading.Lock()

    def register_workflow(self, yaml_text: str | None = None) -> None:
        self._reg.register_workflow(yaml_text or packaged_workflow_yaml())

    def close(self) -> None:
        self._reg.close()

    def describe_work(self) -> ProviderDescriptor:
        from .contracts import CONTRACT_VERSION, ProviderDescriptor
        from .shell import Availability

        return ProviderDescriptor(
            name="work",
            contract_version=CONTRACT_VERSION,
            availability=Availability.AVAILABLE,
            capabilities=("create", "transition", "comment", "history", "search"),
        )

    def describe_identity(self) -> ProviderDescriptor:
        from .contracts import CONTRACT_VERSION, ProviderDescriptor
        from .shell import Availability

        return ProviderDescriptor(
            name="identity",
            contract_version=CONTRACT_VERSION,
            availability=(
                Availability.AVAILABLE
                if self.has_principal_ops()
                else Availability.NOT_CONFIGURED
            ),
            capabilities=("enroll", "revoke", "list", "get_active"),
        )

    def create_issue(
        self,
        *,
        actor: Actor,
        work_item_type: str,
        custom_fields: dict[str, Any] | None = None,
    ) -> tuple[WorkItem, Event]:
        """Create a work item. ``on_behalf_of`` is intentionally not threaded:
        regista's ``create_work_item`` does not accept it (a regista-side
        limitation; agent-delegated creation is a future concern). Transitions
        and comments do thread ``on_behalf_of``.

        ``custom_fields`` must include ``title`` (required by the workflow v2)
        and typically includes ``description``, ``assignee``, and ``priority``.
        A ``display_key`` (e.g. ``DOSSIER-3``) is auto-minted if not already
        present — see :class:`RegistaGateway` docstring for the ownership
        decision (WI-006).
        """
        cf = dict(custom_fields) if custom_fields else {}
        if "display_key" not in cf:
            with self._mint_lock:
                cf["display_key"] = self._mint_display_key()
                return cast(
                    tuple[WorkItem, Event],
                    self._reg.create_work_item(
                        workflow_name=WORKFLOW_NAME,
                        work_item_type=work_item_type,
                        actor_id=actor.actor_id,
                        actor_kind=actor.actor_kind,
                        actor_metadata=_metadata(actor),
                        custom_fields=cf,
                    ),
                )
        return cast(
            tuple[WorkItem, Event],
            self._reg.create_work_item(
                workflow_name=WORKFLOW_NAME,
                work_item_type=work_item_type,
                actor_id=actor.actor_id,
                actor_kind=actor.actor_kind,
                actor_metadata=_metadata(actor),
                custom_fields=cf,
            ),
        )

    def transition(
        self,
        *,
        actor: Actor,
        work_item_id: uuid.UUID,
        transition_name: str,
        payload: dict[str, Any] | None = None,
        custom_fields: dict[str, Any] | None = None,
    ) -> Event:
        return cast(
            Event,
            self._reg.transition(
                work_item_id,
                transition_name,
                actor.actor_id,
                actor_kind=actor.actor_kind,
                actor_metadata=_metadata(actor),
                payload=payload,
                custom_fields=custom_fields,
                on_behalf_of=actor.on_behalf_of,
            ),
        )

    def comment(
        self,
        *,
        actor: Actor,
        work_item_id: uuid.UUID,
        body: str,
    ) -> Event:
        return cast(
            Event,
            self._reg.append_event(
                work_item_id,
                actor.actor_id,
                actor_kind=actor.actor_kind,
                actor_metadata=_metadata(actor),
                transition="comment",
                payload={"body": body},
                on_behalf_of=actor.on_behalf_of,
            ),
        )

    def append_note_event(
        self,
        *,
        actor: Actor,
        entity_id: uuid.UUID,
        transition: str,
        payload: dict[str, Any] | None = None,
    ) -> Event:
        return cast(
            Event,
            self._reg.append_event(
                entity_id,
                actor.actor_id,
                actor_kind=actor.actor_kind,
                actor_metadata=_metadata(actor),
                transition=transition,
                payload=payload,
                on_behalf_of=actor.on_behalf_of,
                entity_kind="note",
            ),
        )

    def get_issue(self, work_item_id: uuid.UUID) -> WorkItem | None:
        return cast(WorkItem | None, self._reg.get_work_item(work_item_id))

    def list_issues(
        self,
        *,
        current_states: list[str] | None = None,
        assignee: str | None = None,
        page_size: int = 100,
    ) -> Any:
        field_filters = {"assignee": assignee} if assignee else None
        return self._reg.query_work_items(
            workflow_name=WORKFLOW_NAME,
            current_states=current_states,
            custom_field_filters=field_filters,
            page_size=page_size,
        )

    def history(self, work_item_id: uuid.UUID) -> list[Event]:
        return cast(list[Event], self._reg.read_events(work_item_id=work_item_id, limit=10_000))

    def read_recent_events(
        self,
        *,
        limit: int = 100,
        actor_id: str | None = None,
        transition: str | None = None,
    ) -> list[Event]:
        """Read recent events across the project in descending time order.

        Used by the activity feed (Plan 018 WI-1.3). Supports optional
        filtering by *actor_id* or *transition* name. Results are
        descending by ``(timestamp, event_seq)`` per regista's contract.
        """
        return cast(
            list[Event],
            self._reg.read_events(actor_id=actor_id, transition=transition, limit=limit),
        )

    def read_events_by_transition(self, transition: str, limit: int = 10_000) -> list[Event]:
        """Read events across the project filtered by transition name.

        Unlike :meth:`history` (which is per-work-item), this scans the
        entire project's event log for events matching *transition*. Used
        by the agent-activity window (Plan 017) to discover cairn
        ``session_attestation`` and ``tool_call_*`` events.
        """
        return cast(list[Event], self._reg.read_events(transition=transition, limit=limit))

    def list_links(self, work_item_id: uuid.UUID) -> list[Any]:
        """Return all live (non-removed) links from *work_item_id*.

        Used by Plan 011 WI-4 (cross-project reference rendering) to show
        outbound value-references as navigable links in the issue detail view.
        """
        if hasattr(self._reg, "list_links"):
            return cast(list[Any], self._reg.list_links(work_item_id))
        return []

    def get_project_catalog_entry(self) -> Any | None:
        """Return this project's catalog row (owner, display_name), or None."""
        if hasattr(self._reg, "get_project_catalog_entry"):
            return self._reg.get_project_catalog_entry()
        return None

    def set_project_owner(
        self, owner_actor_id: str | None, *, updated_by: str | None = None
    ) -> Any:
        """Set or clear the owner for this project (Plan 012 WI-4)."""
        if hasattr(self._reg, "set_project_owner"):
            return self._reg.set_project_owner(owner_actor_id, updated_by=updated_by)
        return None

    def register_project_metadata(
        self,
        *,
        display_name: str | None = None,
        owner_actor_id: str | None = None,
        created_by: str | None = None,
    ) -> Any | None:
        """Insert or update this project's catalog row (Plan 012 WI-4)."""
        if hasattr(self._reg, "register_project_metadata"):
            return self._reg.register_project_metadata(
                display_name=display_name, owner_actor_id=owner_actor_id, created_by=created_by
            )
        return None

    def list_catalog_projects(self) -> list[str]:
        """Return project schema names from the shared catalog (Plan 014 WI-1.1)."""
        reg = self._reg
        if hasattr(reg, "list_projects"):
            try:
                entries = reg.list_projects()
                return [e.schema_name for e in entries]
            except Exception:
                return []
        return []

    def integrity(self, work_item_id: uuid.UUID | None = None) -> ReplayReport:
        return cast(ReplayReport, self._reg.replay(work_item_id=work_item_id))

    def verify_event(self, event: Event) -> dict[str, Any]:
        """Return verification info for a single event's signature.

        Uses regista's ``verify_event_signature`` to check the cryptographic
        binding. Returns a dict with::

            {
                "verified": bool,             # signature valid AND signer known
                "signature_valid": bool,      # the cryptographic check alone
                "signer_registered": bool,    # key_id present in the registry
                "principal_id": str | None,   # from the key's principal binding
                "fingerprint": str | None,     # public-key fingerprint
                "scheme": str | None,          # e.g. "ed25519", "hmac-sha256"
            }

        An unverified or unregistered-signer event is returned with
        ``verified=False`` — the UI must never silently render it as trusted
        (Plan 014 WI-1.3 AC).

        ``signature_valid`` and ``signer_registered`` are reported separately
        because they are different failures: a signature that does not verify
        means the record is *contradicted*, while an unregistered signer means
        it merely cannot be *attributed*. Callers that must tell a human which
        one happened (see ``provenance.verify_session_signatures``) need both;
        callers that only need "may I render this as trusted?" use ``verified``.
        """
        info: dict[str, Any] = {
            "verified": False,
            "signature_valid": False,
            "signer_registered": False,
            "principal_id": None,
            "fingerprint": None,
            "scheme": None,
        }
        try:
            verified = self._reg.verify_event_signature(event)
            info["signature_valid"] = bool(verified)
        except Exception:
            logger.debug("verify_event: signature verification failed", exc_info=True)
            info["signature_valid"] = False

        key_id = getattr(event, "key_id", None)
        if key_id:
            info["key_id"] = str(key_id)
            try:
                public_keys = self._reg.export_public_keys()
                for pk in public_keys:
                    if pk.get("key_id") == key_id:
                        info["principal_id"] = pk.get("principal_id")
                        info["fingerprint"] = pk.get("fingerprint")
                        info["scheme"] = pk.get("scheme")
                        info["signer_registered"] = True
                        break
            except Exception:
                logger.debug("verify_event: public key lookup failed", exc_info=True)
                info["signer_registered"] = False
        info["verified"] = bool(info["signature_valid"]) and (
            not key_id or bool(info["signer_registered"])
        )
        return info

    def has_principal_ops(self) -> bool:
        """True when the backend is real regista with principal-key ops."""
        return hasattr(self._reg, "principals")

    def has_lifecycle_ops(self) -> bool:
        """True when the backend exposes a durable principal lifecycle facade."""
        return hasattr(self._reg, "principal_lifecycle")

    @property
    def principal_lifecycle(self) -> PrincipalLifecycle:
        """Return the regista principal lifecycle facade, or raise if absent."""
        if not self.has_lifecycle_ops():
            raise LifecycleContractError(
                LifecycleErrorCode.DURABLE_OPERATION_REQUIRED,
                "principal lifecycle is not available on this backend",
            )
        return cast(PrincipalLifecycle, self._reg.principal_lifecycle)

    def _test_store(self) -> Any | None:
        if not _TESTING:
            return None
        return getattr(self, "_principal_store", None)

    def list_principals(self, principal_id: str | None = None) -> list[dict[str, Any]]:
        """List principal keys from the regista registry (Plan 015).

        When the backend supports ``PrincipalKeyOps`` (real Regista), this
        delegates to ``reg.principals.list()``. When it doesn't
        (InMemoryRegista), checks for an injected test-double store
        (``_principal_store``), then falls back to an empty list.
        """
        store = self._test_store()
        if store is not None:
            return cast(list[dict[str, Any]], store.list(principal_id))
        if self.has_principal_ops():
            try:
                return cast(list[dict[str, Any]], self._reg.principals.list(principal_id))
            except Exception:
                return []
        return []

    def read_principal_enrollment_events(self, principal_id: str) -> list[Event]:
        """Read principal enrollment/rotation/revocation events.

        Returns an empty list when the backend does not support principal
        entities (e.g. InMemoryRegista without an injected test store).
        """
        reg = self._reg
        if hasattr(reg, "read_principal_enrollment_events"):
            try:
                return cast(
                    list[Event],
                    reg.read_principal_enrollment_events(principal_id=principal_id),
                )
            except Exception:
                logger.debug("read_principal_enrollment_events failed", exc_info=True)
        return []

    def _generate_and_register(
        self,
        principal_id: str,
        *,
        registered_by: str = "system",
        rotate: bool = False,
    ) -> dict[str, Any] | None:
        """Generate a keypair and register/rotate it via the public API.

        Plan 015 WI-3.1: custody (private-key storage) is no longer handled
        by dossier. The caller or a custody provider owns private-key
        generation and storage. Dossier only generates the keypair for
        test/dev paths and registers the public key.
        """
        from .keys import generate_ed25519_keypair

        _private_key, public_key = generate_ed25519_keypair()

        if self.has_principal_ops():
            if rotate:
                entry = cast(
                    dict[str, Any],
                    self._reg.principals.rotate(
                        principal_id,
                        public_key,
                        registered_by=registered_by,
                    ),
                )
            else:
                entry = cast(
                    dict[str, Any],
                    self._reg.principals.register(
                        principal_id,
                        public_key,
                        registered_by=registered_by,
                    ),
                )
        else:
            store = self._test_store()
            if store is None:
                logger.warning(
                    "register_no_store",
                    extra={"principal_id": principal_id},
                )
                return None
            if rotate:
                entry = cast(
                    dict[str, Any],
                    store.rotate(
                        principal_id,
                        public_key,
                        registered_by=registered_by,
                    ),
                )
            else:
                entry = cast(
                    dict[str, Any],
                    store.register(
                        principal_id,
                        public_key,
                        registered_by=registered_by,
                    ),
                )

        return entry

    def enroll_principal(
        self,
        principal_id: str,
        *,
        actor: Actor | None = None,
        private_key_dir: str | None = None,
        secret_backend: str | None = None,
    ) -> dict[str, Any] | None:
        """Enroll a principal through regista (Plan 015 WI-2.1).

        Real regista (Postgres): delegates to ``reg.enroll_principal`` which
        generates the Ed25519 keypair, stores the private key in the secret
        backend, registers the public key, and emits a signed
        ``principal_enrolled`` event — all in one call.

        InMemoryRegista (tests): generates a keypair locally and registers
        via the injected test-double store.

        The returned dict contains only public metadata: ``key_id``,
        ``fingerprint``, ``scheme``. No private key material is ever returned.
        """
        if self.has_principal_ops():
            actor_id = actor.actor_id if actor else "system"
            actor_kind = actor.actor_kind if actor else "system"
            actor_metadata = _metadata(actor) if actor else None
            try:
                return cast(
                    dict[str, Any],
                    self._reg.enroll_principal(
                        principal_id,
                        actor_id=actor_id,
                        actor_kind=actor_kind,
                        actor_metadata=actor_metadata,
                        private_key_dir=private_key_dir,
                        secret_backend=secret_backend,
                    ),
                )
            except Exception as exc:
                detail: dict[str, Any] = {
                    "principal_id": principal_id,
                    "error": type(exc).__name__,
                }
                if isinstance(exc, RegistaError):
                    detail["error_code"] = exc.code.value
                logger.warning("enroll_principal failed", extra=detail)
                return None

        registered_by = actor.actor_id if actor else "system"
        try:
            return self._generate_and_register(
                principal_id,
                registered_by=registered_by,
                rotate=False,
            )
        except Exception as exc:
            detail = {"principal_id": principal_id, "error": type(exc).__name__}
            if isinstance(exc, RegistaError):
                detail["error_code"] = exc.code.value
            logger.warning("enroll_principal failed", extra=detail)
            return None

    def get_principal_key(self, principal_id: str) -> dict[str, Any] | None:
        """Get the active key for a principal, or None if not registered."""
        store = self._test_store()
        if store is not None:
            try:
                return cast(dict[str, Any], store.get_active(principal_id))
            except Exception:
                return None
        if self.has_principal_ops():
            try:
                return cast(dict[str, Any], self._reg.principals.get_active(principal_id))
            except Exception:
                return None
        return None

    def register_principal(
        self,
        principal_id: str,
        *,
        actor: Actor | None = None,
        private_key_dir: str | None = None,
        secret_backend: str | None = None,
    ) -> dict[str, Any] | None:
        """Register a new principal key (Plan 015 WI-2.3).

        Fails closed against real regista: the generate-discard-register
        pattern produces an active key the client cannot use (the private
        key is thrown away). Until regista Plan 031 lands the durable
        lifecycle (prepare → possession proof → approval → atomic commit →
        effective-client receipt), this operation is disabled on the real
        backend. The test-store path remains for dev/test.
        """
        if self.has_principal_ops():
            raise RegistaError(
                code=ErrorCode.SECRET_WRITE_UNSUPPORTED,
                message=(
                    "break-glass key registration is disabled against real "
                    "regista: the generate-discard-register pattern produces "
                    "an active key the client cannot use. Requires regista "
                    "Plan 031 (durable key lifecycle)."
                ),
            )
        registered_by = actor.actor_id if actor else "system"
        return self._generate_and_register(
            principal_id,
            registered_by=registered_by,
            rotate=False,
        )

    def rotate_principal(
        self,
        principal_id: str,
        *,
        actor: Actor | None = None,
        private_key_dir: str | None = None,
        secret_backend: str | None = None,
    ) -> dict[str, Any] | None:
        """Rotate a principal's key (Plan 015 WI-1.2).

        Fails closed against real regista: the generate-discard-register
        pattern produces an active key the client cannot use (the private
        key is thrown away). Until regista Plan 031 lands the durable
        lifecycle (prepare → possession proof → approval → atomic commit →
        effective-client receipt), this operation is disabled on the real
        backend. The test-store path remains for dev/test.
        """
        if self.has_principal_ops():
            raise RegistaError(
                code=ErrorCode.SECRET_WRITE_UNSUPPORTED,
                message=(
                    "key rotation is disabled against real regista: the "
                    "generate-discard-register pattern produces an active "
                    "key the client cannot use. Requires regista Plan 031 "
                    "(durable key lifecycle)."
                ),
            )
        registered_by = actor.actor_id if actor else "system"
        return self._generate_and_register(
            principal_id,
            registered_by=registered_by,
            rotate=True,
        )

    def approve_operation(
        self,
        operation_id: str,
        *,
        approver: Actor,
        approval_digest: str,
        step_up_evidence: str | None = None,
        reason: str = "",
    ) -> Any:
        """Record a dual-control approval for a prepared lifecycle operation.

        The approver is a server-resolved :class:`Actor`; dossier enforces
        separation of duties by refusing self-approval (the approver must not
        be the operation's initiator).  This is the real approval seam; it
        does not generate, hold, or return private key material.
        """
        lifecycle = self.principal_lifecycle
        operation = lifecycle.get_operation(operation_id)
        if operation.actor_id == approver.actor_id:
            raise LifecycleContractError(
                LifecycleErrorCode.INVALID_REQUEST,
                "dual-control approval requires a different approver than the initiator",
            )
        approval = Approval(
            approver_id=approver.actor_id,
            approver_kind=approver.actor_kind,
            approval_digest=approval_digest,
            step_up_evidence=step_up_evidence,
            reason=reason,
        )
        return lifecycle.record_approval(operation_id, approval)

    def _resolve_principal_kind(self, principal_id: str) -> PrincipalKind:
        """Resolve the principal kind from the durable lifecycle registry.

        Revocation must record the actual kind of the principal in the
        operation digest and the signed audit event.  Dossier does not
        default to HUMAN when the kind is unknown; it asks regista's
        lifecycle descriptor and fails closed if the kind cannot be
        determined.
        """
        lifecycle = self.principal_lifecycle
        try:
            descriptor = lifecycle.describe(principal_id)
        except Exception as exc:
            raise LifecycleContractError(
                LifecycleErrorCode.INVALID_REQUEST,
                f"cannot determine principal kind for {principal_id}",
            ) from exc
        return descriptor.principal_kind

    def prepare_revocation_operation(
        self,
        principal_id: str,
        key_id: str,
        *,
        actor: Actor | None = None,
        reason: str = "unspecified",
    ) -> dict[str, Any]:
        """Prepare a revocation lifecycle operation.

        Returns the prepared operation metadata (operation_id, digest, state,
        principal, project).  The caller must obtain approval from a different
        admin and then commit the operation; this method does not approve or
        commit, so it never self-approves.
        """
        lifecycle = self.principal_lifecycle
        initiator = actor or SYSTEM_ACTOR
        principal_kind = self._resolve_principal_kind(principal_id)
        idempotency_key = self._lifecycle_idempotency_key(
            "revoke", initiator.actor_id, principal_id, key_id
        )
        request = RevocationRequest(
            principal_id=principal_id,
            principal_kind=principal_kind,
            actor_id=initiator.actor_id,
            key_id=key_id,
            reason=reason,
            requested_authority="admin",
            policy_version=CONTRACT_VERSION,
        )
        operation = lifecycle.prepare_revocation(request, idempotency_key=idempotency_key)
        return {
            "operation_id": operation.operation_id,
            "digest": operation.digest.value,
            "state": operation.state.value,
            "principal_id": principal_id,
            "project": self._project_name,
        }

    def commit_operation(
        self,
        operation_id: str,
        *,
        expected_digest: str,
    ) -> dict[str, Any]:
        """Commit an approved lifecycle operation."""
        lifecycle = self.principal_lifecycle
        receipt = lifecycle.commit(
            operation_id, expected_digest=expected_digest
        )
        return cast(dict[str, Any], receipt.to_dict())

    def revoke_principal(
        self,
        principal_id: str,
        key_id: str,
        *,
        actor: Actor | None = None,
        approver: Actor | None = None,
        reason: str = "unspecified",
    ) -> dict[str, Any] | None:
        """Revoke a principal's key.

        Against a durable regista lifecycle backend this method is disabled:
        revocation is a protected operation that requires two-phase dual
        control (prepare → approve → commit), so callers must use
        :meth:`prepare_revocation_operation`, :meth:`approve_operation`, and
        :meth:`commit_operation`.  Against the InMemoryRegista test backend it
        falls back to the injected test store or the legacy
        ``principals.revoke`` path.
        """
        _ = actor, approver  # retained for compatibility; ignored on lifecycle path
        if self.has_lifecycle_ops():
            raise LifecycleContractError(
                LifecycleErrorCode.DURABLE_OPERATION_REQUIRED,
                "revocation requires the two-phase prepare/approve/commit flow",
            )
        store = self._test_store()
        if store is not None:
            return cast(dict[str, Any], store.revoke(principal_id, key_id, reason=reason))
        if self.has_principal_ops():
            return cast(
                dict[str, Any],
                self._reg.principals.revoke(principal_id, key_id, reason=reason),
            )
        return None

    def _lifecycle_idempotency_key(
        self,
        operation_type: str,
        actor_id: str,
        principal_id: str,
        key_id: str,
    ) -> str:
        payload = f"{operation_type}:{actor_id}:{principal_id}:{key_id}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def transitions_from(self, state: str, workflow_version: int) -> list[Any]:
        """Return the ``TransitionDef``s whose ``from_state == state`` for the
        registered dossier workflow at ``workflow_version``. The workflow YAML is
        the single source of truth for the state machine; this avoids dossier
        mirroring it in a second hand-maintained dict.
        """
        wf = self._reg.get_workflow(WORKFLOW_NAME, workflow_version)
        return [t for t in wf.transitions if t.from_state == state]

    def _existing_display_keys(self) -> list[str]:
        """Collect all existing display_key custom fields via paginated reads.

        Used to derive the next display-key sequence number. This is a read —
        dossier owns no counter table (WI-006 sequence-ownership decision).
        """
        keys: list[str] = []
        cursor: uuid.UUID | None = None
        while True:
            page: QueryPage[WorkItem] = self._reg.query_work_items(
                workflow_name=WORKFLOW_NAME,
                cursor=cursor,
                page_size=1000,
            )
            for wi in page.items:
                cf = getattr(wi, "custom_fields", None)
                if isinstance(cf, dict):
                    dk = cf.get("display_key")
                    if isinstance(dk, str) and dk:
                        keys.append(dk)
            if not page.has_more:
                break
            cursor = page.cursor
        return keys

    def _mint_display_key(self) -> str:
        """Mint a ``<PREFIX>-<N>`` display key for a new work item.

        ``N`` is ``max(existing sequences) + 1``, where existing sequences are
        parsed from all work items' ``display_key`` custom fields that share
        this project's prefix. Using max (not count) ensures deleted items
        don't cause sequence reuse. The prefix is the project name uppercased
        and sanitized to ``[A-Z0-9_]`` (spaces and hyphens become underscores;
        other characters are stripped).

        Must be called under ``self._mint_lock`` to prevent a TOCTOU race
        between the scan and the create.
        """
        prefix = self._display_prefix()
        existing = self._existing_display_keys()
        max_n = 0
        pfx = f"{prefix}-"
        for key in existing:
            if key.startswith(pfx):
                suffix = key[len(pfx):]
                try:
                    n = int(suffix)
                    if n > max_n:
                        max_n = n
                except ValueError:
                    pass
        return f"{prefix}-{max_n + 1}"

    def _display_prefix(self) -> str:
        """Return the sanitized uppercase prefix for display keys."""
        raw = self._project_name.upper().replace("-", "_").replace(" ", "_")
        return re.sub(r"[^A-Z0-9_]", "", raw) or "PROJECT"
