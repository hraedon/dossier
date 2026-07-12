from __future__ import annotations

import logging
import re
import uuid
from typing import Any, cast

import yaml

import regista
from regista import Event, QueryPage, Regista, RegistaError, ReplayReport, WorkItem

from .actors import Actor

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
    The sequence number is derived from a paginated count of existing work items
    (a read) — dossier owns no counter table. The minted key is stored as a
    ``display_key`` custom field in the regista create event, so the write goes
    through regista, not a side-channel. Two concurrent creates could mint the
    same number; this is acceptable for MVP (single-user, low concurrency) and
    documented here. A regista-side sequence or advisory lock would close the
    race for production.
    """

    def __init__(self, regista: Regista, project_name: str = "dossier") -> None:
        self._reg = regista
        self._project_name = project_name

    def register_workflow(self, yaml_text: str | None = None) -> None:
        self._reg.register_workflow(yaml_text or packaged_workflow_yaml())

    def close(self) -> None:
        self._reg.close()

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

    def set_project_owner(self, owner_actor_id: str | None, *, updated_by: str | None = None) -> Any:
        """Set or clear the owner for this project (Plan 012 WI-4)."""
        if hasattr(self._reg, "set_project_owner"):
            return self._reg.set_project_owner(owner_actor_id, updated_by=updated_by)
        return None

    def register_project_metadata(
        self, *, display_name: str | None = None, owner_actor_id: str | None = None, created_by: str | None = None
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
                "verified": bool,
                "principal_id": str | None,   # from the key's principal binding
                "fingerprint": str | None,     # public-key fingerprint
                "scheme": str | None,          # e.g. "ed25519", "hmac-sha256"
            }

        An unverified or unregistered-signer event is returned with
        ``verified=False`` — the UI must never silently render it as trusted
        (Plan 014 WI-1.3 AC).
        """
        info: dict[str, Any] = {
            "verified": False,
            "principal_id": None,
            "fingerprint": None,
            "scheme": None,
        }
        try:
            verified = self._reg.verify_event_signature(event)
            info["verified"] = bool(verified)
        except Exception:
            logger.debug("verify_event: signature verification failed", exc_info=True)
            info["verified"] = False

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
                        break
                else:
                    info["verified"] = False
            except Exception:
                logger.debug("verify_event: public key lookup failed", exc_info=True)
                info["verified"] = False
        return info

    def has_principal_ops(self) -> bool:
        """True when the backend is real regista with principal-key ops."""
        return hasattr(self._reg, "principals")

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
                return cast(list[Event], reg.read_principal_enrollment_events(principal_id=principal_id))
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

        Plan 015 WI-3.1: custody is no longer handled by dossier. The caller
        or a custody provider owns private-key generation and storage.
        Dossier generates a keypair for test/dev paths and registers the
        public key via the public principal-key API.

        Used by break-glass (WI-2.3) to issue a new key after revoking the
        old one.
        """
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

        Plan 015 WI-3.1: custody is no longer handled by dossier. The caller
        or a custody provider owns private-key generation and storage.
        Dossier generates a keypair for test/dev paths and rotates the
        public key via the public principal-key API.
        """
        registered_by = actor.actor_id if actor else "system"
        return self._generate_and_register(
            principal_id,
            registered_by=registered_by,
            rotate=True,
        )

    def revoke_principal(
        self, principal_id: str, key_id: str, *, reason: str = "unspecified"
    ) -> dict[str, Any] | None:
        """Revoke a principal's key (Plan 015 WI-2.2)."""
        store = self._test_store()
        if store is not None:
            return cast(dict[str, Any], store.revoke(principal_id, key_id, reason=reason))
        if self.has_principal_ops():
            return cast(
                dict[str, Any],
                self._reg.principals.revoke(principal_id, key_id, reason=reason),
            )
        return None

    def transitions_from(self, state: str, workflow_version: int) -> list[Any]:
        """Return the ``TransitionDef``s whose ``from_state == state`` for the
        registered dossier workflow at ``workflow_version``. The workflow YAML is
        the single source of truth for the state machine; this avoids dossier
        mirroring it in a second hand-maintained dict.
        """
        wf = self._reg.get_workflow(WORKFLOW_NAME, workflow_version)
        return [t for t in wf.transitions if t.from_state == state]

    def _count_work_items(self) -> int:
        """Count all work items in this project via paginated reads.

        Used to derive the next display-key sequence number. This is a read —
        dossier owns no counter table (WI-006 sequence-ownership decision).
        """
        count = 0
        cursor: uuid.UUID | None = None
        while True:
            page: QueryPage[WorkItem] = self._reg.query_work_items(
                workflow_name=WORKFLOW_NAME,
                cursor=cursor,
                page_size=1000,
            )
            count += len(page.items)
            if not page.has_more:
                break
            cursor = page.cursor
        return count

    def _mint_display_key(self) -> str:
        """Mint a ``<PREFIX>-<N>`` display key for a new work item.

        ``N`` is ``count + 1``. The prefix is the project name uppercased and
        sanitized to ``[A-Z0-9_]`` (spaces and hyphens become underscores;
        other characters are stripped). See :class:`RegistaGateway` docstring
        for the race-condition caveat.
        """
        n = self._count_work_items() + 1
        raw = self._project_name.upper().replace("-", "_").replace(" ", "_")
        prefix = re.sub(r"[^A-Z0-9_]", "", raw) or "PROJECT"
        return f"{prefix}-{n}"
