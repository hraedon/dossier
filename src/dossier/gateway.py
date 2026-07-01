from __future__ import annotations

import re
import uuid
from typing import TYPE_CHECKING, Any, cast

import yaml

import regista
from regista import Event, QueryPage, Regista, ReplayReport, WorkItem

from .actors import Actor

if TYPE_CHECKING:
    from .config import Settings

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
        # adversarial_review / human_gate are regista built-ins (Plan 023),
        # auto-available by name — dossier registers no local copies (Plan 010).

    @classmethod
    def from_settings(cls, settings: Settings) -> RegistaGateway:
        reg = Regista(
            settings.database_url,
            settings.project,
            settings.hmac_key_path,
            require_ssl=settings.require_ssl,
        )
        return cls(reg, project_name=settings.project)

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

    def integrity(self, work_item_id: uuid.UUID | None = None) -> ReplayReport:
        return cast(ReplayReport, self._reg.replay(work_item_id=work_item_id))

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
