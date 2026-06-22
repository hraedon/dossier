from __future__ import annotations

import uuid
from importlib.resources import files

from regista import Event, Regista, ReplayReport, WorkItem

from .actors import Actor
from .validators import adversarial_review

WORKFLOW_NAME = "dossier"


def packaged_workflow_yaml() -> str:
    return (
        files("dossier")
        .joinpath("workflows", "dossier.workflow.yaml")
        .read_text(encoding="utf-8")
    )


def _metadata(actor: Actor) -> dict:
    role = "system" if actor.actor_kind == "system" else "member"
    return {"display_name": actor.display_name, "role": role}


class RegistaGateway:
    """The only place dossier mutates work-state.

    Every method takes a server-resolved :class:`Actor` and injects it into the
    regista call. There is deliberately no overload that accepts ``actor_id`` /
    ``actor_kind`` from a request body: the actor is trust-rooted in auth and
    threaded through here, which is provenance guarantee G1. Reads are also
    centralised here so dossier has one regista surface.
    """

    def __init__(self, regista: Regista) -> None:
        self._reg = regista
        self._reg.register_validator("adversarial_review", adversarial_review)

    @classmethod
    def from_settings(cls, settings) -> RegistaGateway:
        reg = Regista(
            settings.database_url,
            settings.project,
            settings.hmac_key_path,
            require_ssl=settings.require_ssl,
        )
        return cls(reg)

    def register_workflow(self, yaml_text: str | None = None) -> None:
        self._reg.register_workflow(yaml_text or packaged_workflow_yaml())

    def close(self) -> None:
        self._reg.close()

    def create_issue(
        self,
        *,
        actor: Actor,
        work_item_type: str,
        custom_fields: dict | None = None,
    ) -> tuple[WorkItem, Event]:
        """Create a work item. ``on_behalf_of`` is intentionally not threaded:
        regista's ``create_work_item`` does not accept it (a regista-side
        limitation; agent-delegated creation is a future concern). Transitions
        and comments do thread ``on_behalf_of``.

        ``custom_fields`` must include ``title`` (required by the workflow v2)
        and typically includes ``description``, ``assignee``, and ``priority``.
        """
        return self._reg.create_work_item(
            workflow_name=WORKFLOW_NAME,
            work_item_type=work_item_type,
            actor_id=actor.actor_id,
            actor_kind=actor.actor_kind,
            actor_metadata=_metadata(actor),
            custom_fields=custom_fields,
        )

    def transition(
        self,
        *,
        actor: Actor,
        work_item_id: uuid.UUID,
        transition_name: str,
        payload: dict | None = None,
        custom_fields: dict | None = None,
    ) -> Event:
        return self._reg.transition(
            work_item_id,
            transition_name,
            actor.actor_id,
            actor_kind=actor.actor_kind,
            actor_metadata=_metadata(actor),
            payload=payload,
            custom_fields=custom_fields,
            on_behalf_of=actor.on_behalf_of,
        )

    def comment(
        self,
        *,
        actor: Actor,
        work_item_id: uuid.UUID,
        body: str,
    ) -> Event:
        return self._reg.append_event(
            work_item_id,
            actor.actor_id,
            actor_kind=actor.actor_kind,
            actor_metadata=_metadata(actor),
            transition="comment",
            payload={"body": body},
            on_behalf_of=actor.on_behalf_of,
        )

    def get_issue(self, work_item_id: uuid.UUID) -> WorkItem | None:
        return self._reg.get_work_item(work_item_id)

    def list_issues(
        self,
        *,
        current_states: list[str] | None = None,
        assignee: str | None = None,
        page_size: int = 100,
    ):
        field_filters = {"assignee": assignee} if assignee else None
        return self._reg.query_work_items(
            workflow_name=WORKFLOW_NAME,
            current_states=current_states,
            custom_field_filters=field_filters,
            page_size=page_size,
        )

    def history(self, work_item_id: uuid.UUID) -> list[Event]:
        return self._reg.read_events(work_item_id=work_item_id, limit=10_000)

    def integrity(self) -> ReplayReport:
        return self._reg.replay()
