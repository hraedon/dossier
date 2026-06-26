from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Actor:
    """A resolved, server-trusted actor. This is the root of provenance (G1).

    The authenticated principal becomes an Actor at exactly one point (auth);
    the gateway injects this Actor into every regista mutation. There is no
    path where client input constructs an Actor. agent actors carry
    ``on_behalf_of`` for delegation; human actors do not.

    ``model_lineage`` is the model family for agents (e.g. "glm", "kimi",
    "deepseek", "nemotron") and ``None`` for humans and the system actor. It is
    the family-level identifier the cross-lineage adversarial-review rule
    compares on: a reviewer who shares a model family with an author is a
    same-lineage review and must acknowledge it explicitly. Lineage is only
    meaningful for agents.
    """

    actor_id: str
    actor_kind: str
    display_name: str
    on_behalf_of: dict | None = None
    model_lineage: str | None = None


SYSTEM_ACTOR = Actor(
    actor_id="dossier-system",
    actor_kind="system",
    display_name="dossier system",
)
