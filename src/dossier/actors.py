from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Actor:
    """A resolved, server-trusted actor. This is the root of provenance (G1).

    The authenticated principal becomes an Actor at exactly one point (auth);
    the gateway injects this Actor into every regista mutation. There is no
    path where client input constructs an Actor. agent actors carry
    ``on_behalf_of`` for delegation; human actors do not.
    """

    actor_id: str
    actor_kind: str
    display_name: str
    on_behalf_of: dict | None = None


SYSTEM_ACTOR = Actor(
    actor_id="dossier-system",
    actor_kind="system",
    display_name="dossier system",
)
