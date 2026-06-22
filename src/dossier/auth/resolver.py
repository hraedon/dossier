from __future__ import annotations

from ..actors import Actor
from .backends import Principal


def principal_to_actor(principal: Principal) -> Actor:
    """The G1 keystone: turn a verified principal into a regista Actor.

    This is the single point where an authenticated identity becomes the thing
    the gateway injects into every signed event. The actor is built only from
    the server-verified ``principal`` — there is no parameter here for client
    input. Humans never carry ``on_behalf_of``; agents do (post-MVP).
    """
    return Actor(
        actor_id=principal.stable_id,
        actor_kind="human",
        display_name=principal.display_name,
    )
