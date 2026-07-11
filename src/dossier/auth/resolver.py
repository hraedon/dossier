from __future__ import annotations

from ..actors import Actor
from collections.abc import Sequence

from .backends import GroupIdentity, Principal
from ..authz import encode_group_claim


def principal_to_actor(
    principal: Principal,
    groups: Sequence[GroupIdentity] | None = None,
    group_claim_key: bytes | None = None,
) -> Actor:
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
        groups=_authorization_groups(principal, groups, group_claim_key),
    )


def _authorization_groups(
    principal: Principal,
    groups: Sequence[GroupIdentity] | None = None,
    group_claim_key: bytes | None = None,
) -> tuple[str, ...]:
    """Reduce backend group objects to stable, non-DN authorization claims.

    LDAP groups use immutable object GUIDs. Local development groups have no
    directory GUID and use a case-folded name. Distinguished names are never
    placed in the signed session cookie because they are mutable and may reveal
    directory structure.
    """
    raw_groups: object = (
        groups if groups is not None else principal.raw_attributes.get("groups", [])
    )
    if not isinstance(raw_groups, (list, tuple)):
        return ()
    claims: set[str] = set()
    for group in raw_groups:
        if not isinstance(group, GroupIdentity):
            continue
        if group.guid:
            claims.add(f"guid:{group.guid.lower()}")
        elif group.name:
            claims.add(f"name:{group.name.casefold()}")
    if group_claim_key is not None:
        claims = {encode_group_claim(claim, group_claim_key) for claim in claims}
    return tuple(sorted(claims))
