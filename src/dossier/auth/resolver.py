from __future__ import annotations

from collections.abc import Sequence

from ..actors import Actor
from ..authz import encode_group_claim
from .backends import GroupIdentity, Principal


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

    **Which id the human signs under (WI-035).** When the identity records a
    regista ``principal_id``, that becomes the ``actor_id``; otherwise the
    ``stable_id`` is used as before. This is not a cosmetic choice — regista
    binds each signing key to a ``principal_id``, and both
    ``verify_principal_binding`` and the offline bundle verifier reject an event
    whose ``actor_id`` differs from its key's ``principal_id``
    ("actor-signer mismatch"). A human signing under an id no key is registered
    against therefore *cannot* carry a per-actor signature; regista silently
    falls back to the shared store HMAC key, which is the defect this closes.
    Binding also makes the human one actor across both faces: their CLI already
    acts as ``REGISTA_PRINCIPAL_ID``, and signing dossier events under the
    ``stable_id`` would split one person into two unlinkable actors in the log.

    The ``stable_id`` is kept as an authorization alias so an ACL or
    bootstrap-admin entry written against the pre-binding id still matches. It is
    never used for signing.
    """
    bound = principal.principal_id
    return Actor(
        actor_id=bound or principal.stable_id,
        actor_kind="human",
        display_name=principal.display_name,
        groups=_authorization_groups(principal, groups, group_claim_key),
        principal_id=bound,
        alias_actor_ids=(
            (principal.stable_id,)
            if bound and principal.stable_id and bound != principal.stable_id
            else ()
        ),
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
