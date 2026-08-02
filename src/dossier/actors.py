from __future__ import annotations

from dataclasses import dataclass
from typing import Any


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

    ``principal_id`` is the regista signing principal this identity is bound to
    (WI-035). When it is set, ``actor_id`` **is** that ``principal_id``: regista
    binds a signing key to a principal and both the live verifier and the
    offline bundle verifier reject any event whose ``actor_id`` differs from the
    signing key's ``principal_id`` ("actor-signer mismatch"). So a human can
    only carry a per-actor Ed25519 signature if the id they act under is the id
    their key is registered against. ``principal_id is None`` means the identity
    has no recorded regista principal and therefore no per-actor key —
    :mod:`dossier.signing` decides what happens then.

    ``alias_actor_ids`` carries identifiers this actor was previously known by
    — for a bound human, their auth-backend ``stable_id`` (the local uuid or the
    LDAP ``objectGUID``). Authorization matches on the union of ``actor_id`` and
    the aliases so an ACL, bootstrap-admin list, or owner record written against
    the pre-binding id keeps working after an operator binds a principal. It is
    an *authorization* alias only: it never appears in a signed event.
    """

    actor_id: str
    actor_kind: str
    display_name: str
    on_behalf_of: dict[str, Any] | None = None
    model_lineage: str | None = None
    groups: tuple[str, ...] = ()
    principal_id: str | None = None
    alias_actor_ids: tuple[str, ...] = ()

    @property
    def authorization_identities(self) -> tuple[str, ...]:
        """Identifiers this actor may be named by in an access policy.

        ``actor_id`` plus any ``alias_actor_ids``. Signing never uses this —
        only :meth:`AccessGrant.matches` and the bootstrap-admin grant do.
        """
        return (self.actor_id, *self.alias_actor_ids)


SYSTEM_ACTOR = Actor(
    actor_id="dossier-system",
    actor_kind="system",
    display_name="dossier system",
)
