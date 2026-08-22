"""Authoritative dossier delegation claims used by writes and event readers.

``on_behalf_of`` is dossier's signed application claim. Keeping it in the
application payload is a deliberate dossier contract choice: the claim is
selected from the server-resolved :class:`Actor`, so request payloads cannot
inject or override delegation semantics. This module does not make a claim
about which fields regista may carry in its own envelope.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

_DELEGATION_FIELD = "on_behalf_of"


def authoritative_payload(
    actor: Any,
    payload: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """Return *payload* with the actor's delegation claim as the sole source.

    A caller can neither inject a claim for an actor that has none nor override
    the claim carried by the authenticated actor. The input mapping is copied;
    gateway callers may safely reuse their request payload after this function.
    """
    actor_claim = getattr(actor, _DELEGATION_FIELD, None)
    result = dict(payload) if payload is not None else {}
    result.pop(_DELEGATION_FIELD, None)
    if isinstance(actor_claim, Mapping):
        result[_DELEGATION_FIELD] = dict(actor_claim)
    if payload is None and not result:
        return None
    return result


def event_delegation_claim(event: Any) -> dict[str, Any] | None:
    """Read a delegation claim from either legacy or v6 event representation.

    Legacy events may expose ``on_behalf_of`` directly. v6 events carry the
    dossier application claim in their payload. A valid direct field wins so a
    malformed/absent payload fallback cannot replace legacy event data.
    """
    direct = getattr(event, _DELEGATION_FIELD, None)
    if isinstance(direct, Mapping):
        return dict(direct)
    payload = getattr(event, "payload", None)
    if isinstance(payload, Mapping):
        nested = payload.get(_DELEGATION_FIELD)
        if isinstance(nested, Mapping):
            return dict(nested)
    return None


__all__ = ["authoritative_payload", "event_delegation_claim"]
