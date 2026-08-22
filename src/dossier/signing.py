"""Per-actor signing policy for human events (WI-035).

A human's acceptance is the one signature in the chain that represents human
judgement, so it is the one signature that must not be producible by anybody
else. regista binds each Ed25519 signing key to a ``principal_id`` and both the
live verifier and the offline bundle verifier refuse any event whose
``actor_id`` differs from its key's ``principal_id``. When dossier hands regista
an ``actor_id`` that has no registered key, ``KeySet.resolve_signing_key`` falls
back to ``active_key()`` — the *store-level* HMAC key that every actor and the
server share. The event is still sealed into the chain, so nothing looks broken;
the record just stops attributing anything to anyone. ``regista verify`` reports
it as ``unverifiable (symmetric scheme)``.

That downgrade — Ed25519 non-repudiation to a shared symmetric secret — is the
one this module refuses to let happen quietly. It provides:

* :func:`resolve_signing_identity` — can this actor be signed for per-actor, and
  under which key?
* :class:`HumanSigningPolicy` — ``require`` (refuse the write) or ``warn``
  (attempt the legacy symmetric fallback, loudly, where the backend still
  supports it). Clean v6 epochs reject that fallback and dossier translates
  the rejection into the same actionable refusal.
* :exc:`HumanSigningRefusedError` — an operator-actionable refusal naming the exact
  provisioning command.

The gateway is the only caller: it is the single place dossier mutates
work-state, so it is the only place the policy can be applied without leaving a
bypass.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal, Protocol

from .actors import Actor

logger = logging.getLogger("dossier.signing")

HumanSigningPolicy = Literal["require", "warn"]


class HumanSigningOutcome(StrEnum):
    """Outcome stages for a human signing decision.

    ``FALLBACK_ATTEMPTED`` is emitted before the gateway calls regista. It is
    deliberately distinct from ``FALLBACK_WRITTEN`` because clean v6 may reject
    the shared-key fallback. ``FALLBACK_REFUSED`` means no event was appended.
    """

    PER_ACTOR = "per_actor"
    FALLBACK_ATTEMPTED = "fallback_attempted"
    FALLBACK_WRITTEN = "fallback_written"
    FALLBACK_REFUSED = "fallback_refused"

#: Schemes that carry non-repudiation: the signer holds a private key nobody
#: else has, and a third party can verify with only the public half. Mirrors
#: regista's ``asymmetric_scheme_ids()`` but is resolved from regista at call
#: time so a new PQC scheme registered there is honoured here too.
_FALLBACK_ASYMMETRIC_SCHEMES = frozenset({"ed25519"})

#: The provisioning command an operator runs to close the gap. Kept as one
#: string so the refusal message, the doctor detail, and the docs cannot drift.
PROVISION_HINT = (
    "provision a per-actor signing key: "
    "`agent-suite bootstrap --user <principal_id>` (or "
    "`regista provision-principal --principal <principal_id>`), then record "
    "that principal_id on the dossier identity — a `principal_id` field on the "
    "user's entry in DOSSIER_USERS_PATH for the local backend, or the "
    "DOSSIER_LDAP_PRINCIPAL_ID_ATTR attribute for the LDAP backend"
)


def asymmetric_schemes() -> frozenset[str]:
    """Signing schemes that bind an event to a key only the actor holds."""
    try:
        from regista._signing_scheme import asymmetric_scheme_ids

        ids = frozenset(asymmetric_scheme_ids())
    except Exception:  # pragma: no cover - regista always ships this today
        return _FALLBACK_ASYMMETRIC_SCHEMES
    return ids or _FALLBACK_ASYMMETRIC_SCHEMES


class _KeyExporter(Protocol):
    def export_public_keys(self) -> list[dict[str, Any]]: ...


@dataclass(frozen=True, slots=True)
class SigningIdentity:
    """Whether *actor_id* can be signed for with a key only that actor holds.

    ``key_id`` is the key the write should be pinned to. It is ``None`` when no
    active asymmetric key is bound to this ``actor_id``, in which case
    ``reason`` says why in operator language.
    """

    actor_id: str
    key_id: str | None = None
    scheme: str | None = None
    fingerprint: str | None = None
    reason: str | None = None

    @property
    def per_actor(self) -> bool:
        """True when a per-actor asymmetric key is available for this actor."""
        return self.key_id is not None


@dataclass(frozen=True, slots=True)
class HumanSigningResult:
    """A signing decision plus the outcome stage known so far."""

    identity: SigningIdentity
    outcome: HumanSigningOutcome


class HumanSigningRefusedError(Exception):
    """A human write was refused because it could only be signed symmetrically.

    Raised when a human write cannot be attributed to an active asymmetric key.
    The message is written for the operator who has to fix it, not for the end
    user: it names the identity, says what is missing, and gives the provisioning
    command. Nothing has been written to the event log when this is raised — the
    check runs before the regista call or translates a clean-v6 refusal.
    """

    def __init__(self, actor: Actor, identity: SigningIdentity) -> None:
        self.actor = actor
        self.identity = identity
        self.outcome = HumanSigningOutcome.FALLBACK_REFUSED
        if actor.principal_id is None:
            missing = (
                f"identity {actor.actor_id!r} has no regista principal_id recorded, "
                f"so no per-actor signing key can be found for it"
            )
        else:
            missing = (
                f"principal {actor.principal_id!r} has no active per-actor "
                f"asymmetric signing key registered"
            )
        self.remediation = PROVISION_HINT
        super().__init__(
            f"refusing to record a {actor.actor_kind} action for "
            f"{actor.display_name!r}: {missing}. Signing it with the shared "
            f"store key would produce a symmetric signature that anyone "
            f"holding that key could forge, so the action is not recorded. "
            f"To fix: {self.remediation}."
        )

    @property
    def detail(self) -> dict[str, Any]:
        """Machine-readable body for an API response."""
        return {
            "error": "human_signing_required",
            "message": str(self),
            "actor_id": self.actor.actor_id,
            "principal_id": self.actor.principal_id,
            "remediation": self.remediation,
        }


def resolve_signing_identity(exporter: _KeyExporter, actor: Actor) -> SigningIdentity:
    """Find the active per-actor asymmetric key bound to *actor*, if any.

    Reads regista's ``export_public_keys()`` — the *loaded signing key-set*,
    not the principal registry. That distinction matters: a row in
    ``principal_keys`` proves a key was registered, while presence in the
    key-set proves this process can actually sign with it (the key-set resolves
    every ``secret_ref`` at load). A pre-flight that consulted the registry
    would pass and the signature would still come out symmetric.
    """
    if not actor.actor_id:
        return SigningIdentity(actor_id="", reason="actor has no actor_id")
    if actor.principal_id is None:
        return SigningIdentity(
            actor_id=actor.actor_id,
            reason="no regista principal_id is recorded for this identity",
        )
    try:
        keys = exporter.export_public_keys()
    except Exception:
        logger.debug("signing: export_public_keys failed", exc_info=True)
        return SigningIdentity(
            actor_id=actor.actor_id,
            reason="the signing key-set could not be read",
        )

    asym = asymmetric_schemes()
    candidates = [
        k
        for k in keys
        if k.get("principal_id") == actor.actor_id
        and k.get("status") == "active"
        and str(k.get("scheme")) in asym
    ]
    if not candidates:
        revoked = any(
            k.get("principal_id") == actor.actor_id and k.get("status") == "revoked"
            for k in keys
        )
        return SigningIdentity(
            actor_id=actor.actor_id,
            reason=(
                "every registered key for this principal is revoked"
                if revoked
                else "no active asymmetric key is bound to this principal in the "
                "signing key-set"
            ),
        )
    # Last wins, matching regista's own ``_latest_active_key_for`` preference,
    # so a freshly rotated key is used rather than its predecessor.
    chosen = candidates[-1]
    return SigningIdentity(
        actor_id=actor.actor_id,
        key_id=str(chosen["key_id"]),
        scheme=str(chosen.get("scheme")),
        fingerprint=(str(chosen["fingerprint"]) if chosen.get("fingerprint") else None),
    )


def assess(
    exporter: _KeyExporter,
    actor: Actor,
    *,
    policy: HumanSigningPolicy,
    operation: str,
) -> HumanSigningResult:
    """Apply *policy* and report the signing outcome stage.

    Under ``require`` an unbound identity raises :exc:`HumanSigningRefusedError`
    before anything is written. Under ``warn`` the gateway is allowed to try the
    write, but the result is not known until regista returns.
    """
    identity = resolve_signing_identity(exporter, actor)
    if identity.per_actor:
        return HumanSigningResult(identity, HumanSigningOutcome.PER_ACTOR)
    if policy == "require":
        raise HumanSigningRefusedError(actor, identity)
    logger.warning(
        "provenance.human_signature_fallback_attempted",
        extra={
            "actor_id": actor.actor_id,
            "actor_kind": actor.actor_kind,
            "principal_id": actor.principal_id,
            "operation": operation,
            "reason": identity.reason,
            "outcome": HumanSigningOutcome.FALLBACK_ATTEMPTED.value,
            "consequence": (
                "write outcome is not known; a legacy backend may write a shared-"
                "key event, while clean v6 may refuse the fallback"
            ),
            "remediation": PROVISION_HINT,
        },
    )
    return HumanSigningResult(identity, HumanSigningOutcome.FALLBACK_ATTEMPTED)


def enforce(
    exporter: _KeyExporter,
    actor: Actor,
    *,
    policy: HumanSigningPolicy,
    operation: str,
) -> SigningIdentity:
    """Compatibility wrapper returning the selected signing identity."""
    return assess(exporter, actor, policy=policy, operation=operation).identity


def log_human_signing_fallback_written(
    actor: Actor,
    identity: SigningIdentity,
    operation: str,
) -> None:
    """Record that a warn-policy shared-key event was actually appended."""
    logger.warning(
        "provenance.human_signature_fallback_written",
        extra={
            "actor_id": actor.actor_id,
            "actor_kind": actor.actor_kind,
            "principal_id": actor.principal_id,
            "operation": operation,
            "key_id": identity.key_id,
            "outcome": HumanSigningOutcome.FALLBACK_WRITTEN.value,
            "consequence": (
                "event was written with the shared store key; the signature is "
                "symmetric and cannot attribute this action to this human"
            ),
            "remediation": PROVISION_HINT,
        },
    )


def log_human_signing_fallback_refused(
    actor: Actor,
    identity: SigningIdentity,
    operation: str,
) -> None:
    """Record that clean v6 rejected the attempted shared-key fallback."""
    logger.warning(
        "provenance.human_signature_fallback_refused",
        extra={
            "actor_id": actor.actor_id,
            "actor_kind": actor.actor_kind,
            "principal_id": actor.principal_id,
            "operation": operation,
            "key_id": identity.key_id,
            "outcome": HumanSigningOutcome.FALLBACK_REFUSED.value,
            "consequence": (
                "no event was written; clean v6 refused the shared-key fallback"
            ),
            "remediation": PROVISION_HINT,
        },
    )


def parse_policy(raw: str, *, prod: bool) -> HumanSigningPolicy:
    """Parse ``DOSSIER_HUMAN_SIGNING``; default ``require`` in prod.

    An empty value means "not chosen", which resolves to ``require`` for a
    production posture and ``warn`` otherwise. A dev box with only a store HMAC
    key stays usable; a production deployment fails closed unless the operator
    explicitly asks for the downgrade.
    """
    value = (raw or "").strip().lower()
    if not value:
        return "require" if prod else "warn"
    if value in ("require", "warn"):
        return value  # type: ignore[return-value]
    raise ValueError(
        f"DOSSIER_HUMAN_SIGNING must be 'require' or 'warn', got {raw!r}"
    )
