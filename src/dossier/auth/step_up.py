"""Step-up authentication infrastructure (Plan 020 Phase 3, non-Entra).

This module provides the foundation for step-up authentication: tracking when
a user authenticated, defining which operations require recent authentication,
and producing digest-bound step-up evidence.

For local/LDAP deployments, step-up is password re-entry. This is honest about
its assurance level: it proves the user knows the password *now*, but does not
prove MFA, device compliance, or risk context. High-risk features may require
Entra step-up or remain disabled.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final

DEFAULT_STEP_UP_MAX_AGE_SECONDS: Final[int] = 300  # 5 minutes


class ProtectedOperation(StrEnum):
    """Operations that require recent step-up authentication."""

    KEY_ENROLLMENT = "key_enrollment"
    KEY_ROTATION = "key_rotation"
    KEY_REVOCATION = "key_revocation"
    BREAK_GLASS = "break_glass"
    PROJECT_ACL_CHANGE = "project_acl_change"
    SECRET_REF_CHANGE = "secret_ref_change"
    EVIDENCE_DISCLOSURE = "evidence_disclosure"


PROTECTED_OPERATIONS: Final[frozenset[ProtectedOperation]] = frozenset(ProtectedOperation)


@dataclass(frozen=True)
class StepUpEvidence:
    """Digest-bound proof that the user recently authenticated.

    The evidence binds the authentication time to the exact operation digest,
    so evidence produced for one operation cannot authorize another.
    """

    auth_time: datetime
    operation_digest: str
    principal_id: str
    signature: str
    method: str = "password_reentry"

    def to_dict(self) -> dict[str, str]:
        return {
            "auth_time": self.auth_time.isoformat(),
            "operation_digest": self.operation_digest,
            "principal_id": self.principal_id,
            "signature": self.signature,
            "method": self.method,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> StepUpEvidence:
        return cls(
            auth_time=datetime.fromisoformat(data["auth_time"]),
            operation_digest=data["operation_digest"],
            principal_id=data["principal_id"],
            signature=data["signature"],
            method=data.get("method", "password_reentry"),
        )


def _step_up_key(session_secret: str) -> bytes:
    """Derive the step-up evidence key, domain-separated from session signing.

    The session cookie signer (itsdangerous) and this evidence HMAC must not
    share a raw key: a weakness in one construction must not yield the other.
    """
    return hmac.new(
        session_secret.encode("utf-8"),
        b"dossier.step-up-evidence.v1",
        hashlib.sha256,
    ).digest()


def compute_step_up_signature(
    session_secret: str,
    auth_time: datetime,
    operation_digest: str,
    principal_id: str,
) -> str:
    """Compute the HMAC signature for step-up evidence.

    The signature binds the auth_time, operation_digest, and principal_id
    using a domain-separated key derived from the session secret. The message
    is canonical JSON: no delimiter ambiguity regardless of field content.
    """
    message = json.dumps(
        {
            "auth_time": auth_time.isoformat(),
            "operation_digest": operation_digest,
            "principal_id": principal_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(_step_up_key(session_secret), message, hashlib.sha256).hexdigest()


def produce_step_up_evidence(
    session_secret: str,
    auth_time: datetime,
    operation_digest: str,
    principal_id: str,
    *,
    method: str = "password_reentry",
) -> StepUpEvidence:
    """Produce step-up evidence for a protected operation.

    Called after the user successfully re-authenticates (password re-entry
    for local/LDAP). The evidence is bound to the exact operation digest.
    """
    signature = compute_step_up_signature(
        session_secret,
        auth_time,
        operation_digest,
        principal_id,
    )
    return StepUpEvidence(
        auth_time=auth_time,
        operation_digest=operation_digest,
        principal_id=principal_id,
        signature=signature,
        method=method,
    )


def verify_step_up_evidence(
    session_secret: str,
    evidence: StepUpEvidence,
    expected_operation_digest: str,
    expected_principal_id: str,
    *,
    max_age_seconds: int = DEFAULT_STEP_UP_MAX_AGE_SECONDS,
) -> tuple[bool, str | None]:
    """Verify step-up evidence for a protected operation.

    Returns (valid, error_message). The evidence is valid if:
    - The signature matches (not forged)
    - The operation_digest matches (bound to this operation)
    - The principal_id matches (bound to this user)
    - The auth_time is within max_age_seconds (recent)
    """
    if not hmac.compare_digest(evidence.operation_digest, expected_operation_digest):
        return False, "step-up evidence is bound to a different operation"
    if not hmac.compare_digest(evidence.principal_id, expected_principal_id):
        return False, "step-up evidence is bound to a different principal"
    expected_sig = compute_step_up_signature(
        session_secret,
        evidence.auth_time,
        evidence.operation_digest,
        evidence.principal_id,
    )
    if not hmac.compare_digest(evidence.signature, expected_sig):
        return False, "step-up evidence signature is invalid"
    now = datetime.now(UTC)
    age = (now - evidence.auth_time).total_seconds()
    if age > max_age_seconds:
        return False, (f"step-up authentication is stale ({int(age)}s old, max {max_age_seconds}s)")
    if age < 0:
        return False, "step-up authentication time is in the future"
    return True, None


def is_auth_recent(
    auth_time: datetime | None,
    *,
    max_age_seconds: int = DEFAULT_STEP_UP_MAX_AGE_SECONDS,
) -> bool:
    """Check if the authentication time is within the step-up window."""
    if auth_time is None:
        return False
    now = datetime.now(UTC)
    age = (now - auth_time).total_seconds()
    return 0 <= age <= max_age_seconds


def requires_step_up(operation: str) -> bool:
    """Check if an operation type requires step-up authentication.

    Fails closed on an unrecognized operation label: a typo or a future
    unmapped operation is a loud error, never a silent "not protected".
    """
    return ProtectedOperation(operation) in PROTECTED_OPERATIONS
