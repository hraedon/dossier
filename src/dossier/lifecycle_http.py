from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Any, NoReturn, assert_never

from fastapi import HTTPException, Request, status
from regista import LifecycleContractError, LifecycleErrorCode
from regista.principal_lifecycle import (
    CustodyMode,
    EffectiveReceipt,
    EffectiveReceiptStatus,
    PossessionProof,
    PrincipalKind,
    ProofFormat,
)


def handle_lifecycle_error(exc: LifecycleContractError) -> NoReturn:
    raise HTTPException(http_status_for_lifecycle_error(exc.code), exc.message)


def http_status_for_lifecycle_error(code: LifecycleErrorCode) -> int:
    if code is LifecycleErrorCode.OPERATION_NOT_FOUND:
        return status.HTTP_404_NOT_FOUND
    if code is LifecycleErrorCode.APPROVAL_DIGEST_MISMATCH:
        return status.HTTP_400_BAD_REQUEST
    if code is LifecycleErrorCode.OPERATION_DIGEST_MISMATCH:
        return status.HTTP_400_BAD_REQUEST
    if code is LifecycleErrorCode.OPERATION_EXPIRED:
        return status.HTTP_400_BAD_REQUEST
    if code is LifecycleErrorCode.INVALID_OPERATION_STATE:
        return status.HTTP_409_CONFLICT
    if code is LifecycleErrorCode.DURABLE_OPERATION_REQUIRED:
        return status.HTTP_503_SERVICE_UNAVAILABLE
    if code is LifecycleErrorCode.INVALID_REQUEST:
        return status.HTTP_400_BAD_REQUEST
    if code is LifecycleErrorCode.UNSUPPORTED_SCHEME:
        return status.HTTP_400_BAD_REQUEST
    if code is LifecycleErrorCode.CHALLENGE_NOT_FOUND:
        return status.HTTP_400_BAD_REQUEST
    if code is LifecycleErrorCode.CHALLENGE_EXPIRED:
        return status.HTTP_400_BAD_REQUEST
    if code is LifecycleErrorCode.CHALLENGE_ALREADY_USED:
        return status.HTTP_400_BAD_REQUEST
    if code is LifecycleErrorCode.PROOF_BINDING_MISMATCH:
        return status.HTTP_400_BAD_REQUEST
    if code is LifecycleErrorCode.PROOF_VERIFICATION_FAILED:
        return status.HTTP_400_BAD_REQUEST
    if code is LifecycleErrorCode.OPERATION_ALREADY_COMMITTED:
        return status.HTTP_409_CONFLICT
    if code is LifecycleErrorCode.APPROVER_IS_ACTOR:
        return status.HTTP_400_BAD_REQUEST
    if code is LifecycleErrorCode.APPROVAL_EVIDENCE_REQUIRED:
        return status.HTTP_403_FORBIDDEN
    if code is LifecycleErrorCode.RECEIPT_OBSERVED_AT_INVALID:
        return status.HTTP_400_BAD_REQUEST
    if code is LifecycleErrorCode.AUTHORITY_REQUIRED:
        return status.HTTP_503_SERVICE_UNAVAILABLE
    if code is LifecycleErrorCode.AUTHORITY_MISMATCH:
        return status.HTTP_400_BAD_REQUEST
    assert_never(code)


def require_json_object(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "a JSON object body is required")
    return body


def require_str(body: dict[str, Any], field: str) -> str:
    value = body.get(field)
    if not isinstance(value, str) or not value:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{field} is required")
    return value


def optional_str(body: dict[str, Any], field: str) -> str | None:
    value = body.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{field} must be a string")
    return value


def decode_b64(raw: str, field: str) -> bytes:
    try:
        return base64.b64decode(raw, validate=True)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{field} must be base64")


def decode_public_key(raw: str) -> bytes:
    key = decode_b64(raw, "public_key")
    if len(key) != 32:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"public_key must decode to 32 bytes, got {len(key)}",
        )
    return key


def parse_possession_proof(body: dict[str, Any]) -> PossessionProof:
    raw_format = require_str(body, "format")
    try:
        proof_format = ProofFormat(raw_format)
    except ValueError:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"unsupported proof format {raw_format!r}",
        )
    return PossessionProof(
        format=proof_format,
        challenge_id=require_str(body, "challenge_id"),
        operation_id=require_str(body, "operation_id"),
        operation_digest=require_str(body, "operation_digest"),
        signature=decode_b64(require_str(body, "signature"), "signature"),
    )


async def read_json(request: Request) -> Any:
    try:
        return await request.json()
    except json.JSONDecodeError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "a JSON body is required")


def parse_principal_kind(body: dict[str, Any]) -> PrincipalKind:
    raw = optional_str(body, "principal_kind") or PrincipalKind.HUMAN.value
    try:
        return PrincipalKind(raw)
    except ValueError:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"unsupported principal_kind {raw!r}",
        )


def parse_custody_mode(body: dict[str, Any]) -> str:
    raw = optional_str(body, "custody_mode") or CustodyMode.FILE.value
    try:
        CustodyMode(raw)
    except ValueError:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"unsupported custody_mode {raw!r}",
        )
    return raw


def parse_effective_receipt(body: dict[str, Any]) -> EffectiveReceipt:
    status_raw = require_str(body, "status")
    try:
        receipt_status = EffectiveReceiptStatus(status_raw)
    except ValueError:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"unsupported receipt status {status_raw!r}",
        )
    observed_raw = require_str(body, "observed_at")
    try:
        observed_at = datetime.fromisoformat(observed_raw)
    except ValueError:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "observed_at must be an ISO-8601 timestamp",
        )
    if observed_at.tzinfo is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "observed_at must be timezone-aware",
        )
    signature_raw = optional_str(body, "signature")
    signature = decode_b64(signature_raw, "signature") if signature_raw else None
    return EffectiveReceipt(
        operation_id=require_str(body, "operation_id"),
        operation_digest=require_str(body, "operation_digest"),
        project=require_str(body, "project"),
        principal_id=require_str(body, "principal_id"),
        fingerprint=require_str(body, "fingerprint"),
        client_type=require_str(body, "client_type"),
        client_version=require_str(body, "client_version"),
        status=receipt_status,
        observed_at=observed_at,
        challenge_id=optional_str(body, "challenge_id"),
        signature=signature,
    )
