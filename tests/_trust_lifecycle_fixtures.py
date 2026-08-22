"""Small, self-contained trust-log fixtures for dossier's Postgres flows."""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import nacl.signing
import regista
from regista._trust_domain import (
    derive_core_digest,
    derive_governance_mode,
    derive_trust_domain_id,
    genesis_signature_input,
)
from regista._trust_log import REGISTRAR_DELEGATED, root_signature_input
from regista._trust_log_writer import append_trust_log_event, write_trust_genesis
from regista.testing import V6TestKeyset

TRUST_ROOT = "service:trust-root"
REGISTRAR = "human:alice"


def _timestamp(offset: timedelta = timedelta()) -> str:
    return (datetime.now(UTC) + offset).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _make_genesis(keyset: V6TestKeyset, project_instance_id: str) -> dict[str, Any]:
    root = keyset.key_for(TRUST_ROOT)
    binding_core = {
        "type": "regista.trust-genesis.core",
        "version": 1,
        "signers": [
            {
                "signer_id": TRUST_ROOT,
                "scheme_id": "ed25519",
                "public_key": root.public_key_b64,
                "fingerprint": root.fingerprint,
            }
        ],
        "created_at": _timestamp(),
        "nonce": uuid.uuid4().hex * 2,
    }
    core_digest = derive_core_digest(binding_core)
    document: dict[str, Any] = {
        "type": "regista.trust-genesis",
        "version": 1,
        "binding_core": binding_core,
        "initial_custody": [
            {
                "fingerprint": root.fingerprint,
                "declared_mode": "offline-host",
                "declared_holder": "human:test-owner",
                "attestation": None,
            }
        ],
        "initial_governance": {
            "mode": derive_governance_mode(1, 1),
            "threshold": 1,
            "signer_count": 1,
        },
        "trust_domain_core_digest": core_digest,
        "trust_domain_id": derive_trust_domain_id(core_digest),
        "trust_log": {
            "project_instance_id": project_instance_id,
            "project_name_hint": "trust-log-test",
            "initial_head_event_hash": None,
        },
        "publication": {
            "kind": "git",
            "url": "https://example.invalid/trust-attestations",
            "path": "trust-domain.json",
            "bootstrap": "direct-exchange",
        },
        "signatures": [],
        "countersignatures": [],
        "anchors": [],
    }
    signature = nacl.signing.SigningKey(root.seed).sign(
        genesis_signature_input(document)
    ).signature
    document["signatures"] = [
        {
            "signer_id": TRUST_ROOT,
            "fingerprint": root.fingerprint,
            "scheme_id": "ed25519",
            "signed_at": _timestamp(),
            "signature": base64.b64encode(signature).decode("ascii"),
        }
    ]
    return document


def provision_trust_log(
    dsn: str,
    work_project: str,
    keyset: V6TestKeyset,
    directory: Path,
    approval_verifier: Any | None = None,
) -> tuple[regista.Regista, Path]:
    """Create an estate trust-log schema with Alice as a live registrar."""

    trust_project = f"{work_project}_trust"
    trust_reg = regista.Regista.create_project(
        dsn,
        trust_project,
        hmac_key_path=keyset.path,
    )
    genesis = _make_genesis(keyset, str(uuid.uuid4()))
    genesis_path = directory / f"{trust_project}-genesis.json"
    genesis_path.write_text(json.dumps(genesis, indent=2), encoding="utf-8")
    genesis_path.chmod(0o600)
    write_trust_genesis(
        trust_reg._mgr,
        keys=trust_reg._keys,
        genesis_document=genesis,
        root_principal_id=TRUST_ROOT,
    )

    root = keyset.key_for(TRUST_ROOT)
    registrar = keyset.key_for(REGISTRAR)
    now = datetime.now(UTC)
    delegation: dict[str, Any] = {
        "type": "regista.registrar-delegation",
        "version": 1,
        "trust_domain_id": genesis["trust_domain_id"],
        "registrar_principal_id": REGISTRAR,
        "key_id": registrar.key_id,
        "scheme_id": "ed25519",
        "public_key": registrar.public_key_b64,
        "fingerprint": registrar.fingerprint,
        "scopes": [
            "principal_key_enrolled",
            "principal_key_rotated",
            "principal_key_revoked",
        ],
        "not_before": (now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "not_after": (now + timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "max_operations": None,
        "root_signatures": [],
    }
    delegation_signature = nacl.signing.SigningKey(root.seed).sign(
        root_signature_input(delegation)
    ).signature
    delegation["root_signatures"] = [
        {
            "signer_id": TRUST_ROOT,
            "fingerprint": root.fingerprint,
            "signature": base64.b64encode(delegation_signature).decode("ascii"),
        }
    ]
    append_trust_log_event(
        trust_reg._mgr,
        keys=trust_reg._keys,
        genesis_document=genesis,
        transition=REGISTRAR_DELEGATED,
        payload=delegation,
        entity_kind="principal",
        entity_id=uuid.uuid5(uuid.NAMESPACE_OID, "regista.principal:" + REGISTRAR),
        principal_id=TRUST_ROOT,
        authority="root",
        key_id=root.key_id,
    )
    trust_reg.close()
    return (
        regista.Regista(
            dsn,
            trust_project,
            hmac_key_path=keyset.path,
            approval_verifier=approval_verifier,
            trust_genesis_path=str(genesis_path),
        ),
        genesis_path,
    )
