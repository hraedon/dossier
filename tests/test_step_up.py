"""Tests for step-up authentication infrastructure (Plan 020 Phase 3)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from dossier.auth.step_up import (
    DEFAULT_STEP_UP_MAX_AGE_SECONDS,
    PROTECTED_OPERATIONS,
    ProtectedOperation,
    StepUpEvidence,
    compute_step_up_signature,
    is_auth_recent,
    produce_step_up_evidence,
    requires_step_up,
    verify_step_up_evidence,
)

SECRET = "test-session-secret"
NOW = datetime.now(UTC)


class TestProtectedOperations:
    def test_all_operations_are_protected(self):
        assert len(PROTECTED_OPERATIONS) == len(ProtectedOperation)

    def test_requires_step_up(self):
        assert requires_step_up("key_enrollment") is True
        assert requires_step_up("key_rotation") is True
        assert requires_step_up("key_revocation") is True
        assert requires_step_up("break_glass") is True
        assert requires_step_up("project_acl_change") is True
        assert requires_step_up("secret_ref_change") is True
        assert requires_step_up("evidence_disclosure") is True

    def test_unknown_operation_fails_closed(self):
        # An unrecognized operation label is a loud error, never a silent
        # "not protected" — a typo must not disable step-up.
        with pytest.raises(ValueError):
            requires_step_up("unknown_operation")
        with pytest.raises(ValueError):
            requires_step_up("")


class TestStepUpSignature:
    def test_signature_deterministic(self):
        sig1 = compute_step_up_signature(SECRET, NOW, "digest1", "alice")
        sig2 = compute_step_up_signature(SECRET, NOW, "digest1", "alice")
        assert sig1 == sig2

    def test_signature_binds_to_digest(self):
        sig1 = compute_step_up_signature(SECRET, NOW, "digest1", "alice")
        sig2 = compute_step_up_signature(SECRET, NOW, "digest2", "alice")
        assert sig1 != sig2

    def test_signature_binds_to_principal(self):
        sig1 = compute_step_up_signature(SECRET, NOW, "digest1", "alice")
        sig2 = compute_step_up_signature(SECRET, NOW, "digest1", "bob")
        assert sig1 != sig2

    def test_signature_binds_to_auth_time(self):
        sig1 = compute_step_up_signature(SECRET, NOW, "digest1", "alice")
        later = NOW + timedelta(seconds=1)
        sig2 = compute_step_up_signature(SECRET, later, "digest1", "alice")
        assert sig1 != sig2

    def test_signature_binds_to_secret(self):
        sig1 = compute_step_up_signature(SECRET, NOW, "digest1", "alice")
        sig2 = compute_step_up_signature("other-secret", NOW, "digest1", "alice")
        assert sig1 != sig2


class TestProduceEvidence:
    def test_produce_evidence(self):
        evidence = produce_step_up_evidence(
            SECRET,
            NOW,
            "digest1",
            "alice",
        )
        assert evidence.auth_time == NOW
        assert evidence.operation_digest == "digest1"
        assert evidence.principal_id == "alice"
        assert evidence.method == "password_reentry"
        assert len(evidence.signature) == 64

    def test_produce_evidence_custom_method(self):
        evidence = produce_step_up_evidence(
            SECRET,
            NOW,
            "digest1",
            "alice",
            method="entra_mfa",
        )
        assert evidence.method == "entra_mfa"


class TestVerifyEvidence:
    def test_valid_evidence(self):
        evidence = produce_step_up_evidence(SECRET, NOW, "digest1", "alice")
        valid, error = verify_step_up_evidence(
            SECRET,
            evidence,
            "digest1",
            "alice",
        )
        assert valid is True
        assert error is None

    def test_wrong_digest(self):
        evidence = produce_step_up_evidence(SECRET, NOW, "digest1", "alice")
        valid, error = verify_step_up_evidence(
            SECRET,
            evidence,
            "digest2",
            "alice",
        )
        assert valid is False
        assert "different operation" in (error or "")

    def test_wrong_principal(self):
        evidence = produce_step_up_evidence(SECRET, NOW, "digest1", "alice")
        valid, error = verify_step_up_evidence(
            SECRET,
            evidence,
            "digest1",
            "bob",
        )
        assert valid is False
        assert "different principal" in (error or "")

    def test_forged_signature(self):
        evidence = StepUpEvidence(
            auth_time=NOW,
            operation_digest="digest1",
            principal_id="alice",
            signature="forged" * 8,
        )
        valid, error = verify_step_up_evidence(
            SECRET,
            evidence,
            "digest1",
            "alice",
        )
        assert valid is False
        assert "signature is invalid" in (error or "")

    def test_stale_evidence(self):
        old_time = NOW - timedelta(seconds=DEFAULT_STEP_UP_MAX_AGE_SECONDS + 10)
        evidence = produce_step_up_evidence(SECRET, old_time, "digest1", "alice")
        valid, error = verify_step_up_evidence(
            SECRET,
            evidence,
            "digest1",
            "alice",
        )
        assert valid is False
        assert "stale" in (error or "")

    def test_future_auth_time(self):
        future_time = datetime.now(UTC) + timedelta(seconds=60)
        evidence = produce_step_up_evidence(SECRET, future_time, "digest1", "alice")
        valid, error = verify_step_up_evidence(
            SECRET,
            evidence,
            "digest1",
            "alice",
        )
        assert valid is False
        assert "future" in (error or "")

    def test_custom_max_age(self):
        recent = datetime.now(UTC) - timedelta(seconds=3)
        evidence = produce_step_up_evidence(SECRET, recent, "digest1", "alice")
        valid, error = verify_step_up_evidence(
            SECRET,
            evidence,
            "digest1",
            "alice",
            max_age_seconds=2,
        )
        assert valid is False
        assert "stale" in (error or "")

        valid, error = verify_step_up_evidence(
            SECRET,
            evidence,
            "digest1",
            "alice",
            max_age_seconds=60,
        )
        assert valid is True


class TestIsAuthRecent:
    def test_none_auth_time(self):
        assert is_auth_recent(None) is False

    def test_recent_auth(self):
        assert is_auth_recent(NOW) is True

    def test_old_auth(self):
        old = NOW - timedelta(seconds=DEFAULT_STEP_UP_MAX_AGE_SECONDS + 10)
        assert is_auth_recent(old) is False

    def test_future_auth(self):
        future = datetime.now(UTC) + timedelta(seconds=60)
        assert is_auth_recent(future) is False

    def test_custom_max_age(self):
        recent = datetime.now(UTC) - timedelta(seconds=3)
        assert is_auth_recent(recent, max_age_seconds=2) is False
        assert is_auth_recent(recent, max_age_seconds=60) is True


class TestEvidenceSerialization:
    def test_round_trip(self):
        evidence = produce_step_up_evidence(SECRET, NOW, "digest1", "alice")
        data = evidence.to_dict()
        restored = StepUpEvidence.from_dict(data)
        assert restored.auth_time == evidence.auth_time
        assert restored.operation_digest == evidence.operation_digest
        assert restored.principal_id == evidence.principal_id
        assert restored.signature == evidence.signature
        assert restored.method == evidence.method


class TestDossierApprovalVerifier:
    """Unit tests for the regista ApprovalVerifier implementation."""

    def _make_verifier(self):
        from dossier.auth.step_up import DossierApprovalVerifier

        return DossierApprovalVerifier(SECRET)

    def _make_operation(self, digest_value: str = "digest1"):
        from types import SimpleNamespace

        return SimpleNamespace(digest=SimpleNamespace(value=digest_value))

    def _make_approval(self, approver_id: str = "alice", evidence_json: str | None = None):
        from types import SimpleNamespace

        return SimpleNamespace(approver_id=approver_id, step_up_evidence=evidence_json)

    def test_valid_evidence_returns_true(self):
        import json

        verifier = self._make_verifier()
        evidence = produce_step_up_evidence(SECRET, NOW, "digest1", "alice")
        approval = self._make_approval("alice", json.dumps(evidence.to_dict()))
        assert verifier.verify_approval(self._make_operation("digest1"), approval) is True

    def test_missing_evidence_returns_false(self):
        verifier = self._make_verifier()
        approval = self._make_approval("alice", None)
        assert verifier.verify_approval(self._make_operation(), approval) is False

    def test_empty_string_evidence_returns_false(self):
        verifier = self._make_verifier()
        approval = self._make_approval("alice", "")
        assert verifier.verify_approval(self._make_operation(), approval) is False

    def test_malformed_json_returns_false(self):
        verifier = self._make_verifier()
        approval = self._make_approval("alice", "not-json{{{")
        assert verifier.verify_approval(self._make_operation(), approval) is False

    def test_wrong_digest_returns_false(self):
        import json

        verifier = self._make_verifier()
        evidence = produce_step_up_evidence(SECRET, NOW, "digest1", "alice")
        approval = self._make_approval("alice", json.dumps(evidence.to_dict()))
        # Operation has a different digest.
        assert verifier.verify_approval(self._make_operation("digest2"), approval) is False

    def test_wrong_principal_returns_false(self):
        import json

        verifier = self._make_verifier()
        evidence = produce_step_up_evidence(SECRET, NOW, "digest1", "alice")
        # Approval claims bob, but evidence is bound to alice.
        approval = self._make_approval("bob", json.dumps(evidence.to_dict()))
        assert verifier.verify_approval(self._make_operation("digest1"), approval) is False

    def test_forged_signature_returns_false(self):
        import json

        verifier = self._make_verifier()
        evidence = produce_step_up_evidence(SECRET, NOW, "digest1", "alice")
        data = evidence.to_dict()
        data["signature"] = "forged" * 8
        approval = self._make_approval("alice", json.dumps(data))
        assert verifier.verify_approval(self._make_operation("digest1"), approval) is False

    def test_stale_evidence_returns_false(self):
        import json

        verifier = self._make_verifier()
        old_time = NOW - timedelta(seconds=DEFAULT_STEP_UP_MAX_AGE_SECONDS + 10)
        evidence = produce_step_up_evidence(SECRET, old_time, "digest1", "alice")
        approval = self._make_approval("alice", json.dumps(evidence.to_dict()))
        assert verifier.verify_approval(self._make_operation("digest1"), approval) is False

    def test_never_raises(self):
        """The verifier must never raise — any unexpected input returns False."""
        verifier = self._make_verifier()
        # Completely wrong types.
        assert verifier.verify_approval(None, None) is False  # type: ignore[arg-type]
        assert verifier.verify_approval(42, "string") is False  # type: ignore[arg-type]
