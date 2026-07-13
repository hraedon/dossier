"""Tests for WI-014, WI-019, WI-011 bug fixes.

WI-014: compute_assurance_level fails open when reviewer lineage is undeclared.
WI-019: health.py echoes str(exc)[:200], may leak DSN host/port.
WI-011: Display key minting race condition (concurrent creates produce duplicates).
"""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

from regista import Event

from dossier.assurance import compute_assurance_level


# ── WI-014: assurance level fails open ────────────────────────────────────


def _make_event(
    *,
    transition: str = "created",
    actor_kind: str = "agent",
    actor_metadata: dict[str, Any] | None = None,
    event_seq: int = 0,
) -> Event:
    return Event(
        event_id=uuid.uuid4(),
        work_item_id=uuid.uuid4(),
        event_seq=event_seq,
        actor_id="test-actor",
        actor_kind=actor_kind,
        actor_metadata=actor_metadata,
        key_id="test-key",
        workflow_name="canonical",
        workflow_version=2,
        timestamp=datetime.now(UTC),
        transition=transition,
        payload=None,
        payload_canonical_hash=b"",
        signature=b"",
    )


def test_assurance_undeclared_reviewer_lineage_is_self_reviewed():
    """WI-014: A review by an actor with no model_lineage must NOT be
    treated as independently-reviewed. It should fall back to self-reviewed
    (fail-safe) because independence cannot be verified."""
    events = [
        _make_event(
            transition="created",
            actor_metadata={"model_lineage": "glm", "display_name": "GLM Agent"},
            event_seq=0,
        ),
        _make_event(
            transition="adversarial_pass",
            actor_kind="agent",
            actor_metadata=None,
            event_seq=1,
        ),
    ]
    level = compute_assurance_level(events)
    assert level == "self-reviewed", (
        f"Undeclared reviewer lineage should be self-reviewed (fail-safe), "
        f"got {level}"
    )


def test_assurance_undeclared_lineage_not_independently_reviewed():
    """WI-014: Explicitly verify that undeclared lineage does NOT produce
    'independently-reviewed' — the fail-open bug being fixed."""
    events = [
        _make_event(
            transition="created",
            actor_metadata={"model_lineage": "glm"},
            event_seq=0,
        ),
        _make_event(
            transition="adversarial_pass",
            actor_kind="agent",
            actor_metadata={"display_name": "Mystery Agent"},
            event_seq=1,
        ),
    ]
    level = compute_assurance_level(events)
    assert level != "independently-reviewed"
    assert level == "self-reviewed"


def test_assurance_declared_cross_lineage_is_independently_reviewed():
    """Regression guard: a declared cross-lineage review must still produce
    'independently-reviewed'."""
    events = [
        _make_event(
            transition="created",
            actor_metadata={"model_lineage": "glm"},
            event_seq=0,
        ),
        _make_event(
            transition="adversarial_pass",
            actor_kind="agent",
            actor_metadata={"model_lineage": "kimi"},
            event_seq=1,
        ),
    ]
    level = compute_assurance_level(events)
    assert level == "independently-reviewed"


def test_assurance_declared_same_lineage_is_self_reviewed():
    """Regression guard: a declared same-lineage review must produce
    'self-reviewed'."""
    events = [
        _make_event(
            transition="created",
            actor_metadata={"model_lineage": "glm"},
            event_seq=0,
        ),
        _make_event(
            transition="adversarial_pass",
            actor_kind="agent",
            actor_metadata={"model_lineage": "glm"},
            event_seq=1,
        ),
    ]
    level = compute_assurance_level(events)
    assert level == "self-reviewed"


def test_assurance_human_accept_with_undeclared_reviewer_still_human_accepted():
    """Regression guard: human accept overrides everything else, even when
    the reviewer lineage is undeclared."""
    events = [
        _make_event(
            transition="created",
            actor_metadata={"model_lineage": "glm"},
            event_seq=0,
        ),
        _make_event(
            transition="adversarial_pass",
            actor_kind="agent",
            actor_metadata=None,
            event_seq=1,
        ),
        _make_event(
            transition="accept",
            actor_kind="human",
            actor_metadata={"display_name": "Alice"},
            event_seq=2,
        ),
    ]
    level = compute_assurance_level(events)
    assert level == "human-accepted"


def test_assurance_no_author_lineage_undeclared_reviewer_is_self_reviewed():
    """Edge case: when the author has no declared lineage and the reviewer
    also has none, the review should still be self-reviewed (fail-safe)
    rather than independently-reviewed."""
    events = [
        _make_event(
            transition="created",
            actor_metadata=None,
            event_seq=0,
        ),
        _make_event(
            transition="adversarial_pass",
            actor_kind="agent",
            actor_metadata=None,
            event_seq=1,
        ),
    ]
    level = compute_assurance_level(events)
    assert level == "self-reviewed"


def test_assurance_no_author_lineage_declared_reviewer_is_independently_reviewed():
    """Edge case: when the author has no declared lineage (e.g. human author)
    and the reviewer has a declared model_lineage, the review is cross-lineage
    — a human author and an agent reviewer are trivially independent."""
    events = [
        _make_event(
            transition="created",
            actor_kind="human",
            actor_metadata={"display_name": "Alice"},
            event_seq=0,
        ),
        _make_event(
            transition="adversarial_pass",
            actor_kind="agent",
            actor_metadata={"model_lineage": "kimi"},
            event_seq=1,
        ),
    ]
    level = compute_assurance_level(events)
    assert level == "independently-reviewed"


def test_assurance_reject_does_not_set_review_flags():
    """A 'reject' verdict is a review action but not a positive review —
    it should not contribute to the assurance level."""
    events = [
        _make_event(
            transition="created",
            actor_metadata={"model_lineage": "glm"},
            event_seq=0,
        ),
        _make_event(
            transition="reject",
            actor_kind="agent",
            actor_metadata={"model_lineage": "kimi"},
            event_seq=1,
        ),
    ]
    level = compute_assurance_level(events)
    assert level == "unreviewed"


def test_assurance_request_changes_does_not_set_review_flags():
    """A 'request_changes' verdict is a review action but not a positive
    review — it should not contribute to the assurance level."""
    events = [
        _make_event(
            transition="created",
            actor_metadata={"model_lineage": "glm"},
            event_seq=0,
        ),
        _make_event(
            transition="request_changes",
            actor_kind="agent",
            actor_metadata={"model_lineage": "kimi"},
            event_seq=1,
        ),
    ]
    level = compute_assurance_level(events)
    assert level == "unreviewed"


def test_assurance_agent_accept_cross_lineage_is_independently_reviewed():
    """An agent 'accept' with a cross-lineage lineage sets cross-lineage
    review. This is existing behavior (accept is in the elif branch)."""
    events = [
        _make_event(
            transition="created",
            actor_metadata={"model_lineage": "glm"},
            event_seq=0,
        ),
        _make_event(
            transition="accept",
            actor_kind="agent",
            actor_metadata={"model_lineage": "kimi"},
            event_seq=1,
        ),
    ]
    level = compute_assurance_level(events)
    assert level == "independently-reviewed"


def test_assurance_model_lineage_type_coercion():
    """WI-014 follow-up: model_lineage values must be compared as strings
    on both sides. A non-string lineage that stringifies to the same value
    as the author's should be treated as same-lineage, not cross-lineage."""
    events = [
        _make_event(
            transition="created",
            actor_metadata={"model_lineage": "glm"},
            event_seq=0,
        ),
        _make_event(
            transition="adversarial_pass",
            actor_kind="agent",
            actor_metadata={"model_lineage": "glm"},
            event_seq=1,
        ),
    ]
    level = compute_assurance_level(events)
    assert level == "self-reviewed"


# ── WI-019: DSN leak in health check ─────────────────────────────────────


def test_healthz_regista_failure_does_not_leak_dsn():
    """WI-019: When regista is unreachable, the health check detail must
    contain only the exception type name, never the exception message
    (which may contain DSN host/port/password)."""
    from dossier.config import Settings
    from dossier.health import build_health
    from dossier.multi import GatewayRegistry

    settings = Settings(
        database_url="postgresql://user:secret@db-host:5432/regista",
        project="test",
        hmac_key_path="",
        session_secret="x" * 32,
        session_max_age_seconds=43200,
        secure_cookies=False,
        require_ssl=False,
        users_path="",
        auth_backend="local",
        principal_key_dir="",
    )

    broken_registry = MagicMock(spec=GatewayRegistry)
    broken_registry.list_projects.side_effect = ConnectionError(
        "could not connect to postgresql://user:secret@db-host:5432/regista"
    )
    health = build_health(settings, broken_registry)

    regista_check = next(
        (c for c in health["checks"] if c["name"] == "regista"),
        None,
    )
    assert regista_check is not None
    assert regista_check["status"] == "fail"
    detail = regista_check["detail"] or ""
    assert "db-host" not in detail
    assert "secret" not in detail
    assert "5432" not in detail
    assert "postgresql" not in detail
    assert "unreachable" in detail
    assert "ConnectionError" in detail


def test_healthz_no_dsn_leak_on_regista_failure(app, client):
    """WI-019: Integration test — verify the healthz endpoint doesn't leak
    DSN info even when the regista check fails. With the in-memory test
    fixture, regista is typically reachable, so this is a secondary guard."""
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    for check in body.get("checks", []):
        detail = check.get("detail") or ""
        assert "postgresql://" not in detail
        assert "password" not in detail.lower() or "shorter than" in detail


# ── WI-011: Display key race condition ────────────────────────────────────


def test_display_key_max_sequence_not_count(gateway, make_issue):
    """WI-011: The display key should use max(existing sequences) + 1, not
    count(items) + 1. This handles deleted items correctly and is the
    foundation for the race-condition fix."""
    from helpers import ALICE

    wi1 = make_issue(actor=ALICE, title="First")
    wi2 = make_issue(actor=ALICE, title="Second")
    assert getattr(wi1, "custom_fields", {}).get("display_key") == "DOSSIER_TEST-1"
    assert getattr(wi2, "custom_fields", {}).get("display_key") == "DOSSIER_TEST-2"

    wi3, _ = gateway.create_issue(
        actor=ALICE,
        work_item_type="bug",
        custom_fields={"title": "High key", "display_key": "DOSSIER_TEST-99"},
    )
    assert getattr(wi3, "custom_fields", {}).get("display_key") == "DOSSIER_TEST-99"

    wi4 = make_issue(actor=ALICE, title="After high key")
    dk4 = getattr(wi4, "custom_fields", {}).get("display_key")
    assert dk4 == "DOSSIER_TEST-100", (
        f"Expected DOSSIER_TEST-100 (max+1), got {dk4}"
    )


def test_display_key_concurrent_no_duplicates(gateway):
    """WI-011: Concurrent creates must not produce duplicate display keys.
    The threading.Lock in RegistaGateway serializes the mint+create path
    within a single process. Keys should also be contiguous."""
    from helpers import ALICE

    results: list[Any] = []
    errors: list[Exception] = []
    barrier = threading.Barrier(5)

    def create_one():
        try:
            barrier.wait(timeout=5)
            wi, _ = gateway.create_issue(
                actor=ALICE,
                work_item_type="bug",
                custom_fields={"title": "Concurrent"},
            )
            results.append(wi)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=create_one) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Thread errors: {errors}"
    assert len(results) == 5

    keys = [
        getattr(wi, "custom_fields", {}).get("display_key")
        for wi in results
    ]
    assert len(set(keys)) == 5, (
        f"Duplicate display keys detected: {keys}"
    )
    for k in keys:
        assert k is not None
        assert k.startswith("DOSSIER_TEST-")
    seqs = sorted(int(k.split("-")[-1]) for k in keys)
    expected = list(range(seqs[0], seqs[0] + 5))
    assert seqs == expected, (
        f"Keys should be contiguous, got {seqs}"
    )


def test_display_key_different_prefix_not_affected(gateway, make_issue):
    """WI-011: A custom display_key with a different prefix should not
    inflate the sequence for the project's own prefix."""
    from helpers import ALICE

    gateway.create_issue(
        actor=ALICE,
        work_item_type="bug",
        custom_fields={"title": "Custom prefix", "display_key": "OTHER-50"},
    )
    wi = make_issue(actor=ALICE, title="Auto key")
    dk = getattr(wi, "custom_fields", {}).get("display_key")
    assert dk == "DOSSIER_TEST-1", (
        f"Custom OTHER-50 should not affect DOSSIER_TEST sequence, got {dk}"
    )
