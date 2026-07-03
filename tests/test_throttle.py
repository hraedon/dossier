from __future__ import annotations

import time

from dossier.auth.throttle import LoginThrottler


def test_lockout_after_max_failures():
    throttler = LoginThrottler(max_failures=5, lockout_seconds=300)
    for _ in range(5):
        throttler.record_failure("alice")
    assert throttler.is_locked("alice")


def test_is_locked_false_before_max_failures():
    throttler = LoginThrottler(max_failures=5, lockout_seconds=300)
    for _ in range(4):
        throttler.record_failure("alice")
    assert not throttler.is_locked("alice")


def test_lockout_expires():
    throttler = LoginThrottler(max_failures=5, lockout_seconds=0.1)
    for _ in range(5):
        throttler.record_failure("alice")
    assert throttler.is_locked("alice")
    time.sleep(0.15)
    assert not throttler.is_locked("alice")


def test_record_success_clears_record():
    throttler = LoginThrottler(max_failures=5, lockout_seconds=300)
    for _ in range(3):
        throttler.record_failure("alice")
    throttler.record_success("alice")
    assert "alice" not in throttler._records
    assert not throttler.is_locked("alice")


def test_lockout_remaining_decreases_over_time():
    throttler = LoginThrottler(max_failures=5, lockout_seconds=0.2)
    for _ in range(5):
        throttler.record_failure("alice")
    remaining = throttler.lockout_remaining("alice")
    assert remaining > 0
    time.sleep(0.12)
    remaining2 = throttler.lockout_remaining("alice")
    assert 0 < remaining2 < remaining
    time.sleep(0.12)
    assert throttler.lockout_remaining("alice") == 0


def test_sliding_window_resets():
    throttler = LoginThrottler(max_failures=5, lockout_seconds=0.1)
    for _ in range(4):
        throttler.record_failure("alice")
    assert not throttler.is_locked("alice")
    time.sleep(0.15)
    for _ in range(4):
        throttler.record_failure("alice")
    assert not throttler.is_locked("alice")


def test_max_records_cap_evicts_oldest():
    throttler = LoginThrottler(max_failures=5, lockout_seconds=300)
    throttler._MAX_RECORDS = 10
    for i in range(10):
        throttler.record_failure(f"user{i}")
    assert len(throttler._records) == 10
    assert "user0" in throttler._records
    throttler.record_failure("user10")
    assert len(throttler._records) == 10
    assert "user0" not in throttler._records
    assert "user10" in throttler._records


def test_cleanup_removes_expired_records():
    throttler = LoginThrottler(max_failures=5, lockout_seconds=0.1)
    for _ in range(5):
        throttler.record_failure("alice")
    throttler.record_failure("bob")
    assert "alice" in throttler._records
    assert "bob" in throttler._records
    time.sleep(0.15)
    throttler.cleanup()
    assert "alice" not in throttler._records
    assert "bob" not in throttler._records


def test_lockout_extends_on_repeated_failure():
    throttler = LoginThrottler(max_failures=3, lockout_seconds=0.3)
    for _ in range(3):
        throttler.record_failure("alice")
    assert throttler.is_locked("alice")
    remaining1 = throttler.lockout_remaining("alice")
    time.sleep(0.1)
    throttler.record_failure("alice")
    remaining2 = throttler.lockout_remaining("alice")
    assert remaining2 > remaining1 - 0.1


def test_evict_oldest_skips_locked():
    throttler = LoginThrottler(max_failures=2, lockout_seconds=300)
    throttler._MAX_RECORDS = 5
    for i in range(4):
        throttler.record_failure(f"user{i}")
    for _ in range(2):
        throttler.record_failure("locked_user")
    assert throttler.is_locked("locked_user")
    throttler.record_failure("user5")
    assert "locked_user" in throttler._records
    assert throttler.is_locked("locked_user")
