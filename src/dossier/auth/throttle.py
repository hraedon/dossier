from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class _AttemptRecord:
    failures: int = 0
    first_failure: float = 0.0
    locked_until: float = 0.0


def _normalize_identifier(identifier: str) -> str:
    return identifier.strip().lower()


class LoginThrottler:
    """In-memory per-identifier login attempt throttler.

    Locks an identifier after ``max_failures`` failed attempts within a
    ``lockout_seconds`` window. MVP — per-process, not distributed.

    Throttling model and known gaps:

    - **Fixed-window, not sliding-window.** The failure counter resets when the
      window (``lockout_seconds``) elapses since ``first_failure``. Up to
      ``max_failures - 1`` failures can occur within every window without
      triggering a lockout (e.g. 4 failures per 300 s with the defaults).
    - **Per-identifier only.** Each distinct identifier (after normalization)
      has its own counter. Credential stuffing — rotating usernames against a
      shared password — is not mitigated; an attacker can make
      ``max_failures - 1`` attempts per identifier. Pair this with breach-list
      detection or a global rate limit in a reverse proxy for broad protection.
    - **Per-process.** The counter lives in this process's memory; it is not
      shared across workers or instances. In a multi-worker deployment each
      worker sees only its own fraction of attempts, so the effective limit is
      ``max_failures * worker_count``. For a hard ceiling, back the throttler
      with a shared store (Redis, regista-side accounting) before relying on it.
    """

    _MAX_RECORDS = 10000

    def __init__(self, max_failures: int = 5, lockout_seconds: int = 300) -> None:
        self._max_failures = max_failures
        self._lockout_seconds = lockout_seconds
        self._records: dict[str, _AttemptRecord] = {}

    def is_locked(self, identifier: str) -> bool:
        rec = self._records.get(identifier)
        if rec is None:
            return False
        return rec.locked_until > time.monotonic()

    def record_failure(self, identifier: str) -> None:
        now = time.monotonic()
        rec = self._records.get(identifier)
        if rec is None:
            if len(self._records) >= self._MAX_RECORDS:
                self.cleanup()
                if len(self._records) >= self._MAX_RECORDS:
                    self._evict_oldest()
            rec = _AttemptRecord(failures=1, first_failure=now, locked_until=0.0)
            self._records[identifier] = rec
            return
        if rec.locked_until > now:
            rec.locked_until = now + self._lockout_seconds
            return
        if now - rec.first_failure > self._lockout_seconds:
            rec.failures = 1
            rec.first_failure = now
            rec.locked_until = 0.0
            return
        rec.failures += 1
        if rec.failures >= self._max_failures:
            rec.locked_until = now + self._lockout_seconds

    def record_success(self, identifier: str) -> None:
        self._records.pop(identifier, None)

    def lockout_remaining(self, identifier: str) -> float:
        rec = self._records.get(identifier)
        if rec is None:
            return 0.0
        return max(0.0, rec.locked_until - time.monotonic())

    def cleanup(self) -> None:
        now = time.monotonic()
        expired = [
            key
            for key, rec in self._records.items()
            if rec.locked_until < now and rec.first_failure < now - self._lockout_seconds
        ]
        for key in expired:
            del self._records[key]

    def _evict_oldest(self) -> None:
        now = time.monotonic()
        oldest_key: str | None = None
        oldest_first: float | None = None
        for key, rec in self._records.items():
            if rec.locked_until > now:
                continue
            if oldest_first is None or rec.first_failure < oldest_first:
                oldest_first = rec.first_failure
                oldest_key = key
        if oldest_key is not None:
            del self._records[oldest_key]
