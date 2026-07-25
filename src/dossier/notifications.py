"""Notification emitting seam (Plan 018 Phase 2 / WI-2.1).

dossier decides *what* a human should hear about; agent-wake owns *how* it
reaches them (Plan 005 there). This module is the emitting side: it produces
structured notification events and posts them to a configurable webhook sink.

Principles:
- **Nudge, don't nag.** Immediate path for gate-blocking events
  (``awaiting_your_accept``); batched digests for routine updates.
- **Every notification deep-links to the exact page.** The ``deep_link``
  field carries a full URL to the issue detail page.
- **No sink configured = no error.** The emitter is a no-op when no sink
  URL is set; the health/doctor surface reports a ``warn`` so operators
  know notifications are not being delivered.
- **No SMTP code in dossier.** v1 ships a webhook emitter only.

Event classes (immediate vs digest routing is config, not code):
- ``awaiting_your_accept`` — immediate: an item needs a human accept
  (submitted for review under the strict gate, or adversarial review
  passed and the item is now in ``in_human_review``).
- ``review_requested`` — immediate: an item was submitted for review.
- ``item_returned`` — immediate: changes were requested (item sent back).
- ``chain_verify_failed`` — immediate: operator-scoped; integrity drift
  detected during replay (from Plan 017 WI-2.1's widget backend).
"""

from __future__ import annotations

import json
import hashlib
import hmac
import logging
import re
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

logger = logging.getLogger("dossier.notifications")

_IMMEDIATE_EVENTS = frozenset({
    "awaiting_your_accept",
    "review_requested",
    "item_returned",
    "chain_verify_failed",
})


@dataclass(frozen=True)
class EventClassInfo:
    """A notification-worthy event class, with its human description and the
    default delivery routing (immediate vs digest). Routing is overridable per
    principal via :class:`NotificationPreference`; the default lives here so the
    preference UI can render the policy default alongside the user's choice."""

    event_type: str
    label: str
    description: str
    default_routing: str = "immediate"


EVENT_CLASSES: tuple[EventClassInfo, ...] = (
    EventClassInfo(
        "awaiting_your_accept",
        "Awaiting your accept",
        "An item needs a human accept — submitted for review under the strict "
        "gate, or adversarial review passed and the item awaits your decision.",
    ),
    EventClassInfo(
        "review_requested",
        "Review requested",
        "An item was submitted for review and may need your attention.",
    ),
    EventClassInfo(
        "item_returned",
        "Item returned",
        "Changes were requested and an item was sent back to its author.",
    ),
    EventClassInfo(
        "chain_verify_failed",
        "Chain verification failed",
        "Operator-scoped: integrity drift was detected during replay. The deep "
        "link opens the integrity report (the recovery surface), not a work item.",
    ),
)

_EVENT_TYPES = frozenset(ec.event_type for ec in EVENT_CLASSES)
_ROUTING_VALUES = frozenset({"immediate", "digest"})


@dataclass(frozen=True, slots=True)
class NotificationPreference:
    """A principal's notification preferences: which event classes are enabled,
    and the per-class routing (immediate vs digest).

    These are *user configuration* over the emitter, not derived workflow state
    — so they are a small, legitimate config concern distinct from Plan 018's
    "views derive from the log" principle. The default for every class is
    *enabled* with the class's :attr:`EventClassInfo.default_routing`; a
    principal who opts out of a class simply disables it.
    """

    principal_id: str
    enabled: dict[str, bool] = field(default_factory=dict)
    routing: dict[str, str] = field(default_factory=dict)

    def is_enabled(self, event_type: str) -> bool:
        """Whether ``event_type`` should fire a notification for this principal.

        Unknown classes default to enabled (fail-open on delivery, never silent
        on a new event class the catalog has not taught the UI about yet).
        """
        return self.enabled.get(event_type, True)

    def routing_for(self, event_type: str) -> str:
        default = _default_routing(event_type)
        value = self.routing.get(event_type, default)
        if value not in _ROUTING_VALUES:
            return default
        return value


def _default_routing(event_type: str) -> str:
    for ec in EVENT_CLASSES:
        if ec.event_type == event_type:
            return ec.default_routing
    return "immediate"


def default_preference(principal_id: str) -> NotificationPreference:
    """The policy default preference: every known class enabled, each routed at
    its class default. A principal with no saved record gets this."""
    return NotificationPreference(
        principal_id=principal_id,
        enabled={ec.event_type: True for ec in EVENT_CLASSES},
        routing={ec.event_type: ec.default_routing for ec in EVENT_CLASSES},
    )


def _preference_from_dict(
    principal_id: str, data: dict[str, Any]
) -> NotificationPreference:
    """Reconstruct a preference from persisted JSON, merged over the defaults so
    a newly-added event class defaults on rather than disappearing."""
    base = default_preference(principal_id)
    raw_enabled = data.get("enabled") if isinstance(data, dict) else None
    raw_routing = data.get("routing") if isinstance(data, dict) else None
    enabled = dict(base.enabled)
    if isinstance(raw_enabled, dict):
        for key, val in raw_enabled.items():
            if key in _EVENT_TYPES:
                enabled[key] = bool(val)
    routing = dict(base.routing)
    if isinstance(raw_routing, dict):
        for key, val in raw_routing.items():
            if key in _EVENT_TYPES and val in _ROUTING_VALUES:
                routing[key] = val
    return NotificationPreference(
        principal_id=principal_id, enabled=enabled, routing=routing
    )


def _preference_to_dict(pref: NotificationPreference) -> dict[str, Any]:
    return {"enabled": dict(pref.enabled), "routing": dict(pref.routing)}


class NotificationPreferenceStore(Protocol):
    """Injectable per-principal notification preference store.

    v1 ships a file-backed store (one JSON file per principal) that is
    **instance-local** — correct for the single-primary v1 deployment target.
    A multi-replica deployment would diverge per instance; that consistency is
    the property the durable-notification layer (Plan 019) is scoped to own, so
    this interface is the seam a durable backend replaces without touching the
    routes or emitter.
    """

    def get(self, principal_id: str) -> NotificationPreference: ...

    def save(
        self, principal_id: str, preference: NotificationPreference
    ) -> None: ...


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_-]")


class FilePreferenceStore:
    """A :class:`NotificationPreferenceStore` backed by per-principal JSON files
    in ``state_dir``. Writes are atomic (tmp + replace). Reads of a missing or
    corrupt file return the :func:`default_preference` — a corrupt preference
    never blocks a notification."""

    def __init__(self, state_dir: Path | str) -> None:
        self._dir = Path(state_dir)
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            logger.warning(
                "notification.pref_store_unavailable", extra={"dir": str(self._dir)}
            )

    def _path(self, principal_id: str) -> Path:
        safe = _SAFE_NAME_RE.sub("_", principal_id) or "anonymous"
        return self._dir / f"{safe}.json"

    def get(self, principal_id: str) -> NotificationPreference:
        path = self._path(principal_id)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, FileNotFoundError):
            return default_preference(principal_id)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            logger.warning(
                "notification.pref_corrupt",
                extra={"principal_id": principal_id},
            )
            return default_preference(principal_id)
        if not isinstance(data, dict):
            return default_preference(principal_id)
        return _preference_from_dict(principal_id, data)

    def save(
        self, principal_id: str, preference: NotificationPreference
    ) -> None:
        path = self._path(principal_id)
        try:
            payload = json.dumps(
                _preference_to_dict(preference), sort_keys=True
            ).encode("utf-8")
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(payload)
            tmp.replace(path)
        except OSError:
            logger.warning(
                "notification.pref_save_failed",
                extra={"principal_id": principal_id},
            )


class MemoryPreferenceStore:
    """An in-process :class:`NotificationPreferenceStore` for tests."""

    def __init__(self) -> None:
        self._prefs: dict[str, NotificationPreference] = {}

    def get(self, principal_id: str) -> NotificationPreference:
        return self._prefs.get(principal_id, default_preference(principal_id))

    def save(
        self, principal_id: str, preference: NotificationPreference
    ) -> None:
        self._prefs[principal_id] = preference


@dataclass(frozen=True)
class NotificationEvent:
    """A structured notification event posted to the webhook sink.

    The ``event_type`` determines routing (immediate vs digest). The
    ``principal_id`` identifies who should be notified; the sink (wake's
    ingress) resolves this to a delivery channel. The ``deep_link`` is a
    full URL to the exact page the human should land on.
    """

    event_type: str
    principal_id: str
    project: str
    item_id: str
    item_key: str
    item_title: str
    deep_link: str
    timestamp: str
    detail: str | None = None
    event_id: str = ""

    @property
    def is_immediate(self) -> bool:
        return self.event_type in _IMMEDIATE_EVENTS

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class NotificationEmitter:
    """Posts notification events to a configurable webhook sink.

    The sink URL is set via ``DOSSIER_NOTIFICATION_SINK``. When unset, the
    emitter is a no-op (no error raised); the health check surfaces a
    ``warn`` so operators know notifications are not being delivered.

    The ``base_url`` is used to construct deep links. It defaults to
    ``http://localhost:8000`` for local dev; production sets
    ``DOSSIER_BASE_URL``.
    """

    def __init__(
        self,
        sink_url: str | None,
        base_url: str = "http://localhost:8000",
        *,
        signing_secret: bytes | None = None,
        source: str = "dossier",
        sender_identity: str = "",
        preference_store: NotificationPreferenceStore | None = None,
    ) -> None:
        self._sink_url = sink_url or ""
        self._base_url = base_url.rstrip("/")
        self._signing_secret = signing_secret
        self._source = _safe_header_value(source, "source")
        self._sender_identity = _safe_header_value(
            sender_identity, "sender identity", allow_empty=True
        )
        self._preference_store = preference_store

    @property
    def configured(self) -> bool:
        return bool(self._sink_url)

    def deep_link(self, project_slug: str, work_item_id: Any) -> str:
        return f"{self._base_url}/p/{project_slug}/issues/{work_item_id}"

    def deep_link_for(
        self, event_type: str, project_slug: str, work_item_id: Any
    ) -> str:
        """The deep link for an event class — the "review/recovery" link.

        Review-actionable events link to the exact work item page where the
        human can act. An integrity failure (``chain_verify_failed``) is
        operator-scoped and has no work item: it links to the integrity report
        (the recovery surface), not an issue.
        """
        if event_type == "chain_verify_failed":
            return f"{self._base_url}/evidence/integrity"
        return self.deep_link(project_slug, work_item_id)

    def emit(self, event: NotificationEvent) -> bool:
        """Post a single notification event to the sink.

        Returns ``True`` if the event was posted (or skipped because no
        sink is configured). Returns ``False`` if the POST failed — the
        caller continues regardless; a failed notification must not block
        a transition (the transition already succeeded via regista).
        """
        if not self._sink_url:
            return True

        headers = {"Content-Type": "application/json"}
        if self._signing_secret is None:
            # Backward-compatible generic webhook mode. This is intentionally
            # not described as agent-wake compatible: wake rejects unsigned
            # ingress, and doctor reports this posture as a warning.
            payload = json.dumps(event.to_dict()).encode("utf-8")
        else:
            envelope = self._wake_envelope(event)
            payload = json.dumps(
                envelope, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            signature = hmac.new(
                self._signing_secret, payload, hashlib.sha256
            ).hexdigest()
            headers.update({
                "X-AgentWake-Source": self._source,
                "X-AgentWake-Signature": f"sha256={signature}",
                "X-AgentWake-Event-Id": envelope["event_id"],
            })
            if self._sender_identity:
                headers["X-AgentWake-Identity"] = self._sender_identity
        req = urllib.request.Request(
            self._sink_url,
            data=payload,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()
            logger.info(
                "notification.emitted",
                extra={
                    "event_type": event.event_type,
                    "principal_id": event.principal_id,
                    "project": event.project,
                    "item_key": event.item_key,
                },
            )
            return True
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            logger.warning(
                "notification.emit_failed",
                extra={
                    "event_type": event.event_type,
                    "principal_id": event.principal_id,
                    "error": type(exc).__name__,
                },
            )
            return False

    def _wake_envelope(self, event: NotificationEvent) -> dict[str, Any]:
        event_id = event.event_id or str(uuid.uuid4())
        content = event.detail or f"{event.item_key}: {event.item_title}"
        return {
            "v": 0,
            "event_id": event_id,
            "source": self._source,
            "kind": event.event_type,
            "content": content,
            "wake": False,
            "meta": {
                "target": event.principal_id,
                "deep_link": event.deep_link,
                "project": event.project,
                "item_id": event.item_id,
                "item_key": event.item_key,
                "item_title": event.item_title,
                "notification": event.to_dict(),
            },
        }

    def emit_for_transition(
        self,
        *,
        transition_name: str,
        to_state: str,
        project_slug: str,
        work_item_id: Any,
        item_key: str,
        item_title: str,
        assignee: str,
        creator_id: str | None,
        on_behalf_principal: str | None,
    ) -> NotificationEvent | None:
        """Determine whether a transition is notification-worthy and emit.

        Returns the emitted :class:`NotificationEvent` (or ``None`` if the
        transition was not notification-worthy). The principal to notify is
        resolved as: the assignee (the reviewer who must act) if set, else the
        creator (the item owner who can route it), else the on_behalf principal
        (the human an acting agent represents). The on_behalf principal is the
        stakeholder, not the reviewer, so it is the last resort — an
        ``awaiting_your_accept`` addressed to the on_behalf principal would be
        wrong when a creator can route the item instead. In v1 (flat-open
        authz) any authenticated principal is an eligible reviewer; the sink
        handles routing.
        """
        principal = assignee or creator_id or on_behalf_principal or ""
        if not principal:
            return None

        event_type: str | None = None
        detail: str | None = None

        if transition_name == "submit_for_review":
            if to_state == "in_review":
                event_type = "awaiting_your_accept"
                detail = "item submitted for review — awaiting your accept"
            else:
                event_type = "review_requested"
                detail = "item submitted for review"
        elif transition_name == "adversarial_pass":
            event_type = "awaiting_your_accept"
            detail = "adversarial review passed — awaiting your human accept"
        elif transition_name in ("request_changes", "reject"):
            event_type = "item_returned"
            detail = "changes requested — item returned"

        if event_type is None:
            return None

        # Respect the resolved principal's preferences: a class they have
        # opted out of is suppressed before emission. A missing preference
        # record (the common case) defaults to enabled, so this never
        # silently drops a notification a principal has not configured away.
        if self._preference_store is not None:
            preference = self._preference_store.get(principal)
            if not preference.is_enabled(event_type):
                logger.info(
                    "notification.suppressed",
                    extra={
                        "event_type": event_type,
                        "principal_id": principal,
                        "project": project_slug,
                        "item_key": item_key,
                    },
                )
                return None

        event = NotificationEvent(
            event_type=event_type,
            principal_id=principal,
            project=project_slug,
            item_id=str(work_item_id),
            item_key=item_key,
            item_title=item_title,
            deep_link=self.deep_link_for(event_type, project_slug, work_item_id),
            timestamp=datetime.now(timezone.utc).isoformat(),
            detail=detail,
            event_id=str(uuid.uuid4()),
        )
        self.emit(event)
        return event


def notification_health_check(
    sink_url: str | None,
    secret_ref: str | None = None,
) -> dict[str, Any]:
    """Health-check entry for the notification sink (Plan 018 WI-2.1 AC).

    Returns a ``warn`` when no sink is configured or when the configured sink
    has no signing-secret ref. An authenticated sink posture is ``ok``; the
    caller separately resolves the ref. This is not a connectivity probe — the
    sink may be temporarily unreachable, and emission remains best-effort so a
    notification failure cannot roll back an already-signed transition.
    """
    if not sink_url:
        return {
            "name": "notification_sink",
            "status": "warn",
            "detail": "no sink configured (DOSSIER_NOTIFICATION_SINK) — notifications not delivered",
        }
    if not secret_ref:
        return {
            "name": "notification_sink",
            "status": "warn",
            "detail": (
                "sink configured without DOSSIER_NOTIFICATION_SECRET_REF "
                "(unsigned generic webhook; not agent-wake compatible)"
            ),
        }
    return {
        "name": "notification_sink",
        "status": "ok",
        "detail": "authenticated agent-wake sink configured",
    }


def _safe_header_value(value: str, label: str, *, allow_empty: bool = False) -> str:
    normalized = value.strip()
    if not normalized and not allow_empty:
        raise ValueError(f"notification {label} must not be empty")
    if "\r" in normalized or "\n" in normalized:
        raise ValueError(f"notification {label} contains invalid characters")
    return normalized
