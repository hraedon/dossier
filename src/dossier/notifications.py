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
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("dossier.notifications")

_IMMEDIATE_EVENTS = frozenset({
    "awaiting_your_accept",
    "review_requested",
    "item_returned",
    "chain_verify_failed",
})


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
    ) -> None:
        self._sink_url = sink_url or ""
        self._base_url = base_url.rstrip("/")
        self._signing_secret = signing_secret
        self._source = _safe_header_value(source, "source")
        self._sender_identity = _safe_header_value(
            sender_identity, "sender identity", allow_empty=True
        )

    @property
    def configured(self) -> bool:
        return bool(self._sink_url)

    def deep_link(self, project_slug: str, work_item_id: Any) -> str:
        return f"{self._base_url}/p/{project_slug}/issues/{work_item_id}"

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

        event = NotificationEvent(
            event_type=event_type,
            principal_id=principal,
            project=project_slug,
            item_id=str(work_item_id),
            item_key=item_key,
            item_title=item_title,
            deep_link=self.deep_link(project_slug, work_item_id),
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
