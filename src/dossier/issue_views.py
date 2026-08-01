from __future__ import annotations

from typing import Any

from fastapi import Request
from fastapi.templating import Jinja2Templates
from regista import WorkItem
from starlette.responses import Response

from .assurance import assurance_class, assurance_label, compute_assurance_verdict
from .gateway import RegistaGateway


def render_issue_detail(
    templates: Jinja2Templates,
    request: Request,
    gateway: RegistaGateway,
    issue: WorkItem,
    *,
    project_slug: str,
    context: dict[str, Any],
    transitions: list[tuple[str, str, bool]],
    error: str | None = None,
    signing_downgraded: str | None = None,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> Response:
    events = gateway.history(issue.work_item_id)
    integrity = gateway.integrity(work_item_id=issue.work_item_id)
    links = gateway.list_links(issue.work_item_id)
    event_verifications: dict[int, dict[str, Any]] = {}
    for index, event in enumerate(events):
        try:
            event_verifications[index] = gateway.verify_event(event)
        except Exception:
            event_verifications[index] = {
                "verified": False,
                "principal_id": None,
                "fingerprint": None,
                "scheme": None,
            }
    verdict = compute_assurance_verdict(events)
    assurance = verdict.level
    return templates.TemplateResponse(
        request,
        "issue_detail.html",
        {
            **context,
            "issue": issue,
            "events": events,
            "transitions": transitions,
            "integrity_drift": integrity.replayed_drift,
            "project_slug": project_slug,
            "links": links,
            "error": error,
            "event_verifications": event_verifications,
            "assurance_level": assurance,
            "assurance_label": assurance_label(assurance),
            "assurance_css": assurance_class(assurance),
            "assurance_verdict": verdict,
            "signing_downgraded": signing_downgraded,
        },
        status_code=status_code,
        headers=headers,
    )
