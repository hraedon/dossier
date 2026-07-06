from __future__ import annotations

import logging
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.templating import Jinja2Templates
from regista import RegistaError, WorkItem
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.staticfiles import StaticFiles

from .actors import Actor
from .assurance import (
    assurance_class,
    assurance_label,
    compute_assurance_level,
)
from .auth.backends import CredentialBackend, Principal
from .auth.resolver import principal_to_actor
from .auth.sessions import issue_csrf_token, session_middleware, verify_csrf
from .auth.throttle import LoginThrottler, _normalize_identifier
from .authz import can_read_project
from .config import Settings
from .gateway import RegistaGateway, packaged_workflow_version
from .keys import PrincipalKeyManager, _validate_principal_id
from .multi import GatewayRegistry, project_to_slug, slug_to_project
from .secrets import is_backend_ref
from . import web

logger = logging.getLogger("dossier.app")

_ACTOR_SESSION_KEY = "actor"
_STATIC_DIR = Path(__file__).parent / "static"
_TEMPLATE_DIR = Path(__file__).parent / "templates"

_OPEN_STATES = ["open", "in_progress", "blocked", "deferred", "in_review", "in_human_review"]


def _is_form_request(request: Request) -> bool:
    ct = request.headers.get("content-type", "")
    return "application/x-www-form-urlencoded" in ct


def _wants_html(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "text/html" in accept


class LoginRequired(Exception):
    """Raised by HTML-route dependencies when no authenticated actor is present.

    FastAPI renders ``HTTPException(302)`` as a JSON body (``{"detail": ...}``),
    which a browser user sees as raw text. This custom exception is caught by a
    registered handler that emits a clean ``RedirectResponse`` to ``/login``.
    """


_ADMIN_ACTOR_IDS: set[str] = set()


def _is_admin(actor: Actor) -> bool:
    """v1 admin check: any actor whose ID is in the configured admin set.

    The admin set is populated from the ``DOSSIER_ADMIN_IDS`` env var
    (comma-separated). In v1, this is a simple allowlist — v1.1/v1.5 will
    integrate with the project catalog's team/role mapping.
    """
    return actor.actor_id in _ADMIN_ACTOR_IDS


def _configure_admin_ids() -> None:
    """Load admin IDs from the DOSSIER_ADMIN_IDS env var."""
    import os

    raw = os.environ.get("DOSSIER_ADMIN_IDS", "")
    ids = {s.strip() for s in raw.split(",") if s.strip()}
    _ADMIN_ACTOR_IDS.clear()
    _ADMIN_ACTOR_IDS.update(ids)


async def _credential_login(
    request: Request, backend: CredentialBackend
) -> tuple[Principal | None, bool]:
    """Extract credentials from the request and verify them via ``backend``.

    This isolates the credential-in-hand assumption — a password arrives at
    ``/login`` and is verified synchronously — so a future federated
    ``/auth/callback`` route (Entra/OIDC) is a sibling that never edits this
    path. Returns ``(principal, is_form_request)``.
    """
    form_req = _is_form_request(request)
    if form_req:
        form = await request.form()
        username = str(form.get("username", ""))
        password = str(form.get("password", ""))
    else:
        try:
            payload = await request.json()
        except Exception:
            return None, form_req
        if not isinstance(payload, dict):
            return None, form_req
        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))

    principal = backend.authenticate(username, password)
    return principal, form_req


def create_app(
    settings: Settings,
    registry: GatewayRegistry,
    backend: CredentialBackend,
) -> FastAPI:
    """Build the FastAPI app with session auth wired to ``registry`` and ``backend``.

    The actor is resolved server-side at login and stored in the signed session
    as a plain dict; ``current_actor`` reconstructs the :class:`Actor` from that
    dict on each request. The session cookie is signed (itsdangerous) so the
    client cannot tamper with ``actor_id`` / ``actor_kind``. Display-name changes
    in the backend require re-login; the ``actor_id`` (the provenance-critical
    part) is stable and immutable. This is the G1 invariant
    (``docs/provenance-model.md``).
    """
    _configure_admin_ids()
    app = FastAPI(title="dossier")
    app.state.settings = settings
    app.state.registry = registry
    app.state.backend = backend
    key_manifest_path = settings.hmac_key_path
    if key_manifest_path and is_backend_ref(key_manifest_path):
        if key_manifest_path.lower().startswith("file:"):
            key_manifest_path = key_manifest_path.split(":", 1)[1]
        else:
            key_manifest_path = ""
    key_mgr = PrincipalKeyManager(
        settings.principal_key_dir or None,
        key_manifest_path=key_manifest_path or None,
    )
    app.state.key_manager = key_mgr

    def _actor_key_custody_ready() -> bool:
        hmac_path = settings.hmac_key_path
        if not hmac_path:
            return True
        if is_backend_ref(hmac_path) and not hmac_path.lower().startswith("file:"):
            return False
        return True

    _rotation_throttle: dict[str, float] = {}
    _rotation_cooldown_seconds = 60.0

    def _rotation_allowed(actor_id: str) -> bool:
        import time

        last = _rotation_throttle.get(actor_id)
        if last is None:
            return True
        return (time.monotonic() - last) >= _rotation_cooldown_seconds

    def _record_rotation(actor_id: str) -> None:
        import time

        _rotation_throttle[actor_id] = time.monotonic()

    throttler = LoginThrottler()

    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))
    templates.env.globals.update(
        transition_label=web.transition_label,
        actor_display=web.actor_display,
        on_behalf_display=web.on_behalf_display,
        event_verdict=web.event_verdict,
        is_same_lineage_acknowledged=web.is_same_lineage_acknowledged,
        format_timestamp=web.format_timestamp,
        status_pill_class=web.status_pill_class,
        issue_title=web.issue_title,
        issue_field=web.issue_field,
        display_key=web.display_key,
        last_event_time=web.last_event_time,
        kind_badge=web.kind_badge,
        project_to_slug=project_to_slug,
        link_target_url=web.link_target_url,
        link_target_label=web.link_target_label,
        is_cross_project_link=web.is_cross_project_link,
        owner_display=web.owner_display,
        project_display_name=web.project_display_name,
        state_description=web.state_description,
    )
    app.state.templates = templates

    app.add_middleware(session_middleware(settings))  # type: ignore[arg-type]

    @app.exception_handler(LoginRequired)
    async def _login_required_handler(request: Request, exc: LoginRequired) -> RedirectResponse:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    def current_actor(request: Request) -> Actor:
        data = request.session.get(_ACTOR_SESSION_KEY)
        if not isinstance(data, dict):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")
        try:
            return Actor(**data)
        except TypeError:
            request.session.clear()
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "session invalid; please re-authenticate"
            )

    def current_actor_or_redirect(request: Request) -> Actor:
        data = request.session.get(_ACTOR_SESSION_KEY)
        if not isinstance(data, dict):
            raise LoginRequired()
        try:
            return Actor(**data)
        except TypeError:
            request.session.clear()
            raise LoginRequired()

    def actor_context(request: Request, actor: Actor) -> dict[str, Any]:
        return {
            "actor": actor,
            "csrf_token": issue_csrf_token(request.session),
            "projects": [p for p in registry.list_projects() if can_read_project(actor, p)],
            "is_admin": _is_admin(actor),
        }

    def resolve_gateway(project_slug: str, actor: Actor) -> RegistaGateway:
        try:
            project = slug_to_project(project_slug)
        except ValueError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown project {project_slug!r}")
        if not can_read_project(actor, project):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "access denied")
        try:
            return registry.get(project)
        except (KeyError, RegistaError):
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown project {project_slug!r}")

    def transitions_for(gateway: RegistaGateway, wi: WorkItem) -> list[tuple[str, str, bool]]:
        version = getattr(wi, "workflow_version", None) or packaged_workflow_version()
        tdefs = gateway.transitions_from(wi.current_state, version)
        return [web.transition_tuple(t) for t in tdefs]

    @app.get("/healthz")
    def healthz() -> Any:
        from .health import build_health, has_failures

        health = build_health(settings, registry)
        if has_failures(health):
            return JSONResponse(status_code=503, content=health)
        return health

    @app.get("/csrf")
    def get_csrf(request: Request) -> dict[str, str]:
        token = issue_csrf_token(request.session)
        return {"csrf_token": token}

    @app.get("/login")
    def login_form(request: Request) -> Response:
        csrf = issue_csrf_token(request.session)
        return templates.TemplateResponse(
            request,
            "login.html",
            {"csrf_token": csrf, "error": None},
        )

    @app.post("/login", response_model=None)
    async def login(
        request: Request,
        _: None = Depends(verify_csrf),
    ) -> Response | dict[str, str]:
        form_req = _is_form_request(request)
        if form_req:
            username = str((await request.form()).get("username", ""))
        else:
            try:
                payload = await request.json()
            except Exception:
                payload = None
            username = str(payload.get("username", "")) if isinstance(payload, dict) else ""

        throttle_key = _normalize_identifier(username)

        if throttler.is_locked(throttle_key):
            if form_req:
                csrf = issue_csrf_token(request.session)
                return templates.TemplateResponse(
                    request,
                    "login.html",
                    {
                        "csrf_token": csrf,
                        "error": "too many failed attempts; try again later",
                    },
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                )
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "too many failed attempts; try again later",
            )

        principal, form_req = await _credential_login(request, backend)
        if principal is None:
            if throttler.is_locked(throttle_key):
                if form_req:
                    csrf = issue_csrf_token(request.session)
                    return templates.TemplateResponse(
                        request,
                        "login.html",
                        {
                            "csrf_token": csrf,
                            "error": "too many failed attempts; try again later",
                        },
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    )
                raise HTTPException(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    "too many failed attempts; try again later",
                )
            throttler.record_failure(throttle_key)
            if form_req:
                csrf = issue_csrf_token(request.session)
                return templates.TemplateResponse(
                    request,
                    "login.html",
                    {"csrf_token": csrf, "error": "invalid credentials"},
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

        throttler.record_success(throttle_key)
        actor = principal_to_actor(principal)
        request.session.clear()
        new_csrf = issue_csrf_token(request.session)
        request.session[_ACTOR_SESSION_KEY] = asdict(actor)

        if form_req:
            return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
        return {
            "actor_id": actor.actor_id,
            "display_name": actor.display_name,
            "csrf_token": new_csrf,
        }

    @app.post("/logout", response_model=None)
    async def logout(request: Request, _: None = Depends(verify_csrf)) -> Response | dict[str, bool]:
        request.session.clear()
        if _is_form_request(request) or _wants_html(request):
            return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
        return {"ok": True}

    @app.get("/me")
    def me(actor: Actor = Depends(current_actor)) -> dict[str, Any]:
        return asdict(actor)

    # ---- cross-project dashboard (Plan 014 WI-1.2) ----

    _DASHBOARD_MAX_ITEMS = 200

    @app.get("/")
    def dashboard(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        filter_project: str | None = Query(default=None, alias="project"),
        filter_status: str | None = Query(default=None, alias="status"),
        filter_assignee: str | None = Query(default=None, alias="assignee"),
        search_query: str | None = Query(default=None, alias="q"),
    ) -> Response:
        import logging

        logger = logging.getLogger("dossier.dashboard")
        project_rows: list[dict[str, Any]] = []
        all_items: list[dict[str, Any]] = []

        states_filter = [filter_status] if filter_status else _OPEN_STATES

        for project in registry.list_projects():
            if not can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                page = gw.list_issues(
                    current_states=states_filter,
                    assignee=filter_assignee or None,
                )
                items = list(page.items)
                count = len(items)
                catalog_entry = gw.get_project_catalog_entry()
            except Exception:
                logger.warning("dashboard: project %s unreachable", project, exc_info=True)
                count = 0
                catalog_entry = None
                items = []
            slug = project_to_slug(project)
            project_rows.append({
                "slug": slug,
                "name": project,
                "open_count": count,
                "catalog_entry": catalog_entry,
            })
            if filter_project and slug != filter_project:
                continue
            for wi in items:
                title = web.issue_title(wi)
                if search_query:
                    searchable = f"{web.display_key(wi)} {title} {web.issue_field(wi, 'assignee', '')}".lower()
                    if search_query.lower() not in searchable:
                        continue
                all_items.append({
                    "key": web.display_key(wi),
                    "title": title,
                    "project_slug": slug,
                    "state": wi.current_state,
                    "assignee": web.issue_field(wi, "assignee", ""),
                    "updated": web.last_event_time(wi),
                    "issue_url": f"/p/{slug}/issues/{wi.work_item_id}",
                    "project_url": f"/p/{slug}",
                })

        total_count = len(all_items)
        dashboard_items = all_items[:_DASHBOARD_MAX_ITEMS]

        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {
                **ctx,
                "project_rows": project_rows,
                "dashboard_items": dashboard_items,
                "total_count": total_count,
                "max_items": _DASHBOARD_MAX_ITEMS,
                "filter_project": filter_project or "",
                "filter_status": filter_status or "",
                "filter_assignee": filter_assignee or "",
                "search_query": search_query or "",
            },
        )

    # ---- estate-wide search (Plan 014 WI-2.1) ----

    @app.get("/search")
    def search_route(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        q: str | None = Query(default=None),
    ) -> Response:
        import logging

        logger = logging.getLogger("dossier.search")
        results: list[dict[str, Any]] = []
        query = (q or "").strip().lower()

        if query:
            for project in registry.list_projects():
                if not can_read_project(actor, project):
                    continue
                try:
                    gw = registry.get(project)
                    page = gw.list_issues(page_size=500)
                    for wi in page.items:
                        title = web.issue_title(wi)
                        key = web.display_key(wi)
                        assignee = web.issue_field(wi, "assignee", "")
                        searchable = f"{key} {title} {assignee}".lower()
                        if query in searchable:
                            slug = project_to_slug(project)
                            results.append({
                                "key": key,
                                "title": title,
                                "project_slug": slug,
                                "state": wi.current_state,
                                "assignee": assignee,
                                "issue_url": f"/p/{slug}/issues/{wi.work_item_id}",
                                "project_url": f"/p/{slug}",
                            })
                except Exception:
                    logger.warning("search: project %s unreachable", project, exc_info=True)

        project_count = len({r["project_slug"] for r in results})

        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "search.html",
            {
                **ctx,
                "search_query": q or "",
                "search_results": results,
                "result_count": len(results),
                "project_count": project_count,
            },
        )

    # ---- project-scoped routes (Plan 011 WI-2) ----

    @app.get("/p/{project}")
    def project_index(
        project: str,
        request: Request,
        states: list[str] | None = Query(default=None, alias="status"),
        assignee: str | None = Query(default=None),
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        gw = resolve_gateway(project, actor)
        page = gw.list_issues(current_states=states, assignee=assignee)
        catalog_entry = gw.get_project_catalog_entry()
        ctx = actor_context(request, actor)
        ctx["current_project"] = slug_to_project(project)
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                **ctx,
                "issues": list(page.items),
                "filter_states": states or [],
                "filter_assignee": assignee or "",
                "project_slug": project,
                "catalog_entry": catalog_entry,
            },
        )

    @app.get("/p/{project}/issues/new")
    def issue_new_form(
        project: str,
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        resolve_gateway(project, actor)
        ctx = actor_context(request, actor)
        ctx["current_project"] = slug_to_project(project)
        return templates.TemplateResponse(
            request,
            "issue_new.html",
            {**ctx, "project_slug": project, "error": None},
        )

    @app.post("/p/{project}/issues")
    async def create_issue_route(
        project: str,
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        _: None = Depends(verify_csrf),
    ) -> Response:
        gw = resolve_gateway(project, actor)
        form = await request.form()
        work_item_type = str(form.get("type", "bug"))
        title = str(form.get("title", "")).strip()
        description = str(form.get("description", ""))
        assignee = str(form.get("assignee", "")).strip()
        priority = str(form.get("priority", "normal"))

        if not title:
            ctx = actor_context(request, actor)
            ctx["current_project"] = slug_to_project(project)
            return templates.TemplateResponse(
                request,
                "issue_new.html",
                {**ctx, "project_slug": project, "error": "title is required"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        custom_fields: dict[str, Any] = {
            "title": title,
            "description": description,
            "assignee": assignee,
            "priority": priority,
        }

        try:
            wi, _ = gw.create_issue(
                actor=actor,
                work_item_type=work_item_type,
                custom_fields=custom_fields,
            )
        except RegistaError as exc:
            ctx = actor_context(request, actor)
            ctx["current_project"] = slug_to_project(project)
            return templates.TemplateResponse(
                request,
                "issue_new.html",
                {**ctx, "project_slug": project, "error": exc.message},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        return RedirectResponse(
            url=f"/p/{project}/issues/{wi.work_item_id}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.get("/p/{project}/issues/{work_item_id}")
    def issue_detail_route(
        project: str,
        work_item_id: uuid.UUID,
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        gw = resolve_gateway(project, actor)
        wi = gw.get_issue(work_item_id)
        if wi is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "issue not found")
        events = gw.history(work_item_id)
        transitions = transitions_for(gw, wi)
        integrity = gw.integrity(work_item_id=work_item_id)
        links = gw.list_links(work_item_id)

        event_verifications: dict[int, dict[str, Any]] = {}
        for i, event in enumerate(events):
            try:
                event_verifications[i] = gw.verify_event(event)
            except Exception:
                event_verifications[i] = {
                    "verified": False,
                    "principal_id": None,
                    "fingerprint": None,
                    "scheme": None,
                }

        assurance = compute_assurance_level(events)

        ctx = actor_context(request, actor)
        ctx["current_project"] = slug_to_project(project)
        return templates.TemplateResponse(
            request,
            "issue_detail.html",
            {
                **ctx,
                "issue": wi,
                "events": events,
                "transitions": transitions,
                "integrity_drift": integrity.replayed_drift,
                "project_slug": project,
                "links": links,
                "error": None,
                "event_verifications": event_verifications,
                "assurance_level": assurance,
                "assurance_label": assurance_label(assurance),
                "assurance_css": assurance_class(assurance),
            },
        )

    @app.post("/p/{project}/issues/{work_item_id}/transitions")
    async def transition_route(
        project: str,
        work_item_id: uuid.UUID,
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        _: None = Depends(verify_csrf),
    ) -> Response:
        gw = resolve_gateway(project, actor)
        form = await request.form()
        transition_name = str(form.get("transition_name", ""))
        review_note = str(form.get("review_note", "")).strip()
        same_lineage_ack = form.get("same_lineage_acknowledged") == "on"

        payload: dict[str, Any] = {}
        if transition_name in web._REVIEW_VERDICTS:
            payload["review_note"] = review_note
            if same_lineage_ack:
                payload["same_lineage_acknowledged"] = True

        try:
            gw.transition(
                actor=actor,
                work_item_id=work_item_id,
                transition_name=transition_name,
                payload=payload,
            )
        except RegistaError as exc:
            wi = gw.get_issue(work_item_id)
            if wi is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "issue not found")
            events = gw.history(work_item_id)
            transitions = transitions_for(gw, wi)
            integrity = gw.integrity(work_item_id=work_item_id)
            links = gw.list_links(work_item_id)

            event_verifications: dict[int, dict[str, Any]] = {}
            for i, event in enumerate(events):
                try:
                    event_verifications[i] = gw.verify_event(event)
                except Exception:
                    event_verifications[i] = {
                        "verified": False,
                        "principal_id": None,
                        "fingerprint": None,
                        "scheme": None,
                    }
            assurance = compute_assurance_level(events)

            ctx = actor_context(request, actor)
            ctx["current_project"] = slug_to_project(project)
            return templates.TemplateResponse(
                request,
                "issue_detail.html",
                {
                    **ctx,
                    "issue": wi,
                    "events": events,
                    "transitions": transitions,
                    "integrity_drift": integrity.replayed_drift,
                    "project_slug": project,
                    "links": links,
                    "error": exc.message,
                    "event_verifications": event_verifications,
                    "assurance_level": assurance,
                    "assurance_label": assurance_label(assurance),
                    "assurance_css": assurance_class(assurance),
                },
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        return RedirectResponse(
            url=f"/p/{project}/issues/{work_item_id}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.post("/p/{project}/issues/{work_item_id}/comments")
    async def comment_route(
        project: str,
        work_item_id: uuid.UUID,
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        _: None = Depends(verify_csrf),
    ) -> Response:
        gw = resolve_gateway(project, actor)
        form = await request.form()
        body = str(form.get("body", "")).strip()
        if body:
            gw.comment(actor=actor, work_item_id=work_item_id, body=body)
        return RedirectResponse(
            url=f"/p/{project}/issues/{work_item_id}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.post("/p/{project}/owner")
    async def set_owner_route(
        project: str,
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        _: None = Depends(verify_csrf),
    ) -> Response:
        require_admin(actor)
        gw = resolve_gateway(project, actor)
        form = await request.form()
        owner = str(form.get("owner_actor_id", "")).strip()
        try:
            gw.set_project_owner(
                owner_actor_id=owner or None,
                updated_by=actor.actor_id,
            )
        except RegistaError:
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "failed to update project owner",
            )
        return RedirectResponse(
            url=f"/p/{project}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    # ---- my signing identity (Plan 015 WI-1.1) ----

    @app.get("/me/identity")
    def my_identity(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        ctx = actor_context(request, actor)
        principal_key = None
        rotation_allowed = _rotation_allowed(actor.actor_id)
        key_events: list[dict[str, Any]] = []

        for project in registry.list_projects():
            if not can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                principal_key = gw.get_principal_key(actor.actor_id)
                if principal_key:
                    key_events = [
                        {
                            "transition": web.transition_label(getattr(ev, "transition", "")),
                            "timestamp": web.format_timestamp(getattr(ev, "timestamp", None)),
                            "key_id": ev.payload.get("key_id") if isinstance(ev.payload, dict) else None,
                            "fingerprint": ev.payload.get("fingerprint") if isinstance(ev.payload, dict) else None,
                        }
                        for ev in gw.read_principal_enrollment_events(actor.actor_id)
                    ]
                    break
            except Exception:
                pass

        ctx["principal_key"] = principal_key
        ctx["rotation_allowed"] = rotation_allowed
        ctx["key_events"] = key_events
        return templates.TemplateResponse(
            request,
            "my_identity.html",
            ctx,
        )

    @app.post("/me/key/rotate", response_model=None)
    async def rotate_my_key(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        _: None = Depends(verify_csrf),
    ) -> Response:
        if not _actor_key_custody_ready():
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "actor-key custody requires a file-backed key manifest; remote backends are a v1.1 seam",
            )

        if not _rotation_allowed(actor.actor_id):
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "rotation rate-limited; try again later",
            )

        private_key, new_public_key = key_mgr.generate(actor.actor_id)
        try:
            success_count = 0
            errors: list[str] = []
            for project in registry.list_projects():
                if not can_read_project(actor, project):
                    continue
                try:
                    gw = registry.get(project)
                    old_key = gw.get_principal_key(actor.actor_id)
                    result = gw.rotate_principal(
                        actor.actor_id, new_public_key, registered_by=actor.actor_id
                    )
                    if not result:
                        errors.append(f"{project}: rotation returned no result")
                        continue
                    try:
                        key_mgr.store_private_key(
                            actor.actor_id, result["key_id"], private_key
                        )
                    except Exception as store_exc:
                        try:
                            gw.revoke_principal(
                                actor.actor_id,
                                result["key_id"],
                                reason="private-key custody failure",
                            )
                        except Exception:
                            pass
                        if old_key is not None:
                            try:
                                old_public_key = bytes.fromhex(old_key["public_key"])
                                gw.register_principal(
                                    actor.actor_id,
                                    old_public_key,
                                    registered_by=actor.actor_id,
                                )
                            except Exception:
                                pass
                        errors.append(f"{project}: {store_exc}")
                        continue
                    success_count += 1
                except Exception as exc:
                    errors.append(f"{project}: {exc}")
        finally:
            del private_key

        if errors:
            logger.warning("key.rotation_partial_failure", extra={
                "actor_id": actor.actor_id,
                "success_count": success_count,
                "errors": errors,
            })

        if success_count == 0:
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR, "key rotation failed"
            )

        _record_rotation(actor.actor_id)
        return RedirectResponse(url="/me/identity", status_code=status.HTTP_303_SEE_OTHER)

    # ---- my signing history (Plan 015 WI-1.3) ----

    @app.get("/me/signing-history")
    def my_signing_history(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        import logging

        logger = logging.getLogger("dossier.signing_history")
        signed_events: list[dict[str, Any]] = []

        for project in registry.list_projects():
            if not can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                page = gw.list_issues(page_size=500)
                for wi in page.items:
                    events = gw.history(wi.work_item_id)
                    for event in events:
                        if getattr(event, "actor_id", None) != actor.actor_id:
                            continue
                        try:
                            vinfo = gw.verify_event(event)
                            verified = vinfo.get("verified", False)
                        except Exception:
                            verified = False
                        slug = project_to_slug(project)
                        signed_events.append({
                            "timestamp": web.format_timestamp(getattr(event, "timestamp", None)),
                            "project_slug": slug,
                            "issue_url": f"/p/{slug}/issues/{wi.work_item_id}",
                            "display_key": web.display_key(wi),
                            "title": web.issue_title(wi),
                            "transition": web.transition_label(getattr(event, "transition", "")),
                            "verified": verified,
                        })
            except Exception:
                logger.warning("signing history: project %s unreachable", project, exc_info=True)

        signed_events.sort(key=lambda e: e["timestamp"], reverse=True)

        ctx = actor_context(request, actor)
        ctx["signed_events"] = signed_events
        return templates.TemplateResponse(
            request,
            "my_signing_history.html",
            ctx,
        )

    # ---- admin: principal roster + enrollment (Plan 015 WI-2.1) ----

    def require_admin(actor: Actor) -> None:
        if not _is_admin(actor):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "admin access required")

    @app.get("/admin/principals")
    def principal_roster(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        require_admin(actor)
        ctx = actor_context(request, actor)

        all_principals: list[dict[str, Any]] = []
        seen_keys: set[str] = set()
        for project in registry.list_projects():
            if not can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                principals = gw.list_principals()
                for p in principals:
                    kid = p.get("key_id", "")
                    if kid and kid not in seen_keys:
                        seen_keys.add(kid)
                        all_principals.append(p)
            except Exception:
                pass

        ctx["principals"] = all_principals
        return templates.TemplateResponse(
            request,
            "principal_roster.html",
            ctx,
        )

    @app.post("/admin/principals/enroll", response_model=None)
    async def enroll_principal(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        _: None = Depends(verify_csrf),
    ) -> Response:
        require_admin(actor)
        form = await request.form()
        principal_id = str(form.get("principal_id", "")).strip()

        if not principal_id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "principal_id is required")

        try:
            _validate_principal_id(principal_id)
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

        private_key_dir = settings.principal_key_dir or None

        success_count = 0
        errors: list[str] = []
        for project in registry.list_projects():
            if not can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                if gw.has_principal_ops():
                    result = gw.enroll_principal(
                        principal_id,
                        actor=actor,
                        private_key_dir=private_key_dir,
                    )
                else:
                    new_public_key = key_mgr.generate_and_store(principal_id)
                    result = gw.register_principal(
                        principal_id, new_public_key, registered_by=actor.actor_id
                    )
                if result:
                    success_count += 1
            except Exception as exc:
                errors.append(f"{project}: {exc}")

        if errors:
            logger.warning("key.enrollment_partial_failure", extra={
                "principal_id": principal_id,
                "actor_id": actor.actor_id,
                "success_count": success_count,
                "errors": errors,
            })

        if success_count == 0:
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR, "principal enrollment failed"
            )

        return RedirectResponse(url="/admin/principals", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/principals/{principal_id}/revoke", response_model=None)
    async def revoke_principal_route(
        principal_id: str,
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        _: None = Depends(verify_csrf),
    ) -> Response:
        require_admin(actor)
        reason = "revoked by admin"

        success_count = 0
        errors: list[str] = []
        for project in registry.list_projects():
            if not can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                key_info = gw.get_principal_key(principal_id)
                if key_info:
                    gw.revoke_principal(
                        principal_id, key_info["key_id"], reason=reason
                    )
                    success_count += 1
            except Exception as exc:
                errors.append(f"{project}: {exc}")

        if success_count == 0:
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR, "principal revocation failed"
            )

        return RedirectResponse(url="/admin/principals", status_code=status.HTTP_303_SEE_OTHER)

    # ---- break-glass (Plan 015 WI-2.3) ----

    @app.get("/admin/break-glass")
    def break_glass_form(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        require_admin(actor)
        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "break_glass.html",
            ctx,
        )

    @app.post("/admin/break-glass", response_model=None)
    async def break_glass_action(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        _: None = Depends(verify_csrf),
    ) -> Response:
        require_admin(actor)
        form = await request.form()
        principal_id = str(form.get("principal_id", "")).strip()
        raw_reason = str(form.get("reason", "")).strip()
        confirmer_id = str(form.get("confirmer_id", "")).strip()

        if not principal_id or not raw_reason or not confirmer_id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "all fields are required")

        if confirmer_id == actor.actor_id:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "dual-control requires a different confirmer",
            )

        if confirmer_id not in _ADMIN_ACTOR_IDS:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "confirmer must be an admin",
            )

        reason = " ".join(raw_reason.split())[:500]

        if not _actor_key_custody_ready():
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "actor-key custody requires a file-backed key manifest; remote backends are a v1.1 seam",
            )

        try:
            private_key, new_public_key = key_mgr.generate(principal_id)
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

        success_count = 0
        errors: list[str] = []
        for project in registry.list_projects():
            if not can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                old_key = gw.get_principal_key(principal_id)
                if old_key is not None:
                    gw.revoke_principal(
                        principal_id,
                        old_key["key_id"],
                        reason=f"break-glass: {reason}",
                    )
                result = gw.register_principal(
                    principal_id,
                    new_public_key,
                    registered_by=actor.actor_id,
                )
                if not result:
                    errors.append(f"{project}: break-glass returned no result")
                    continue
                try:
                    key_mgr.store_private_key(
                        principal_id, result["key_id"], private_key
                    )
                except Exception as store_exc:
                    try:
                        gw.revoke_principal(
                            principal_id,
                            result["key_id"],
                            reason="private-key custody failure",
                        )
                    except Exception:
                        pass
                    if old_key is not None:
                        try:
                            old_public_key = bytes.fromhex(old_key["public_key"])
                            gw.register_principal(
                                principal_id,
                                old_public_key,
                                registered_by=actor.actor_id,
                            )
                        except Exception:
                            pass
                    errors.append(f"{project}: {store_exc}")
                    continue
                success_count += 1
            except Exception as exc:
                errors.append(f"{project}: {exc}")

        try:
            del private_key
        except NameError:
            pass

        if errors:
            logger.warning("break_glass.partial_failure", extra={
                "principal_id": principal_id,
                "actor_id": actor.actor_id,
                "success_count": success_count,
                "errors": errors,
            })

        if success_count == 0:
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "break-glass key rotation failed",
            )

        logger.warning(
            "break_glass.executed",
            extra={
                "principal_id": principal_id,
                "actor_id": actor.actor_id,
                "confirmer_id": confirmer_id,
                "reason": reason,
                "projects_succeeded": success_count,
                "errors": errors,
            },
        )

        return RedirectResponse(url="/admin/principals", status_code=status.HTTP_303_SEE_OTHER)

    return app
