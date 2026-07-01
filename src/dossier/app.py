from __future__ import annotations

import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.templating import Jinja2Templates
from regista import RegistaError, WorkItem
from starlette.responses import RedirectResponse, Response
from starlette.staticfiles import StaticFiles

from .actors import Actor
from .auth.backends import CredentialBackend, Principal
from .auth.resolver import principal_to_actor
from .auth.sessions import issue_csrf_token, session_middleware, verify_csrf
from .auth.throttle import LoginThrottler, _normalize_identifier
from .config import Settings
from .gateway import RegistaGateway, packaged_workflow_version
from .multi import GatewayRegistry, project_to_slug, slug_to_project
from . import web

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
    app = FastAPI(title="dossier")
    app.state.settings = settings
    app.state.registry = registry
    app.state.backend = backend
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
            "projects": registry.list_projects(),
        }

    def resolve_gateway(project_slug: str) -> RegistaGateway:
        try:
            project = slug_to_project(project_slug)
        except ValueError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown project {project_slug!r}")
        try:
            return registry.get(project)
        except (KeyError, RegistaError):
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown project {project_slug!r}")

    def transitions_for(gateway: RegistaGateway, wi: WorkItem) -> list[tuple[str, str, bool]]:
        version = getattr(wi, "workflow_version", None) or packaged_workflow_version()
        tdefs = gateway.transitions_from(wi.current_state, version)
        return [web.transition_tuple(t) for t in tdefs]

    @app.get("/healthz")
    def healthz() -> dict[str, bool]:
        return {"ok": True}

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

    # ---- cross-project landing (Plan 011 WI-3) ----

    @app.get("/")
    def landing(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        import logging

        logger = logging.getLogger("dossier.landing")
        project_rows: list[dict[str, Any]] = []
        for project in registry.list_projects():
            try:
                gw = registry.get(project)
                page = gw.list_issues(current_states=_OPEN_STATES)
                count = len(page.items)
            except Exception:
                logger.warning("landing: project %s unreachable", project, exc_info=True)
                count = 0
            project_rows.append({
                "slug": project_to_slug(project),
                "name": project,
                "open_count": count,
            })
        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "landing.html",
            {**ctx, "project_rows": project_rows},
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
        gw = resolve_gateway(project)
        page = gw.list_issues(current_states=states, assignee=assignee)
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
            },
        )

    @app.get("/p/{project}/issues/new")
    def issue_new_form(
        project: str,
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        resolve_gateway(project)
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
        gw = resolve_gateway(project)
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
        gw = resolve_gateway(project)
        wi = gw.get_issue(work_item_id)
        if wi is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "issue not found")
        events = gw.history(work_item_id)
        transitions = transitions_for(gw, wi)
        integrity = gw.integrity(work_item_id=work_item_id)
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
                "error": None,
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
        gw = resolve_gateway(project)
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
                    "error": exc.message,
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
        gw = resolve_gateway(project)
        form = await request.form()
        body = str(form.get("body", "")).strip()
        if body:
            gw.comment(actor=actor, work_item_id=work_item_id, body=body)
        return RedirectResponse(
            url=f"/p/{project}/issues/{work_item_id}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    return app
