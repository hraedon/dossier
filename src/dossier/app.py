from __future__ import annotations

import uuid
from dataclasses import asdict
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.templating import Jinja2Templates
from regista import RegistaError
from starlette.responses import RedirectResponse
from starlette.staticfiles import StaticFiles

from .actors import Actor
from .auth.backends import AuthBackend
from .auth.resolver import principal_to_actor
from .auth.sessions import issue_csrf_token, session_middleware, verify_csrf
from .config import Settings
from .gateway import RegistaGateway
from . import web

_ACTOR_SESSION_KEY = "actor"
_STATIC_DIR = Path(__file__).parent / "static"
_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _is_form_request(request: Request) -> bool:
    ct = request.headers.get("content-type", "")
    return "application/x-www-form-urlencoded" in ct


def _wants_html(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "text/html" in accept


def create_app(
    settings: Settings,
    gateway: RegistaGateway,
    backend: AuthBackend,
) -> FastAPI:
    """Build the FastAPI app with session auth wired to ``gateway`` and ``backend``.

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
    app.state.gateway = gateway
    app.state.backend = backend

    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))
    templates.env.globals.update(
        transition_label=web.transition_label,
        actor_display=web.actor_display,
        on_behalf_display=web.on_behalf_display,
        event_verdict=web.event_verdict,
        format_timestamp=web.format_timestamp,
        status_pill_class=web.status_pill_class,
        issue_title=web.issue_title,
        issue_field=web.issue_field,
        last_event_time=web.last_event_time,
        kind_badge=web.kind_badge,
    )
    app.state.templates = templates

    app.add_middleware(session_middleware(settings))

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
            raise HTTPException(
                status.HTTP_302_FOUND,
                headers={"Location": "/login"},
            )
        try:
            return Actor(**data)
        except TypeError:
            request.session.clear()
            raise HTTPException(
                status.HTTP_302_FOUND,
                headers={"Location": "/login"},
            )

    def actor_context(request: Request, actor: Actor) -> dict:
        return {
            "actor": actor,
            "csrf_token": issue_csrf_token(request.session),
        }

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    @app.get("/csrf")
    def get_csrf(request: Request) -> dict:
        token = issue_csrf_token(request.session)
        return {"csrf_token": token}

    @app.get("/login")
    def login_form(request: Request):
        csrf = issue_csrf_token(request.session)
        return templates.TemplateResponse(
            request,
            "login.html",
            {"csrf_token": csrf, "error": None},
        )

    @app.post("/login")
    async def login(
        request: Request,
        _: None = Depends(verify_csrf),
    ):
        form_req = _is_form_request(request)
        if form_req:
            form = await request.form()
            username = str(form.get("username", ""))
            password = str(form.get("password", ""))
        else:
            payload = await request.json()
            username = payload.get("username", "")
            password = payload.get("password", "")

        principal = backend.authenticate(username, password)
        if principal is None:
            if form_req:
                csrf = issue_csrf_token(request.session)
                return templates.TemplateResponse(
                    request,
                    "login.html",
                    {"csrf_token": csrf, "error": "invalid credentials"},
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

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

    @app.post("/logout")
    async def logout(request: Request, _: None = Depends(verify_csrf)):
        request.session.clear()
        if _is_form_request(request) or _wants_html(request):
            return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
        return {"ok": True}

    @app.get("/me")
    def me(actor: Actor = Depends(current_actor)) -> dict:
        return asdict(actor)

    @app.get("/")
    def index(
        request: Request,
        states: list[str] | None = Query(default=None, alias="status"),
        assignee: str | None = Query(default=None),
        actor: Actor = Depends(current_actor_or_redirect),
    ):
        page = gateway.list_issues(current_states=states, assignee=assignee)
        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                **ctx,
                "issues": list(page.items),
                "filter_states": states or [],
                "filter_assignee": assignee or "",
            },
        )

    @app.get("/issues/new")
    def issue_new_form(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ):
        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "issue_new.html",
            {**ctx, "error": None},
        )

    @app.post("/issues")
    async def create_issue_route(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        _: None = Depends(verify_csrf),
    ):
        form = await request.form()
        work_item_type = str(form.get("type", "bug"))
        title = str(form.get("title", "")).strip()
        description = str(form.get("description", ""))
        assignee = str(form.get("assignee", "")).strip()
        priority = str(form.get("priority", "normal"))

        if not title:
            ctx = actor_context(request, actor)
            return templates.TemplateResponse(
                request,
                "issue_new.html",
                {**ctx, "error": "title is required"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        custom_fields: dict = {
            "title": title,
            "description": description,
            "assignee": assignee,
            "priority": priority,
        }

        wi, _ = gateway.create_issue(
            actor=actor,
            work_item_type=work_item_type,
            custom_fields=custom_fields,
        )
        return RedirectResponse(
            url=f"/issues/{wi.work_item_id}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.get("/issues/{work_item_id}")
    def issue_detail_route(
        work_item_id: uuid.UUID,
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ):
        wi = gateway.get_issue(work_item_id)
        if wi is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "issue not found")
        events = gateway.history(work_item_id)
        transitions = web.transitions_from(wi.current_state)
        integrity = gateway.integrity()
        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "issue_detail.html",
            {
                **ctx,
                "issue": wi,
                "events": events,
                "transitions": transitions,
                "integrity_drift": integrity.replayed_drift,
                "error": None,
            },
        )

    @app.post("/issues/{work_item_id}/transitions")
    async def transition_route(
        work_item_id: uuid.UUID,
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        _: None = Depends(verify_csrf),
    ):
        form = await request.form()
        transition_name = str(form.get("transition_name", ""))
        review_note = str(form.get("review_note", "")).strip()

        payload = {"review_note": review_note} if review_note else None

        try:
            gateway.transition(
                actor=actor,
                work_item_id=work_item_id,
                transition_name=transition_name,
                payload=payload,
            )
        except RegistaError as exc:
            wi = gateway.get_issue(work_item_id)
            if wi is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "issue not found")
            events = gateway.history(work_item_id)
            transitions = web.transitions_from(wi.current_state)
            integrity = gateway.integrity()
            ctx = actor_context(request, actor)
            return templates.TemplateResponse(
                request,
                "issue_detail.html",
                {
                    **ctx,
                    "issue": wi,
                    "events": events,
                    "transitions": transitions,
                    "integrity_drift": integrity.replayed_drift,
                    "error": exc.message,
                },
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        return RedirectResponse(
            url=f"/issues/{work_item_id}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.post("/issues/{work_item_id}/comments")
    async def comment_route(
        work_item_id: uuid.UUID,
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        _: None = Depends(verify_csrf),
    ):
        form = await request.form()
        body = str(form.get("body", "")).strip()
        if body:
            gateway.comment(actor=actor, work_item_id=work_item_id, body=body)
        return RedirectResponse(
            url=f"/issues/{work_item_id}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    return app
