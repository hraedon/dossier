from __future__ import annotations

import hmac
import json
import logging
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.templating import Jinja2Templates
from regista import ErrorCode as ErrorCode  # type: ignore[attr-defined]
from regista import LifecycleContractError, WorkItem
from regista import RegistaError as RegistaError  # type: ignore[attr-defined]
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.staticfiles import StaticFiles

from . import web
from .actors import Actor
from .administration import (
    AdminSummary,
    read_access_policy,
    read_admin_summary,
    read_project_list,
)
from .attribution import event_delegation_claim
from .auth.backends import CredentialBackend, Principal
from .auth.resolver import principal_to_actor
from .auth.sessions import issue_csrf_token, session_middleware, verify_csrf
from .auth.step_up import (
    ProtectedOperation,
    is_auth_recent,
    produce_step_up_evidence,
    requires_step_up,
    verify_step_up_evidence,
)
from .auth.throttle import LoginThrottler, _normalize_identifier
from .authz import (
    ProjectAccessPolicy,
    build_project_access_policy,
    can_read_project,
)
from .config import Settings
from .evidence import (
    EventVerification,
    EvidenceSummary,
    read_event_verifications,
    read_evidence_summary,
    read_integrity_report,
)
from .gateway import RegistaGateway, packaged_workflow_version
from .issue_views import render_issue_detail
from .keys import _validate_principal_id
from .knowledge import (
    NoteDetail,
    NoteSummary,
    create_note,
    get_note,
    list_notes,
    search_notes,
    verify_note,
)
from .lifecycle_http import (
    decode_b64 as _decode_b64,
)
from .lifecycle_http import (
    decode_public_key as _decode_public_key,
)
from .lifecycle_http import (
    handle_lifecycle_error as _handle_lifecycle_error,
)
from .lifecycle_http import (
    optional_str as _optional_str,
)
from .lifecycle_http import (
    parse_custody_mode as _parse_custody_mode,
)
from .lifecycle_http import (
    parse_effective_receipt as _parse_effective_receipt,
)
from .lifecycle_http import (
    parse_possession_proof as _parse_possession_proof,
)
from .lifecycle_http import (
    parse_principal_kind as _parse_principal_kind,
)
from .lifecycle_http import (
    read_json as _read_json,
)
from .lifecycle_http import (
    require_json_object as _require_json_object,
)
from .lifecycle_http import (
    require_str as _require_str,
)
from .multi import GatewayRegistry, project_to_slug, slug_to_project
from .notifications import (
    EVENT_CLASSES,
    FilePreferenceStore,
    MemoryPreferenceStore,
    NotificationEmitter,
    NotificationPreference,
    NotificationPreferenceStore,
)
from .operations import (
    EstateSummary,
    read_estate_summary,
    read_operations_findings,
)
from .provenance import (
    SessionSummary,
    read_session_detail,
    read_session_summaries,
    unverifiable_session_detail,
)
from .shell import build_shell
from .signing import HumanSigningRefusedError
from .views import (
    ActivityEntry,
    MyWorkEntry,
    ReviewQueueEntry,
    read_activity_feed,
    read_my_work,
    read_review_queue,
)

logger = logging.getLogger("dossier.app")

_ACTOR_SESSION_KEY = "actor"
_AUTH_TIME_SESSION_KEY = "auth_time"
_USERNAME_SESSION_KEY = "username"

_PROTECTED_OP_FOR_LIFECYCLE: Final = {
    "enrollment": ProtectedOperation.KEY_ENROLLMENT,
    "rotation": ProtectedOperation.KEY_ROTATION,
    "revocation": ProtectedOperation.KEY_REVOCATION,
}


def _session_auth_time(request: Request) -> datetime | None:
    raw = request.session.get(_AUTH_TIME_SESSION_KEY)
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


_STATIC_DIR = Path(__file__).parent / "static"
_TEMPLATE_DIR = Path(__file__).parent / "templates"

_OPEN_STATES = ["open", "in_progress", "blocked", "deferred", "in_review", "in_human_review"]


def _is_form_request(request: Request) -> bool:
    ct = request.headers.get("content-type", "")
    return "application/x-www-form-urlencoded" in ct


def _wants_html(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return True
    content_type = request.headers.get("content-type", "")
    return "application/x-www-form-urlencoded" in content_type


class LoginRequiredError(Exception):
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

    access_policy: ProjectAccessPolicy | None = None
    if settings.project_access_mode != "open":
        access_policy = build_project_access_policy(
            settings.project_acl_path,
            settings.bootstrap_administrators,
            group_claim_key=settings.session_secret.encode("utf-8"),
        )
        if access_policy.is_empty:
            # Deny-by-default with nothing declared: the app starts (so
            # /healthz, /livez and `dossier doctor` can explain the state) but
            # it discloses nothing. Say so once, loudly, at startup.
            logging.getLogger("dossier.authz").error(
                "project access mode is %s but no ACL "
                "(DOSSIER_PROJECT_ACL_PATH) and no bootstrap administrators "
                "(DOSSIER_BOOTSTRAP_ADMINS) are configured — every project "
                "will be denied. See docs/project-access.md.",
                settings.project_access_mode,
            )
    app.state.project_access_policy = access_policy

    def _can_read_project(actor: Actor, project: str) -> bool:
        return can_read_project(
            actor,
            project,
            access_policy,
            mode=settings.project_access_mode,
        )

    from .secrets import resolve_secret_bytes

    notification_secret = (
        resolve_secret_bytes(settings.notification_secret_ref)
        if settings.notification_sink and settings.notification_secret_ref
        else None
    )
    if settings.notification_pref_dir:
        preference_store: NotificationPreferenceStore = FilePreferenceStore(
            settings.notification_pref_dir
        )
    else:
        preference_store = MemoryPreferenceStore()
    app.state.preference_store = preference_store
    notifier = NotificationEmitter(
        sink_url=settings.notification_sink,
        base_url=settings.base_url,
        signing_secret=notification_secret,
        source=settings.notification_source,
        sender_identity=settings.notification_identity,
        preference_store=preference_store,
    )
    app.state.notifier = notifier

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
        harness_display=web.harness_display,
        verification_status_class=web.verification_status_class,
        verification_status_label=web.verification_status_label,
        verification_pill_class=web.verification_pill_class,
        tool_call_status_class=web.tool_call_status_class,
        format_digest=web.format_digest,
        format_bytes=web.format_bytes,
        safe_path=web.safe_path,
        session_principal_display=web.session_principal_display,
        pluralize=web.pluralize,
    )
    app.state.templates = templates

    app.add_middleware(session_middleware(settings))  # type: ignore[arg-type]

    # TrustedHostMiddleware (Plan 015 WI-1.1) — only wired when
    # DOSSIER_ALLOWED_HOSTS is set, so dev (unset) keeps the current behavior.
    # In prod the operator should set it; the doctor warns when prod lacks it.
    if settings.allowed_hosts:
        from starlette.middleware.trustedhost import TrustedHostMiddleware

        app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))

    @app.exception_handler(LoginRequiredError)
    async def _login_required_handler(
        request: Request, exc: LoginRequiredError
    ) -> RedirectResponse:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    @app.exception_handler(HumanSigningRefusedError)
    async def _human_signing_refused_handler(
        request: Request, exc: HumanSigningRefusedError
    ) -> JSONResponse:
        """Refuse the write with an operator-actionable 409 (WI-035).

        409 rather than 500: nothing is broken, the deployment's signing state
        simply conflicts with recording this action. The body names the identity
        and the provisioning command. ``X-Dossier-Human-Signing: refused`` marks
        it for any client that only reads headers.
        """
        logger.warning(
            "provenance.human_signature_refused",
            extra={
                "actor_id": exc.actor.actor_id,
                "principal_id": exc.actor.principal_id,
                "path": request.url.path,
                "reason": exc.identity.reason,
            },
        )
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content=exc.detail,
            headers={"X-Dossier-Human-Signing": "refused"},
        )

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
            raise LoginRequiredError()
        try:
            return Actor(**data)
        except TypeError:
            request.session.clear()
            raise LoginRequiredError()

    def actor_context(request: Request, actor: Actor) -> dict[str, Any]:
        admin = _is_admin(actor)
        return {
            "actor": actor,
            "csrf_token": issue_csrf_token(request.session),
            "projects": [p for p in registry.list_projects() if _can_read_project(actor, p)],
            "is_admin": admin,
            "shell": build_shell(request.url.path, actor, is_admin=admin),
        }

    def resolve_gateway(project_slug: str, actor: Actor) -> RegistaGateway:
        try:
            project = slug_to_project(project_slug)
        except ValueError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown project {project_slug!r}")
        if not _can_read_project(actor, project):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "access denied")
        try:
            return registry.get(project)
        except (KeyError, RegistaError):
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown project {project_slug!r}")

    def transitions_for(gateway: RegistaGateway, wi: WorkItem) -> list[tuple[str, str, bool]]:
        version = getattr(wi, "workflow_version", None) or packaged_workflow_version()
        tdefs = gateway.transitions_from(wi.current_state, version)
        return [web.transition_tuple(t) for t in tdefs]

    def _render_issue_detail_error(
        request: Request,
        gw: RegistaGateway,
        project: str,
        work_item_id: uuid.UUID,
        actor: Actor,
        *,
        error: str,
        status_code: int,
        headers: dict[str, str] | None = None,
    ) -> Response:
        """Re-render the issue page with *error* in the callout.

        Shared by every failed mutation on the issue detail page so a rejected
        transition always lands the human back on the item with the reason,
        rather than on a JSON error body.
        """
        wi = gw.get_issue(work_item_id)
        if wi is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "issue not found")
        ctx = actor_context(request, actor)
        ctx["current_project"] = slug_to_project(project)
        return render_issue_detail(
            templates,
            request,
            gw,
            wi,
            project_slug=project,
            context=ctx,
            transitions=transitions_for(gw, wi),
            error=error,
            status_code=status_code,
            headers=headers,
        )

    @app.get("/healthz")
    def healthz() -> Any:
        from .health import build_health, has_failures

        health = build_health(settings, registry)
        if has_failures(health):
            return JSONResponse(status_code=503, content=health)
        return health

    @app.get("/livez")
    def livez() -> dict[str, str]:
        return {"status": "alive"}

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
        actor = principal_to_actor(
            principal,
            backend.fetch_groups(principal),
            settings.session_secret.encode("utf-8"),
        )
        request.session.clear()
        new_csrf = issue_csrf_token(request.session)
        request.session[_ACTOR_SESSION_KEY] = asdict(actor)
        request.session[_AUTH_TIME_SESSION_KEY] = datetime.now(UTC).isoformat()
        request.session[_USERNAME_SESSION_KEY] = username

        if form_req:
            return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
        return {
            "actor_id": actor.actor_id,
            "display_name": actor.display_name,
            "csrf_token": new_csrf,
        }

    @app.post("/logout", response_model=None)
    async def logout(
        request: Request, _: None = Depends(verify_csrf)
    ) -> Response | dict[str, bool]:
        request.session.clear()
        if _is_form_request(request) or _wants_html(request):
            return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
        return {"ok": True}

    @app.post("/auth/step-up", response_model=None)
    async def step_up_reentry(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        _: None = Depends(verify_csrf),
    ) -> Response:
        """Password re-entry for step-up authentication (Plan 020 Phase 3).

        Refreshes the session's last-proven-authentication time so protected
        operations (key lifecycle approvals) can require recent auth. This is
        honest about its assurance level: it proves the user knows the
        password *now*; it is not MFA. The password is verified against the
        configured credential backend for the *session's own* username — a
        different account's password never refreshes this session.
        """
        form_req = _is_form_request(request)
        if form_req:
            password = str((await request.form()).get("password", ""))
        else:
            body = _require_json_object(await _read_json(request))
            password = _require_str(body, "password")

        username = request.session.get(_USERNAME_SESSION_KEY)
        if not isinstance(username, str) or not username:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "session invalid; please re-authenticate"
            )

        throttle_key = _normalize_identifier(f"stepup:{username}")
        if throttler.is_locked(throttle_key):
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "too many failed attempts; try again later",
            )

        principal = backend.authenticate(username, password)
        if principal is None or principal.stable_id != actor.actor_id:
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
        request.session[_AUTH_TIME_SESSION_KEY] = datetime.now(UTC).isoformat()
        if form_req:
            return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get("/me")
    def me(actor: Actor = Depends(current_actor)) -> dict[str, Any]:
        # Authorization group claims are server-trusted session state, not a
        # public identity field. In particular, do not disclose directory
        # membership identifiers through this convenience endpoint.
        return {
            "actor_id": actor.actor_id,
            "actor_kind": actor.actor_kind,
            "display_name": actor.display_name,
            "on_behalf_of": actor.on_behalf_of,
            "model_lineage": actor.model_lineage,
        }

    # ---- cross-project dashboard (Plan 014 WI-1.2) ----

    _dashboard_max_items = 200

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
            if not _can_read_project(actor, project):
                continue
            unreachable = False
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
                unreachable = True
                count = 0
                catalog_entry = None
                items = []
            slug = project_to_slug(project)
            project_rows.append(
                {
                    "slug": slug,
                    "name": project,
                    "open_count": count,
                    "catalog_entry": catalog_entry,
                    "unreachable": unreachable,
                }
            )
            if filter_project and slug != filter_project:
                continue
            for wi in items:
                title = web.issue_title(wi)
                if search_query:
                    searchable = (
                        f"{web.display_key(wi)} {title} {web.issue_field(wi, 'assignee', '')}"
                    ).lower()
                    if search_query.lower() not in searchable:
                        continue
                all_items.append(
                    {
                        "key": web.display_key(wi),
                        "title": title,
                        "project_slug": slug,
                        "state": wi.current_state,
                        "assignee": web.issue_field(wi, "assignee", ""),
                        "updated": web.last_event_time(wi),
                        "issue_url": f"/p/{slug}/issues/{wi.work_item_id}",
                        "project_url": f"/p/{slug}",
                    }
                )

        total_count = len(all_items)
        dashboard_items = all_items[:_dashboard_max_items]

        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {
                **ctx,
                "project_rows": project_rows,
                "dashboard_items": dashboard_items,
                "total_count": total_count,
                "max_items": _dashboard_max_items,
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
                if not _can_read_project(actor, project):
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
                            results.append(
                                {
                                    "key": key,
                                    "title": title,
                                    "project_slug": slug,
                                    "state": wi.current_state,
                                    "assignee": assignee,
                                    "issue_url": f"/p/{slug}/issues/{wi.work_item_id}",
                                    "project_url": f"/p/{slug}",
                                }
                            )
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

    # ---- agent-activity window: session list + detail (Plan 017 WI-1.1) ----

    @app.get("/sessions")
    def sessions_route(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        filter_project: str | None = Query(default=None, alias="project"),
    ) -> Response:
        import logging

        logger = logging.getLogger("dossier.sessions")
        all_sessions: list[SessionSummary] = []
        unreachable_projects: list[str] = []

        for project in registry.list_projects():
            if not _can_read_project(actor, project):
                continue
            if filter_project:
                slug = project_to_slug(project)
                if slug != filter_project:
                    continue
            try:
                gw = registry.get(project)
                sessions = read_session_summaries(gw, project_to_slug(project))
            except Exception:
                logger.warning("sessions: project %s unreachable", project, exc_info=True)
                unreachable_projects.append(project)
                sessions = []
            all_sessions.extend(sessions)

        all_sessions.sort(key=lambda s: s.attested_at or datetime.min, reverse=True)

        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "sessions.html",
            {
                **ctx,
                "sessions": all_sessions,
                "filter_project": filter_project or "",
                "unreachable_projects": unreachable_projects,
            },
        )

    @app.get("/p/{project}/sessions/{session_id}")
    def session_detail_route(
        project: str,
        session_id: str,
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        gw = resolve_gateway(project, actor)
        try:
            detail = read_session_detail(gw, session_id, project)
        except Exception as exc:
            logger.warning(
                "session detail unreadable for %s/%s", project, session_id, exc_info=True
            )
            detail = unverifiable_session_detail(session_id, project, exc)
        if detail is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found")

        ctx = actor_context(request, actor)
        ctx["current_project"] = slug_to_project(project)
        return templates.TemplateResponse(
            request,
            "session_detail.html",
            {
                **ctx,
                "detail": detail,
                "project_slug": project,
                "session_id": session_id,
            },
        )

    # ---- review queue (Plan 018 WI-1.1) ----

    @app.get("/review")
    def review_queue_route(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        import logging

        logger = logging.getLogger("dossier.review_queue")
        all_entries: list[ReviewQueueEntry] = []

        for project in registry.list_projects():
            if not _can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                entries = read_review_queue(gw, project_to_slug(project))
            except Exception:
                logger.warning("review queue: project %s unreachable", project, exc_info=True)
                entries = []
            all_entries.extend(entries)

        all_entries.sort(
            key=lambda e: (
                0 if e.state == "in_human_review" else (1 if e.strict_gate else 2),
                -e.age_hours,
            ),
        )

        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "review_queue.html",
            {
                **ctx,
                "entries": all_entries,
            },
        )

    # ---- my work (Plan 018 WI-1.2) ----

    @app.get("/my-work")
    def my_work_route(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        import logging

        logger = logging.getLogger("dossier.my_work")
        all_entries: list[MyWorkEntry] = []

        for project in registry.list_projects():
            if not _can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                entries = read_my_work(gw, project_to_slug(project), actor.actor_id)
            except Exception:
                logger.warning("my work: project %s unreachable", project, exc_info=True)
                entries = []
            all_entries.extend(entries)

        grouped: dict[str, list[MyWorkEntry]] = {}
        for entry in all_entries:
            grouped.setdefault(entry.state, []).append(entry)
        state_order = [
            "in_review",
            "in_human_review",
            "in_progress",
            "open",
            "blocked",
            "deferred",
            "done",
        ]
        ordered_groups = [(state, grouped[state]) for state in state_order if state in grouped]
        for state in sorted(grouped):
            if state not in state_order:
                ordered_groups.append((state, grouped[state]))

        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "my_work.html",
            {
                **ctx,
                "groups": ordered_groups,
                "total_count": len(all_entries),
            },
        )

    # ---- activity feed (Plan 018 WI-1.3) ----

    @app.get("/feed")
    def activity_feed_route(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        filter_project: str | None = Query(default=None, alias="project"),
        filter_actor_kind: str | None = Query(default=None, alias="actor_kind"),
        filter_transition: str | None = Query(default=None, alias="transition"),
        page: int = Query(default=1, ge=1),
    ) -> Response:
        import logging

        logger = logging.getLogger("dossier.feed")
        page_size = 50
        all_entries: list[ActivityEntry] = []

        for project in registry.list_projects():
            if not _can_read_project(actor, project):
                continue
            if filter_project:
                slug = project_to_slug(project)
                if slug != filter_project:
                    continue
            try:
                gw = registry.get(project)
                entries = read_activity_feed(
                    gw,
                    project_to_slug(project),
                    limit=page_size * 3,
                    actor_kind_filter=filter_actor_kind,
                    transition_filter=filter_transition,
                )
            except Exception:
                logger.warning("feed: project %s unreachable", project, exc_info=True)
                entries = []
            all_entries.extend(entries)

        all_entries.sort(key=lambda e: e.timestamp, reverse=True)
        total = len(all_entries)
        start = (page - 1) * page_size
        end = start + page_size
        page_entries = all_entries[start:end]
        has_next = end < total

        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "activity_feed.html",
            {
                **ctx,
                "entries": page_entries,
                "filter_project": filter_project or "",
                "filter_actor_kind": filter_actor_kind or "",
                "filter_transition": filter_transition or "",
                "page": page,
                "has_next": has_next,
                "has_prev": page > 1,
                "total_count": total,
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
        import logging

        logger = logging.getLogger("dossier.work")
        gw = resolve_gateway(project, actor)
        ctx = actor_context(request, actor)
        ctx["current_project"] = slug_to_project(project)
        # The work store (list_issues) and the catalog entry (owner/display
        # name) are independent reads. A catalog failure must not hide
        # successfully fetched work — only a work-store failure renders the
        # explicit "unreachable" state; a catalog failure degrades the owner
        # chip to "unassigned" while the issue list is still shown.
        unreachable = False
        try:
            page = gw.list_issues(current_states=states, assignee=assignee)
            issues = list(page.items)
        except Exception:
            logger.warning("project_index: project %s unreachable", project, exc_info=True)
            issues = []
            unreachable = True
        try:
            catalog_entry = gw.get_project_catalog_entry()
        except Exception:
            logger.warning("project_index: catalog entry for %s unreadable", project, exc_info=True)
            catalog_entry = None
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                **ctx,
                "issues": issues,
                "filter_states": states or [],
                "filter_assignee": assignee or "",
                "project_slug": project,
                "catalog_entry": catalog_entry,
                "unreachable": unreachable,
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
            wi, _created_event = gw.create_issue(
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
        signing: str = "",
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        gw = resolve_gateway(project, actor)
        wi = gw.get_issue(work_item_id)
        if wi is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "issue not found")
        ctx = actor_context(request, actor)
        ctx["current_project"] = slug_to_project(project)
        return render_issue_detail(
            templates,
            request,
            gw,
            wi,
            project_slug=project,
            context=ctx,
            transitions=transitions_for(gw, wi),
            signing_downgraded=(
                gw.signing_identity(actor).reason
                if signing == "downgraded" and actor.actor_kind == "human"
                else None
            ),
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

        # WI-035: resolve the signing posture before the write so the outcome can
        # be reported whichever way it goes. ``gw.transition`` re-runs the check
        # and is the authority; this probe only decides what the operator sees.
        signing_posture = gw.signing_identity(actor)

        try:
            gw.transition(
                actor=actor,
                work_item_id=work_item_id,
                transition_name=transition_name,
                payload=payload,
            )
        except HumanSigningRefusedError as exc:
            # Rendered rather than handed to the global handler so the human sees
            # why their acceptance was not recorded, in the page they were on.
            logger.warning(
                "provenance.human_signature_refused",
                extra={
                    "actor_id": actor.actor_id,
                    "principal_id": actor.principal_id,
                    "transition": transition_name,
                    "reason": exc.identity.reason,
                    "outcome": exc.outcome.value,
                },
            )
            return _render_issue_detail_error(
                request,
                gw,
                project,
                work_item_id,
                actor,
                error=str(exc),
                status_code=status.HTTP_409_CONFLICT,
                headers={"X-Dossier-Human-Signing": "refused"},
            )
        except RegistaError as exc:
            return _render_issue_detail_error(
                request,
                gw,
                project,
                work_item_id,
                actor,
                error=exc.message,
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        try:
            wi_post = gw.get_issue(work_item_id)
            if wi_post is not None:
                events = gw.history(work_item_id)
                creator_id: str | None = None
                for ev in events:
                    if ev.transition == "created":
                        creator_id = ev.actor_id
                        break
                last_ev = events[-1] if events else None
                on_behalf_principal: str | None = None
                if last_ev is not None:
                    ob = event_delegation_claim(last_ev)
                    if ob is not None:
                        pid = ob.get("principal_id")
                        if pid:
                            on_behalf_principal = str(pid)
                notifier.emit_for_transition(
                    transition_name=transition_name,
                    to_state=wi_post.current_state,
                    project_slug=project,
                    work_item_id=work_item_id,
                    item_key=web.display_key(wi_post),
                    item_title=web.issue_title(wi_post),
                    assignee=web.issue_field(wi_post, "assignee", ""),
                    creator_id=creator_id,
                    on_behalf_principal=on_behalf_principal,
                )
        except Exception:
            logger.warning("notification.emit_error", exc_info=True)

        # The write happened but could only be sealed with the shared store key
        # (``human_signing="warn"``). Say so on the response *and* carry it into
        # the page the human lands on — a downgrade the operator never sees is the
        # failure mode WI-035 exists to remove.
        if actor.actor_kind == "human" and not signing_posture.per_actor:
            return RedirectResponse(
                url=f"/p/{project}/issues/{work_item_id}?signing=downgraded",
                status_code=status.HTTP_303_SEE_OTHER,
                headers={"X-Dossier-Human-Signing": "downgraded"},
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
            if not _can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                principal_key = gw.get_principal_key(actor.actor_id)
                if principal_key:
                    key_events = [
                        {
                            "transition": web.transition_label(getattr(ev, "transition", "")),
                            "timestamp": web.format_timestamp(getattr(ev, "timestamp", None)),
                            "key_id": (
                                ev.payload.get("key_id") if isinstance(ev.payload, dict) else None
                            ),
                            "fingerprint": (
                                ev.payload.get("fingerprint")
                                if isinstance(ev.payload, dict)
                                else None
                            ),
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
        if not _rotation_allowed(actor.actor_id):
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "rotation rate-limited; try again later",
            )

        private_key_dir = settings.principal_key_dir or None
        success_count = 0
        errors: list[str] = []
        for project in registry.list_projects():
            if not _can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                result = gw.rotate_principal(
                    actor.actor_id,
                    actor=actor,
                    private_key_dir=private_key_dir,
                )
                if not result:
                    errors.append(f"{project}: rotation returned no result")
                    continue
                success_count += 1
            except RegistaError as exc:
                if exc.code in (
                    ErrorCode.SECRET_WRITE_UNSUPPORTED,
                    ErrorCode.SECRET_WRITE_EXTERNAL,
                ):
                    raise HTTPException(
                        status.HTTP_400_BAD_REQUEST,
                        exc.message,
                    )
                errors.append(f"{project}: {type(exc).__name__}")
            except Exception as exc:
                errors.append(f"{project}: {type(exc).__name__}")

        if errors:
            logger.warning(
                "key.rotation_partial_failure",
                extra={
                    "actor_id": actor.actor_id,
                    "success_count": success_count,
                    "errors": errors,
                },
            )

        if success_count == 0:
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "key rotation failed")

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
            if not _can_read_project(actor, project):
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
                        signed_events.append(
                            {
                                "timestamp": web.format_timestamp(
                                    getattr(event, "timestamp", None)
                                ),
                                "project_slug": slug,
                                "issue_url": f"/p/{slug}/issues/{wi.work_item_id}",
                                "display_key": web.display_key(wi),
                                "title": web.issue_title(wi),
                                "transition": web.transition_label(
                                    getattr(event, "transition", "")
                                ),
                                "verified": verified,
                            }
                        )
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

    # ---- notification preferences (Plan 018 WI-2.2 / GJ-7) ----

    def _preference_rows(actor: Actor) -> list[dict[str, Any]]:
        preference = app.state.preference_store.get(actor.actor_id)
        rows: list[dict[str, Any]] = []
        for ec in EVENT_CLASSES:
            rows.append(
                {
                    "event_type": ec.event_type,
                    "label": ec.label,
                    "description": ec.description,
                    "default_routing": ec.default_routing,
                    "enabled": preference.is_enabled(ec.event_type),
                    "routing": preference.routing_for(ec.event_type),
                    "is_recovery": ec.event_type == "chain_verify_failed",
                }
            )
        return rows

    @app.get("/me/notifications")
    def my_notifications(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        ctx = actor_context(request, actor)
        ctx["preference_rows"] = _preference_rows(actor)
        ctx["sink_configured"] = app.state.notifier.configured
        return templates.TemplateResponse(
            request,
            "my_notifications.html",
            ctx,
        )

    @app.post("/me/notifications", response_model=None)
    async def save_notifications(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        _: None = Depends(verify_csrf),
    ) -> Response:
        form = await request.form()
        enabled: dict[str, bool] = {}
        routing: dict[str, str] = {}
        for ec in EVENT_CLASSES:
            # A checkbox is present in the POST body only when checked, so
            # absence means the principal opted out of that class.
            enabled[ec.event_type] = f"{ec.event_type}_enabled" in form
            routing[ec.event_type] = str(form.get(f"{ec.event_type}_routing", ec.default_routing))
        app.state.preference_store.save(
            actor.actor_id,
            NotificationPreference(principal_id=actor.actor_id, enabled=enabled, routing=routing),
        )
        return RedirectResponse(
            url="/me/notifications",
            status_code=status.HTTP_303_SEE_OTHER,
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
            if not _can_read_project(actor, project):
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

        # Determine whether any accessible project has a durable lifecycle
        # backend — if so, the legacy in-process enrollment form is not a
        # supported production control and the template says so plainly.
        has_durable_lifecycle = False
        for project in registry.list_projects():
            if not _can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                if gw.has_lifecycle_ops():
                    has_durable_lifecycle = True
                    break
            except Exception:
                pass

        ctx["principals"] = all_principals
        ctx["has_durable_lifecycle"] = has_durable_lifecycle
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
            if not _can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                result = gw.enroll_principal(
                    principal_id,
                    actor=actor,
                    private_key_dir=private_key_dir,
                )
                if result:
                    success_count += 1
            except RegistaError as exc:
                if exc.code in (
                    ErrorCode.SECRET_WRITE_UNSUPPORTED,
                    ErrorCode.SECRET_WRITE_EXTERNAL,
                ):
                    raise HTTPException(
                        status.HTTP_400_BAD_REQUEST,
                        "in-process enrollment is disabled: it generates "
                        "private key material in the web process. Use the "
                        "client-signer enrollment flow "
                        "(POST /admin/p/{project}/lifecycle/enroll/prepare)",
                    )
                errors.append(f"{project}: {type(exc).__name__}")
            except Exception as exc:
                errors.append(f"{project}: {type(exc).__name__}")

        if errors:
            logger.warning(
                "key.enrollment_partial_failure",
                extra={
                    "principal_id": principal_id,
                    "actor_id": actor.actor_id,
                    "success_count": success_count,
                    "errors": errors,
                },
            )

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
        form = await request.form()
        reason = " ".join(str(form.get("reason", "")).strip().split())
        if not reason:
            reason = "revoked by admin"
        if len(reason) > 500:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "reason must be 500 characters or fewer"
            )

        prepared: list[dict[str, Any]] = []
        errors: list[str] = []
        fallback_revoked: list[str] = []
        for project in registry.list_projects():
            if not _can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                key_info = gw.get_principal_key(principal_id)
                if key_info is None:
                    continue
                if gw.has_lifecycle_ops():
                    operation = gw.prepare_revocation_operation(
                        principal_id,
                        key_info["key_id"],
                        actor=actor,
                        reason=reason,
                    )
                    prepared.append(
                        {
                            **operation,
                            "project": project,
                            "project_slug": project_to_slug(project),
                        }
                    )
                else:
                    gw.revoke_principal(
                        principal_id,
                        key_info["key_id"],
                        reason=reason,
                    )
                    fallback_revoked.append(project)
            except LifecycleContractError as exc:
                errors.append(f"{project}: {exc.message}")
            except RegistaError as exc:
                errors.append(f"{project}: {exc.message}")
            except Exception as exc:
                errors.append(f"{project}: {type(exc).__name__}")

        if not prepared and not fallback_revoked:
            if errors:
                detail = errors[0] if errors else "principal revocation failed"
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail)
            raise HTTPException(status.HTTP_404_NOT_FOUND, "principal not found")

        if fallback_revoked and not prepared:
            return RedirectResponse(url="/admin/principals", status_code=status.HTTP_303_SEE_OTHER)

        if _wants_html(request):
            ctx = actor_context(request, actor)
            ctx["principal_id"] = principal_id
            ctx["operations"] = prepared
            ctx["errors"] = errors
            return templates.TemplateResponse(
                request,
                "lifecycle_pending.html",
                ctx,
            )
        return JSONResponse({"operations": prepared, "errors": errors})

    # ---- break-glass (Plan 015 WI-2.3) ----
    #
    # Break-glass registration of a new signing key requires a client-side
    # possession proof from a key-custody helper that does not exist yet.  Until
    # that helper lands, the web process must not generate or hold private keys.
    # The honest first-increment behavior is to fail closed with a clear
    # "not yet available" response rather than simulate dual control with a
    # soft confirmer_id text field.

    @app.get("/admin/break-glass")
    def break_glass_form(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        require_admin(actor)
        ctx = actor_context(request, actor)
        ctx["not_available"] = True
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
        message = (
            "break-glass key registration is not yet available: it requires the "
            "key-custody signing helper that produces a client-side possession "
            "proof without the web process holding private keys"
        )
        if _wants_html(request):
            ctx = actor_context(request, actor)
            ctx["not_available"] = True
            ctx["not_available_message"] = message
            return templates.TemplateResponse(
                request,
                "break_glass.html",
                ctx,
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
            )
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, message)

    @app.post("/admin/p/{project}/lifecycle/{operation_id}/approve", response_model=None)
    async def approve_lifecycle_operation(
        project: str,
        operation_id: str,
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        _: None = Depends(verify_csrf),
    ) -> Response:
        require_admin(actor)
        gw = resolve_gateway(project, actor)
        form = await request.form()
        approval_reason = str(form.get("reason", "")).strip()
        form_digest = str(form.get("approval_digest", "")).strip()

        if not form_digest:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "approval_digest is required: confirm the exact operation you "
                "are approving by submitting its digest",
            )

        try:
            operation = gw.principal_lifecycle.get_operation(operation_id)
        except LifecycleContractError as exc:
            _handle_lifecycle_error(exc)
        server_digest = operation.digest.value
        if not hmac.compare_digest(form_digest, server_digest):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "approval digest does not match the server operation",
            )

        # Step-up (Plan 020 Phase 3): key-lifecycle approvals are protected
        # operations and require recent authentication. A fresh login counts;
        # an old session must re-authenticate via POST /auth/step-up.
        #
        # Trust model: the enforcement gate is *recency of authentication*
        # (from the server-signed session); the evidence is the audit artifact
        # of that gate, bound to this exact operation digest and approver.
        # Evidence is produced AND verified server-side in one step — the
        # verifier stays live on the enforcement path, and there is no
        # client-supplied-evidence parameter to misuse.
        protected_op = _PROTECTED_OP_FOR_LIFECYCLE.get(operation.operation_type.value)
        if protected_op is None:
            # A lifecycle operation type with no protected-operation mapping
            # is a code defect, not a "not protected" answer: fail closed.
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                f"no protected-operation mapping for lifecycle operation "
                f"{operation.operation_type.value!r}",
            )
        step_up_json: str | None = None
        if requires_step_up(protected_op.value):
            auth_time = _session_auth_time(request)
            if auth_time is None or not is_auth_recent(auth_time):
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    "step-up authentication required: re-authenticate via "
                    "POST /auth/step-up before approving this operation",
                )
            evidence = produce_step_up_evidence(
                settings.session_secret,
                auth_time,
                server_digest,
                actor.actor_id,
            )
            valid, verify_error = verify_step_up_evidence(
                settings.session_secret,
                evidence,
                expected_operation_digest=server_digest,
                expected_principal_id=actor.actor_id,
            )
            if not valid:
                # Produce/verify disagreeing in one process is a server-side
                # defect; it must never surface as an approval.
                raise HTTPException(
                    status.HTTP_500_INTERNAL_SERVER_ERROR,
                    f"step-up evidence self-check failed: {verify_error}",
                )
            step_up_json = json.dumps(evidence.to_dict())

        try:
            gw.approve_operation(
                operation_id,
                approver=actor,
                approval_digest=server_digest,
                step_up_evidence=step_up_json,
                reason=approval_reason,
            )
        except LifecycleContractError as exc:
            _handle_lifecycle_error(exc)
        try:
            gw.commit_operation(operation_id, expected_digest=server_digest)
        except LifecycleContractError as exc:
            _handle_lifecycle_error(exc)
        if _wants_html(request):
            return RedirectResponse(url="/admin/principals", status_code=status.HTTP_303_SEE_OTHER)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    # ---- client-signer lifecycle exchange (Plan 031 §5 / Plan 015 v1) ----
    #
    # The web process never generates or holds private keys. The client signer
    # (`regista signer …`) generates the keypair, custodies the private key,
    # and signs the challenges these endpoints issue; dossier initiates and
    # approves. Each endpoint accepts and returns the same versioned JSON the
    # signer CLI emits, so an operator pipes CLI output straight to curl
    # (after `GET /csrf`, sending the token as the X-CSRF-Token header).

    @app.post("/admin/p/{project}/lifecycle/enroll/prepare", response_model=None)
    async def prepare_enrollment_with_key_route(
        project: str,
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        _: None = Depends(verify_csrf),
    ) -> Response:
        require_admin(actor)
        gw = resolve_gateway(project, actor)
        body = _require_json_object(await _read_json(request))
        principal_id = _require_str(body, "principal_id")
        try:
            _validate_principal_id(principal_id)
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
        public_key = _decode_public_key(_require_str(body, "public_key"))
        principal_kind = _parse_principal_kind(body)
        custody_mode = _parse_custody_mode(body)
        reason = _optional_str(body, "reason") or "initial enrollment"
        try:
            result = gw.prepare_enrollment_with_key(
                principal_id,
                public_key,
                actor=actor,
                principal_kind=principal_kind,
                custody_mode=custody_mode,
                reason=reason,
            )
        except LifecycleContractError as exc:
            _handle_lifecycle_error(exc)
        return JSONResponse(result)

    @app.post("/admin/p/{project}/lifecycle/rotate/prepare", response_model=None)
    async def prepare_rotation_with_key_route(
        project: str,
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        _: None = Depends(verify_csrf),
    ) -> Response:
        require_admin(actor)
        gw = resolve_gateway(project, actor)
        body = _require_json_object(await _read_json(request))
        principal_id = _require_str(body, "principal_id")
        try:
            _validate_principal_id(principal_id)
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
        public_key = _decode_public_key(_require_str(body, "public_key"))
        old_key_id = _require_str(body, "old_key_id")
        principal_kind = _parse_principal_kind(body)
        custody_mode = _parse_custody_mode(body)
        reason = _optional_str(body, "reason") or "key rotation"
        try:
            result = gw.prepare_rotation_with_key(
                principal_id,
                public_key,
                old_key_id,
                actor=actor,
                principal_kind=principal_kind,
                custody_mode=custody_mode,
                reason=reason,
            )
        except LifecycleContractError as exc:
            _handle_lifecycle_error(exc)
        return JSONResponse(result)

    @app.post("/admin/p/{project}/lifecycle/{operation_id}/possession", response_model=None)
    async def submit_possession_proof_route(
        project: str,
        operation_id: str,
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        _: None = Depends(verify_csrf),
    ) -> Response:
        require_admin(actor)
        gw = resolve_gateway(project, actor)
        body = _require_json_object(await _read_json(request))
        proof = _parse_possession_proof(body)
        if proof.operation_id != operation_id:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "proof operation_id does not match the request path",
            )
        try:
            result = gw.submit_possession_proof(operation_id, proof)
        except LifecycleContractError as exc:
            _handle_lifecycle_error(exc)
        return JSONResponse(result)

    @app.post(
        "/admin/p/{project}/lifecycle/{operation_id}/rotation-authorization",
        response_model=None,
    )
    async def submit_rotation_authorization_route(
        project: str,
        operation_id: str,
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        _: None = Depends(verify_csrf),
    ) -> Response:
        """Submit the superseded key's detached signature for a rotation."""
        require_admin(actor)
        gw = resolve_gateway(project, actor)
        body = _require_json_object(await _read_json(request))
        signature = _decode_b64(_require_str(body, "old_key_signature"), "old_key_signature")
        try:
            result = gw.submit_rotation_authorization(operation_id, signature)
        except LifecycleContractError as exc:
            _handle_lifecycle_error(exc)
        return JSONResponse(result)

    @app.post(
        "/admin/p/{project}/lifecycle/{operation_id}/effective-challenge",
        response_model=None,
    )
    async def issue_effective_challenge_route(
        project: str,
        operation_id: str,
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        _: None = Depends(verify_csrf),
    ) -> Response:
        require_admin(actor)
        gw = resolve_gateway(project, actor)
        try:
            challenge = gw.issue_effective_challenge(operation_id)
        except LifecycleContractError as exc:
            _handle_lifecycle_error(exc)
        return JSONResponse(challenge)

    @app.post(
        "/admin/p/{project}/lifecycle/{operation_id}/effective-receipt",
        response_model=None,
    )
    async def record_effective_receipt_route(
        project: str,
        operation_id: str,
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        _: None = Depends(verify_csrf),
    ) -> Response:
        require_admin(actor)
        gw = resolve_gateway(project, actor)
        body = _require_json_object(await _read_json(request))
        receipt = _parse_effective_receipt(body)
        if receipt.operation_id != operation_id:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "receipt operation_id does not match the request path",
            )
        try:
            result = gw.record_effective_receipt(operation_id, receipt)
        except LifecycleContractError as exc:
            _handle_lifecycle_error(exc)
        return JSONResponse(result)

    # ---- evidence area (Plan 024 Phase 2) ----

    @app.get("/evidence")
    def evidence_index(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        import logging

        logger = logging.getLogger("dossier.evidence")
        all_summaries: list[EvidenceSummary] = []
        all_verifications: list[EventVerification] = []

        for project in registry.list_projects():
            if not _can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                slug = project_to_slug(project)
                summary = read_evidence_summary(gw, slug)
                all_summaries.append(summary)
                verifications = read_event_verifications(gw, limit=50)
                all_verifications.extend(verifications)
            except Exception:
                logger.warning("evidence: project %s unreachable", project, exc_info=True)

        all_verifications.sort(key=lambda v: v.timestamp, reverse=True)
        all_verifications = all_verifications[:100]

        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "evidence_index.html",
            {
                **ctx,
                "summaries": all_summaries,
                "verifications": all_verifications,
            },
        )

    @app.get("/evidence/integrity")
    def evidence_integrity_route(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        import logging

        logger = logging.getLogger("dossier.evidence")
        all_reports: list[dict[str, Any]] = []

        for project in registry.list_projects():
            if not _can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                report = read_integrity_report(gw)
                report["project_slug"] = project_to_slug(project)
                all_reports.append(report)
            except Exception:
                logger.warning("evidence/integrity: project %s unreachable", project, exc_info=True)

        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "evidence_integrity.html",
            {
                **ctx,
                "reports": all_reports,
            },
        )

    @app.get("/evidence/events")
    def evidence_events_route(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        import logging

        logger = logging.getLogger("dossier.evidence")
        all_verifications: list[EventVerification] = []

        for project in registry.list_projects():
            if not _can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                verifications = read_event_verifications(gw, limit=100)
                all_verifications.extend(verifications)
            except Exception:
                logger.warning("evidence/events: project %s unreachable", project, exc_info=True)

        all_verifications.sort(key=lambda v: v.timestamp, reverse=True)

        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "evidence_events.html",
            {
                **ctx,
                "verifications": all_verifications,
            },
        )

    # ---- operations area (Plan 024 Phase 4) ----

    @app.get("/operations")
    def operations_index(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        import logging

        logger = logging.getLogger("dossier.operations")
        all_estates: list[EstateSummary] = []
        all_findings: list[Any] = []

        for project in registry.list_projects():
            if not _can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                slug = project_to_slug(project)
                estate = read_estate_summary(gw, slug)
                all_estates.append(estate)
                findings = read_operations_findings(gw)
                all_findings.extend(findings)
            except Exception:
                logger.warning("operations: project %s unreachable", project, exc_info=True)

        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "operations_index.html",
            {
                **ctx,
                "estates": all_estates,
                "findings": all_findings,
            },
        )

    # ---- administration area (Plan 024 Phase 3) ----

    @app.get("/admin")
    def admin_index(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        require_admin(actor)
        import logging

        logger = logging.getLogger("dossier.admin")
        all_summaries: list[AdminSummary] = []

        for project in registry.list_projects():
            if not _can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                slug = project_to_slug(project)
                summary = read_admin_summary(
                    gw,
                    actor,
                    _is_admin(actor),
                    project_slug=slug,
                )
                all_summaries.append(summary)
            except Exception:
                logger.warning("admin: project %s unreachable", project, exc_info=True)

        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "admin_index.html",
            {
                **ctx,
                "summaries": all_summaries,
            },
        )

    @app.get("/admin/projects")
    def admin_projects_route(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        require_admin(actor)
        import logging

        logger = logging.getLogger("dossier.admin")
        all_projects: list[Any] = []

        for project in registry.list_projects():
            if not _can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                projects = read_project_list(gw)
                for p in projects:
                    all_projects.append((project_to_slug(project), p))
            except Exception:
                logger.warning("admin/projects: project %s unreachable", project, exc_info=True)

        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "admin_projects.html",
            {
                **ctx,
                "project_rows": all_projects,
            },
        )

    @app.get("/admin/access")
    def admin_access_route(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        require_admin(actor)
        import logging

        logger = logging.getLogger("dossier.admin")
        all_policies: list[Any] = []

        for project in registry.list_projects():
            if not _can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                slug = project_to_slug(project)
                policy = read_access_policy(
                    gw,
                    slug,
                    actor=actor,
                    is_admin=_is_admin(actor),
                    admin_ids=tuple(sorted(_ADMIN_ACTOR_IDS)),
                )
                all_policies.append(policy)
            except Exception:
                logger.warning("admin/access: project %s unreachable", project, exc_info=True)

        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "admin_access.html",
            {
                **ctx,
                "policies": all_policies,
            },
        )

    # ---- activity area (Plan 024 Phase 2 — enhanced index) ----

    @app.get("/activity")
    def activity_index(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        import logging

        logger = logging.getLogger("dossier.activity")
        all_sessions: list[SessionSummary] = []
        all_entries: list[ActivityEntry] = []
        unreachable_projects: list[str] = []

        for project in registry.list_projects():
            if not _can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                slug = project_to_slug(project)
                sessions = read_session_summaries(gw, slug)
                all_sessions.extend(sessions)
                entries = read_activity_feed(gw, slug, limit=50)
                all_entries.extend(entries)
            except Exception:
                logger.warning("activity: project %s unreachable", project, exc_info=True)
                unreachable_projects.append(project)

        all_sessions.sort(key=lambda s: s.attested_at or datetime.min, reverse=True)
        all_entries.sort(key=lambda e: e.timestamp, reverse=True)
        all_entries = all_entries[:100]

        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "activity_index.html",
            {
                **ctx,
                "sessions": all_sessions,
                "entries": all_entries,
                "session_count": len(all_sessions),
                "entry_count": len(all_entries),
                "unreachable_projects": unreachable_projects,
            },
        )

    # ---- knowledge area (Plan 024 Phase 1 + Plan 009) ----

    @app.get("/knowledge")
    def knowledge_index(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        import logging

        logger = logging.getLogger("dossier.knowledge")
        all_notes: list[NoteSummary] = []
        unreachable_projects: list[str] = []

        for project in registry.list_projects():
            if not _can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                notes = list_notes(gw, limit=100)
                all_notes.extend(notes)
            except Exception:
                logger.warning("knowledge: project %s unreachable", project, exc_info=True)
                unreachable_projects.append(project)

        all_notes.sort(key=lambda n: n.updated_at, reverse=True)

        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "knowledge_index.html",
            {
                **ctx,
                "notes": all_notes,
                "note_count": len(all_notes),
                "unreachable_projects": unreachable_projects,
            },
        )

    @app.get("/knowledge/search")
    def knowledge_search(
        request: Request,
        q: str = Query("", alias="q"),
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        import logging

        logger = logging.getLogger("dossier.knowledge")
        all_results: list[NoteSummary] = []
        unreachable_projects: list[str] = []

        if q.strip():
            for project in registry.list_projects():
                if not _can_read_project(actor, project):
                    continue
                try:
                    gw = registry.get(project)
                    results = search_notes(gw, q, limit=50)
                    all_results.extend(results)
                except Exception:
                    logger.warning(
                        "knowledge/search: project %s unreachable",
                        project,
                        exc_info=True,
                    )
                    unreachable_projects.append(project)

        all_results.sort(key=lambda n: n.updated_at, reverse=True)

        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "knowledge_search.html",
            {
                **ctx,
                "results": all_results,
                "query": q,
                "result_count": len(all_results),
                "unreachable_projects": unreachable_projects,
            },
        )

    @app.get("/knowledge/new")
    def knowledge_new(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "knowledge_new.html",
            {**ctx},
        )

    @app.get("/knowledge/{note_id}")
    def knowledge_detail(
        request: Request,
        note_id: str,
        actor: Actor = Depends(current_actor_or_redirect),
    ) -> Response:
        import logging

        logger = logging.getLogger("dossier.knowledge")
        detail: NoteDetail | None = None
        verification: dict[str, Any] = {}

        for project in registry.list_projects():
            if not _can_read_project(actor, project):
                continue
            try:
                gw = registry.get(project)
                detail = get_note(gw, note_id)
                if detail is not None:
                    verification = verify_note(gw, note_id)
                    break
            except Exception:
                logger.warning("knowledge/detail: project %s unreachable", project, exc_info=True)

        if detail is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "note not found")

        ctx = actor_context(request, actor)
        return templates.TemplateResponse(
            request,
            "knowledge_detail.html",
            {
                **ctx,
                "note": detail,
                "verification": verification,
            },
        )

    @app.post("/knowledge/create", response_model=None)
    async def knowledge_create(
        request: Request,
        actor: Actor = Depends(current_actor_or_redirect),
        _: None = Depends(verify_csrf),
    ) -> Response:
        form = await request.form()
        title = str(form.get("title", "")).strip()[:200]
        body = str(form.get("body", "")).strip()[:10000]
        if not title:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "title is required")

        gw: RegistaGateway | None = None
        for project in registry.list_projects():
            if _can_read_project(actor, project):
                gw = registry.get(project)
                break
        if gw is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "no accessible project available",
            )

        note_id = create_note(gw, actor=actor, title=title, body=body)
        return RedirectResponse(
            url=f"/knowledge/{note_id}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    return app
