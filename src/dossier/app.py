from __future__ import annotations

from dataclasses import asdict

from fastapi import Body, Depends, FastAPI, HTTPException, Request, status

from .actors import Actor
from .auth.backends import AuthBackend
from .auth.resolver import principal_to_actor
from .auth.sessions import issue_csrf_token, session_middleware, verify_csrf
from .config import Settings
from .gateway import RegistaGateway

_ACTOR_SESSION_KEY = "actor"


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

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    @app.get("/csrf")
    def get_csrf(request: Request) -> dict:
        token = issue_csrf_token(request.session)
        return {"csrf_token": token}

    @app.post("/login")
    async def login(
        request: Request,
        payload: dict = Body(...),
        _: None = Depends(verify_csrf),
    ) -> dict:
        username = payload.get("username", "")
        password = payload.get("password", "")
        principal = backend.authenticate(username, password)
        if principal is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
        actor = principal_to_actor(principal)
        request.session.clear()
        new_csrf = issue_csrf_token(request.session)
        request.session[_ACTOR_SESSION_KEY] = asdict(actor)
        return {
            "actor_id": actor.actor_id,
            "display_name": actor.display_name,
            "csrf_token": new_csrf,
        }

    @app.post("/logout")
    def logout(request: Request, _: None = Depends(verify_csrf)) -> dict:
        request.session.clear()
        return {"ok": True}

    @app.get("/me")
    def me(actor: Actor = Depends(current_actor)) -> dict:
        return asdict(actor)

    return app
