from __future__ import annotations

import hmac
import secrets

from fastapi import HTTPException, Request, status
from starlette.middleware.sessions import SessionMiddleware

_CSRF_SESSION_KEY = "csrf_token"


def session_middleware(settings) -> type[SessionMiddleware]:
    """Build a configured ``SessionMiddleware`` subclass from ``settings``.

    The session cookie is ``HttpOnly`` + ``SameSite=Lax`` always, and ``Secure``
    when ``settings.secure_cookies`` is true. ``secure_cookies=False`` is
    dev-only (local without TLS); never set it false in production.
    """

    class _ConfiguredSessionMiddleware(SessionMiddleware):
        def __init__(self, app) -> None:
            super().__init__(
                app,
                secret_key=settings.session_secret,
                max_age=settings.session_max_age_seconds,
                same_site="lax",
                https_only=settings.secure_cookies,
            )

    return _ConfiguredSessionMiddleware


def issue_csrf_token(session: dict) -> str:
    """Get-or-create the per-session CSRF token (double-submit pattern).

    Stored in the signed session so it cannot be read or forged by the client
    except through the session cookie itself. Stable for the session lifetime.
    """
    token = session.get(_CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[_CSRF_SESSION_KEY] = token
    return token


async def verify_csrf(request: Request) -> None:
    """Validate the double-submit CSRF token on state-changing requests.

    Reads the submitted token from the ``X-CSRF-Token`` header, falling back to
    a ``csrf_token`` form field. Compares against the session token with
    :func:`hmac.compare_digest`. Raises 403 on mismatch or if no token has been
    issued (the client must call ``GET /csrf`` first).
    """
    expected = request.session.get(_CSRF_SESSION_KEY)
    if not expected:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "csrf token not issued")
    submitted = request.headers.get("X-CSRF-Token")
    if not submitted:
        form = await request.form()
        submitted = form.get("csrf_token")
    if not submitted or not hmac.compare_digest(str(expected), str(submitted)):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "csrf token mismatch")
