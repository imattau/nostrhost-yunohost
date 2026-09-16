"""NostrHost portal-api server (authd + portal Nostr sign-in, 127.0.0.1:6788).

The Caddy ``forward_auth`` front ends for native ``web.route`` resources point
at ``/nostr/auth-request`` on this server, and the portal proxies
``/nostrhost/portalapi/*`` here for the Nostr sign-in + identity routes (the
routes the legacy moulinette ``portalapi`` entry point used to serve before
the framework was retired).  The OIDC compatibility endpoints ride along.

Runs as a low-privilege user (ynh-portal) on the loopback; every route here
is public by design (the authd authorizes against the session + the native
permission projection itself).
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response
from fastapi.routing import APIRoute
from starlette.responses import JSONResponse, PlainTextResponse

from nostrhost import problems, web

logger = logging.getLogger("nostr-portal-api")


def update_route():
    """PUT /nostrhost/portalapi/update — self-service fullname edit.

    Nostr-only sign-in has no password to change; this only lets a signed-in
    user update their own display name. Writes the account store directly
    (no lifecycle/approval chain — the native ``user.update`` tool is
    admin-gated and NIP-98-signed, which the session-cookie-only portal
    caller cannot produce).
    """
    from yunohost.nostr_account import _session_username
    from yunohost.nostrhost.accounts import save_users, user_get, users

    username = _session_username()
    if not username:
        raise web.HTTPResponse("not signed in", 401)

    payload = web.request.json or {}
    fullname = (payload.get("fullname") or "").strip()
    if len(fullname) < 2:
        # Raised web.HTTPResponse carries no JSON body, and the portal client
        # reads error.value.data.path / .error — return a real JSON 400 (sync
        # routes run in a threadpool, so the web.response.status override is
        # lost: the response status must ride on the Response itself).
        return JSONResponse(
            {"path": "fullname", "error": "Full name must be at least 2 characters."},
            status_code=400,
        )

    record = user_get(username) or {}
    record["fullname"] = fullname
    all_users = users()
    all_users[username] = record
    save_users(all_users)

    return {"fullname": fullname}


def logout_route():
    """GET /nostrhost/portalapi/logout — clear the portal session.

    Deletes the session file + the nostrhost.portal cookie so the user is
    signed out of the portal (and, transitively, the admin console which
    authenticates through the same session). Always returns ok (idempotent).
    """
    try:
        from yunohost.authenticators.ldap_ynhuser import Authenticator

        Authenticator().delete_session_cookie()
    except Exception as exc:  # noqa: BLE001 - session may already be gone
        logger.warning("logout session cleanup failed: %s", exc)
    return {"ok": True}


_CLIENT_REPORT_APPS = ("portal", "admin")
_CLIENT_REPORT_MAX_BYTES = 16_384


def client_error_report_route():
    """POST /nostrhost/portalapi/report — bounded client-side error report.

    The portal/admin SPAs capture window errors, unhandled rejections and Vue
    render/component errors and post them here (batched). Each event lands in
    the structured problem log (kind=client, source=portal) so the
    ``logs.problems`` introspection tool can diagnose SPA render/JS failures.
    Public by design (errors occur before/without sign-in); the payload is
    size-bounded and message/stack are policy-redacted on write.
    """
    from nostrhost import problems

    request = web.current_request()
    if len(getattr(request.state, "body_bytes", b"")) > _CLIENT_REPORT_MAX_BYTES:
        raise web.HTTPResponse("report too large", 413)
    try:
        payload = web.request.json or {}
    except Exception:  # noqa: BLE001 - malformed body
        payload = {}
    if not isinstance(payload, dict):
        raise web.HTTPResponse("malformed report", 400)
    events = payload.get("events")
    if isinstance(events, list):
        events = [e for e in events[:50] if isinstance(e, dict)]
    elif isinstance(payload.get("message"), str):
        events = [payload]
    else:
        events = []
    if not events:
        raise web.HTTPResponse("empty report", 400)
    for event in events:
        app_name = str(event.get("app") or "portal")
        if app_name not in _CLIENT_REPORT_APPS:
            app_name = "portal"
        message = str(event.get("message") or "")[:2000]
        stack = str(event.get("stack") or "")[:8000]
        route = str(event.get("route") or "")[:500]
        if not message and not stack:
            continue
        problems.record(
            request,
            status=None,
            code="client_error",
            message=f"{app_name} SPA error{(' at ' + route) if route else ''}: {message}",
            kind="client",
            source="portal",
        )
    return {"ok": True}


class _WebRoute(APIRoute):
    """Binds the per-request context, drains queued cookies/status onto the
    response, and maps a raised ``web.HTTPResponse`` / unexpected exception to
    a response (every portal route is public; there is no authorizer here)."""

    def get_route_handler(self) -> Callable[[Request], Any]:
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            token = web.begin(request)
            started = time.perf_counter()
            error_exc: BaseException | None = None
            try:
                request.state.body_bytes = await request.body()
                try:
                    response = await original(request)
                except web.HTTPResponse as exc:
                    response = exc.to_response()
                    error_exc = exc
                except Exception as exc:  # noqa: BLE001 - last error boundary
                    logger.exception(
                        "unhandled error on %s %s (rid=%s)",
                        request.method,
                        request.url.path,
                        problems.request_id(request),
                    )
                    response = PlainTextResponse("internal server error", status_code=500)
                    error_exc = exc
                status = web.get_status()
                if status is not None and isinstance(response, Response):
                    response.status_code = status
                return problems.finalize(
                    web.apply_cookies(response),
                    request,
                    started=started,
                    exc=error_exc,
                    kind="render" if isinstance(error_exc, Exception) and getattr(response, "status_code", 0) >= 500 else "portal",
                    source="portal",
                )
            finally:
                web.end(token)

        return handler


def build_app() -> FastAPI:
    """Build the portal-api FastAPI app with the authd + Nostr routes."""
    from yunohost.nostr_account import (
        identities_route,
        link_challenge_route,
        link_route,
        nip05_route,
        register_signer_route,
        rename_route,
        revoke_route,
        revoke_signer_route,
        signers_route,
        unlink_route,
    )
    from yunohost.nostr_login import auth_request_route, challenge_route, login_route
    from yunohost.nostr_oidc import authorize, discovery, jwks, token, userinfo
    from yunohost.nostrhost.portal_settings import portal_me_route, portal_public_route

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.router.route_class = _WebRoute

    app.get("/public")(portal_public_route)
    app.get("/me")(portal_me_route)
    app.put("/update")(update_route)
    app.get("/logout")(logout_route)
    app.post("/report")(client_error_report_route)
    app.get("/nostr/challenge")(challenge_route)
    app.post("/nostr/login")(login_route)
    app.get("/nostr/auth-request")(auth_request_route)
    app.get("/nostr/identities")(identities_route)
    app.post("/nostr/link/challenge")(link_challenge_route)
    app.post("/nostr/link")(link_route)
    app.post("/nostr/identities/revoke")(revoke_route)
    app.post("/nostr/identities/rename")(rename_route)
    app.post("/nostr/unlink")(unlink_route)
    app.get("/nostr/signers")(signers_route)
    app.post("/nostr/signers")(register_signer_route)
    app.post("/nostr/signers/revoke")(revoke_signer_route)
    app.get("/.well-known/nostr.json")(nip05_route)
    app.get("/.well-known/openid-configuration")(discovery)
    app.get("/oidc/authorize")(authorize)
    app.post("/oidc/token")(token)
    app.get("/oidc/userinfo")(userinfo)
    app.get("/oidc/jwks.json")(jwks)

    return app


def run(host: str = "127.0.0.1", port: int = 6788, *, app: FastAPI | None = None) -> None:
    """Serve the portal-api (used by bin/nostr-portal-api)."""
    uvicorn.run(app or build_app(), host=host, port=port, log_level="info")


if __name__ == "__main__":  # pragma: no cover - exercised through bin/nostr-portal-api
    run()
