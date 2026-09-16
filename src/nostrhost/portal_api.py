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
from typing import Any, Callable

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response
from fastapi.routing import APIRoute
from starlette.responses import PlainTextResponse

from nostrhost import web

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
        web.response.status = 400
        return {"path": "fullname", "error": "Full name must be at least 2 characters."}

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


class _WebRoute(APIRoute):
    """Binds the per-request context, drains queued cookies/status onto the
    response, and maps a raised ``web.HTTPResponse`` / unexpected exception to
    a response (every portal route is public; there is no authorizer here)."""

    def get_route_handler(self) -> Callable[[Request], Any]:
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            token = web.begin(request)
            try:
                request.state.body_bytes = await request.body()
                try:
                    response = await original(request)
                except web.HTTPResponse as exc:
                    response = exc.to_response()
                except Exception:  # noqa: BLE001 - last error boundary
                    logger.exception("unhandled error on %s %s", request.method, request.url.path)
                    response = PlainTextResponse("internal server error", status_code=500)
                status = web.get_status()
                if status is not None and isinstance(response, Response):
                    response.status_code = status
                return web.apply_cookies(response)
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
