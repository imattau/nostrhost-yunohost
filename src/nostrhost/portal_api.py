"""NostrHost portal-api server (authd + portal Nostr sign-in, 127.0.0.1:6788).

The Caddy ``forward_auth`` front ends for native ``web.route`` resources point
at ``/nostr/auth-request`` on this server, and the portal proxies
``/yunohost/portalapi/*`` here for the Nostr sign-in + identity routes (the
routes the legacy moulinette ``portalapi`` entry point used to serve before
the framework was retired).  The OIDC compatibility endpoints ride along.

Runs as a low-privilege user (ynh-portal) on the loopback; every route here
is public by design (the authd authorizes against the session + the native
permission projection itself).
"""

from __future__ import annotations

from typing import Any

from bottle import Bottle, HTTPResponse, request


def build_app() -> Bottle:
    """Build the portal-api Bottle app with the authd + Nostr routes."""
    from yunohost.nostr_account import (
        identities_route,
        link_challenge_route,
        link_route,
        nip05_route,
        rename_route,
        revoke_route,
        unlink_route,
    )
    from yunohost.nostr_login import auth_request_route, challenge_route, login_route
    from yunohost.nostr_oidc import authorize, discovery, jwks, token, userinfo

    app = Bottle()

    app.get("/nostr/challenge", callback=challenge_route)
    app.post("/nostr/login", callback=login_route)
    app.get("/nostr/auth-request", callback=auth_request_route)
    app.get("/nostr/identities", callback=identities_route)
    app.post("/nostr/link/challenge", callback=link_challenge_route)
    app.post("/nostr/link", callback=link_route)
    app.post("/nostr/identities/revoke", callback=revoke_route)
    app.post("/nostr/identities/rename", callback=rename_route)
    app.post("/nostr/unlink", callback=unlink_route)
    app.get("/.well-known/nostr.json", callback=nip05_route)
    app.get("/.well-known/openid-configuration", callback=discovery)
    app.get("/oidc/authorize", callback=authorize)
    app.post("/oidc/token", callback=token)
    app.get("/oidc/userinfo", callback=userinfo)
    app.get("/oidc/jwks.json", callback=jwks)

    return app


def run(host: str = "127.0.0.1", port: int = 6788, *, app: Bottle | None = None) -> None:
    """Serve the portal-api (used by bin/nostr-portal-api)."""
    (app or build_app()).run(host=host, port=port)


if __name__ == "__main__":  # pragma: no cover - exercised through bin/nostr-portal-api
    run()