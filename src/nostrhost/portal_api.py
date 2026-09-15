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

from bottle import Bottle

logger = logging.getLogger("nostr-portal-api")


def update_route():
    """PUT /nostrhost/portalapi/update — self-service fullname edit.

    Nostr-only sign-in has no password to change; this only lets a signed-in
    user update their own display name. Writes the account store directly
    (no lifecycle/approval chain — the native ``user.update`` tool is
    admin-gated and NIP-98-signed, which the session-cookie-only portal
    caller cannot produce).
    """
    from bottle import HTTPResponse, request, response

    from yunohost.nostr_account import _session_username
    from yunohost.nostrhost.accounts import save_users, user_get, users

    username = _session_username()
    if not username:
        raise HTTPResponse("not signed in", 401)

    payload = request.json or {}
    fullname = (payload.get("fullname") or "").strip()
    if len(fullname) < 2:
        response.status = 400
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


def build_app() -> Bottle:
    """Build the portal-api Bottle app with the authd + Nostr routes."""
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

    app = Bottle()

    app.get("/public", callback=portal_public_route)
    app.get("/me", callback=portal_me_route)
    app.put("/update", callback=update_route)
    app.get("/logout", callback=logout_route)
    app.get("/nostr/challenge", callback=challenge_route)
    app.post("/nostr/login", callback=login_route)
    app.get("/nostr/auth-request", callback=auth_request_route)
    app.get("/nostr/identities", callback=identities_route)
    app.post("/nostr/link/challenge", callback=link_challenge_route)
    app.post("/nostr/link", callback=link_route)
    app.post("/nostr/identities/revoke", callback=revoke_route)
    app.post("/nostr/identities/rename", callback=rename_route)
    app.post("/nostr/unlink", callback=unlink_route)
    app.get("/nostr/signers", callback=signers_route)
    app.post("/nostr/signers", callback=register_signer_route)
    app.post("/nostr/signers/revoke", callback=revoke_signer_route)
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
