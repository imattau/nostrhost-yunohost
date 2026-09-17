"""Native HTTP API (Moulinette API replacement, Stage 5).

A FastAPI (ASGI, uvicorn) app exposing the same native operations as the
``nostrhost`` CLI
over HTTP, authenticated with NIP-98 (no passwords): every request carries
``Authorization: Nostr <base64 event>``; the event signature is verified, the
signer pubkey resolved to a linked identity, and the caller authorized (for
v1: an admin -- the operator or a configured admin npub).  Read operations
execute directly; write operations execute through the same safe handlers as
the CLI (the API is the local admin surface).  The full control-plane
operation boundary (kind-2200 requests, approvals, capability scopes) lives in
``nostr_operationsd`` / ``nostr-opctl``; capability-scoped authorization for
the API is a follow-up.

Responses are JSON.  Errors map to HTTP status codes with
``{"error": "...", "code": "..."}`` bodies.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from typing import Any, Callable
from urllib.parse import urlunsplit

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from fastapi.routing import APIRoute

from nostrhost import problems, web

from .cli import (
    _agent_contribution_settings_get,
    _agent_export_get,
    _agent_export_list,
    _agent_mode_get,
    _agent_model_profile,
    _agent_model_recommend,
    _agent_model_status,
    _agent_status,
    _TOOL_HANDLERS,
    _State,
    _run_lifecycle,
)
from .core import NostrHostError
from .app_management import app_catalog_logo_urls, attach_app_logos, catalogue_lifecycle_plan, merge_catalogue_and_installed, native_app_removal_plan, native_app_settings, plan_native_change_url, plan_native_settings_update
from .package_engine import PackageError
from .mcp_endpoint import export_ca_bundle, read_endpoint_config
from yunohost.nostr_identity import (
    IdentityError,
    _operator_config,
    _parse_pubkey,
    list_identities,
    list_identities_for_username,
    publish_to_relay,
    resolve_pubkey,
    resolve_username,
)
from yunohost.nostr_operations import (
    OperationError,
    approve_operation,
    build_approval_template,
    build_rejection_template,
    get_operation,
    list_capabilities,
    list_operations,
    reject_operation,
    validate_signed_approval,
    validate_signed_rejection,
)
from nostrhost_policy.auth.nip98 import Nip98Error, verify_nip98_request
from nostrhost_policy.auth.replay import ReplayCache

API_VERSION = 1

logger = logging.getLogger("nostrhost-api")

# The current request comes from the shared per-request context (see
# nostrhost.web), which the route wrapper binds for every request and the
# session authenticator also reads.
_req = web.current_request

# Replay protection for NIP-98 API requests. Single-process in-memory TTL
# cache (same limitation and rationale as nostrhost-policy's own): the API
# service runs a single uvicorn worker on the box.
_NIP98_REPLAY_CACHE = ReplayCache(ttl_seconds=300)


def _external_request_url() -> str:
    """The request URL as the caller signed it in its NIP-98 ``u`` tag.

    The API is fronted by Caddy, which preserves the original ``Host`` header
    and adds ``X-Forwarded-Proto``; reconstruct the external URL so the exact
    ``u`` tag the admin SPA / CLI signed (``https://host/package/...``) is
    what gets compared. Direct loopback callers get the loopback URL.
    """
    parts = _req().url
    scheme = _req().headers.get("X-Forwarded-Proto") or parts.scheme or "http"
    host = _req().headers.get("X-Forwarded-Host") or parts.netloc
    return urlunsplit((scheme, host, parts.path, parts.query, ""))


class ApiError(Exception):
    """Error that maps to an HTTP response."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _json_error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"error": message, "code": code}, status_code=status)


def _json_safe(value: Any) -> Any:
    """Recursively convert values the default JSON encoder can't handle
    (datetimes, sets) to JSON-safe primitives — e.g. service.status returns
    ``last_state_change`` as a datetime, which otherwise 500s every response."""
    import datetime

    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, set):
        return sorted(value, key=str)
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return value


def _run_tool(name: str, args: dict[str, Any]) -> Any:
    try:
        return _json_safe(_TOOL_HANDLERS[name](**args))
    except (NostrHostError, OperationError, IdentityError) as exc:
        raise ApiError(400, "operation_failed", str(exc)) from exc


# GET routes whose entire body is a single forward to `_run_tool` with no
# other request handling: either no arguments, or the route's own path
# parameters passed straight through (renamed to the tool's argument name
# where it differs). Declared once here instead of as ~26 near-identical
# one-line route functions; a route with any extra logic (query-string
# parsing, error handling, response post-processing, ...) stays an explicit
# function below.
_SIMPLE_GET_FORWARDS: tuple[tuple[str, str, dict[str, str]], ...] = (
    # /package/operations/<request_id> is served by package_operations_get
    # below (control-relay replay), not a plain audit.get forward.
    ("/package/system/version", "system.version", {}),
    ("/package/system/status", "system.status", {}),
    # Cached apt/app updates + pending-migrations flag (no network refresh).
    ("/package/system/updates", "updates.check", {}),
    ("/package/domain/list", "domain.list", {}),
    # Intent, desired/actual DNS, diff, and routes for a native domain.
    ("/package/domain/{domain}/inspect", "domain.inspect", {"domain": "domain"}),
    # Nsite gateway status: enabled, mode, domain, service health.
    ("/package/nsite/gateway/status", "nsite.gateway.status", {}),
    # Registered sites and the gateway mode.
    ("/package/nsite/list", "nsite.list", {}),
    # Validated nsite manifests on the catalogue + lookup relays. Served by an
    # explicit handler below (reads the `refresh` query param to bypass cache).
    # Attached custom domains (read only).
    ("/package/nsite/domain/list", "nsite.domain.list", {}),
    # Desired-vs-actual DNS plan for a domain (no changes).
    ("/package/dns/plan/{domain}", "dns.plan", {"domain": "domain"}),
    ("/package/dns/verify/{domain}", "dns.verify", {"domain": "domain"}),
    # DDNS watcher status: last-seen public IPs and dynamic-IP domains.
    ("/package/dns/watch", "dns.watch", {}),
    ("/package/dns/subscriptions", "dns.subscriptions", {}),
    ("/package/network/public-ip", "network.public_ip", {}),
    # Configured DNS credential references (names only, never values).
    ("/package/credential/list", "credential.list", {}),
    ("/package/diagnosis/ignored", "diagnosis.ignored", {}),
    ("/package/catalog/get/{app_id}", "catalog.get", {"app_id": "app_id"}),
    ("/package/catalog/candidates", "catalog.candidates", {}),
    ("/package/catalog/history", "catalog.history", {}),
    ("/package/catalog/profile", "catalog.profile.get", {}),
    ("/package/catalog/announcements", "catalog.announcements", {}),
    ("/package/app/list", "app.list", {}),
    ("/package/user/list", "user.list", {}),
    ("/package/user/group/list", "user.group.list", {}),
    ("/package/user/permission/info/{permission}", "user.permission.info", {"permission": "permission"}),
    ("/package/settings/get/{key}", "settings.get", {"key": "key"}),
)


def _register_simple_get_forwards(app: FastAPI, table: tuple[tuple[str, str, dict[str, str]], ...]) -> None:
    for path, tool, arg_map in table:

        def make_handler(tool_name: str, mapping: dict[str, str]) -> Callable[[Request], Any]:
            def handler(request: Request) -> Any:
                params = request.path_params
                return _run_tool(tool_name, {tool_arg: params[route_arg] for tool_arg, route_arg in mapping.items()})

            return handler

        app.get(path)(make_handler(tool, arg_map))


def _build_admin_set(
    *,
    admin_pubkeys: tuple[str, ...] = (),
    operator_pubkey: str | None = None,
) -> set[str]:
    """The admin pubkey set: configured admin pubkeys + the operator."""
    admins = set(admin_pubkeys)
    if operator_pubkey:
        admins.add(operator_pubkey)
    return admins


def _session_infos() -> dict[str, Any] | None:
    """The current portal session payload (admin credential), or None.

    Reads the host-only ``nostrhost.admin`` cookie first — the separate admin
    credential minted alongside the domain-wide SSO cookie (H4). Falls back to
    the SSO cookie so nodes minted before the split keep working.
    """
    try:
        from yunohost.authenticators.ldap_ynhuser import Authenticator

        infos = Authenticator().get_admin_cookie()
    except Exception:  # pragma: no cover - session store hiccup
        return None
    return dict(infos) if isinstance(infos, dict) else None


def _session_csrf_token(infos: dict[str, Any] | None) -> str:
    """The expected CSRF token for ``infos`` (empty when there is no session)."""
    if not infos:
        return ""
    from yunohost.authenticators.ldap_ynhuser import session_csrf_token

    return session_csrf_token(infos)


def _require_csrf_header(infos: dict[str, Any] | None) -> None:
    """H4: cookie-session requests must carry the per-request CSRF token.

    NIP-98 requests authenticate with a signed bearer header (unforgeable,
    CSRF-safe) and skip this. The portal-session path is cookie-based, so it
    requires ``X-Nostrhost-CSRF`` — a token only same-origin JS can read (the
    public ``/package/session`` probe) and only the holder of ``infos`` can
    compute. A cross-origin page cannot set a custom header without a CORS
    preflight (which the API does not allow for other origins), so a subdomain
    XSS can no longer ride the domain-wide SSO cookie to drive the admin API.
    """
    header = _req().headers.get("X-Nostrhost-CSRF", "")
    if not header or not secrets.compare_digest(header, _session_csrf_token(infos)):
        raise ApiError(403, "csrf_required", "cookie-session requests require a valid X-Nostrhost-CSRF header")


def _session_username() -> str | None:
    """The session user from the admin session cookie, or None.

    Reuses the portal session validation (Authenticator.get_admin_cookie) so
    the native API shares the portal's sign-in state: once a user signs in at
    the portal, the same host-only admin credential authenticates the admin
    console — no second login or NIP-07 signer needed.
    """
    infos = _session_infos()
    return str(infos.get("user")) if infos and infos.get("user") else None


def _session_admin_pubkey(admins: set[str]) -> str | None:
    """If a valid portal session exists whose linked identity is an admin,
    return that identity's pubkey, else None."""
    username = _session_username()
    if not username:
        return None
    try:
        identities = resolve_username(username)
    except Exception:  # pragma: no cover - identity store unavailable
        identities = []
    for identity in identities:
        if identity.pubkey in admins:
            return identity.pubkey
    return None


def _session_linked_pubkeys() -> list[str]:
    """All linked identity pubkeys for the portal session user (order kept).

    Unlike ``_session_admin_pubkey`` this does not require an identity to be
    an admin: the scope-aware nsite routes (see ``NSITE_ROUTE_SCOPES``)
    authorize any linked identity and check the caller's kind-31100 granted
    scopes instead — the portal "My site" surface (D8). Callers must already
    have validated the session's CSRF token (see ``_require_csrf_header``).
    """
    infos = _session_infos()
    if not infos:
        return []
    username = infos.get("user")
    if not username:
        return []
    try:
        identities = resolve_username(str(username))
    except Exception:  # pragma: no cover - identity store unavailable
        identities = []
    return [identity.pubkey for identity in identities if getattr(identity, "pubkey", None)]


def _granted_scopes(pubkey: str) -> set[str]:
    """The kind-31100 capability scopes granted to ``pubkey`` (best-effort).

    Mirrors ``nostr_operationsd``'s subject->scope projection so the HTTP
    routes gate a non-admin caller exactly like the signed operation chain
    does (D8: the portal surface rides the same scope path). An unreachable
    control relay yields an empty set — admins bypass this check entirely.
    """
    try:
        grants = list_capabilities()
    except Exception:  # noqa: BLE001 - relay/config hiccup: fail closed
        return set()
    for grant in grants:
        if grant.get("pubkey") == pubkey:
            return {str(scope) for scope in (grant.get("scopes") or [])}
    return set()

# Route -> required scope(s) for the nsite family. A non-admin caller (NIP-98
# or portal session) needs one of the listed scopes via a kind-31100 grant;
# admins bypass. Each entry mirrors its tool's scope in nostr_operations.TOOLS
# so the HTTP surface gates exactly like the signed operation chain.
NSITE_ROUTE_SCOPES: dict[str, tuple[str, ...]] = {
    "/package/nsite/gateway/status": ("nsites.read",),
    "/package/nsite/gateway/enable": ("nsites.admin",),
    "/package/nsite/gateway/disable": ("nsites.admin",),
    "/package/nsite/gateway/configure": ("nsites.admin",),
    "/package/nsite/list": ("nsites.read",),
    "/package/nsite/discover": ("nsites.read",),
    "/package/nsite/block/list": ("nsites.read",),
    "/package/nsite/block/add": ("nsites.admin",),
    "/package/nsite/block/remove": ("nsites.admin",),
    "/package/nsite/block/set": ("nsites.admin",),
    "/package/nsite/inspect": ("nsites.read",),
    "/package/nsite/resolve": ("nsites.read",),
    "/package/nsite/validate": ("nsites.read",),
    "/package/nsite/reachability": ("nsites.read",),
    "/package/nsite/publish/plan": ("nsites.read",),
    "/package/nsite/register": ("nsites.admin",),
    "/package/nsite/unregister": ("nsites.admin",),
    "/package/nsite/publish": ("nsites.publish",),
    "/package/nsite/snapshot": ("nsites.publish",),
    "/package/nsite/mirror": ("nsites.publish",),
    "/package/nsite/domain/list": ("nsites.read",),
    "/package/nsite/domain/attach": ("nsites.admin",),
    "/package/nsite/domain/detach": ("nsites.admin",),
}


def default_authorizer(
    *,
    admin_pubkeys: tuple[str, ...] = (),
    operator_pubkey: str | None = None,
    scoped_routes: dict[str, tuple[str, ...]] | None = None,
) -> Callable[[str], str]:
    """NIP-98 / session authorizer: verify the request identity and authorize
    it for the requested route.

    Two mutually-exclusive authentication paths:

    - NIP-98 ``Authorization: Nostr <base64 event>`` (the existing signer
      path): verify the event and resolve the signer pubkey to a linked
      identity.
    - Portal session cookie (``nostrhost.portal``): validate the portal
      session and resolve the session user's linked identity. This is the
      admin-console path: the user signs in once at the portal and the same
      cookie authorizes the console.

    Routes in ``scoped_routes`` (the nsite family by default) additionally
    accept non-admin linked identities that hold one of the route's scopes
    (kind-31100 capability grants) — the portal "My site" surface (D8).
    Everything else stays admin-only (operator or configured admin pubkeys).
    """

    scoped_routes = NSITE_ROUTE_SCOPES if scoped_routes is None else scoped_routes
    admins = _build_admin_set(admin_pubkeys=admin_pubkeys, operator_pubkey=operator_pubkey)

    def resolve_callers() -> list[str]:
        header = _req().headers.get("Authorization", "")
        if header.startswith("Nostr "):
            # Full NIP-98 verification: kind 27235, freshness against clock
            # skew, exact u/method binding, sha256(payload) body binding, and
            # replay protection (see nostrhost_policy.auth.nip98). Signature-
            # only checks are deliberately NOT used here: they would let any
            # validly signed event by an admin key (a kind-1 note, a relay-auth
            # challenge) be replayed as an API credential.
            try:
                verified = verify_nip98_request(
                    authorization_header=header,
                    method=_req().method,
                    url=_external_request_url(),
                    body=_req().scope.get("nostrhost.body", b""),
                    replay_cache=_NIP98_REPLAY_CACHE,
                )
            except Nip98Error as exc:
                raise ApiError(401, "invalid_nip98", str(exc)) from exc
            pubkey = verified.pubkey
            try:
                identity = resolve_pubkey(pubkey)
            except Exception:  # noqa: BLE001 - unlinked/unknown or unavailable store
                identity = None
            if identity is None:
                raise ApiError(403, "identity_not_linked", "pubkey is not a linked identity")
            return [pubkey]

        # Portal-session path: no NIP-98 header, use the admin session cookie.
        # H4: this cookie-based path requires the per-request CSRF token, so a
        # cross-origin page (even a same-site subdomain XSS) cannot drive the
        # admin API by riding the domain-wide SSO cookie.
        infos = _session_infos()
        if infos is None:
            raise ApiError(
                401,
                "authentication_required",
                "missing NIP-98 Authorization header or portal session",
            )
        _require_csrf_header(infos)
        username = infos.get("user")
        if not username:
            raise ApiError(401, "authentication_required", "invalid portal session")
        try:
            identities = resolve_username(str(username))
        except Exception:  # noqa: BLE001 - identity store unavailable
            identities = []
        callers = [identity.pubkey for identity in identities if getattr(identity, "pubkey", None)]
        if callers:
            return callers
        if username:
            raise ApiError(403, "not_authorized", "session user has no linked nostr identity")
        raise ApiError(
            401,
            "authentication_required",
            "missing NIP-98 Authorization header or portal session",
        )

    def authorize(rule: str = "") -> str:
        callers = resolve_callers()
        required = scoped_routes.get(str(rule))
        if required is None or any(caller in admins for caller in callers):
            admin = next((caller for caller in callers if caller in admins), None)
            if admin is None:
                raise ApiError(403, "not_authorized", "pubkey is not an admin")
            return admin
        for caller in callers:
            granted = _granted_scopes(caller)
            if any(scope in granted for scope in required):
                return caller
        raise ApiError(
            403,
            "not_authorized",
            f"requires one of the scopes: {', '.join(sorted(required))}",
        )

    return authorize


_PUBLIC_RULES = ("/package/healthz", "/package/session")


class _ApiRoute(APIRoute):
    """Per-route auth and error mapping (replaces bottle's
    ``_AuthErrorsPlugin``).

    Authorizes the request before running the endpoint (except the two public
    routes), stores the resolved admin pubkey on ``request.state``, and maps
    ``ApiError`` / operation errors / unexpected exceptions to the JSON error
    envelope the clients expect.
    """

    def get_route_handler(self) -> Callable[[Request], Any]:
        original = super().get_route_handler()
        rule = self.path

        async def handler(request: Request) -> Response:
            token = web.begin(request)
            started = time.perf_counter()
            try:
                # Cache the raw body: NIP-98 binds sha256(payload) to it and
                # _json_body() parses the same bytes.
                request.state.body_bytes = await request.body()
                if rule not in _PUBLIC_RULES:
                    try:
                        request.state.admin_pubkey = request.app.state.authorizer(rule)
                    except ApiError as exc:
                        response = web.apply_cookies(_json_error(exc.status, exc.code, exc.message))
                        return problems.finalize(response, request, started=started, exc=exc, kind="auth")
                try:
                    response = await original(request)
                except ApiError as exc:
                    response = web.apply_cookies(_json_error(exc.status, exc.code, exc.message))
                    return problems.finalize(response, request, started=started, exc=exc, kind="api_error")
                except (NostrHostError, OperationError, IdentityError) as exc:
                    response = web.apply_cookies(_json_error(400, "operation_failed", str(exc)))
                    return problems.finalize(response, request, started=started, exc=exc, kind="operation")
                except Exception as exc:  # noqa: BLE001 - last error boundary
                    # Do not echo the raw exception back to the caller: paths,
                    # config snippets and provider error strings can leak
                    # internals (M18). The details go to the server log; the
                    # client gets a generic message.
                    logger.exception(
                        "unhandled error on %s %s (rid=%s)",
                        request.method,
                        request.url.path,
                        problems.request_id(request),
                    )
                    response = web.apply_cookies(_json_error(500, "internal_error", "internal server error"))
                    return problems.finalize(response, request, started=started, exc=exc, kind="unhandled")
                # The session authenticator may have queued a cookie refresh
                # (extending the admin/portal cookie) while resolving auth.
                return problems.finalize(web.apply_cookies(response), request, started=started)
            finally:
                web.end(token)

        return handler


def _optional_list(value: str | None) -> list[str] | None:
    if value is None:
        return None
    return [item for item in value.split(",") if item]


def _default_event_stream(request_id: str) -> Any:
    """Live relay subscription for one operation's chain events."""
    from nostrhost import events as events_module

    return events_module.stream_operation_events(
        request_id,
        relay_url=_config_control_relay() or "ws://127.0.0.1:4848",
        timeout=60.0,
    )


def build_app(
    *,
    authorizer: Callable[[str], str] | None = None,
    admin_pubkeys: tuple[str, ...] = (),
    operator_pubkey: str | None = None,
    event_stream: Callable[[str], Any] | None = None,
) -> FastAPI:
    """Build the native API FastAPI app.

    ``event_stream(request_id)`` yields operation chain events for the SSE
    ``/events/<id>`` endpoint (default: live relay subscription).
    """
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.router.route_class = _ApiRoute
    app.state.authorizer = authorizer or default_authorizer(
        admin_pubkeys=admin_pubkeys, operator_pubkey=operator_pubkey
    )
    stream = event_stream or _default_event_stream
    _register_simple_get_forwards(app, _SIMPLE_GET_FORWARDS)

    @app.get("/package/healthz")
    def healthz() -> dict[str, Any]:
        return {"ok": True, "version": API_VERSION}

    @app.get("/package/session")
    def session() -> dict[str, Any]:
        """Public session probe for the admin SPA: whether a portal session
        exists, who it is, and whether that identity is an admin.

        Unlike every other route this is intentionally NOT admin-gated: the
        console uses it to decide whether to show the console, redirect to the
        portal login, or refuse non-admin access. It never leaks secrets —
        only the session user's username + admin flag, plus the per-session
        CSRF token the console must echo on cookie-authenticated requests
        (H4). The token is only useful same-origin (no CORS for other
        origins), so exposing it here does not weaken the CSRF protection.
        """
        infos = _session_infos()
        username = infos.get("user") if infos else None
        pubkey = None
        admin_pubkey = None
        admins = _build_admin_set(admin_pubkeys=admin_pubkeys, operator_pubkey=operator_pubkey)
        if username is not None:
            try:
                identities = resolve_username(str(username))
            except Exception:  # pragma: no cover - identity store unavailable
                identities = []
            for identity in identities:
                if pubkey is None:
                    pubkey = identity.pubkey
                if identity.pubkey in admins:
                    admin_pubkey = identity.pubkey
                    break
        return {
            "authenticated": username is not None,
            "username": username,
            # The admin identity when one of the user's linked keys is an
            # admin (mirrors _session_admin_pubkey, which every other route's
            # authorizer uses); falls back to the first linked identity so a
            # non-admin session still has a pubkey to display.
            "pubkey": admin_pubkey or pubkey,
            "admin": admin_pubkey is not None,
            "csrf_token": _session_csrf_token(infos),
        }

    @app.get("/package/events/{request_id}")
    def events(request_id: str) -> Any:
        """Server-Sent Events: live progress/result for one operation."""
        from nostrhost import events as events_module

        def frame() -> Any:
            yield events_module.sse_ping()
            for event in stream(request_id):
                yield events_module.sse_format(event)

        return StreamingResponse(
            frame(),
            media_type=None,
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    # -- operations (audit history + pending approvals) ----------------------
    #
    # The real handlers for GET/POST /package/operations... (list, get,
    # approve, reject) are registered further down, alongside the
    # approval/rejection-template routes they share context with. Do not
    # re-add plain audit.list/audit.get forwards for these paths.

    # -- system -------------------------------------------------------------

    @app.post("/package/system/updates/refresh")
    def system_updates_refresh() -> Any:
        body = _json_body()
        return _run_tool("updates.refresh", {"target": body.get("target", "apps")})

    @app.post("/package/system/updates/apply")
    def system_updates_apply() -> Any:
        """Apply pending apt/app upgrades. High-risk/require-approval: routed
        through the signed operation chain (owner co-signature), not _run_tool."""
        body = _json_body()
        return _run_lifecycle("system.upgrade", {"target": body.get("target", "system")}, state=_State())

    @app.get("/package/system/migrations")
    def system_migrations() -> Any:
        return _run_tool(
            "system.migrations",
            {
                "pending": _req().query_params.get("pending", "").lower() == "true",
                "done": _req().query_params.get("done", "").lower() == "true",
            },
        )

    @app.post("/package/system/migrate")
    def system_migrate() -> Any:
        """Run/skip/force-rerun migrations. High-risk/irreversible: routed
        through the signed operation chain (owner co-signature), not _run_tool."""
        body = _json_body()
        return _run_lifecycle("system.migrate", body, state=_State())

    # -- domain / dns ---------------------------------------------------------

    @app.post("/package/domain/add")
    def domain_add() -> Any:
        """Register a native domain: plan DNS, apply, stand up Caddy routes,
        record state. High-risk: routed through the signed operation chain
        (owner co-signature), not _run_tool."""
        body = _json_body()
        return _run_lifecycle(
            "domain.add",
            {
                "domain": body.get("domain", ""),
                "provider_type": body.get("provider_type", "manual"),
                "provider_zone": body.get("provider_zone"),
                "credential": body.get("credential"),
                "primary": bool(body.get("primary", False)),
                "ipv4": bool(body.get("ipv4", True)),
                "ipv6": bool(body.get("ipv6", True)),
                "wildcard": bool(body.get("wildcard", True)),
                "nip05": bool(body.get("nip05", False)),
                "tls_caa": body.get("tls_caa"),
                "apply_dns": bool(body.get("apply_dns", True)),
                "verify": bool(body.get("verify", True)),
            },
            state=_State(),
        )

    @app.post("/package/domain/remove")
    def domain_remove() -> Any:
        """Remove a native domain (blocks while apps use it; deletes owned
        DNS only). High-risk: routed through the signed operation chain."""
        body = _json_body()
        return _run_lifecycle(
            "domain.remove",
            {"domain": body.get("domain", ""), "force": bool(body.get("force", False))},
            state=_State(),
        )

    # -- nsite gateway --------------------------------------------------------

    @app.post("/package/nsite/gateway/enable")
    def nsite_gateway_enable() -> Any:
        """Enable the nsite gateway on a dedicated registered domain."""
        body = _json_body()
        return _run_lifecycle(
            "nsite.gateway.enable",
            {
                "domain": body.get("domain", ""),
                "lookup_relays": body.get("lookup_relays"),
                "extra_relays": body.get("extra_relays"),
                "fallback_servers": body.get("fallback_servers"),
                "allow_http": bool(body.get("allow_http", False)),
                "max_blob_bytes": body.get("max_blob_bytes"),
                "cache_quota_bytes": body.get("cache_quota_bytes"),
            },
            state=_State(),
        )

    @app.post("/package/nsite/gateway/disable")
    def nsite_gateway_disable() -> Any:
        """Disable the nsite gateway: stop the unit, remove the Caddy route."""
        return _run_lifecycle("nsite.gateway.disable", {}, state=_State())

    @app.post("/package/nsite/gateway/configure")
    def nsite_gateway_configure() -> Any:
        """Update the nsite gateway config and reload."""
        body = _json_body()
        return _run_lifecycle(
            "nsite.gateway.configure",
            {
                "domain": body.get("domain", ""),
                "lookup_relays": body.get("lookup_relays"),
                "extra_relays": body.get("extra_relays"),
                "fallback_servers": body.get("fallback_servers"),
                "allow_http": bool(body.get("allow_http", False)),
                "max_blob_bytes": body.get("max_blob_bytes"),
                "cache_quota_bytes": body.get("cache_quota_bytes"),
            },
            state=_State(),
        )

    # -- nsite sites / publishing (Phase 3a) --------------------------------

    @app.get("/package/nsite/inspect")
    def nsite_inspect() -> Any:
        """One registered site record."""
        return _run_tool(
            "nsite.inspect",
            {
                "pubkey": _req().query_params.get("pubkey", ""),
                "d": _req().query_params.get("d", ""),
            },
        )

    @app.get("/package/nsite/resolve")
    def nsite_resolve() -> Any:
        """Fetch the current manifest for a label/pubkey from public relays
        (read only, bounded)."""
        return _run_tool(
            "nsite.resolve",
            {
                "label": _req().query_params.get("label", ""),
                "pubkey": _req().query_params.get("pubkey", ""),
                "d": _req().query_params.get("d", ""),
                "relays": _optional_list(_req().query_params.get("relays")),
                "limit": int(_req().query_params.get("limit", "5")),
                "timeout": float(_req().query_params.get("timeout", "8")),
            },
        )

    @app.post("/package/nsite/validate")
    def nsite_validate_manifest() -> Any:
        """Validate a candidate manifest event; no network."""
        body = _json_body()
        return _run_tool("nsite.validate_manifest", {"event": body.get("event")})

    @app.post("/package/nsite/reachability")
    def nsite_reachability() -> Any:
        """Relay/server reachability probes (bounded)."""
        body = _json_body()
        return _run_tool(
            "nsite.reachability",
            {
                "relays": body.get("relays"),
                "servers": body.get("servers"),
                "timeout": float(body.get("timeout", "5")),
            },
        )

    @app.post("/package/nsite/publish/plan")
    def nsite_publish_plan() -> Any:
        """Blob inventory to an unsigned manifest + plan_sha256 (D7), or a
        copy plan from a source site (Phase 5, ``copy_of``)."""
        body = _json_body()
        return _run_tool(
            "nsite.publish.plan",
            {
                "pubkey": body.get("pubkey", ""),
                "kind": int(body.get("kind", 15128)),
                "d": body.get("d", ""),
                "items": body.get("items"),
                "site": body.get("site", ""),
                "servers": body.get("servers"),
                "relays": body.get("relays"),
                "copy_of": body.get("copy_of", ""),
            },
        )

    @app.post("/package/nsite/register")
    def nsite_register() -> Any:
        """Add a hosted-mode allowlist entry. Approval-gated."""
        body = _json_body()
        return _run_lifecycle(
            "nsite.register",
            {
                "pubkey": body.get("pubkey", ""),
                "kind": int(body.get("kind", 15128)),
                "d": body.get("d", ""),
                "title": body.get("title", ""),
            },
            state=_State(),
        )

    @app.post("/package/nsite/unregister")
    def nsite_unregister() -> Any:
        """Remove a hosted-mode allowlist entry. Approval-gated."""
        body = _json_body()
        return _run_lifecycle(
            "nsite.unregister",
            {"pubkey": body.get("pubkey", ""), "d": body.get("d", "")},
            state=_State(),
        )

    @app.get("/package/nsite/discover")
    def nsite_discover(request: Request) -> Any:
        """Validated nsite manifests on the catalogue + lookup relays.

        ``?refresh=1`` bypasses the 5-minute server-side cache and forces a
        live relay scan (the Browse tab's Refresh button)."""
        refresh = request.query_params.get("refresh") in ("1", "true")
        return _run_tool("nsite.discover", {"refresh": refresh})

    @app.get("/package/nsite/block/list")
    def nsite_block_list() -> Any:
        """The operator's mute list (blocked npub pubkeys)."""
        return _run_tool("nsite.block.list", {})

    @app.post("/package/nsite/block/add")
    def nsite_block_add() -> Any:
        """Add one npub to the operator's mute list. Approval-gated."""
        body = _json_body()
        return _run_lifecycle(
            "nsite.block.add",
            {"pubkey": body.get("pubkey", "")},
            state=_State(),
        )

    @app.post("/package/nsite/block/remove")
    def nsite_block_remove() -> Any:
        """Remove one npub from the operator's mute list. Approval-gated."""
        body = _json_body()
        return _run_lifecycle(
            "nsite.block.remove",
            {"pubkey": body.get("pubkey", "")},
            state=_State(),
        )

    @app.post("/package/nsite/block/set")
    def nsite_block_set() -> Any:
        """Replace the operator's mute list. Approval-gated."""
        body = _json_body()
        return _run_lifecycle(
            "nsite.block.set",
            {"pubkeys": body.get("pubkeys", [])},
            state=_State(),
        )

    @app.post("/package/nsite/publish")
    def nsite_publish() -> Any:
        """Verify a signed manifest, broadcast to relays, record the site.
        Approval-gated."""
        body = _json_body()
        return _run_lifecycle(
            "nsite.publish",
            {
                "event": body.get("event"),
                "plan_sha256": body.get("plan_sha256", ""),
                "relays": body.get("relays"),
            },
            state=_State(),
        )

    @app.post("/package/nsite/snapshot")
    def nsite_snapshot() -> Any:
        """Record a client-signed kind-5128 snapshot. Approval-gated."""
        body = _json_body()
        return _run_lifecycle(
            "nsite.snapshot",
            {
                "event": body.get("event"),
                "plan_sha256": body.get("plan_sha256", ""),
                "relays": body.get("relays"),
            },
            state=_State(),
        )

    @app.post("/package/nsite/mirror")
    def nsite_mirror() -> Any:
        """Re-upload a site's missing blobs to the selected servers from the
        draft area. Approval-gated."""
        body = _json_body()
        return _run_lifecycle(
            "nsite.mirror",
            {
                "pubkey": body.get("pubkey", ""),
                "d": body.get("d", ""),
                "servers": body.get("servers", []),
            },
            state=_State(),
        )

    # -- nsite custom domains (Phase 4) ------------------------------------

    @app.post("/package/nsite/domain/attach")
    def nsite_domain_attach() -> Any:
        """Attach a custom FQDN to a registered site (ownership proof via
        CNAME to the gateway domain or a TXT challenge). Approval-gated."""
        body = _json_body()
        return _run_lifecycle(
            "nsite.domain.attach",
            {
                "fqdn": body.get("fqdn", ""),
                "pubkey": body.get("pubkey", ""),
                "d": body.get("d", ""),
                "method": body.get("method", "cname"),
                "verify": bool(body.get("verify", True)),
            },
            state=_State(),
        )

    @app.post("/package/nsite/domain/detach")
    def nsite_domain_detach() -> Any:
        """Detach a custom FQDN (removes the Caddy route and marker only).
        Approval-gated."""
        body = _json_body()
        return _run_lifecycle(
            "nsite.domain.detach",
            {"fqdn": body.get("fqdn", "")},
            state=_State(),
        )

    @app.post("/package/dns/apply")
    def dns_apply() -> Any:
        """Apply the DNS plan for a domain through its provider. High-risk:
        routed through the signed operation chain (owner co-signature)."""
        body = _json_body()
        return _run_lifecycle("dns.apply", {"domain": body.get("domain", "")}, state=_State())

    @app.post("/package/dns/subscribe")
    def dns_subscribe() -> Any:
        """Claim a nostr-native free hostname (identity-backed Dynette).
        High-risk: routed through the signed operation chain (owner
        co-signature), not _run_tool."""
        body = _json_body()
        return _run_lifecycle(
            "dns.subscribe",
            {
                "hostname": body.get("hostname", ""),
                "secret": body.get("secret"),
                "rotate": bool(body.get("rotate", False)),
            },
            state=_State(),
        )

    @app.post("/package/dns/unsubscribe")
    def dns_unsubscribe() -> Any:
        """Release a nostr-native free-hostname subscription and drop its
        broker secret. High-risk: routed through the signed operation chain."""
        body = _json_body()
        return _run_lifecycle("dns.unsubscribe", {"hostname": body.get("hostname", "")}, state=_State())

    # -- network / dns credentials --------------------------------------------

    @app.post("/package/credential/set")
    def credential_set() -> Any:
        """Store a DNS provider token in the credential broker. High-risk:
        routed through the signed operation chain (owner co-signature)."""
        body = _json_body()
        return _run_lifecycle(
            "credential.set",
            {
                "provider": body.get("provider", ""),
                "name": body.get("name", ""),
                "value": body.get("value", ""),
            },
            state=_State(),
        )

    @app.post("/package/credential/remove")
    def credential_remove() -> Any:
        """Remove a DNS provider token from the credential broker. High-risk:
        routed through the signed operation chain (owner co-signature)."""
        body = _json_body()
        return _run_lifecycle(
            "credential.remove",
            {"provider": body.get("provider", ""), "name": body.get("name", "")},
            state=_State(),
        )

    # -- backup ---------------------------------------------------------------

    @app.get("/package/backup/list")
    def backup_list() -> Any:
        with_info = _req().query_params.get("with_info", "").lower() == "true"
        return _run_tool("backup.list", {"with_info": with_info})

    @app.get("/package/backup/{name}")
    def backup_info(name: str) -> Any:
        with_details = _req().query_params.get("with_details", "").lower() == "true"
        return _run_tool("backup.info", {"name": name, "with_details": with_details})

    @app.post("/package/backup/create")
    def backup_create() -> Any:
        """Create a local backup archive. Medium-risk: still routed through
        the signed operation chain (owner co-signature), not _run_tool."""
        body = _json_body()
        return _run_lifecycle(
            "backup.create",
            {
                "name": body.get("name"),
                "description": body.get("description"),
                "apps": body.get("apps", []),
                "system": body.get("system", []),
                "output_directory": body.get("output_directory"),
            },
            state=_State(),
        )

    @app.post("/package/backup/restore")
    def backup_restore() -> Any:
        """Restore a local backup archive. High-risk: routed through the
        signed operation chain (owner co-signature), not _run_tool."""
        body = _json_body()
        return _run_lifecycle(
            "backup.restore",
            {
                "name": body.get("name", ""),
                "apps": body.get("apps", []),
                "system": body.get("system", []),
                "force": bool(body.get("force", False)),
            },
            state=_State(),
        )

    @app.post("/package/backup/delete")
    def backup_delete() -> Any:
        """Delete a local backup archive. High-risk/irreversible: routed
        through the signed operation chain (owner co-signature)."""
        body = _json_body()
        return _run_lifecycle("backup.delete", {"name": body.get("name", "")}, state=_State())

    # -- diagnosis --------------------------------------------------------------

    @app.post("/package/diagnosis/run")
    def diagnosis_run() -> Any:
        """Run diagnosis categories and return the cached report. No-approval,
        but POST since it runs real checks and mutates the diagnosis cache
        (same as /package/system/updates/refresh)."""
        body = _json_body()
        return _run_tool(
            "diagnosis.run",
            {
                "categories": body.get("categories", []),
                "force": bool(body.get("force", False)),
                "full": bool(body.get("full", False)),
            },
        )

    @app.post("/package/diagnosis/ignore")
    def diagnosis_ignore() -> Any:
        """Add a diagnosis ignore filter. Routed through the signed operation
        chain (owner co-signature), not _run_tool."""
        body = _json_body()
        return _run_lifecycle("diagnosis.ignore", {"filter": body.get("filter", [])}, state=_State())

    @app.post("/package/diagnosis/unignore")
    def diagnosis_unignore() -> Any:
        """Remove a diagnosis ignore filter. Routed through the signed
        operation chain (owner co-signature), not _run_tool."""
        body = _json_body()
        return _run_lifecycle("diagnosis.unignore", {"filter": body.get("filter", [])}, state=_State())

    # -- firewall ---------------------------------------------------------------

    @app.get("/package/firewall/list")
    def firewall_list() -> Any:
        protocol = _req().query_params.get("protocol", "tcp")
        forwarded = _req().query_params.get("forwarded", "").lower() == "true"
        return _run_tool("firewall.list", {"protocol": protocol, "forwarded": forwarded})

    @app.post("/package/firewall/open")
    def firewall_open() -> Any:
        """Open a firewall port. High-risk: routed through the signed
        operation chain (owner co-signature), not _run_tool."""
        body = _json_body()
        return _run_lifecycle(
            "firewall.open",
            {
                "port": body.get("port", ""),
                "protocol": body.get("protocol", ""),
                "comment": body.get("comment", "opened via native operation"),
                "upnp": bool(body.get("upnp", False)),
            },
            state=_State(),
        )

    @app.post("/package/firewall/close")
    def firewall_close() -> Any:
        """Close a firewall port. High-risk: routed through the signed
        operation chain (owner co-signature), not _run_tool."""
        body = _json_body()
        return _run_lifecycle(
            "firewall.close",
            {
                "port": body.get("port", ""),
                "protocol": body.get("protocol", ""),
                "upnp_only": bool(body.get("upnp_only", False)),
            },
            state=_State(),
        )

    @app.post("/package/firewall/reload")
    def firewall_reload() -> Any:
        """Re-apply the current firewall rule set. High-risk: routed through
        the signed operation chain (owner co-signature), not _run_tool."""
        body = _json_body()
        return _run_lifecycle("firewall.reload", {"skip_upnp": bool(body.get("skip_upnp", False))}, state=_State())

    # -- service ------------------------------------------------------------

    @app.get("/package/service/status")
    def service_status() -> Any:
        names = _optional_list(_req().query_params.get("names"))
        return _run_tool("service.status", {"names": names} if names else {})

    @app.post("/package/service/restart")
    def service_restart() -> Any:
        """Restart one named service. A write with real consequences (a bad
        restart can take an app or the control plane down): routed through the
        signed operation chain (policy + approval), not _run_tool."""
        body = _json_body()
        return _run_lifecycle("service.restart", {"name": body.get("name", "")}, state=_State())

    @app.post("/package/service/control")
    def service_control() -> Any:
        """Start/stop/restart one named service. Same write-risk tier as
        service.restart: routed through the signed operation chain."""
        body = _json_body()
        return _run_lifecycle(
            "service.control",
            {"name": body.get("name", ""), "action": body.get("action", "")},
            state=_State(),
        )

    # -- agent ----------------------------------------------------------------

    @app.get("/package/agent/status")
    def agent_status() -> Any:
        return _agent_status()

    @app.post("/package/agent/init")
    def agent_init() -> Any:
        # H5: agent writes route through the signed operation chain (policy /
        # approval / audit) instead of a direct handler call.
        return _run_lifecycle("agent.init", {}, state=_State())

    @app.post("/package/agent/enable")
    def agent_enable() -> Any:
        return _run_lifecycle("agent.enable", {}, state=_State())

    @app.post("/package/agent/disable")
    def agent_disable() -> Any:
        return _run_lifecycle("agent.disable", {}, state=_State())

    @app.get("/package/agent/models/profile")
    def agent_models_profile() -> Any:
        return _agent_model_profile()

    @app.get("/package/agent/models/recommend")
    def agent_models_recommend() -> Any:
        return _agent_model_recommend()

    @app.post("/package/agent/models/download")
    def agent_models_download() -> Any:
        body = _json_body()
        return _run_lifecycle(
            "agent.model.download",
            {"model_id": body.get("model_id", ""), "evaluation_only": bool(body.get("evaluation_only", False))},
            state=_State(),
        )

    @app.post("/package/agent/models/select")
    def agent_models_select() -> Any:
        body = _json_body()
        return _run_lifecycle("agent.model.select", {"model_id": body.get("model_id", "")}, state=_State())

    @app.get("/package/agent/models/status")
    def agent_models_status() -> Any:
        return _agent_model_status()

    @app.get("/package/agent/mode")
    def agent_mode_get() -> Any:
        return _agent_mode_get()

    @app.post("/package/agent/mode")
    def agent_mode_set() -> Any:
        body = _json_body()
        return _run_lifecycle(
            "agent.mode.set", {"level": body.get("level", ""), "confirm": bool(body.get("confirm", False))}, state=_State()
        )

    @app.get("/package/agent/export/list")
    def agent_export_list() -> Any:
        # The object-wrapped shape is the stable client contract (the admin
        # SPA / MCP read `cycles`).
        return {"cycles": _agent_export_list()}

    @app.post("/package/agent/export/run")
    def agent_export_run() -> Any:
        body = _json_body()
        return _run_lifecycle("agent.export.run", {"cycle_id": body.get("cycle_id", "")}, state=_State())

    @app.get("/package/agent/export/{candidate_file_id}")
    def agent_export_get(candidate_file_id: str) -> Any:
        return _agent_export_get(candidate_file_id)

    @app.get("/package/agent/contribution/settings")
    def agent_contribution_settings_get() -> Any:
        return _agent_contribution_settings_get()

    @app.post("/package/agent/contribution/settings")
    def agent_contribution_settings_set() -> Any:
        """Touches Hugging Face credentials and, via auto_submit, can flip on
        the resident daemon submitting every completed cycle with no click
        needed. Admin-only, and routed through the signed operation chain so
        the toggle and its approval are audited (H5)."""
        body = _json_body()
        return _run_lifecycle(
            "agent.contribution.settings.set",
            {
                "dataset_repo": body.get("dataset_repo", ""),
                "token": body.get("token") or None,
                "auto_submit": bool(body.get("auto_submit", False)),
            },
            state=_State(),
        )

    @app.post("/package/agent/contribution/submit")
    def agent_contribution_submit() -> Any:
        """Causes real network egress of exactly one already-prepared candidate
        file the admin explicitly chose. Admin-only, approval-gated via the
        signed operation chain."""
        body = _json_body()
        return _run_lifecycle("agent.contribution.submit", {"candidate_file_id": body.get("candidate_file_id", "")}, state=_State())

    @app.post("/package/agent/contribution/share")
    def agent_contribution_share() -> Any:
        """Redacts and submits one completed cycle in a single call -- the
        admin-facing "Share" action. Combines export/run + contribution/submit
        so the UI no longer needs a separate prepare-then-review step before
        sharing; the redaction plus the community repo's own CI validation
        are the safeguards, on this path exactly as on automatic submission.
        Approval-gated via the signed operation chain."""
        body = _json_body()
        return _run_lifecycle("agent.contribution.share", {"cycle_id": body.get("cycle_id", "")}, state=_State())

    # -- catalog --------------------------------------------------------------

    @app.get("/package/catalog/list")
    def catalog_list() -> Any:
        result = _run_tool("catalog.list", {})
        # The catalogue CLI emits a bare list; the admin client expects the
        # trusted entries under an "entries" key.
        if isinstance(result, list):
            entries: list[dict[str, Any]] = result
            out: dict[str, Any] = {"entries": entries}
        else:
            out = dict(result)
            entries = out.get("entries") or []
        # Phase 5: annotate kind-32267 entries that are served as a registered
        # nsite (the normal nostrhost catalogue — nsites are never a separate
        # catalogue). The annotation is best-effort: it must not break the
        # catalogue listing when the gateway is not enabled.
        try:
            from .nsites.service import NsiteService

            links = NsiteService().catalogue_nsite_links()
        except Exception:  # noqa: BLE001 - annotation is cosmetic
            links = {}
        if links:
            for entry in entries:
                decl = entry.get("declaration") or {}
                address = f"32267:{decl.get('Publisher', '')}:{decl.get('AppID', '')}"
                link = links.get(address)
                if link:
                    entry["nsite"] = link
        # Best-effort logos from the YunoHost app catalogue (native declarations
        # carry no logo of their own); entries without one render a monogram.
        logos = app_catalog_logo_urls()
        if logos:
            for entry in entries:
                decl = entry.get("declaration") or {}
                app_id = decl.get("AppID") or decl.get("app_id")
                logo = logos.get(app_id) if isinstance(app_id, str) else None
                if logo:
                    entry["logo"] = logo
        return out

    @app.post("/package/catalog/publish")
    def catalog_publish() -> Any:
        body = _json_body()
        # H5: catalogue writes go through the signed operation chain (policy /
        # approval / audit), not a direct handler call.
        return _run_lifecycle(
            "catalog.publish", {"app_id": body.get("app_id", ""), "relays": body.get("relays", "")}, state=_State()
        )

    @app.post("/package/catalog/declare")
    def catalog_declare() -> Any:
        body = _json_body()
        return _run_lifecycle(
            "catalog.declare",
            {"package": body.get("package"), "repository": body.get("repository", ""), "relays": body.get("relays", "")},
            state=_State(),
        )

    @app.post("/package/catalog/verify")
    def catalog_verify() -> Any:
        body = _json_body()
        return _run_tool("catalog.verify", {"event_or_naddr": body.get("event_or_naddr", "")})

    @app.post("/package/catalog/attest")
    def catalog_attest() -> Any:
        body = _json_body()
        return _run_lifecycle(
            "catalog.attest",
            {
                "app_id": body.get("app_id", ""),
                "publisher": body.get("publisher", ""),
                "claim": body.get("claim", ""),
                "comment": body.get("comment", ""),
                "relays": body.get("relays", ""),
            },
            state=_State(),
        )

    @app.get("/package/catalog/trust")
    def catalog_trust() -> Any:
        query = _req().query_params
        required_checks = [item for item in query.get("required_checks", "").split(",") if item]
        trusted_verifiers = [item for item in query.get("trusted_verifiers", "").split(",") if item]
        min_attestations = query.get("min_attestations", "")
        return _run_tool(
            "catalog.trust",
            {
                "attestation_policy": query.get("attestation_policy", "off"),
                "min_attestations": int(min_attestations) if min_attestations.isdigit() else 0,
                "required_checks": required_checks,
                "trusted_verifiers": trusted_verifiers,
            },
        )

    @app.post("/package/catalog/reverify")
    def catalog_reverify() -> Any:
        body = _json_body()
        return _run_tool("catalog.reverify", {"app_id": body.get("app_id", "")})

    @app.post("/package/catalog/profile")
    def catalog_profile_set() -> Any:
        body = _json_body()
        return _run_lifecycle(
            "catalog.profile.set",
            {
                "name": body.get("name", ""),
                "about": body.get("about", ""),
                "picture": body.get("picture", ""),
                "nip05": body.get("nip05", ""),
                "website": body.get("website", ""),
                "relays": body.get("relays", ""),
            },
            state=_State(),
        )

    @app.post("/package/catalog/announce")
    def catalog_announce() -> Any:
        body = _json_body()
        return _run_lifecycle(
            "catalog.announce", {"app_id": body.get("app_id", ""), "relays": body.get("relays", "")}, state=_State()
        )

    # -- app ----------------------------------------------------------------

    @app.get("/package/app/management")
    def app_management() -> Any:
        catalogue_error = None
        try:
            catalogue = _run_tool("catalog.list", {})
        except ApiError as exc:
            # Keep the local inventory useful while the optional catalogue
            # service is unavailable, and make the degraded state explicit.
            catalogue = {"entries": []}
            catalogue_error = exc.message
        installed = _run_tool("app.list", {})
        result = {"apps": merge_catalogue_and_installed(catalogue, installed)}
        attach_app_logos(result["apps"], app_catalog_logo_urls())
        if catalogue_error:
            result["catalogue_error"] = catalogue_error
        return result

    @app.get("/package/app/{app_id}/settings")
    def app_settings(app_id: str) -> Any:
        try:
            return native_app_settings(app_id)
        except PackageError as exc:
            raise ApiError(404 if "not installed" in str(exc) else 400, "app_settings_unavailable", str(exc)) from exc

    def apply_catalogue_lifecycle(app_id: str, action: str, body: dict[str, Any]) -> Any:
        if set(body) != {"plan_sha256"}:
            raise ApiError(400, "invalid_request", "lifecycle apply requires plan_sha256")
        try:
            envelope = catalogue_lifecycle_plan(app_id, action)
        except PackageError as exc:
            raise ApiError(400, "invalid_app_lifecycle", str(exc)) from exc
        if body.get("plan_sha256") != envelope["plan_sha256"]:
            raise ApiError(409, "plan_changed", "The app or catalogue changed after this plan was reviewed. Review the refreshed plan before applying.")
        result = _run_lifecycle("package.reconcile", {"plan": envelope}, state=_State())
        if not result.get("ok"):
            return JSONResponse(
                {"error": result.get("reason") or result.get("state") or f"{action} was rejected", "code": "operation_rejected", "operation": result},
                status_code=409,
            )
        return {"operation": result, "action": action, "package": envelope.get("package")}

    @app.post("/package/app/{app_id}/install/plan")
    def app_install_plan(app_id: str) -> Any:
        if _json_body():
            raise ApiError(400, "invalid_request", "install plan does not accept a request body")
        try:
            return catalogue_lifecycle_plan(app_id, "install")
        except PackageError as exc:
            raise ApiError(400, "invalid_app_lifecycle", str(exc)) from exc

    @app.post("/package/app/{app_id}/install/apply")
    def app_install_apply(app_id: str) -> Any:
        return apply_catalogue_lifecycle(app_id, "install", _json_body())

    @app.post("/package/app/{app_id}/upgrade/plan")
    def app_upgrade_plan(app_id: str) -> Any:
        if _json_body():
            raise ApiError(400, "invalid_request", "upgrade plan does not accept a request body")
        try:
            return catalogue_lifecycle_plan(app_id, "upgrade")
        except PackageError as exc:
            raise ApiError(400, "invalid_app_lifecycle", str(exc)) from exc

    @app.post("/package/app/{app_id}/upgrade/apply")
    def app_upgrade_apply(app_id: str) -> Any:
        return apply_catalogue_lifecycle(app_id, "upgrade", _json_body())

    @app.post("/package/app/{app_id}/remove/plan")
    def app_remove_plan(app_id: str) -> Any:
        if _json_body():
            raise ApiError(400, "invalid_request", "remove plan does not accept a request body")
        try:
            return native_app_removal_plan(app_id)
        except PackageError as exc:
            raise ApiError(400, "invalid_app_lifecycle", str(exc)) from exc

    @app.post("/package/app/{app_id}/remove/apply")
    def app_remove_apply(app_id: str) -> Any:
        body = _json_body()
        if set(body) != {"plan_sha256"}:
            raise ApiError(400, "invalid_request", "remove apply requires plan_sha256")
        try:
            envelope = native_app_removal_plan(app_id)
        except PackageError as exc:
            raise ApiError(400, "invalid_app_lifecycle", str(exc)) from exc
        if body.get("plan_sha256") != envelope["plan_sha256"]:
            raise ApiError(409, "plan_changed", "Installed app state changed after this plan was reviewed. Review the refreshed plan before applying.")
        result = _run_lifecycle("package.reconcile", {"plan": envelope}, state=_State())
        if not result.get("ok"):
            return JSONResponse(
                {"error": result.get("reason") or result.get("state") or "removal was rejected", "code": "operation_rejected", "operation": result},
                status_code=409,
            )
        return {"operation": result, "action": "remove", "package": envelope.get("package")}

    @app.post("/package/app/{app_id}/settings/plan")
    def app_settings_plan(app_id: str) -> Any:
        body = _json_body()
        if set(body) != {"values"}:
            raise ApiError(400, "invalid_request", "settings plan accepts only a values object")
        try:
            return plan_native_settings_update(app_id, body.get("values"))
        except PackageError as exc:
            raise ApiError(400, "invalid_app_settings", str(exc)) from exc

    @app.post("/package/app/{app_id}/settings/apply")
    def app_settings_apply(app_id: str) -> Any:
        body = _json_body()
        if set(body) != {"values", "plan_sha256"}:
            raise ApiError(400, "invalid_request", "settings apply requires values and plan_sha256")
        try:
            envelope = plan_native_settings_update(app_id, body.get("values"))
        except PackageError as exc:
            raise ApiError(400, "invalid_app_settings", str(exc)) from exc
        if body.get("plan_sha256") != envelope["plan_sha256"]:
            raise ApiError(409, "plan_changed", "The app or its settings changed after this plan was reviewed. Review the refreshed plan before applying.")
        result = _run_lifecycle("package.reconcile", {"plan": {key: value for key, value in envelope.items() if key != "settings_diff"}}, state=_State())
        if not result.get("ok"):
            return JSONResponse(
                {"error": result.get("reason") or result.get("state") or "settings change was rejected", "code": "operation_rejected", "operation": result},
                status_code=409,
            )
        return {"operation": result, "settings_diff": envelope["settings_diff"]}

    @app.post("/package/app/{app_id}/change-url/plan")
    def app_change_url_plan(app_id: str) -> Any:
        body = _json_body()
        if set(body) != {"domain", "path"}:
            raise ApiError(400, "invalid_request", "change-url plan requires domain and path")
        try:
            return plan_native_change_url(app_id, body.get("domain"), body.get("path"))
        except PackageError as exc:
            raise ApiError(400, "invalid_app_lifecycle", str(exc)) from exc

    @app.post("/package/app/{app_id}/change-url/apply")
    def app_change_url_apply(app_id: str) -> Any:
        body = _json_body()
        if set(body) != {"domain", "path", "plan_sha256"}:
            raise ApiError(400, "invalid_request", "change-url apply requires domain, path and plan_sha256")
        try:
            envelope = plan_native_change_url(app_id, body.get("domain"), body.get("path"))
        except PackageError as exc:
            raise ApiError(400, "invalid_app_lifecycle", str(exc)) from exc
        if body.get("plan_sha256") != envelope["plan_sha256"]:
            raise ApiError(409, "plan_changed", "The app or another app's route changed after this plan was reviewed. Review the refreshed plan before applying.")
        result = _run_lifecycle("package.reconcile", {"plan": {key: value for key, value in envelope.items() if key != "url_diff"}}, state=_State())
        if not result.get("ok"):
            return JSONResponse(
                {"error": result.get("reason") or result.get("state") or "change-url was rejected", "code": "operation_rejected", "operation": result},
                status_code=409,
            )
        return {"operation": result, "action": "change-url", "url_diff": envelope["url_diff"]}

    @app.post("/package/app/remove")
    def app_remove() -> Any:
        """Remove one installed app. Data-loss-capable (purge): routed through
        the signed operation chain (policy + approval), not _run_tool."""
        body = _json_body()
        return _run_lifecycle(
            "app.remove",
            {"app": body.get("app", ""), "purge": bool(body.get("purge", False))},
            state=_State(),
        )

    # -- user (YunoHost accounts) ---------------------------------------------

    @app.post("/package/user/create")
    def user_create() -> Any:
        """Create a YunoHost user account/mailbox. Medium-risk: routed
        through the signed operation chain (owner co-signature), not
        _run_tool (user.create is require_approval=True in the registry)."""
        body = _json_body()
        return _run_lifecycle(
            "user.create",
            {
                "username": body.get("username", ""),
                "domain": body.get("domain", ""),
                "password": body.get("password", ""),
                "fullname": body.get("fullname", ""),
                "mailbox_quota": body.get("mailbox_quota", "0"),
                "admin": bool(body.get("admin", False)),
            },
            state=_State(),
        )

    @app.post("/package/user/update")
    def user_update() -> Any:
        """Update an existing user. Medium-risk: routed through the signed
        operation chain (owner co-signature), not _run_tool (user.update is
        require_approval=True in the registry)."""
        body = _json_body()
        return _run_lifecycle(
            "user.update",
            {
                "username": body.get("username", ""),
                "mail": body.get("mail"),
                "change_password": body.get("change_password"),
                "add_mailforward": body.get("add_mailforward"),
                "remove_mailforward": body.get("remove_mailforward"),
                "add_mailalias": body.get("add_mailalias"),
                "remove_mailalias": body.get("remove_mailalias"),
                "mailbox_quota": body.get("mailbox_quota"),
                "fullname": body.get("fullname"),
            },
            state=_State(),
        )

    @app.post("/package/user/delete")
    def user_delete() -> Any:
        """Delete a YunoHost user account. High-risk/irreversible: routed
        through the signed operation chain (owner co-signature), not
        _run_tool."""
        body = _json_body()
        return _run_lifecycle(
            "user.delete",
            {
                "username": body.get("username", ""),
                "purge": bool(body.get("purge", False)),
                "force": bool(body.get("force", False)),
            },
            state=_State(),
        )

    # -- user group -------------------------------------------------------------

    @app.post("/package/user/group/create")
    def user_group_create() -> Any:
        """Create a new user group. Medium-risk: routed through the signed
        operation chain (owner co-signature), not _run_tool."""
        body = _json_body()
        return _run_lifecycle(
            "user.group.create",
            {"groupname": body.get("groupname", ""), "gid": body.get("gid")},
            state=_State(),
        )

    @app.post("/package/user/group/update")
    def user_group_update() -> Any:
        """Add/remove usernames from a group. Medium-risk: routed through
        the signed operation chain (owner co-signature), not _run_tool."""
        body = _json_body()
        return _run_lifecycle(
            "user.group.update",
            {
                "groupname": body.get("groupname", ""),
                "add": body.get("add"),
                "remove": body.get("remove"),
            },
            state=_State(),
        )

    @app.post("/package/user/group/delete")
    def user_group_delete() -> Any:
        """Delete a user group. High-risk/irreversible: routed through the
        signed operation chain (owner co-signature), not _run_tool."""
        body = _json_body()
        return _run_lifecycle(
            "user.group.delete",
            {"groupname": body.get("groupname", ""), "force": bool(body.get("force", False))},
            state=_State(),
        )

    # -- user permission ----------------------------------------------------

    @app.get("/package/user/permission/list")
    def user_permission_list() -> Any:
        full = _req().query_params.get("full", "").lower() == "true"
        return _run_tool("user.permission.list", {"full": full})

    @app.post("/package/user/permission/add")
    def user_permission_add() -> Any:
        """Grant users/groups access to a permission. Medium-risk: routed
        through the signed operation chain (owner co-signature), not
        _run_tool."""
        body = _json_body()
        return _run_lifecycle(
            "user.permission.add",
            {"permission": body.get("permission", ""), "names": body.get("names", [])},
            state=_State(),
        )

    @app.post("/package/user/permission/remove")
    def user_permission_remove() -> Any:
        """Revoke users/groups access to a permission. Medium-risk: routed
        through the signed operation chain (owner co-signature), not
        _run_tool."""
        body = _json_body()
        return _run_lifecycle(
            "user.permission.remove",
            {"permission": body.get("permission", ""), "names": body.get("names", [])},
            state=_State(),
        )

    @app.post("/package/user/permission/update")
    def user_permission_update() -> Any:
        """Update a permission's label/tile visibility, not membership.
        Medium-risk: routed through the signed operation chain (owner
        co-signature), not _run_tool."""
        body = _json_body()
        return _run_lifecycle(
            "user.permission.update",
            {
                "permission": body.get("permission", ""),
                "label": body.get("label"),
                "show_tile": body.get("show_tile"),
            },
            state=_State(),
        )

    # -- power ----------------------------------------------------------------

    @app.post("/package/system/reboot")
    def system_reboot() -> Any:
        """Reboot the host. High-risk, irreversible-ish: routed through the
        signed operation chain (owner co-signature), not _run_tool."""
        return _run_lifecycle("system.reboot", {}, state=_State())

    @app.post("/package/system/shutdown")
    def system_shutdown() -> Any:
        """Power off the host. High-risk, requires out-of-band power-on to
        recover: routed through the signed operation chain (owner
        co-signature), not _run_tool."""
        return _run_lifecycle("system.shutdown", {}, state=_State())

    # -- settings -------------------------------------------------------------

    @app.get("/package/nostr/connectivity")
    def nostr_connectivity_get() -> Any:
        from .connectivity import public_view

        return public_view(control_relay=_config_control_relay() or "ws://127.0.0.1:4848")

    @app.post("/package/nostr/connectivity/check")
    def nostr_connectivity_check() -> Any:
        from .connectivity import ConnectivityError, check_destinations

        body = _json_body()
        if set(body) != {"relays", "blossom_servers"}:
            raise ApiError(400, "invalid_request", "connection check requires relays and blossom_servers")
        try:
            return check_destinations(body["relays"], body["blossom_servers"])
        except ConnectivityError as exc:
            raise ApiError(400, "invalid_connectivity", str(exc)) from exc

    @app.post("/package/nostr/connectivity/plan")
    def nostr_connectivity_plan() -> Any:
        from .connectivity import ConnectivityError, plan_config

        body = _json_body()
        if set(body) != {"configuration"}:
            raise ApiError(400, "invalid_request", "connectivity plan requires a configuration object")
        try:
            return plan_config(body["configuration"])
        except ConnectivityError as exc:
            raise ApiError(400, "invalid_connectivity", str(exc)) from exc

    @app.post("/package/nostr/connectivity/apply")
    def nostr_connectivity_apply() -> Any:
        from .connectivity import ConnectivityError, plan_config

        body = _json_body()
        if set(body) != {"configuration", "plan_sha256"}:
            raise ApiError(400, "invalid_request", "connectivity apply requires configuration and plan_sha256")
        try:
            plan = plan_config(body["configuration"])
        except ConnectivityError as exc:
            raise ApiError(400, "invalid_connectivity", str(exc)) from exc
        if body["plan_sha256"] != plan["plan_sha256"]:
            raise ApiError(409, "plan_changed", "Nostr network settings changed after review. Review the refreshed plan.")
        result = _run_lifecycle(
            "nostr.connectivity.set",
            {"configuration": body["configuration"], "plan_sha256": body["plan_sha256"]},
            state=_State(),
        )
        return {"operation": result, "effective": plan["effective"]}

    @app.get("/package/domain/primary")
    def domain_primary_get() -> Any:
        from .domains.primary import primary_status

        return primary_status()

    @app.post("/package/domain/primary/plan")
    def domain_primary_plan() -> Any:
        from .domains.primary import plan_primary

        body = _json_body()
        if set(body) != {"domain"}:
            raise ApiError(400, "invalid_request", "server address plan requires a domain")
        try:
            return plan_primary(str(body["domain"]))
        except Exception as exc:
            raise ApiError(400, "domain_not_ready", str(exc)) from exc

    @app.post("/package/domain/primary/apply")
    def domain_primary_apply() -> Any:
        from .domains.primary import plan_primary

        body = _json_body()
        if set(body) != {"domain", "plan_sha256"}:
            raise ApiError(400, "invalid_request", "server address apply requires domain and plan_sha256")
        try:
            plan = plan_primary(str(body["domain"]))
        except Exception as exc:
            raise ApiError(400, "domain_not_ready", str(exc)) from exc
        if body["plan_sha256"] != plan["plan_sha256"]:
            raise ApiError(409, "plan_changed", "Domain state changed after review. Review the refreshed plan.")
        result = _run_lifecycle(
            "domain.primary.set",
            {"domain": body["domain"], "plan_sha256": body["plan_sha256"]},
            state=_State(),
        )
        return {"operation": result, "admin_url": plan["new_admin_url"], "portal_url": plan["new_portal_url"]}

    @app.get("/package/settings/list")
    def settings_list() -> Any:
        full = _req().query_params.get("full", "").lower() == "true"
        return _run_tool("settings.list", {"full": full})

    @app.post("/package/settings/set")
    def settings_set() -> Any:
        """Set a global YunoHost setting. Medium-risk: routed through the
        signed operation chain (owner co-signature), not _run_tool."""
        body = _json_body()
        return _run_lifecycle(
            "settings.set",
            {"key": body.get("key", ""), "value": body.get("value")},
            state=_State(),
        )

    @app.post("/package/settings/reset")
    def settings_reset() -> Any:
        """Reset a global YunoHost setting to its default. Medium-risk:
        routed through the signed operation chain (owner co-signature), not
        _run_tool."""
        body = _json_body()
        return _run_lifecycle("settings.reset", {"key": body.get("key", "")}, state=_State())

    @app.post("/package/settings/reset_all")
    def settings_reset_all() -> Any:
        """Reset all global YunoHost settings to their defaults. High-risk:
        routed through the signed operation chain (owner co-signature), not
        _run_tool."""
        return _run_lifecycle("settings.reset_all", {}, state=_State())

    # -- package ------------------------------------------------------------

    @app.post("/package/plan")
    def package_plan() -> Any:
        body = _json_body()
        return _run_tool("package.plan", {"package": body.get("package"), "catalogue": body.get("catalogue")})

    @app.post("/package/authoring/fetch_manifest")
    def package_fetch_manifest() -> Any:
        body = _json_body()
        return _run_tool(
            "package.fetch_manifest",
            {
                "repository": body.get("repository", ""),
                "revision": body.get("revision", ""),
                "package_path": body.get("package_path", ""),
            },
        )

    @app.post("/package/reconcile")
    def package_reconcile() -> Any:
        body = _json_body()
        # Applying a caller-supplied reconcile plan is a write that changes
        # machine state: routed through the signed operation chain (which
        # re-validates the plan digest and runs policy/approval), not _run_tool.
        return _run_lifecycle("package.reconcile", {"plan": body.get("plan")}, state=_State())

    # -- identity (npub user model) ------------------------------------------

    @app.get("/package/identity/list")
    def identity_list() -> Any:
        username = _req().query_params.get("username")
        if username:
            identities = [_identity_dict(i) for i in list_identities_for_username(username)]
        else:
            identities = [_identity_dict(i) for i in list_identities()]
        # Stable client contract: identities ride under an `identities` key.
        return {"identities": identities}

    @app.get("/package/identity/resolve/{value}")
    def identity_resolve(value: str) -> Any:
        if value.startswith("npub1") or (len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value)):
            identity = resolve_pubkey(_parse_pubkey(value))
            return _identity_dict(identity) if identity else None
        identities = [_identity_dict(i) for i in resolve_username(value)]
        return {"identities": identities}

    @app.post("/package/identity/link")
    def identity_link() -> Any:
        body = _json_body()
        # H5: identity writes route through the signed operation chain; the
        # operator key never travels in the args (the handler reads config).
        return _run_lifecycle(
            "identity.link",
            {
                "username": body.get("username", ""),
                "pubkey_or_npub": body.get("pubkey_or_npub", ""),
                "signer_type": body.get("signer_type", "unknown"),
                "label": body.get("label"),
                "enabled": bool(body.get("enabled", True)),
            },
            state=_State(),
        )

    @app.post("/package/identity/revoke")
    def identity_revoke() -> Any:
        body = _json_body()
        return _run_lifecycle("identity.revoke", {"pubkey_or_npub": body.get("pubkey_or_npub", "")}, state=_State())

    # -- capability -----------------------------------------------------------

    @app.get("/package/capability/list")
    def capability_list() -> Any:
        return {"grants": list_capabilities(admin_sk=_config_admin_sk(), control_relay=_config_control_relay())}

    @app.post("/package/capability/grant")
    def capability_grant() -> Any:
        body = _json_body()
        # H5: capability writes route through the signed operation chain; the
        # admin signing key never travels in the args.
        return _run_lifecycle(
            "capability.grant",
            {"pubkey": body.get("pubkey", ""), "scopes": body.get("scopes", []), "type_": body.get("type", "agent")},
            state=_State(),
        )

    @app.post("/package/capability/delegate")
    def capability_delegate() -> Any:
        body = _json_body()
        return _run_lifecycle(
            "capability.delegate",
            {"pubkey": body.get("pubkey", ""), "scopes": body.get("scopes", []), "expires_at": int(body.get("expires_at", 0))},
            state=_State(),
        )

    @app.post("/package/capability/revoke")
    def capability_revoke() -> Any:
        body = _json_body()
        return _run_lifecycle("capability.revoke", {"delegation_id": body.get("delegation_id", "")}, state=_State())

    # -- mcp endpoint (Caddy route + CA trust, `nostrhost mcp route`) --------

    @app.get("/package/mcp/endpoint")
    def mcp_endpoint_info() -> Any:
        config = read_endpoint_config()
        return {"configured": config is not None, **(config or {})}

    @app.get("/package/mcp/ca-bundle")
    def mcp_ca_bundle() -> Any:
        """The combined CA bundle for a remote MCP client to trust this
        node's certificate — only meaningful when the MCP domain uses
        Caddy's internal CA (a lab/test domain); a public ACME certificate
        needs no client-side trust change, so ``available`` is false."""
        bundle = export_ca_bundle()
        if bundle is None:
            return {"available": False}
        return {"available": True, "pem": bundle.decode("utf-8", errors="replace")}

    # -- operations (kind-2200..2204 approval chain) -------------------------
    #
    # The admin console's OperationsView lists pending/past operations and
    # approves/rejects them. There is no separate operations database - the
    # control relay's own event store is authoritative, so list/get replay
    # the chain (see nostr_operations.list_operations/get_operation).
    #
    # Approve/reject accept an optional pre-signed `event`: the browser signs
    # it itself via a connected NIP-46 bunker (build_approval_template /
    # build_rejection_template give it the exact event to sign) so the
    # approval is auditable as coming from the admin's own remote signer
    # rather than the server's local admin key. Without `event`, the route
    # falls back to signing with the server-held admin/operator key, exactly
    # as `nostr-opctl approve/reject` already does.

    @app.get("/package/operations")
    def package_operations_list() -> Any:
        limit = _req().query_params.get("limit")
        return {"entries": list_operations(limit=int(limit) if limit else None, control_relay=_config_control_relay())}

    @app.get("/package/operations/{request_id}")
    def package_operations_get(request_id: str) -> Any:
        entry = get_operation(request_id, control_relay=_config_control_relay())
        if entry is None:
            raise ApiError(404, "not_found", f"no operation {request_id!r} on the control relay")
        return entry

    @app.get("/package/operations/{request_id}/approval-template")
    def package_operations_approval_template(request_id: str) -> Any:
        note = _req().query_params.get("note") or None
        return build_approval_template(_authorized_pubkey(), request_id, note)

    @app.get("/package/operations/{request_id}/rejection-template")
    def package_operations_rejection_template(request_id: str) -> Any:
        reason = _req().query_params.get("reason") or None
        return build_rejection_template(_authorized_pubkey(), request_id, reason)

    @app.post("/package/operations/{request_id}/approve")
    def package_operations_approve(request_id: str) -> Any:
        body = _json_body()
        signed_event = body.get("event")
        if signed_event is not None:
            if not isinstance(signed_event, dict):
                raise ApiError(400, "invalid_body", "event must be a signed Nostr event object")
            if signed_event.get("pubkey") != _authorized_pubkey():
                raise ApiError(403, "not_authorized", "the signed approval must come from the authenticated admin")
            event = validate_signed_approval(signed_event, request_id)
            publish_to_relay(_config_control_relay() or "ws://127.0.0.1:4848", event)
        else:
            event = approve_operation(
                request_id,
                admin_sk=_config_admin_sk(),
                control_relay=_config_control_relay(),
                note=body.get("note"),
            )
        return {"ok": True, "request_id": request_id, "event_id": event["id"]}

    @app.post("/package/operations/{request_id}/reject")
    def package_operations_reject(request_id: str) -> Any:
        body = _json_body()
        signed_event = body.get("event")
        if signed_event is not None:
            if not isinstance(signed_event, dict):
                raise ApiError(400, "invalid_body", "event must be a signed Nostr event object")
            if signed_event.get("pubkey") != _authorized_pubkey():
                raise ApiError(403, "not_authorized", "the signed rejection must come from the authenticated admin")
            event = validate_signed_rejection(signed_event, request_id)
            publish_to_relay(_config_control_relay() or "ws://127.0.0.1:4848", event)
        else:
            event = reject_operation(
                request_id,
                admin_sk=_config_admin_sk(),
                control_relay=_config_control_relay(),
                reason=body.get("reason"),
            )
        return {"ok": True, "request_id": request_id, "event_id": event["id"]}

    return app


def _authorized_pubkey() -> str:
    """The admin pubkey the route resolved for this request.

    Always set once a route body runs (the authorizer raises and short-circuits
    the response otherwise) - the one exception is /healthz, which never calls
    this."""
    pubkey = getattr(_req().state, "admin_pubkey", None)
    if not pubkey:
        raise ApiError(401, "authentication_required", "no authenticated identity for this request")
    return pubkey


def _json_body() -> dict[str, Any]:
    raw = getattr(_req().state, "body_bytes", b"")
    try:
        body = json.loads(raw) if raw else None
    except (ValueError, TypeError):  # noqa: BLE001 - malformed JSON
        body = None
    if not isinstance(body, dict):
        raise ApiError(400, "invalid_body", "request body must be a JSON object")
    return body


def _config_operator_sk() -> str | None:
    import os

    sk = os.environ.get("NOSTRHOST_OPERATOR_SK")
    if sk:
        return sk
    try:
        return _operator_config().operator_sk
    except (IdentityError, OSError):
        return None


def _config_admin_sk() -> str | None:
    import os

    sk = os.environ.get("NOSTRHOST_ADMIN_SK")
    if sk:
        return sk
    try:
        return _operator_config().operator_sk
    except (IdentityError, OSError):
        return None


def _config_control_relay() -> str | None:
    import os

    relay = os.environ.get("NOSTRHOST_CONTROL_RELAY")
    if relay:
        return relay
    try:
        return _operator_config().control_relay
    except (IdentityError, OSError):
        return None


def _identity_pubkeys_from_config() -> tuple[tuple[str, ...], str | None]:
    """Derive (admin_pubkeys, operator_pubkey) from operator.toml when the
    caller did not pass them explicitly — makes `nostr-api` self-contained
    behind the nostr-api systemd unit (no environment injection needed)."""
    try:
        cfg = _operator_config()
    except (IdentityError, OSError):
        return (), None
    return tuple(cfg.admins), cfg.operator_pubkey


def _identity_dict(identity: Any) -> dict[str, Any]:
    return {
        "pubkey": identity.pubkey,
        "username": identity.username,
        "signer_type": identity.signer_type,
        "label": identity.label,
        "enabled": identity.enabled,
        "created_at": identity.created_at,
        "last_used": identity.last_used,
    }


def run(
    host: str = "127.0.0.1",
    port: int = 8190,
    *,
    admin_pubkeys: tuple[str, ...] = (),
    operator_pubkey: str | None = None,
    app: FastAPI | None = None,
) -> None:
    """Serve the native API (used by bin/nostr-api).

    When neither ``operator_pubkey`` nor ``admin_pubkeys`` is given, the
    operator + admins are derived from /etc/nostrhost/operator.toml (the
    nostr-api unit relies on this; nothing needs to be injected)."""
    # Every write route runs its lifecycle through a local OperationEngine
    # (see cli._run_lifecycle / nostr_operations.run_signed_chain), reusing
    # nostr_operationsd's own logger. That daemon's entrypoint configures
    # logging itself (nostr_operationsd.run()), but this one previously
    # didn't -- so an execution failure's `logger.error(...)` had no handler
    # anywhere in the process and was silently dropped, on top of the
    # client-side "operation rejected" bug. Same setup as every other
    # nostr-*d entrypoint (nostr_operationsd.run(), nostr_identityd.run(), …).
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    # Same headless-moulinette setup as every nostr-*d daemon (operationsd,
    # identityd, permissiond): native tools that shell into the yunohost
    # toolchain (diagnosis.run, updates.check, app.*, user.*, ...) read
    # Moulinette.interface.type via yunohost.log's ActionLogger and otherwise
    # fail with AttributeError: 'NoneType' object has no attribute 'type'.
    from yunohost.nostr_identity import _init_headless_yunohost

    _init_headless_yunohost()
    if app is None and operator_pubkey is None and not admin_pubkeys:
        admin_pubkeys, operator_pubkey = _identity_pubkeys_from_config()
    app = app or build_app(admin_pubkeys=admin_pubkeys, operator_pubkey=operator_pubkey)
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":  # pragma: no cover - exercised through bin/nostr-api
    run()
