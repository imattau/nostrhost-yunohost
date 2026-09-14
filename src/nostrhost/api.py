"""Native HTTP API (Moulinette API replacement, Stage 5).

A Bottle app exposing the same native operations as the ``nostrhost`` CLI
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

import base64
import json
from typing import Any, Callable

from bottle import Bottle, HTTPResponse, request

from .cli import (
    _agent_contribution_settings_get,
    _agent_contribution_settings_set,
    _agent_contribution_submit,
    _agent_export_get,
    _agent_export_list,
    _agent_export_run,
    _agent_init,
    _agent_mode_get,
    _agent_mode_set,
    _agent_model_download,
    _agent_model_profile,
    _agent_model_recommend,
    _agent_model_select,
    _agent_model_status,
    _agent_service,
    _agent_status,
    _TOOL_HANDLERS,
    _State,
    _run_lifecycle,
)
from .core import NostrHostError
from .app_management import catalogue_lifecycle_plan, merge_catalogue_and_installed, native_app_removal_plan, native_app_settings, plan_native_settings_update
from .package_engine import PackageError
from .mcp_endpoint import export_ca_bundle, read_endpoint_config
from yunohost.nostr_identity import (
    IdentityError,
    _operator_config,
    _parse_pubkey,
    link_identity,
    list_identities,
    list_identities_for_username,
    resolve_pubkey,
    resolve_username,
    revoke_identity,
)
from yunohost.nostr_operations import (
    OperationError,
    approve_operation,
    delegate_capability,
    grant_capability,
    list_capabilities,
    reject_operation,
    revoke_delegation,
)
from nostrhost_auth.auth.nostr_verify import parse_and_verify_event

API_VERSION = 1


class ApiError(Exception):
    """Error that maps to an HTTP response."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _json_error(status: int, code: str, message: str) -> HTTPResponse:
    return HTTPResponse(
        json.dumps({"error": message, "code": code}),
        status=status,
        headers={"Content-Type": "application/json"},
    )


def _json_safe(value: Any) -> Any:
    """Recursively convert values Bottle's default JSON encoder can't handle
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
        return _TOOL_HANDLERS[name](**args)
    except (NostrHostError, OperationError, IdentityError) as exc:
        raise ApiError(400, "operation_failed", str(exc)) from exc


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


def _session_username() -> str | None:
    """The session user from the ``nostrhost.portal`` cookie, or None.

    Reuses the portal session validation (Authenticator.get_session_cookie)
    so the native API shares the portal's sign-in state: once a user signs in
    at the portal, the same cookie authenticates the admin console — no second
    login or NIP-07 signer needed.
    """
    try:
        from yunohost.nostr_account import _session_username as portal_session_user
    except Exception:  # pragma: no cover - import fallback
        portal_session_user = None
    if portal_session_user is None:
        return None
    try:
        return portal_session_user()
    except Exception:  # pragma: no cover - session store hiccup
        return None


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


def default_authorizer(
    *,
    admin_pubkeys: tuple[str, ...] = (),
    operator_pubkey: str | None = None,
) -> Callable[[], str]:
    """NIP-98 / session authorizer: verify the request identity and require an
    admin (operator or configured).

    Two mutually-exclusive authentication paths:

    - NIP-98 ``Authorization: Nostr <base64 event>`` (the existing signer
      path): verify the event, resolve the signer pubkey to a linked identity,
      and require the pubkey to be an admin.
    - Portal session cookie (``nostrhost.portal``): validate the portal
      session, resolve the session user's linked identity, and require one of
      its pubkeys to be an admin. This is the admin-console path: the user
      signs in once at the portal and the same cookie authorizes the console.
    """

    admins = _build_admin_set(admin_pubkeys=admin_pubkeys, operator_pubkey=operator_pubkey)

    def authorize() -> str:
        header = request.headers.get("Authorization", "")
        if header.startswith("Nostr "):
            try:
                event_json = base64.b64decode(header[6:], validate=True).decode("utf-8")
            except Exception as exc:  # noqa: BLE001 - malformed base64
                raise ApiError(401, "invalid_auth", f"malformed NIP-98 header: {exc}") from exc
            try:
                event = parse_and_verify_event(event_json)
                pubkey = event.author().to_hex()
            except Exception as exc:  # noqa: BLE001 - signature/timestamp failure
                raise ApiError(401, "invalid_signature", f"NIP-98 event rejected: {exc}") from exc
            try:
                identity = resolve_pubkey(pubkey)
            except Exception:  # noqa: BLE001 - unlinked/unknown or unavailable store
                identity = None
            if identity is None:
                raise ApiError(403, "identity_not_linked", "pubkey is not a linked identity")
            if pubkey not in admins:
                raise ApiError(403, "not_authorized", "pubkey is not an admin")
            return pubkey

        # Portal-session path: no NIP-98 header, use the portal login cookie.
        pubkey = _session_admin_pubkey(admins)
        if pubkey is not None:
            return pubkey
        if _session_username() is not None:
            raise ApiError(403, "not_authorized", "session user is not an admin")
        raise ApiError(
            401,
            "authentication_required",
            "missing NIP-98 Authorization header or portal session",
        )

    return authorize


class _AuthErrorsPlugin:
    """Bottle plugin: authorize before each route (except /healthz) and map
    ApiError to JSON responses."""

    name = "nostrhost-auth"

    def __init__(self, authorizer: Callable[[], str]) -> None:
        self.authorizer = authorizer
        self.app: Bottle | None = None

    def setup(self, app: Bottle) -> None:
        self.app = app

    def apply(self, callback: Callable[..., Any], route: Any) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Accept both layouts so /healthz and /session stay public.
            if isinstance(route, dict):
                rule = route.get("rule", "")
            else:
                rule = getattr(route, "rule", "")
            if str(rule) not in ("/package/healthz", "/package/session"):
                try:
                    self.authorizer()
                except ApiError as exc:
                    return _json_error(exc.status, exc.code, exc.message)
            try:
                result = callback(*args, **kwargs)
                if isinstance(result, HTTPResponse):
                    return result
                # Sanitise datetimes/sets so Bottle's default encoder can
                # serialise tool results (e.g. service.status's datetimes).
                return _json_safe(result)
            except ApiError as exc:
                return _json_error(exc.status, exc.code, exc.message)
            except (NostrHostError, OperationError, IdentityError) as exc:
                return _json_error(400, "operation_failed", str(exc))
            except Exception as exc:  # noqa: BLE001 - last error boundary
                return _json_error(500, "internal_error", str(exc))

        return wrapper

    def close(self) -> None:
        pass


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
    authorizer: Callable[[], str] | None = None,
    admin_pubkeys: tuple[str, ...] = (),
    operator_pubkey: str | None = None,
    event_stream: Callable[[str], Any] | None = None,
) -> Bottle:
    """Build the native API Bottle app.

    ``event_stream(request_id)`` yields operation chain events for the SSE
    ``/events/<id>`` endpoint (default: live relay subscription).
    """
    app = Bottle()
    auth = authorizer or default_authorizer(admin_pubkeys=admin_pubkeys, operator_pubkey=operator_pubkey)
    app.install(_AuthErrorsPlugin(auth))
    stream = event_stream or _default_event_stream

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
        only the session user's username + admin flag.
        """
        username = _session_username()
        pubkey = None
        admin_pubkey = None
        admins = _build_admin_set(admin_pubkeys=admin_pubkeys, operator_pubkey=operator_pubkey)
        if username is not None:
            try:
                identities = resolve_username(username)
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
        }

    @app.get("/package/events/<request_id>")
    def events(request_id: str) -> Any:
        """Server-Sent Events: live progress/result for one operation."""
        from nostrhost import events as events_module

        def frame() -> Any:
            yield events_module.sse_ping()
            for event in stream(request_id):
                yield events_module.sse_format(event)

        response = HTTPResponse(
            frame(),
            headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )
        return response

    # -- operations (audit history + pending approvals) ----------------------

    @app.get("/package/operations")
    def operations_list() -> Any:
        limit_param = request.query.get("limit")
        try:
            limit = int(limit_param) if limit_param else None
        except ValueError:
            raise ApiError(400, "invalid_query", "'limit' must be an integer")
        return _run_tool("audit.list", {"limit": limit})

    @app.get("/package/operations/<request_id>")
    def operations_get(request_id: str) -> Any:
        return _run_tool("audit.get", {"audit_id": request_id})

    @app.post("/package/operations/<request_id>/approve")
    def operations_approve(request_id: str) -> Any:
        body = _json_body()
        try:
            event = approve_operation(request_id, note=body.get("note"))
        except OperationError as exc:
            raise ApiError(400, "operation_failed", str(exc)) from exc
        return {"ok": True, "request_id": request_id, "event_id": event.get("id")}

    @app.post("/package/operations/<request_id>/reject")
    def operations_reject(request_id: str) -> Any:
        body = _json_body()
        try:
            event = reject_operation(request_id, reason=body.get("reason"))
        except OperationError as exc:
            raise ApiError(400, "operation_failed", str(exc)) from exc
        return {"ok": True, "request_id": request_id, "event_id": event.get("id")}

    # -- system -------------------------------------------------------------

    @app.get("/package/system/version")
    def system_version() -> Any:
        return _run_tool("system.version", {})

    @app.get("/package/system/status")
    def system_status() -> Any:
        """Host status (platform, hostname, load) for the Overview dashboard."""
        return _run_tool("system.status", {})

    @app.get("/package/system/updates")
    def system_updates() -> Any:
        """Cached apt/app updates + pending-migrations flag (no network refresh)."""
        return _run_tool("updates.check", {})

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
                "pending": request.query.get("pending", "").lower() == "true",
                "done": request.query.get("done", "").lower() == "true",
            },
        )

    @app.post("/package/system/migrate")
    def system_migrate() -> Any:
        """Run/skip/force-rerun migrations. High-risk/irreversible: routed
        through the signed operation chain (owner co-signature), not _run_tool."""
        body = _json_body()
        return _run_lifecycle("system.migrate", body, state=_State())

    # -- domain / dns ---------------------------------------------------------

    @app.get("/package/domain/list")
    def domain_list() -> Any:
        return _run_tool("domain.list", {})

    @app.get("/package/domain/<domain>/inspect")
    def domain_inspect(domain: str) -> Any:
        """Intent, desired/actual DNS, diff, and routes for a native domain."""
        return _run_tool("domain.inspect", {"domain": domain})

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

    @app.get("/package/nsite/gateway/status")
    def nsite_gateway_status() -> Any:
        """Nsite gateway status: enabled, mode, domain, service health."""
        return _run_tool("nsite.gateway.status", {})

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

    @app.get("/package/nsite/list")
    def nsite_list() -> Any:
        """Registered sites and the gateway mode."""
        return _run_tool("nsite.list", {})

    @app.get("/package/nsite/inspect")
    def nsite_inspect() -> Any:
        """One registered site record."""
        return _run_tool(
            "nsite.inspect",
            {
                "pubkey": request.query.get("pubkey", ""),
                "d": request.query.get("d", ""),
            },
        )

    @app.get("/package/nsite/resolve")
    def nsite_resolve() -> Any:
        """Fetch the current manifest for a label/pubkey from public relays
        (read only, bounded)."""
        return _run_tool(
            "nsite.resolve",
            {
                "label": request.query.get("label", ""),
                "pubkey": request.query.get("pubkey", ""),
                "d": request.query.get("d", ""),
                "relays": _optional_list(request.query.get("relays")),
                "limit": int(request.query.get("limit", "5")),
                "timeout": float(request.query.get("timeout", "8")),
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
        """Blob inventory to an unsigned manifest + plan_sha256 (D7)."""
        body = _json_body()
        return _run_tool(
            "nsite.publish.plan",
            {
                "pubkey": body.get("pubkey", ""),
                "kind": int(body.get("kind", 15128)),
                "d": body.get("d", ""),
                "items": body.get("items", []),
                "servers": body.get("servers"),
                "relays": body.get("relays"),
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

    @app.get("/package/dns/plan/<domain>")
    def dns_plan(domain: str) -> Any:
        """Desired-vs-actual DNS plan for a domain (no changes)."""
        return _run_tool("dns.plan", {"domain": domain})

    @app.post("/package/dns/apply")
    def dns_apply() -> Any:
        """Apply the DNS plan for a domain through its provider. High-risk:
        routed through the signed operation chain (owner co-signature)."""
        body = _json_body()
        return _run_lifecycle("dns.apply", {"domain": body.get("domain", "")}, state=_State())

    @app.get("/package/dns/verify/<domain>")
    def dns_verify(domain: str) -> Any:
        return _run_tool("dns.verify", {"domain": domain})

    @app.get("/package/dns/watch")
    def dns_watch() -> Any:
        """DDNS watcher status: last-seen public IPs and dynamic-IP domains."""
        return _run_tool("dns.watch", {})

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

    @app.get("/package/dns/subscriptions")
    def dns_subscriptions() -> Any:
        return _run_tool("dns.subscriptions", {})

    @app.post("/package/dns/unsubscribe")
    def dns_unsubscribe() -> Any:
        """Release a nostr-native free-hostname subscription and drop its
        broker secret. High-risk: routed through the signed operation chain."""
        body = _json_body()
        return _run_lifecycle("dns.unsubscribe", {"hostname": body.get("hostname", "")}, state=_State())

    # -- network / dns credentials --------------------------------------------

    @app.get("/package/network/public-ip")
    def network_public_ip() -> Any:
        return _run_tool("network.public_ip", {})

    @app.get("/package/credential/list")
    def credential_list() -> Any:
        """Configured DNS credential references (names only, never values)."""
        return _run_tool("credential.list", {})

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
        with_info = request.query.get("with_info", "").lower() == "true"
        return _run_tool("backup.list", {"with_info": with_info})

    @app.get("/package/backup/<name>")
    def backup_info(name: str) -> Any:
        with_details = request.query.get("with_details", "").lower() == "true"
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

    @app.get("/package/diagnosis/ignored")
    def diagnosis_ignored() -> Any:
        return _run_tool("diagnosis.ignored", {})

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
        protocol = request.query.get("protocol", "tcp")
        forwarded = request.query.get("forwarded", "").lower() == "true"
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
        return _run_tool("service.status", {"names": _optional_list(request.query.get("names"))})

    @app.post("/package/service/restart")
    def service_restart() -> Any:
        body = _json_body()
        return _run_tool("service.restart", {"name": body.get("name", "")})

    @app.post("/package/service/control")
    def service_control() -> Any:
        body = _json_body()
        return _run_tool("service.control", {"name": body.get("name", ""), "action": body.get("action", "")})

    # -- agent ----------------------------------------------------------------

    @app.get("/package/agent/status")
    def agent_status() -> Any:
        return _agent_status()

    @app.post("/package/agent/init")
    def agent_init() -> Any:
        return _agent_init()

    @app.post("/package/agent/enable")
    def agent_enable() -> Any:
        return _agent_service("enable")

    @app.post("/package/agent/disable")
    def agent_disable() -> Any:
        return _agent_service("disable")

    @app.get("/package/agent/models/profile")
    def agent_models_profile() -> Any:
        return _agent_model_profile()

    @app.get("/package/agent/models/recommend")
    def agent_models_recommend() -> Any:
        return _agent_model_recommend()

    @app.post("/package/agent/models/download")
    def agent_models_download() -> Any:
        body = _json_body()
        return _agent_model_download(body.get("model_id", ""), bool(body.get("evaluation_only", False)))

    @app.post("/package/agent/models/select")
    def agent_models_select() -> Any:
        body = _json_body()
        return _agent_model_select(body.get("model_id", ""))

    @app.get("/package/agent/models/status")
    def agent_models_status() -> Any:
        return _agent_model_status()

    @app.get("/package/agent/mode")
    def agent_mode_get() -> Any:
        return _agent_mode_get()

    @app.post("/package/agent/mode")
    def agent_mode_set() -> Any:
        body = _json_body()
        return _agent_mode_set(body.get("level", ""), bool(body.get("confirm", False)))

    @app.get("/package/agent/export/list")
    def agent_export_list() -> Any:
        # Bottle 0.12's response casting only auto-serialises a dict, not a
        # bare list, at the route's top level (same reason catalog_list
        # below wraps its result) -- wrap the array under a key.
        return {"cycles": _agent_export_list()}

    @app.post("/package/agent/export/run")
    def agent_export_run() -> Any:
        body = _json_body()
        return _agent_export_run(body.get("cycle_id", ""))

    @app.get("/package/agent/export/<candidate_file_id>")
    def agent_export_get(candidate_file_id: str) -> Any:
        return _agent_export_get(candidate_file_id)

    @app.get("/package/agent/contribution/settings")
    def agent_contribution_settings_get() -> Any:
        return _agent_contribution_settings_get()

    @app.post("/package/agent/contribution/settings")
    def agent_contribution_settings_set() -> Any:
        """Touches Hugging Face credentials and, via auto_submit, can flip on
        the resident daemon submitting every completed cycle with no human
        review. Same admin-only NIP-98/session trust level as
        agent_init/agent_enable above -- this is a local admin-API setting,
        not a host operation, so it does not go through the
        nostr-operationsd signed tool chain."""
        body = _json_body()
        return _agent_contribution_settings_set(
            body.get("dataset_repo", ""),
            body.get("token") or None,
            bool(body.get("auto_submit", False)),
        )

    @app.post("/package/agent/contribution/submit")
    def agent_contribution_submit() -> Any:
        """Causes real network egress of exactly one reviewed candidate file
        the admin explicitly chose. Same admin-only trust level as above."""
        body = _json_body()
        return _agent_contribution_submit(body.get("candidate_file_id", ""))

    # -- catalog --------------------------------------------------------------

    @app.get("/package/catalog/list")
    def catalog_list() -> Any:
        result = _run_tool("catalog.list", {})
        # The catalogue CLI emits a bare list; the admin client expects the
        # trusted entries under an "entries" key.
        if isinstance(result, list):
            return {"entries": result}
        return result

    @app.get("/package/catalog/get/<app_id>")
    def catalog_get(app_id: str) -> Any:
        return _run_tool("catalog.get", {"app_id": app_id})

    # -- app ----------------------------------------------------------------

    @app.get("/package/app/list")
    def app_list() -> Any:
        return _run_tool("app.list", {})

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
        if catalogue_error:
            result["catalogue_error"] = catalogue_error
        return result

    @app.get("/package/app/<app_id>/settings")
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
            return HTTPResponse(
                json.dumps({"error": result.get("reason") or result.get("state") or f"{action} was rejected", "code": "operation_rejected", "operation": result}),
                status=409,
                headers={"Content-Type": "application/json"},
            )
        return {"operation": result, "action": action, "package": envelope.get("package")}

    @app.post("/package/app/<app_id>/install/plan")
    def app_install_plan(app_id: str) -> Any:
        if _json_body():
            raise ApiError(400, "invalid_request", "install plan does not accept a request body")
        try:
            return catalogue_lifecycle_plan(app_id, "install")
        except PackageError as exc:
            raise ApiError(400, "invalid_app_lifecycle", str(exc)) from exc

    @app.post("/package/app/<app_id>/install/apply")
    def app_install_apply(app_id: str) -> Any:
        return apply_catalogue_lifecycle(app_id, "install", _json_body())

    @app.post("/package/app/<app_id>/upgrade/plan")
    def app_upgrade_plan(app_id: str) -> Any:
        if _json_body():
            raise ApiError(400, "invalid_request", "upgrade plan does not accept a request body")
        try:
            return catalogue_lifecycle_plan(app_id, "upgrade")
        except PackageError as exc:
            raise ApiError(400, "invalid_app_lifecycle", str(exc)) from exc

    @app.post("/package/app/<app_id>/upgrade/apply")
    def app_upgrade_apply(app_id: str) -> Any:
        return apply_catalogue_lifecycle(app_id, "upgrade", _json_body())

    @app.post("/package/app/<app_id>/remove/plan")
    def app_remove_plan(app_id: str) -> Any:
        if _json_body():
            raise ApiError(400, "invalid_request", "remove plan does not accept a request body")
        try:
            return native_app_removal_plan(app_id)
        except PackageError as exc:
            raise ApiError(400, "invalid_app_lifecycle", str(exc)) from exc

    @app.post("/package/app/<app_id>/remove/apply")
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
            return HTTPResponse(
                json.dumps({"error": result.get("reason") or result.get("state") or "removal was rejected", "code": "operation_rejected", "operation": result}),
                status=409,
                headers={"Content-Type": "application/json"},
            )
        return {"operation": result, "action": "remove", "package": envelope.get("package")}

    @app.post("/package/app/<app_id>/settings/plan")
    def app_settings_plan(app_id: str) -> Any:
        body = _json_body()
        if set(body) != {"values"}:
            raise ApiError(400, "invalid_request", "settings plan accepts only a values object")
        try:
            return plan_native_settings_update(app_id, body.get("values"))
        except PackageError as exc:
            raise ApiError(400, "invalid_app_settings", str(exc)) from exc

    @app.post("/package/app/<app_id>/settings/apply")
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
            return HTTPResponse(
                json.dumps({"error": result.get("reason") or result.get("state") or "settings change was rejected", "code": "operation_rejected", "operation": result}),
                status=409,
                headers={"Content-Type": "application/json"},
            )
        return {"operation": result, "settings_diff": envelope["settings_diff"]}

    @app.post("/package/app/remove")
    def app_remove() -> Any:
        body = _json_body()
        return _run_tool("app.remove", {"app": body.get("app", ""), "purge": bool(body.get("purge", False))})

    # -- user (YunoHost accounts) ---------------------------------------------

    @app.get("/package/user/list")
    def user_list() -> Any:
        return _run_tool("user.list", {})

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

    @app.get("/package/user/group/list")
    def user_group_list() -> Any:
        return _run_tool("user.group.list", {})

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
        full = request.query.get("full", "").lower() == "true"
        return _run_tool("user.permission.list", {"full": full})

    @app.get("/package/user/permission/info/<permission>")
    def user_permission_info(permission: str) -> Any:
        return _run_tool("user.permission.info", {"permission": permission})

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

    @app.get("/package/settings/list")
    def settings_list() -> Any:
        full = request.query.get("full", "").lower() == "true"
        return _run_tool("settings.list", {"full": full})

    @app.get("/package/settings/get/<key>")
    def settings_get(key: str) -> Any:
        return _run_tool("settings.get", {"key": key})

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

    @app.post("/package/reconcile")
    def package_reconcile() -> Any:
        body = _json_body()
        return _run_tool("package.reconcile", {"plan": body.get("plan")})

    # -- identity (npub user model) ------------------------------------------

    @app.get("/package/identity/list")
    def identity_list() -> Any:
        username = request.query.get("username")
        if username:
            identities = [_identity_dict(i) for i in list_identities_for_username(username)]
        else:
            identities = [_identity_dict(i) for i in list_identities()]
        # Bottle's json plugin cannot serialise a top-level list; wrap it.
        return {"identities": identities}

    @app.get("/package/identity/resolve/<value>")
    def identity_resolve(value: str) -> Any:
        if value.startswith("npub1") or (len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value)):
            identity = resolve_pubkey(_parse_pubkey(value))
            return _identity_dict(identity) if identity else None
        identities = [_identity_dict(i) for i in resolve_username(value)]
        return {"identities": identities}

    @app.post("/package/identity/link")
    def identity_link() -> Any:
        body = _json_body()
        return link_identity(
            body.get("username", ""),
            body.get("pubkey_or_npub", ""),
            operator_sk=_config_operator_sk(),
            control_relay=_config_control_relay(),
            signer_type=body.get("signer_type", "unknown"),
            label=body.get("label"),
            enabled=bool(body.get("enabled", True)),
        )

    @app.post("/package/identity/revoke")
    def identity_revoke() -> Any:
        body = _json_body()
        return revoke_identity(
            body.get("pubkey_or_npub", ""),
            operator_sk=_config_operator_sk(),
            control_relay=_config_control_relay(),
        )

    # -- capability -----------------------------------------------------------

    @app.get("/package/capability/list")
    def capability_list() -> Any:
        return {"grants": list_capabilities(admin_sk=_config_admin_sk(), control_relay=_config_control_relay())}

    @app.post("/package/capability/grant")
    def capability_grant() -> Any:
        body = _json_body()
        return grant_capability(
            body.get("pubkey", ""),
            body.get("scopes", []),
            type_=body.get("type", "agent"),
            admin_sk=_config_admin_sk(),
            control_relay=_config_control_relay(),
        )

    @app.post("/package/capability/delegate")
    def capability_delegate() -> Any:
        body = _json_body()
        return delegate_capability(
            body.get("pubkey", ""),
            body.get("scopes", []),
            int(body.get("expires_at", 0)),
            delegator_sk=_config_operator_sk(),
            control_relay=_config_control_relay(),
        )

    @app.post("/package/capability/revoke")
    def capability_revoke() -> Any:
        body = _json_body()
        return revoke_delegation(
            body.get("delegation_id", ""),
            delegator_sk=_config_operator_sk(),
            control_relay=_config_control_relay(),
        )

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

    return app


def _json_body() -> dict[str, Any]:
    try:
        body = request.json
    except Exception:  # noqa: BLE001 - bottle raises on malformed JSON
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
    app: Bottle | None = None,
) -> None:
    """Serve the native API (used by bin/nostr-api).

    When neither ``operator_pubkey`` nor ``admin_pubkeys`` is given, the
    operator + admins are derived from /etc/nostrhost/operator.toml (the
    nostr-api unit relies on this; nothing needs to be injected)."""
    if app is None and operator_pubkey is None and not admin_pubkeys:
        admin_pubkeys, operator_pubkey = _identity_pubkeys_from_config()
    app = app or build_app(admin_pubkeys=admin_pubkeys, operator_pubkey=operator_pubkey)
    app.run(host=host, port=port)


if __name__ == "__main__":  # pragma: no cover - exercised through bin/nostr-api
    run()
