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

from .cli import _TOOL_HANDLERS
from .core import NostrHostError
from yunohost.nostr_identity import (
    IdentityError,
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
    delegate_capability,
    grant_capability,
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


def _run_tool(name: str, args: dict[str, Any]) -> Any:
    try:
        return _TOOL_HANDLERS[name](**args)
    except (NostrHostError, OperationError, IdentityError) as exc:
        raise ApiError(400, "operation_failed", str(exc)) from exc


def default_authorizer(
    *,
    admin_pubkeys: tuple[str, ...] = (),
    operator_pubkey: str | None = None,
) -> Callable[[], str]:
    """NIP-98 authorizer: verify the Authorization header, resolve the linked
    identity, and require the pubkey to be an admin (operator or configured)."""

    admins = set(admin_pubkeys)
    if operator_pubkey:
        admins.add(operator_pubkey)

    def authorize() -> str:
        header = request.headers.get("Authorization", "")
        if not header.startswith("Nostr "):
            raise ApiError(401, "authentication_required", "missing NIP-98 Authorization header")
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
            if str(route.rule) != "/healthz":
                try:
                    self.authorizer()
                except ApiError as exc:
                    return _json_error(exc.status, exc.code, exc.message)
            try:
                return callback(*args, **kwargs)
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


def build_app(
    *,
    authorizer: Callable[[], str] | None = None,
    admin_pubkeys: tuple[str, ...] = (),
    operator_pubkey: str | None = None,
) -> Bottle:
    """Build the native API Bottle app."""
    app = Bottle()
    auth = authorizer or default_authorizer(admin_pubkeys=admin_pubkeys, operator_pubkey=operator_pubkey)
    app.install(_AuthErrorsPlugin(auth))

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"ok": True, "version": API_VERSION}

    # -- system -------------------------------------------------------------

    @app.get("/system/version")
    def system_version() -> Any:
        return _run_tool("system.version", {})

    # -- service ------------------------------------------------------------

    @app.get("/service/status")
    def service_status() -> Any:
        return _run_tool("service.status", {"names": _optional_list(request.query.get("names"))})

    @app.post("/service/restart")
    def service_restart() -> Any:
        body = _json_body()
        return _run_tool("service.restart", {"name": body.get("name", "")})

    @app.post("/service/control")
    def service_control() -> Any:
        body = _json_body()
        return _run_tool("service.control", {"name": body.get("name", ""), "action": body.get("action", "")})

    # -- app ----------------------------------------------------------------

    @app.get("/app/list")
    def app_list() -> Any:
        return _run_tool("app.list", {})

    @app.post("/app/remove")
    def app_remove() -> Any:
        body = _json_body()
        return _run_tool("app.remove", {"app": body.get("app", ""), "purge": bool(body.get("purge", False))})

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

    @app.get("/identity/list")
    def identity_list() -> Any:
        username = request.query.get("username")
        if username:
            return [_identity_dict(i) for i in list_identities_for_username(username)]
        return [_identity_dict(i) for i in list_identities()]

    @app.get("/identity/resolve/<value>")
    def identity_resolve(value: str) -> Any:
        if value.startswith("npub1") or (len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value)):
            identity = resolve_pubkey(_parse_pubkey(value))
            return _identity_dict(identity) if identity else None
        return [_identity_dict(i) for i in resolve_username(value)]

    @app.post("/identity/link")
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

    @app.post("/identity/revoke")
    def identity_revoke() -> Any:
        body = _json_body()
        return revoke_identity(
            body.get("pubkey_or_npub", ""),
            operator_sk=_config_operator_sk(),
            control_relay=_config_control_relay(),
        )

    # -- capability -----------------------------------------------------------

    @app.post("/capability/grant")
    def capability_grant() -> Any:
        body = _json_body()
        return grant_capability(
            body.get("pubkey", ""),
            body.get("scopes", []),
            type_=body.get("type", "agent"),
            admin_sk=_config_admin_sk(),
            control_relay=_config_control_relay(),
        )

    @app.post("/capability/delegate")
    def capability_delegate() -> Any:
        body = _json_body()
        return delegate_capability(
            body.get("pubkey", ""),
            body.get("scopes", []),
            int(body.get("expires_at", 0)),
            delegator_sk=_config_operator_sk(),
            control_relay=_config_control_relay(),
        )

    @app.post("/capability/revoke")
    def capability_revoke() -> Any:
        body = _json_body()
        return revoke_delegation(
            body.get("delegation_id", ""),
            delegator_sk=_config_operator_sk(),
            control_relay=_config_control_relay(),
        )

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

    return os.environ.get("NOSTRHOST_OPERATOR_SK")


def _config_admin_sk() -> str | None:
    import os

    return os.environ.get("NOSTRHOST_ADMIN_SK")


def _config_control_relay() -> str | None:
    import os

    return os.environ.get("NOSTRHOST_CONTROL_RELAY")


def _identity_dict(identity: Any) -> dict[str, Any]:
    return {
        "pubkey": identity.pubkey,
        "username": identity.ynh_username,
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
    """Serve the native API (used by bin/nostr-api)."""
    app = app or build_app(admin_pubkeys=admin_pubkeys, operator_pubkey=operator_pubkey)
    app.run(host=host, port=port)


if __name__ == "__main__":  # pragma: no cover - exercised through bin/nostr-api
    run()
