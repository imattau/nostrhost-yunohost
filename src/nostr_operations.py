"""Nostr-native operation chain for the derivative fork (roadmap §4 / Phase 3).

The operation slice proves the architectural claim of the whole project:
signed Nostr events drive YunoHost through a controlled execution boundary.

Chain kinds (see libs/nostrhost-control EVENT-PROTOCOL.md §2.1):

    REQUEST   npub-agent   kind 2200   {"tool": "...", "args": {...}}
    APPROVAL  npub-admin   kind 2201   e -> request id
    REJECTION npub-admin   kind 2202   e -> request id
    EXECUTION npub-server  kind 2203   e -> request id
    RESULT    npub-server  kind 2204   e -> request id   {"ok": bool, ...}

Every step is a unique immutable stored event: the chain is the audit log.
The executor (nostr_operationsd) enforces the state machine and authorisation;
this module provides the authoring side (what the CLI/tests sign and publish)
and the safe-tool registry the executor runs against.

Phase 3 posture: only read-only tools are in the default registry; every tool
requires an admin approval before execution. Scopes use the nostrhost-policy
vocabulary (server.read / apps.read / services.read) so grants (kind 31100)
stay meaningful across the stack.

Heavy dependencies are imported lazily; transport and keys are injectable for
tests, mirroring nostr_identity.py.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Callable

from .nostr_identity import IdentityError, _operator_config, _sign_event, publish_to_relay

# Chain kinds (must match eventmodel.go / EVENT-PROTOCOL.md).
KIND_OPERATION_REQUEST = 2200
KIND_OPERATION_APPROVAL = 2201
KIND_OPERATION_REJECTION = 2202
KIND_EXECUTION_STARTED = 2203
KIND_EXECUTION_RESULT = 2204
KIND_CAPABILITY = 31100

CHAIN_KINDS = (
    KIND_OPERATION_REQUEST,
    KIND_OPERATION_APPROVAL,
    KIND_OPERATION_REJECTION,
    KIND_EXECUTION_STARTED,
    KIND_EXECUTION_RESULT,
)

# Scope names (nostrhost-policy vocabulary) for the safe read-only tools.
SCOPE_SERVER_READ = "server.read"
SCOPE_APPS_READ = "apps.read"
SCOPE_SERVICES_READ = "services.read"


class OperationError(ValueError):
    """The operation request failed (unknown tool, bad args, config, …)."""


@dataclass(frozen=True)
class ToolSpec:
    """One executable tool: its scope, approval requirement and real handler.

    `handler` is the *safe* wrapper — a thin call into the fork's own
    decorated function. The executor backend injects a fake for tests.
    """

    name: str
    handler: Callable[..., Any]
    scope: str
    require_approval: bool = True
    description: str = ""


def _safe_system_version(**args: Any) -> dict[str, Any]:
    from yunohost.tools import tools_versions

    return tools_versions()


def _safe_app_list(**args: Any) -> dict[str, Any]:
    from yunohost.app import app_list

    return app_list(**args)


def _safe_service_status(**args: Any) -> dict[str, Any]:
    from yunohost.service import service_status

    return service_status(**args)


# The default registry: read-only, approval-gated. Safe by construction —
# nothing here can mutate server state.
TOOLS: dict[str, ToolSpec] = {
    "system.version": ToolSpec(
        name="system.version",
        handler=_safe_system_version,
        scope=SCOPE_SERVER_READ,
        description="read-only OS/package version information",
    ),
    "app.list": ToolSpec(
        name="app.list",
        handler=_safe_app_list,
        scope=SCOPE_APPS_READ,
        description="list installed applications",
    ),
    "service.status": ToolSpec(
        name="service.status",
        handler=_safe_service_status,
        scope=SCOPE_SERVICES_READ,
        description="status of running services",
    ),
}


def tool_spec(name: str) -> ToolSpec | None:
    """Look up a tool by name, or None for an unknown tool."""
    return TOOLS.get(name)


def known_tools() -> list[str]:
    return sorted(TOOLS)


# --------------------------------------------------------------------------- #
# event authoring (each chain step is signed by the actor's own key)

def _derive_pubkey(sk: str) -> str:
    from coincurve import PublicKeyXOnly

    return PublicKeyXOnly.from_secret(bytes.fromhex(sk)).format().hex()


def _e_tag(request_id: str) -> list[list[str]]:
    return [["e", request_id]]


def _json_default(obj: Any) -> Any:
    """JSON-serialise non-primitive values found in tool results (service
    status carries datetimes, sets, …) so the signed 2204 content builds."""
    import datetime

    if isinstance(obj, (datetime.datetime, datetime.date, datetime.time)):
        return obj.isoformat()
    if isinstance(obj, set):
        return sorted(obj, key=str)
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")


def build_operation_request(
    requester_sk: str,
    requester_pubkey: str,
    tool: str,
    args: dict[str, Any],
    *,
    target: str | None = None,
) -> dict[str, Any]:
    """Build (without publishing) a kind-2200 operation request."""
    tags = [["p", target]] if target else []
    content = json.dumps({"tool": tool, "args": args}, default=_json_default)
    return _sign_event(requester_sk, requester_pubkey, KIND_OPERATION_REQUEST, content, tags)


def build_approval(admin_sk: str, admin_pubkey: str, request_id: str, note: str | None = None) -> dict[str, Any]:
    """Build (without publishing) a kind-2201 approval for a request."""
    content = json.dumps({"note": note}, default=_json_default) if note is not None else ""
    return _sign_event(admin_sk, admin_pubkey, KIND_OPERATION_APPROVAL, content, _e_tag(request_id))


def build_rejection(admin_sk: str, admin_pubkey: str, request_id: str, reason: str | None = None) -> dict[str, Any]:
    """Build (without publishing) a kind-2202 rejection for a request."""
    content = json.dumps({"reason": reason}, default=_json_default) if reason is not None else ""
    return _sign_event(admin_sk, admin_pubkey, KIND_OPERATION_REJECTION, content, _e_tag(request_id))


def build_execution_started(server_sk: str, server_pubkey: str, request_id: str) -> dict[str, Any]:
    """Build (without publishing) a kind-2203 execution-started event."""
    return _sign_event(server_sk, server_pubkey, KIND_EXECUTION_STARTED, "", _e_tag(request_id))


def build_execution_result(
    server_sk: str,
    server_pubkey: str,
    request_id: str,
    *,
    ok: bool,
    **extra: Any,
) -> dict[str, Any]:
    """Build (without publishing) a kind-2204 execution-result event."""
    content = json.dumps({"ok": ok, **extra}, default=_json_default)
    return _sign_event(server_sk, server_pubkey, KIND_EXECUTION_RESULT, content, _e_tag(request_id))


def build_capability(
    admin_sk: str,
    admin_pubkey: str,
    subject_pubkey: str,
    type_: str,
    scopes: list[str],
) -> dict[str, Any]:
    """Build (without publishing) a kind-31100 capability grant for a subject."""
    content = json.dumps({"type": type_, "scopes": scopes}, default=_json_default)
    return _sign_event(admin_sk, admin_pubkey, KIND_CAPABILITY, content, [["d", subject_pubkey]])


def _admin_keys(admin_sk: str | None, control_relay: str | None) -> tuple[str, str]:
    cfg = _operator_config(admin_sk, control_relay)
    return cfg.operator_sk, cfg.operator_pubkey


# --------------------------------------------------------------------------- #
# publish side (used by bin/nostr-opctl and the live integration test)

def request_operation(
    tool: str,
    args: dict[str, Any] | None = None,
    *,
    requester_sk: str | None = None,
    control_relay: str | None = None,
    target: str | None = None,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Publish a kind-2200 request as `requester_sk` (default: operator key)."""
    if tool_spec(tool) is None:
        raise OperationError(f"unknown tool {tool!r} (known: {', '.join(known_tools())})")
    sk = requester_sk or _operator_config(None, control_relay).operator_sk
    event = build_operation_request(sk, _derive_pubkey(sk), tool, args or {}, target=target)
    (transport or publish_to_relay)(_control_relay(control_relay), event)
    return event


def approve_operation(
    request_id: str,
    *,
    admin_sk: str | None = None,
    control_relay: str | None = None,
    note: str | None = None,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Publish a kind-2201 approval as an admin (default: operator key)."""
    sk, pubkey = _admin_keys(admin_sk, control_relay)
    event = build_approval(sk, pubkey, request_id, note)
    (transport or publish_to_relay)(_control_relay(control_relay), event)
    return event


def reject_operation(
    request_id: str,
    *,
    admin_sk: str | None = None,
    control_relay: str | None = None,
    reason: str | None = None,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Publish a kind-2202 rejection as an admin (default: operator key)."""
    sk, pubkey = _admin_keys(admin_sk, control_relay)
    event = build_rejection(sk, pubkey, request_id, reason)
    (transport or publish_to_relay)(_control_relay(control_relay), event)
    return event


def grant_capability(
    subject_pubkey: str,
    scopes: list[str],
    *,
    type_: str = "agent",
    admin_sk: str | None = None,
    control_relay: str | None = None,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Publish a kind-31100 capability grant for `subject_pubkey` as an admin."""
    sk, pubkey = _admin_keys(admin_sk, control_relay)
    event = build_capability(sk, pubkey, subject_pubkey, type_, scopes)
    (transport or publish_to_relay)(_control_relay(control_relay), event)
    return event


def _control_relay(control_relay: str | None) -> str:
    return control_relay or os.environ.get("NOSTRHOST_CONTROL_RELAY") or "ws://127.0.0.1:4848"