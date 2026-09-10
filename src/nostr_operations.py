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

Phase 3 posture: the registry is read-only tools plus a deliberately small set
of bounded write tools (``service.restart``, ``service.control``,
``app.remove``) that are single-target by construction and approval-gated;
every write requires an admin approval before execution. Scopes use the
nostrhost-policy vocabulary (server.read / apps.read / apps.write /
services.read / services.write) so grants (kind 31100) stay meaningful across
the stack.

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

# Scope names (nostrhost-policy vocabulary). Read scopes cover the safe
# read-only tools; write scopes gate the minimal control executor's
# write-capable operations (approval-gated on top of the scope).
SCOPE_SERVER_READ = "server.read"
SCOPE_APPS_READ = "apps.read"
SCOPE_APPS_WRITE = "apps.write"
SCOPE_SERVICES_READ = "services.read"
SCOPE_SERVICES_WRITE = "services.write"
SCOPE_STATE_WRITE = "state.write"


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


def _safe_app_remove(app: str = "", purge: bool = False, **args: Any) -> dict[str, Any]:
    """Remove one installed app — the rollback reverse-action for the
    package-install change class.

    Bounded by construction: a single app id (never a list) and an explicit
    purge flag; no other args. The engine additionally requires the
    ``apps.write`` scope and admin approval, so removal stays an audited,
    signed chain step and can never happen through a repository change."""
    app = str(app or "").strip()
    if args:
        raise OperationError(f"app.remove does not accept extra args: {sorted(args)}")
    if not app:
        raise OperationError("app.remove requires a non-empty 'app'")
    from yunohost.app import app_remove

    app_remove(app, purge=bool(purge))
    return {"app": app, "purge": bool(purge)}


def _safe_service_status(**args: Any) -> dict[str, Any]:
    from yunohost.service import service_status

    return service_status(**args)


def _safe_service_restart(name: str = "", **args: Any) -> dict[str, Any]:
    """The minimal WRITE operation: restart one named service.

    Bounded by construction: a single, known service name (never a list),
    no extra args. The engine additionally requires both the `services.write`
    scope and admin approval, so the executor stays the only path to machine
    state and every write is an audited, signed chain step."""
    name = str(name or "").strip()
    if args:
        raise OperationError(f"service.restart does not accept extra args: {sorted(args)}")
    if not name:
        raise OperationError("service.restart requires a non-empty 'name'")
    from yunohost.service import _get_services, service_restart, service_status

    if name not in _get_services():
        raise OperationError(f"unknown service {name!r}")
    service_restart(name)
    return {"service": name, "status": service_status(name)["status"]}


def _safe_service_control(name: str = "", action: str = "", **args: Any) -> dict[str, Any]:
    """Bounded service control (start/stop/restart one named service).

    The reverse-action primitive for the rollback planner's runtime-setting
    class, and the same risk posture as ``service.restart``: a single, known
    service name and a fixed action vocabulary, approval-gated on top of the
    ``services.write`` scope."""
    name = str(name or "").strip()
    action = str(action or "").strip()
    if args:
        raise OperationError(f"service.control does not accept extra args: {sorted(args)}")
    if not name:
        raise OperationError("service.control requires a non-empty 'name'")
    if action not in ("start", "stop", "restart"):
        raise OperationError("service.control action must be one of: start, stop, restart")
    from yunohost.service import _get_services, service_restart, service_start, service_status, service_stop

    if name not in _get_services():
        raise OperationError(f"unknown service {name!r}")
    {"start": service_start, "stop": service_stop, "restart": service_restart}[action](name)
    return {"service": name, "action": action, "status": service_status(name)["status"]}


def _run_rollback_apply(
    args: dict[str, Any], *, backend: Any, restic: Any, repo: Any = None
) -> dict[str, Any]:
    """Execute a rollback plan through the operation chain (the shared path).

    ``args`` must be exactly ``{"plan": {...}}`` — a plan produced by
    ``build_rollback_plan``. The plan's own steps run through the *same*
    ``backend`` the engine executes (so a fake backend keeps tests off real
    yunohost), restore-required steps through ``restic``, and only automatic
    steps with a registry tool are touched. ``approve=True`` is correct here
    because the operation chain already gated this request (scope + kind-2201
    admin approval); a bare ``apply_rollback_plan`` still refuses without it.
    """
    if set(args) != {"plan"} or not isinstance(args.get("plan"), dict):
        raise OperationError("rollback.apply requires exactly one argument: 'plan' (a rollback plan dict)")
    plan = args["plan"]
    if not isinstance(plan.get("steps"), list) or not plan["steps"]:
        raise OperationError("rollback.apply requires a plan with a non-empty 'steps' list")
    if plan.get("approved"):
        raise OperationError("rollback plan already executed")
    from .nostr_rollback import apply_rollback_plan

    report = apply_rollback_plan(plan, backend=backend, restic=restic, approve=True, repo=repo)
    # Keep the per-step report for the audit result while allowing the daemon
    # to distinguish a complete rollback from a partial/manual one.
    return {"steps": report, "_ok": bool(plan.get("_ok"))}


def _safe_rollback_apply(plan: Any = None, **args: Any) -> dict[str, Any]:
    """Standalone rollback.apply handler (bare-backend path).

    Bounded by construction: the only accepted argument is the plan itself.
    Sub-step execution and Restic restore are wired from the live config, so
    the tool stays bounded to registry tools + restore even outside the
    daemon. The daemon overrides this with the chain path
    (:func:`_run_rollback_apply` with its own backend + restic)."""
    if args:
        raise OperationError(f"rollback.apply does not accept extra args: {sorted(args)}")
    from .nostr_operationsd import YnhExecutorBackend
    from .nostr_restic import restic_client

    restic = restic_client() if isinstance(plan, dict) and plan.get("restic_snapshot") else None
    return _run_rollback_apply({"plan": plan}, backend=YnhExecutorBackend(), restic=restic)


# The default registry: read-only tools plus one minimal write operation
# (service.restart). Read tools are safe by construction; the write tool is
# safe by gating — `services.write` scope + admin approval on top of the
# chain, and it is bounded to a single known service name.
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
    "app.remove": ToolSpec(
        name="app.remove",
        handler=_safe_app_remove,
        scope=SCOPE_APPS_WRITE,
        description="remove one installed app (rollback reverse-action, write operation)",
    ),
    "service.status": ToolSpec(
        name="service.status",
        handler=_safe_service_status,
        scope=SCOPE_SERVICES_READ,
        description="status of running services",
    ),
    "service.restart": ToolSpec(
        name="service.restart",
        handler=_safe_service_restart,
        scope=SCOPE_SERVICES_WRITE,
        description="restart one named service (write operation)",
    ),
    "service.control": ToolSpec(
        name="service.control",
        handler=_safe_service_control,
        scope=SCOPE_SERVICES_WRITE,
        description="start/stop/restart one named service (rollback reverse-action)",
    ),
    "rollback.apply": ToolSpec(
        name="rollback.apply",
        handler=_safe_rollback_apply,
        scope=SCOPE_STATE_WRITE,
        description="execute an assisted rollback plan (write operation, admin-approval-gated)",
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
