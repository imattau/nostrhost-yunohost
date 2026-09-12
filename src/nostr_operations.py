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

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .nostr_identity import _operator_config, _sign_event, publish_to_relay
from .nostr_operations_state import OpState

# Chain kinds (must match eventmodel.go / EVENT-PROTOCOL.md).
KIND_OPERATION_REQUEST = 2200
KIND_OPERATION_APPROVAL = 2201
KIND_OPERATION_REJECTION = 2202
KIND_EXECUTION_STARTED = 2203
KIND_EXECUTION_RESULT = 2204
KIND_EXECUTION_PROGRESS = 2205
KIND_CAPABILITY = 31100
KIND_DELEGATION = 27236
KIND_DELEGATION_REVOCATION = 27237
DELEGATION_MAX_LIFETIME = 30 * 24 * 3600

CHAIN_KINDS = (
    KIND_OPERATION_REQUEST,
    KIND_OPERATION_APPROVAL,
    KIND_OPERATION_REJECTION,
    KIND_EXECUTION_STARTED,
    KIND_EXECUTION_RESULT,
    KIND_EXECUTION_PROGRESS,
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
SCOPE_DOMAINS_READ = "domains.read"
SCOPE_DOMAINS_WRITE = "domains.write"
SCOPE_DNS_WRITE = "dns.write"
KNOWN_SCOPES = frozenset(
    {
        SCOPE_SERVER_READ,
        SCOPE_APPS_READ,
        SCOPE_APPS_WRITE,
        SCOPE_SERVICES_READ,
        SCOPE_SERVICES_WRITE,
        SCOPE_STATE_WRITE,
        SCOPE_DOMAINS_READ,
        SCOPE_DOMAINS_WRITE,
        SCOPE_DNS_WRITE,
    }
)


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


def _safe_package_plan(package: dict[str, Any] | None = None, catalogue: dict[str, Any] | None = None, **args: Any) -> dict[str, Any]:
    if args or not isinstance(package, dict):
        raise OperationError("package.plan requires a package object and optional catalogue provenance")
    from nostrhost.package_engine import package_plan_envelope

    try:
        return package_plan_envelope(package, catalogue=catalogue)
    except (TypeError, ValueError) as exc:
        raise OperationError(f"invalid native package: {exc}") from exc


def _safe_package_reconcile(
    plan: dict[str, Any] | list[dict[str, Any]] | None = None,
    _executor: Any = None,
    **args: Any,
) -> dict[str, Any]:
    if args or not isinstance(plan, (dict, list)) or not plan:
        raise OperationError("package.reconcile requires a native plan envelope")
    from nostrhost.package_engine import apply_reconciled_plan, operation_from_dict, validate_plan_envelope

    if isinstance(plan, dict):
        try:
            operations = validate_plan_envelope(plan)
        except (TypeError, ValueError) as exc:
            raise OperationError(f"invalid native plan envelope: {exc}") from exc
        plan_digest = plan["plan_sha256"]
        legacy = False
    else:
        # Compatibility for callers that have not yet moved to the signed
        # envelope. New control-plane requests must use the envelope form.
        operations = [operation_from_dict(item) for item in plan]
        plan_digest = ""
        legacy = True
    if _executor is None:
        # Direct calls remain available for local recovery/debug tooling. The
        # signed control-plane path supplies the executor from
        # YnhExecutorBackend, keeping provider construction out of request
        # handling and making the authority boundary explicit.
        from nostrhost.native_providers import NativeOperationExecutor, native_providers

        _executor = NativeOperationExecutor(native_providers())
    results = apply_reconciled_plan(operations, _executor)
    return {"operations": len(results), "results": results, "plan_sha256": plan_digest, "legacy_plan": legacy}


def _safe_system_version(**args: Any) -> dict[str, Any]:
    from yunohost.tools import tools_versions

    return tools_versions()


def _safe_app_list(**args: Any) -> dict[str, Any]:
    """List installed applications — native packages from the resource-engine
    state, plus the legacy YunoHost registry (best-effort)."""
    native: dict[str, Any] = {}
    try:
        from nostrhost.native_providers import installed_package_manifest

        for state_file in sorted(Path("/var/lib/nostrhost/state/packages").glob("*-manifest.json")):
            app_id = state_file.name[: -len("-manifest.json")]
            try:
                manifest = installed_package_manifest(app_id)
            except Exception:  # noqa: BLE001 - a broken state file is a listing warning
                manifest = None
            if not isinstance(manifest, dict):
                continue
            app = manifest.get("app") or {}
            native[app_id] = {
                "id": app_id,
                "version": app.get("version"),
                "name": {"en": app.get("name") or app_id},
                "repository": "nostrhost",
                "source": "nostr",
                "native": True,
            }
    except Exception:  # noqa: BLE001 - state listing is additive
        native = {}
    legacy: dict[str, Any] = {}
    try:
        from yunohost.app import app_list

        legacy = app_list(**args) or {}
    except Exception:  # noqa: BLE001 - a partially-registered native app must not break the list
        legacy = {}
    if legacy:
        apps = dict(legacy.get("apps") or {})
        apps.update(native)
        return {"apps": apps}
    if native:
        return {"apps": native}
    return legacy


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


def _run_reconcile_apply(args: dict[str, Any], *, backend: Any, repo: Any = None) -> dict[str, Any]:
    """Execute an approved reconciliation plan through the shared chain."""
    if set(args) != {"plan"} or not isinstance(args.get("plan"), dict):
        raise OperationError("state.reconcile requires exactly one argument: 'plan'")
    from .nostr_state import apply_reconciliation_plan

    plan = args["plan"]
    report = apply_reconciliation_plan(plan, backend=backend, approve=True, repo=repo)
    return {"changes": report, "_ok": all(row["status"] == "executed" for row in report)}


def _safe_domain_list(**args: Any) -> dict[str, Any]:
    from .nostrhost.domains.operations import _safe_domain_list as _impl

    return _impl(**args)


def _safe_domain_inspect(domain: str = "", **args: Any) -> dict[str, Any]:
    from .nostrhost.domains.operations import _safe_domain_inspect as _impl

    return _impl(domain=domain, **args)


def _safe_domain_add(**args: Any) -> dict[str, Any]:
    from .nostrhost.domains.operations import _safe_domain_add as _impl

    return _impl(**args)


def _safe_domain_remove(domain: str = "", force: bool = False, **args: Any) -> dict[str, Any]:
    from .nostrhost.domains.operations import _safe_domain_remove as _impl

    return _impl(domain=domain, force=force, **args)


def _safe_dns_plan(domain: str = "", **args: Any) -> dict[str, Any]:
    from .nostrhost.domains.operations import _safe_dns_plan as _impl

    return _impl(domain=domain, **args)


def _safe_dns_apply(domain: str = "", **args: Any) -> dict[str, Any]:
    from .nostrhost.domains.operations import _safe_dns_apply as _impl

    return _impl(domain=domain, **args)


def _safe_dns_verify(domain: str = "", **args: Any) -> dict[str, Any]:
    from .nostrhost.domains.operations import _safe_dns_verify as _impl

    return _impl(domain=domain, **args)


def _safe_network_public_ip(**args: Any) -> dict[str, Any]:
    from .nostrhost.domains.operations import _safe_network_public_ip as _impl

    return _impl(**args)


def _safe_reconcile_apply(plan: Any = None, **args: Any) -> dict[str, Any]:
    if args:
        raise OperationError(f"state.reconcile does not accept extra args: {sorted(args)}")
    from .nostr_operationsd import YnhExecutorBackend

    return _run_reconcile_apply({"plan": plan}, backend=YnhExecutorBackend())


# The default registry: read-only tools plus one minimal write operation
# (service.restart). Read tools are safe by construction; the write tool is
# safe by gating — `services.write` scope + admin approval on top of the
# chain, and it is bounded to a single known service name.
TOOLS: dict[str, ToolSpec] = {
    "package.plan": ToolSpec(
        name="package.plan", handler=_safe_package_plan, scope=SCOPE_APPS_READ,
        require_approval=False, description="validate and plan a native package",
    ),
    "package.reconcile": ToolSpec(
        name="package.reconcile", handler=_safe_package_reconcile, scope=SCOPE_APPS_WRITE,
        description="apply an approved native package operation plan",
    ),
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
    "state.reconcile": ToolSpec(
        name="state.reconcile",
        handler=_safe_reconcile_apply,
        scope=SCOPE_STATE_WRITE,
        description="apply an approved, bounded reconciliation plan",
    ),
    "domain.list": ToolSpec(
        name="domain.list",
        handler=_safe_domain_list,
        scope=SCOPE_DOMAINS_READ,
        require_approval=False,
        description="list registered native domains",
    ),
    "domain.inspect": ToolSpec(
        name="domain.inspect",
        handler=_safe_domain_inspect,
        scope=SCOPE_DOMAINS_READ,
        require_approval=False,
        description="inspect a native domain: intent, desired/actual DNS, diff, routes",
    ),
    "domain.add": ToolSpec(
        name="domain.add",
        handler=_safe_domain_add,
        scope=SCOPE_DOMAINS_WRITE,
        description="register a native domain: plan DNS, apply, stand up Caddy routes, record state",
    ),
    "domain.remove": ToolSpec(
        name="domain.remove",
        handler=_safe_domain_remove,
        scope=SCOPE_DOMAINS_WRITE,
        description="remove a native domain (blocks while apps use it; deletes owned DNS only)",
    ),
    "dns.plan": ToolSpec(
        name="dns.plan",
        handler=_safe_dns_plan,
        scope=SCOPE_DOMAINS_READ,
        require_approval=False,
        description="compute the desired-vs-actual DNS plan for a domain (no changes)",
    ),
    "dns.apply": ToolSpec(
        name="dns.apply",
        handler=_safe_dns_apply,
        scope=SCOPE_DNS_WRITE,
        description="apply the DNS plan for a domain through its provider",
    ),
    "dns.verify": ToolSpec(
        name="dns.verify",
        handler=_safe_dns_verify,
        scope=SCOPE_DOMAINS_READ,
        require_approval=False,
        description="verify a domain's DNS records resolve",
    ),
    "network.public_ip": ToolSpec(
        name="network.public_ip",
        handler=_safe_network_public_ip,
        scope=SCOPE_SERVER_READ,
        require_approval=False,
        description="current public IPv4/IPv6 address",
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


def _is_hex64(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value)


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
    actor_pubkey: str | None = None,
) -> dict[str, Any]:
    """Build a kind-2200 request, optionally naming the authenticated actor."""
    if actor_pubkey is not None and not _is_hex64(actor_pubkey):
        raise OperationError("actor pubkey must be 64-hex")
    tags = [["p", target]] if target else []
    if actor_pubkey:
        tags.append(["actor", actor_pubkey.lower()])
    content = json.dumps({"tool": tool, "args": args}, default=_json_default)
    return _sign_event(requester_sk, requester_pubkey, KIND_OPERATION_REQUEST, content, tags)


def build_approval(admin_sk: str, admin_pubkey: str, request_id: str, note: str | None = None) -> dict[str, Any]:
    """Build (without publishing) a kind-2201 approval for a request."""
    content = json.dumps({"note": note}, default=_json_default) if note is not None else ""
    return _sign_event(admin_sk, admin_pubkey, KIND_OPERATION_APPROVAL, content, _e_tag(request_id))


def build_approval_template(admin_pubkey: str, request_id: str, note: str | None = None) -> dict[str, Any]:
    """Build the unsigned NIP-46 approval event passed to a remote signer.

    The signer (normally a bunker reached through NIP-46) must return this
    event with its ``id`` and ``sig`` fields populated.  The ``nip46`` marker
    makes the privileged approval explicit in the audit chain while keeping
    the existing 2201 state transition and relay compatibility.
    """
    if not _is_hex64(admin_pubkey) or not _is_hex64(request_id):
        raise OperationError("approval pubkey and request id must be 64-hex")
    content = json.dumps({"note": note}, default=_json_default) if note is not None else ""
    return {
        "pubkey": admin_pubkey,
        "created_at": int(time.time()),
        "kind": KIND_OPERATION_APPROVAL,
        "tags": _e_tag(request_id) + [["t", "nip46"]],
        "content": content,
    }


def validate_signed_approval(event: dict[str, Any], request_id: str) -> dict[str, Any]:
    """Validate a remote-signed NIP-46 approval before it is published."""
    if event.get("kind") != KIND_OPERATION_APPROVAL or event.get("pubkey") is None:
        raise OperationError("NIP-46 signer returned a non-approval event")
    tags = event.get("tags") or []
    if _e_tag(request_id)[0] not in tags:
        raise OperationError("NIP-46 approval does not target the requested operation")
    if ["t", "nip46"] not in tags:
        raise OperationError("NIP-46 approval is missing its audit marker")
    required = ("id", "sig", "created_at", "content")
    if any(key not in event for key in required) or not _is_hex64(str(event["id"])):
        raise OperationError("NIP-46 signer returned an incomplete event")
    serialized = json.dumps(
        [0, event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]],
        separators=(",", ":"), ensure_ascii=False,
    ).encode()
    if hashlib.sha256(serialized).hexdigest() != event["id"]:
        raise OperationError("NIP-46 approval id does not match its contents")
    try:
        from coincurve import PublicKeyXOnly
        if not PublicKeyXOnly(bytes.fromhex(str(event["pubkey"]))).verify(bytes.fromhex(str(event["sig"])), bytes.fromhex(event["id"])):
            raise OperationError("NIP-46 approval signature is invalid")
    except ValueError as exc:
        raise OperationError("NIP-46 approval contains invalid key or signature encoding") from exc
    return event


def build_rejection(admin_sk: str, admin_pubkey: str, request_id: str, reason: str | None = None) -> dict[str, Any]:
    """Build (without publishing) a kind-2202 rejection for a request."""
    content = json.dumps({"reason": reason}, default=_json_default) if reason is not None else ""
    return _sign_event(admin_sk, admin_pubkey, KIND_OPERATION_REJECTION, content, _e_tag(request_id))


def build_execution_started(server_sk: str, server_pubkey: str, request_id: str, *, actor_pubkey: str | None = None) -> dict[str, Any]:
    """Build (without publishing) a kind-2203 execution-started event."""
    if actor_pubkey is not None and not _is_hex64(actor_pubkey):
        raise OperationError("actor pubkey must be 64-hex")
    tags = _e_tag(request_id)
    if actor_pubkey:
        tags.append(["actor", actor_pubkey.lower()])
    return _sign_event(server_sk, server_pubkey, KIND_EXECUTION_STARTED, "", tags)


def build_execution_result(
    server_sk: str,
    server_pubkey: str,
    request_id: str,
    *,
    ok: bool,
    actor_pubkey: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Build (without publishing) a kind-2204 execution-result event."""
    if actor_pubkey is not None and not _is_hex64(actor_pubkey):
        raise OperationError("actor pubkey must be 64-hex")
    content = json.dumps({"ok": ok, **extra}, default=_json_default)
    tags = _e_tag(request_id)
    if actor_pubkey:
        tags.append(["actor", actor_pubkey.lower()])
    return _sign_event(server_sk, server_pubkey, KIND_EXECUTION_RESULT, content, tags)


def build_execution_progress(
    server_sk: str,
    server_pubkey: str,
    request_id: str,
    *,
    stage: str,
    progress: float | None = None,
    message: str | None = None,
    actor_pubkey: str | None = None,
) -> dict[str, Any]:
    """Build (without publishing) a kind-2205 execution-progress event.

    ``stage`` names the execution phase (e.g. ``database``), ``progress`` is
    an optional 0..1 completion estimate, ``message`` an optional human
    update.  Links to the request via the ``e`` tag so subscribers can filter.
    """
    if actor_pubkey is not None and not _is_hex64(actor_pubkey):
        raise OperationError("actor pubkey must be 64-hex")
    content: dict[str, Any] = {"operation": request_id, "stage": stage}
    if progress is not None:
        content["progress"] = max(0.0, min(1.0, float(progress)))
    if message is not None:
        content["message"] = message
    tags = _e_tag(request_id)
    if actor_pubkey:
        tags.append(["actor", actor_pubkey.lower()])
    return _sign_event(
        server_sk,
        server_pubkey,
        KIND_EXECUTION_PROGRESS,
        json.dumps(content, default=_json_default),
        tags,
    )


def execution_progress(
    request_id: str,
    stage: str,
    *,
    progress: float | None = None,
    message: str | None = None,
    server_sk: str | None = None,
    control_relay: str | None = None,
    actor_pubkey: str | None = None,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Publish a kind-2205 execution-progress event as the operator/server.

    Tools and the executor call this to report an operation's live progress;
    interfaces (admin UI via SSE, CLI, MCP) subscribe to the chain to render
    it.  The event links to the request and is signed by the server key.
    """
    cfg = _operator_config(server_sk, control_relay)
    event = build_execution_progress(
        cfg.operator_sk,
        cfg.operator_pubkey,
        request_id,
        stage=stage,
        progress=progress,
        message=message,
        actor_pubkey=actor_pubkey,
    )
    (transport or publish_to_relay)(_control_relay(control_relay), event)
    return event


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


def build_delegation(
    delegator_sk: str, delegator_pubkey: str, delegate_pubkey: str,
    server_pubkey: str, scopes: list[str], expires_at: int,
) -> dict[str, Any]:
    """Build a server-scoped, expiring kind-27236 delegation event."""
    now = int(time.time())
    if not scopes or any(scope not in KNOWN_SCOPES for scope in scopes):
        raise OperationError("delegation scopes must be known and non-empty")
    if expires_at <= now or expires_at - now > DELEGATION_MAX_LIFETIME:
        raise OperationError("delegation expiry must be in the future and within 30 days")
    tags = [["p", delegate_pubkey], ["server", server_pubkey], ["expiry", str(expires_at)]]
    tags.extend([["scope", scope] for scope in scopes])
    return _sign_event(delegator_sk, delegator_pubkey, KIND_DELEGATION, "", tags)


def build_delegation_revocation(delegator_sk: str, delegator_pubkey: str, delegation_id: str) -> dict[str, Any]:
    """Build a kind-27237 revocation for a delegation event."""
    if not _is_hex64(delegation_id):
        raise OperationError("delegation id must be 64-hex")
    return _sign_event(delegator_sk, delegator_pubkey, KIND_DELEGATION_REVOCATION, "", [["e", delegation_id]])


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
    actor_pubkey: str | None = None,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Publish a kind-2200 request as `requester_sk` (default: operator key)."""
    if tool_spec(tool) is None:
        raise OperationError(f"unknown tool {tool!r} (known: {', '.join(known_tools())})")
    sk = requester_sk or _operator_config(None, control_relay).operator_sk
    event = build_operation_request(sk, _derive_pubkey(sk), tool, args or {}, target=target, actor_pubkey=actor_pubkey)
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


def approve_operation_nip46(
    request_id: str,
    *,
    signer: Callable[[dict[str, Any]], dict[str, Any]],
    admin_pubkey: str,
    control_relay: str | None = None,
    note: str | None = None,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Request a privileged approval from a NIP-46 signer and publish it.

    ``signer`` is deliberately injectable: the web portal can provide its
    bunker signer, while tests and other adapters can use a local fake.
    """
    unsigned = build_approval_template(admin_pubkey, request_id, note)
    event = validate_signed_approval(signer(unsigned), request_id)
    if event["pubkey"] != admin_pubkey:
        raise OperationError("NIP-46 signer returned an event from an unexpected approval identity")
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


def delegate_capability(
    delegate_pubkey: str,
    scopes: list[str],
    expires_at: int,
    *,
    delegator_sk: str | None = None,
    server_pubkey: str | None = None,
    control_relay: str | None = None,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Publish a signed, server-scoped delegation from the selected key."""
    cfg = _operator_config(delegator_sk, control_relay)
    event = build_delegation(cfg.operator_sk, cfg.operator_pubkey, delegate_pubkey, server_pubkey or cfg.server_pubkey, scopes, expires_at)
    (transport or publish_to_relay)(_control_relay(control_relay), event)
    return event


def revoke_delegation(
    delegation_id: str,
    *,
    delegator_sk: str | None = None,
    control_relay: str | None = None,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Publish a signed revocation for a delegation event."""
    cfg = _operator_config(delegator_sk, control_relay)
    event = build_delegation_revocation(cfg.operator_sk, cfg.operator_pubkey, delegation_id)
    (transport or publish_to_relay)(_control_relay(control_relay), event)
    return event


def _control_relay(control_relay: str | None) -> str:
    return control_relay or os.environ.get("NOSTRHOST_CONTROL_RELAY") or "ws://127.0.0.1:4848"


# --------------------------------------------------------------------------- #
# local signed chain (used by the CLI for native app lifecycle writes)

def local_chain_deps(*, operator_sk: str | None = None, control_relay: str | None = None) -> dict[str, Any]:
    """Wire the local execution plane exactly like ``nostr-operationsd.run``.

    Returns live ``state`` (StateRecorder over the state repo with the Restic
    snapshot hook), ``restic`` (client when configured) and ``policy`` (native
    policy adapter when the shared policy lib is installed). Any piece that
    cannot be built degrades to ``None`` rather than blocking writes, matching
    the daemon's posture.
    """
    cfg = _operator_config(operator_sk, control_relay)
    restic: Any = None
    try:
        from .nostr_restic import ResticClient, load_restic_config

        conf = load_restic_config()
        if conf is not None:
            restic = ResticClient(repo=conf.repo, password=conf.password, binary=conf.binary, host=conf.host, tag=conf.tag, timeout=conf.timeout)
    except Exception:  # noqa: BLE001 - restic is optional
        restic = None
    policy: Any = None
    try:
        from .nostrhost_native_policy import build_native_policy_adapter

        policy = build_native_policy_adapter()
    except Exception:  # noqa: BLE001 - policy is optional on old nodes
        policy = None
    state: Any = None
    try:
        from .nostr_restic import restic_snapshot_hook
        from .nostr_state import StateRecorder, StateRepo, state_dir_from_env

        state = StateRecorder(
            StateRepo(state_dir_from_env(), cfg.server_pubkey),
            capabilities=lambda: {},
            restic_hook=restic_snapshot_hook() if restic is not None else None,
        )
    except Exception:  # noqa: BLE001 - state history is additive
        state = None
    return {"state": state, "restic": restic, "policy": policy}


def run_signed_chain(
    tool: str,
    args: dict[str, Any] | None = None,
    *,
    operator_sk: str | None = None,
    control_relay: str | None = None,
    server_sk: str | None = None,
    admins: list[str] | None = None,
    backend: Any = None,
    state: Any = None,
    restic: Any = None,
    policy: Any = None,
    policy_owner: str | None = None,
    approve: bool = True,
) -> dict[str, Any]:
    """Run one signed operation request end-to-end through the local engine.

    The local admin is the operator: this builds a kind-2200 request signed
    by the operator, feeds it to an ``OperationEngine`` wired like the daemon
    (native backend, pre/post StateRecorder, optional Restic + policy adapter)
    and approves it as the operator admin, so every write still passes the
    same authorisation / policy / approval gate a remote agent's request does.
    Returns the execution-result body (``{ok, result, policy, request_id}``);
    a policy denial or pending-approval state is returned with ``ok: False``
    rather than raising.

    Remote/distributed writes keep using ``request_operation`` /
    ``approve_operation`` through the relay + daemon; this is the local
    variant for CLI lifecycle commands. ``backend`` / ``state`` / ``restic`` /
    ``policy`` are injectable for tests (defaults come from
    :func:`local_chain_deps` / ``YnhExecutorBackend``).
    """
    spec = tool_spec(tool)
    if spec is None:
        raise OperationError(f"unknown tool {tool!r} (known: {', '.join(known_tools())})")
    if backend is None:
        from .nostr_operationsd import YnhExecutorBackend

        backend = YnhExecutorBackend()
    cfg = _operator_config(operator_sk, control_relay, admins=admins, server_sk=server_sk)
    sk = operator_sk or cfg.operator_sk
    pk = _derive_pubkey(sk)
    if state is None and restic is None and policy is None and admins is None:
        deps = local_chain_deps(operator_sk=operator_sk, control_relay=control_relay)
        state, restic, policy = deps["state"], deps["restic"], deps["policy"]
    from .nostr_operationsd import OperationEngine

    engine = OperationEngine(
        publish=lambda _event: None,
        server_sk=cfg.server_sk,
        admins=cfg.admins,
        backend=backend,
        state=state,
        restic=restic,
        policy=policy,
        policy_owner=policy_owner or cfg.operator_pubkey,
    )
    request = build_operation_request(sk, pk, tool, args or {}, actor_pubkey=pk)
    if not engine.handle_event(request):
        raise OperationError(f"{tool} request was rejected before approval")
    record = engine.records.get(request["id"])
    if record is None:
        raise OperationError(f"{tool} request was not accepted")
    if record.state == OpState.REJECTED:
        return {"ok": False, "request_id": request["id"], "state": record.state.value, "reason": record.reason}
    if not approve:
        return {"ok": False, "request_id": request["id"], "state": record.state.value, "pending_approval": True}
    approval = build_approval(sk, pk, request["id"], note="local operator approval")
    if not engine.handle_event(approval):
        raise OperationError(f"{tool} approval was not accepted")
    record = engine.records[request["id"]]
    if record.state not in (OpState.SUCCEEDED, OpState.FAILED, OpState.REJECTED):
        return {"ok": False, "request_id": request["id"], "state": record.state.value}
    body = dict(record.result or {})
    body["request_id"] = request["id"]
    body["state"] = record.state.value
    return body
