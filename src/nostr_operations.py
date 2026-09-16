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
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from .nostr_identity import _is_hex64, _operator_config, _sign_event, publish_to_relay
from .nostr_operations_state import OpState
from .nostrhost.domains.operations import (  # noqa: E402 - domain.*/dns.*/credential.* handlers
    _safe_credential_list,
    _safe_credential_remove,
    _safe_credential_set,
    _safe_dns_apply,
    _safe_dns_plan,
    _safe_dns_subscribe,
    _safe_dns_subscriptions,
    _safe_dns_unsubscribe,
    _safe_dns_verify,
    _safe_dns_watch,
    _safe_domain_add,
    _safe_domain_inspect,
    _safe_domain_list,
    _safe_domain_remove,
    _safe_network_public_ip,
)
from .nostrhost.nsites.operations import (  # noqa: E402 - nsite.* input models + handlers
    DomainAttachArgs,
    DomainDetachArgs,
    GatewayArgs,
    GatewayDisableArgs,
    MirrorArgs,
    PublishArgs,
    PublishPlanArgs,
    ReachabilityArgs,
    ResolveArgs,
    SiteArgs,
    SiteRegisterArgs,
    ValidateManifestArgs,
    _safe_gateway_configure as _safe_nsite_gateway_configure,
    _safe_gateway_disable as _safe_nsite_gateway_disable,
    _safe_gateway_enable as _safe_nsite_gateway_enable,
    _safe_gateway_status as _safe_nsite_gateway_status,
    _safe_nsite_domain_attach,
    _safe_nsite_domain_detach,
    _safe_nsite_domain_list,
    _safe_nsite_inspect,
    _safe_nsite_list,
    _safe_nsite_mirror,
    _safe_nsite_publish,
    _safe_nsite_publish_plan,
    _safe_nsite_reachability,
    _safe_nsite_register,
    _safe_nsite_resolve,
    _safe_nsite_snapshot,
    _safe_nsite_unregister,
    _safe_nsite_validate,
)

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
# write-capable operations (approval-gated on top of the scope). Coarse
# write scopes (apps.write / services.write / state.write) are NostrHost
# natives for primitives that span several granular actions (the resource
# reconciler, the bounded service controller, the state layer); the granular
# scopes come from the shared nostrhost-policy Scope enum so grants and
# delegations verify against the ops that consume them.
SCOPE_SERVER_READ = "server.read"
SCOPE_DIAGNOSIS_READ = "diagnosis.read"
SCOPE_DIAGNOSIS_WRITE = "diagnosis.write"
SCOPE_APPS_READ = "apps.read"
SCOPE_APPS_INSTALL = "apps.install"
SCOPE_APPS_UPGRADE = "apps.upgrade"
SCOPE_APPS_REMOVE = "apps.remove"
SCOPE_APPS_WRITE = "apps.write"
SCOPE_APPS_CONFIG_READ = "apps.config.read"
SCOPE_APPS_CONFIG_WRITE = "apps.config.write"
SCOPE_SERVICES_READ = "services.read"
SCOPE_SERVICES_RESTART = "services.restart"
SCOPE_SERVICES_WRITE = "services.write"
SCOPE_STATE_WRITE = "state.write"
SCOPE_BACKUPS_READ = "backups.read"
SCOPE_BACKUPS_CREATE = "backups.create"
SCOPE_BACKUPS_RESTORE = "backups.restore"
SCOPE_USERS_READ = "users.read"
SCOPE_USERS_WRITE = "users.write"
SCOPE_USERS_DELETE = "users.delete"
SCOPE_SYSTEM_UPDATE = "system.update"
SCOPE_SYSTEM_UPGRADE = "system.upgrade"
SCOPE_FIREWALL_READ = "firewall.read"
SCOPE_FIREWALL_WRITE = "firewall.write"
SCOPE_DOMAINS_READ = "domains.read"
SCOPE_DOMAINS_WRITE = "domains.write"
SCOPE_DNS_WRITE = "dns.write"
SCOPE_DNS_CREDENTIALS_WRITE = "dns.credentials.write"
SCOPE_DNS_CREDENTIALS_READ = "dns.credentials.read"
SCOPE_CATALOG_READ = "catalog.inspect"
SCOPE_CATALOG_VERIFY = "catalog.verify"
SCOPE_CATALOG_PUBLISH = "catalog.publish"
SCOPE_LOGS_READ = "logs.read"
SCOPE_BACKUPS_DELETE = "backups.delete"
SCOPE_SYSTEM_MIGRATE = "system.migrate"
SCOPE_AUDIT_READ = "audit.read"
SCOPE_SYSTEM_POWER = "system.power"
SCOPE_SETTINGS_READ = "settings.read"
SCOPE_SETTINGS_WRITE = "settings.write"
SCOPE_NSITES_READ = "nsites.read"
SCOPE_NSITES_ADMIN = "nsites.admin"
SCOPE_NSITES_PUBLISH = "nsites.publish"
SCOPE_IDENTITY_WRITE = "identity.write"
SCOPE_CAPABILITY_WRITE = "capability.write"
SCOPE_AGENT_WRITE = "agent.write"
KNOWN_SCOPES = frozenset(
    {
        SCOPE_SERVER_READ,
        SCOPE_DIAGNOSIS_READ,
        SCOPE_DIAGNOSIS_WRITE,
        SCOPE_APPS_READ,
        SCOPE_APPS_INSTALL,
        SCOPE_APPS_UPGRADE,
        SCOPE_APPS_REMOVE,
        SCOPE_APPS_WRITE,
        SCOPE_APPS_CONFIG_READ,
        SCOPE_APPS_CONFIG_WRITE,
        SCOPE_SERVICES_READ,
        SCOPE_SERVICES_RESTART,
        SCOPE_SERVICES_WRITE,
        SCOPE_STATE_WRITE,
        SCOPE_BACKUPS_READ,
        SCOPE_BACKUPS_CREATE,
        SCOPE_BACKUPS_RESTORE,
        SCOPE_USERS_READ,
        SCOPE_USERS_WRITE,
        SCOPE_USERS_DELETE,
        SCOPE_SYSTEM_UPDATE,
        SCOPE_SYSTEM_UPGRADE,
        SCOPE_FIREWALL_READ,
        SCOPE_FIREWALL_WRITE,
        SCOPE_DOMAINS_READ,
        SCOPE_DOMAINS_WRITE,
        SCOPE_DNS_WRITE,
        SCOPE_DNS_CREDENTIALS_WRITE,
        SCOPE_DNS_CREDENTIALS_READ,
        SCOPE_CATALOG_READ,
        SCOPE_CATALOG_VERIFY,
        SCOPE_CATALOG_PUBLISH,
        SCOPE_LOGS_READ,
        SCOPE_BACKUPS_DELETE,
        SCOPE_SYSTEM_MIGRATE,
        SCOPE_AUDIT_READ,
        SCOPE_SYSTEM_POWER,
        SCOPE_SETTINGS_READ,
        SCOPE_SETTINGS_WRITE,
        SCOPE_NSITES_READ,
        SCOPE_NSITES_ADMIN,
        SCOPE_NSITES_PUBLISH,
        SCOPE_IDENTITY_WRITE,
        SCOPE_CAPABILITY_WRITE,
        SCOPE_AGENT_WRITE,
    }
)


class OperationError(ValueError):
    """The operation request failed (unknown tool, bad args, config, …)."""


CATALOG_SCHEMA_VERSION = 2


class OperationResult(RootModel[dict[str, Any]]):
    """JSON result boundary used until an operation declares a narrower model.

    Every operation has an output schema and is validated before publication.
    Operation-specific models can narrow this contract without changing the
    executor or any generated consumer.
    """


@dataclass(frozen=True, kw_only=True)
class ToolSpec:
    """One executable tool: its scope, approval requirement and real handler.

    `handler` is the *safe* wrapper — a thin call into the fork's own
    decorated function. The executor backend injects a fake for tests.

    `input_model` / `result_model` are optional Pydantic models whose JSON
    Schema drives generated interfaces (MCP tool schemas, Admin forms, API
    docs) — the registry is the single source of truth (MCP transition
    Phase 0 / docs/MCP-TRANSITION.md). `risk` and `reversibility` feed the
    operation catalogue and risk classification.
    """

    name: str
    handler: Callable[..., Any]
    scope: str
    require_approval: bool = True
    description: str = ""
    input_model: Any = None
    result_model: Any = None
    risk: str = "low"  # low | medium | high
    reversibility: str = "reversible"  # reversible | partial | irreversible
    required_scopes: tuple[str, ...] = ()  # additional scopes the caller must hold
    contract_version: int = 1
    effect: str = ""
    state_impact: str = "none"
    verification_rule: str | None = None
    sensitive_input_paths: tuple[str, ...] = ()
    sensitive_result_paths: tuple[str, ...] = ()
    untrusted_result_paths: tuple[str, ...] = ()

    @property
    def scopes(self) -> tuple[str, ...]:
        return (self.scope, *self.required_scopes)

    def input_schema(self) -> dict[str, Any] | None:
        """The JSON Schema for this tool's arguments, if an input model exists."""
        if self.input_model is None:
            return None
        return self.input_model.model_json_schema()

    def result_schema(self) -> dict[str, Any]:
        model = self.result_model or OperationResult
        return model.model_json_schema()

    def validate_args(self, args: dict[str, Any]) -> dict[str, Any]:
        """Coerce/validate ``args`` through the input model when present.

        Returns the validated (coerced) arguments. Unknown tools or models
        that reject the input raise :class:`OperationError`."""
        if self.input_model is None:
            if not isinstance(args, dict):
                raise OperationError(f"{self.name} arguments must be a JSON object")
            return dict(args)
        if not isinstance(args, dict):
            raise OperationError(f"{self.name} arguments must be a JSON object")
        try:
            return self.input_model.model_validate(args).model_dump(exclude_none=True)
        except Exception as exc:  # pydantic ValidationError -> OperationError
            raise OperationError(f"invalid arguments for {self.name}: {exc}") from exc

    def validate_result(self, result: Any) -> Any:
        model = self.result_model or OperationResult
        try:
            validated = model.model_validate(result)
            if isinstance(validated, RootModel):
                return validated.root
            return validated.model_dump(exclude_none=True)
        except Exception as exc:
            raise OperationError(f"invalid result for {self.name}: {exc}") from exc


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ServiceRestartArgs(_Strict):
    name: str = Field(description="one known service name to restart")


class ServiceStatusArgs(_Strict):
    name: str = Field(default="", description="optional known service name")


class ServiceControlArgs(_Strict):
    name: str = Field(description="one known service name to control")
    action: Literal["start", "stop", "restart"] = Field(description="the action to run")


class AppRemoveArgs(_Strict):
    app: str = Field(description="one installed app id to remove")
    purge: bool = False


class PackageReconcileArgs(_Strict):
    plan: dict[str, Any] = Field(description="the signed native package plan envelope (from package.plan)")


class RollbackApplyArgs(_Strict):
    plan: dict[str, Any] = Field(description="the rollback plan produced by the rollback planner")


class StateReconcileArgs(_Strict):
    plan: dict[str, Any] = Field(description="the approved reconciliation plan for the state layer")


class IdentityLinkArgs(_Strict):
    username: str = Field(description="the YunoHost account to link")
    pubkey_or_npub: str = Field(description="the npub/hex pubkey to link to the account")
    signer_type: str = Field(default="unknown", description="nip07 | nip46 | passkey | unknown")
    label: str | None = Field(default=None, description="optional display label for the identity")
    enabled: bool = Field(default=True, description="whether the identity link is active")


class IdentityRevokeArgs(_Strict):
    pubkey_or_npub: str = Field(description="the npub/hex pubkey whose link to revoke")


class CapabilityGrantArgs(_Strict):
    pubkey: str = Field(description="the subject pubkey to grant scopes to")
    scopes: list[str] = Field(description="the scopes to grant (empty list revokes)")
    type_: str = Field(default="agent", description="grant type: agent | service | …")


class CapabilityDelegateArgs(_Strict):
    pubkey: str = Field(description="the delegate pubkey")
    scopes: list[str] = Field(description="the scopes to delegate")
    expires_at: int = Field(description="unix timestamp the delegation expires at")


class CapabilityRevokeArgs(_Strict):
    delegation_id: str = Field(description="the delegation event id to revoke")


class _EmptyArgs(_Strict):
    pass


class AgentModelDownloadArgs(_Strict):
    model_id: str = Field(description="the model identifier to download")
    evaluation_only: bool = Field(default=False, description="only fetch the evaluation harness")


class AgentModelSelectArgs(_Strict):
    model_id: str = Field(description="the model identifier to activate")


class AgentModeSetArgs(_Strict):
    level: str = Field(description="the agent operation mode level")
    confirm: bool = Field(default=False, description="acknowledge the mode's implications")


class AgentExportRunArgs(_Strict):
    cycle_id: str = Field(description="the completed agent cycle to export")


class AgentContributionSettingsSetArgs(_Strict):
    dataset_repo: str = Field(description="the Hugging Face dataset repo")
    token: str | None = Field(default=None, description="Hugging Face token (stored, never returned)")
    auto_submit: bool = Field(default=False, description="submit every completed cycle automatically")


class AgentContributionSubmitArgs(_Strict):
    candidate_file_id: str = Field(description="the prepared candidate file to submit")


class AgentContributionShareArgs(_Strict):
    cycle_id: str = Field(description="the completed agent cycle to redact and share")


class DomainAddArgs(_Strict):
    domain: str = Field(description="the hostname to register (e.g. foo.example.com)")
    provider_type: str = Field(
        default="manual", description="DNS provider: manual | cloudflare | duckdns | dynu | dynette | desec"
    )
    provider_zone: str | None = Field(default=None, description="DNS zone for the provider (apex name)")
    credential: str | None = Field(
        default=None, description="secret:dns/<provider>/<name> reference for the provider token"
    )
    primary: bool = False
    ipv4: bool = True
    ipv6: bool = True
    wildcard: bool = True
    nip05: bool = False
    tls_caa: list[str] | None = Field(default=None, description="issuer CAA records to publish")
    apply_dns: bool = True
    verify: bool = True


class DomainRemoveArgs(_Strict):
    domain: str
    force: bool = False


class DnsApplyArgs(_Strict):
    domain: str


class DnsSubscribeArgs(_Strict):
    hostname: str = Field(description="a <label> under nohost.me / noho.st / ynh.fr to claim")
    secret: str | None = Field(default=None, description="TSIG secret; generated if omitted")
    rotate: bool = False


class DnsUnsubscribeArgs(_Strict):
    hostname: str


class CredentialSetArgs(_Strict):
    provider: str
    name: str
    value: str = Field(description="the provider token to store")


class CredentialRemoveArgs(_Strict):
    provider: str
    name: str


# Risk / reversibility tiers used across the registry (MCP transition §6).
RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"
REVERSIBLE = "reversible"
REVERSIBLE_WITH_PLAN = "partial"
IRREVERSIBLE = "irreversible"


def _safe_package_plan(package: dict[str, Any] | None = None, catalogue: dict[str, Any] | None = None, **args: Any) -> dict[str, Any]:
    if args or not isinstance(package, dict):
        raise OperationError("package.plan requires a package object and optional catalogue provenance")
    from nostrhost.package_engine import package_plan_envelope

    try:
        return package_plan_envelope(package, catalogue=catalogue)
    except (TypeError, ValueError) as exc:
        raise OperationError(f"invalid native package: {exc}") from exc


def _safe_package_fetch_manifest(repository: str = "", revision: str = "", package_path: str = "", **args: Any) -> dict[str, Any]:
    if args or not repository:
        raise OperationError("package.fetch_manifest requires a repository URL")
    from nostrhost.package_authoring import fetch_manifest_from_repository

    try:
        return fetch_manifest_from_repository(repository, revision=revision, package_path=package_path)
    except ValueError as exc:
        raise OperationError(str(exc)) from exc


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
                "movable": isinstance(manifest.get("web"), dict),
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
        legacy_apps = legacy.get("apps") or {}
        if isinstance(legacy_apps, dict):
            apps = dict(legacy_apps)
        elif isinstance(legacy_apps, list):
            # YunoHost's app_list() returns a list of AppInfo objects, while
            # some adapters expose an id-keyed mapping. Normalize both shapes
            # before merging the native package registry.
            apps = {
                app["id"]: app
                for app in legacy_apps
                if isinstance(app, dict) and isinstance(app.get("id"), str)
            }
        else:
            apps = {}
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


def _safe_service_status(names: str | list[str] | None = None, name: str = "", **args: Any) -> dict[str, Any]:
    """Read all managed services or a subset (a single name or a list)."""
    if args:
        raise OperationError(f"service.status does not accept extra args: {sorted(args)}")
    from yunohost.service import _get_services, service_status

    if isinstance(names, str):
        names = [names]
    if not names and name:
        names = [name]
    if names:
        unknown = [n for n in names if n not in _get_services()]
        if unknown:
            raise OperationError(f"unknown service(s) {', '.join(unknown)!r}")
        # service_status() accepts a single name or a list; keep a single name
        # as a bare string for compatibility with its own signature.
        return service_status(names[0] if len(names) == 1 else names)
    return service_status()


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


# domain.*, nsite.* and dns.*/credential.* tools call their implementations
# in nostrhost/domains/operations.py and nostrhost/nsites/operations.py
# directly (imported above) — the OperationEngine invokes ToolSpec.handler
# with **args, and those implementations already accept the right keyword
# arguments, so a forwarding wrapper here would add nothing but another
# place to keep in sync. Only tools with real dispatch logic (chain lookups,
# lazy-imported backends) get a local function; see _safe_reconcile_apply
# and _safe_rollback_apply above.


def _safe_reconcile_apply(plan: Any = None, **args: Any) -> dict[str, Any]:
    if args:
        raise OperationError(f"state.reconcile does not accept extra args: {sorted(args)}")
    from .nostr_operationsd import YnhExecutorBackend

    return _run_reconcile_apply({"plan": plan}, backend=YnhExecutorBackend())


# -- identity / capability / agent writes (H5) ------------------------------ #
#
# These are admin-only host-plane operations. Each handler pulls the ambient
# operator/admin keys from the fork config itself, so the secret key never
# travels in the operation's ``args`` (and never leaks into state snapshots
# or the audit trail). Routing them through the signed chain gives them the
# same policy / approval / audit boundary as every other write.

def _safe_identity_link(
    username: str = "",
    pubkey_or_npub: str = "",
    *,
    signer_type: str = "unknown",
    label: str | None = None,
    enabled: bool = True,
    **extra: Any,
) -> dict[str, Any]:
    if extra:
        raise OperationError(f"identity.link does not accept extra args: {sorted(extra)}")
    from .nostr_identity import link_identity

    return link_identity(
        username, pubkey_or_npub, signer_type=signer_type, label=label, enabled=bool(enabled)
    )


def _safe_identity_revoke(pubkey_or_npub: str = "", **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"identity.revoke does not accept extra args: {sorted(extra)}")
    from .nostr_identity import revoke_identity

    return revoke_identity(pubkey_or_npub)


def _safe_capability_grant(pubkey: str = "", scopes: list[str] | None = None, type_: str = "agent", **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"capability.grant does not accept extra args: {sorted(extra)}")
    if not pubkey:
        raise OperationError("capability.grant requires a pubkey")
    return grant_capability(pubkey, list(scopes or []), type_=type_)


def _safe_capability_delegate(pubkey: str = "", scopes: list[str] | None = None, expires_at: int = 0, **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"capability.delegate does not accept extra args: {sorted(extra)}")
    if not pubkey:
        raise OperationError("capability.delegate requires a pubkey")
    return delegate_capability(pubkey, list(scopes or []), int(expires_at))


def _safe_capability_revoke(delegation_id: str = "", **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"capability.revoke does not accept extra args: {sorted(extra)}")
    if not delegation_id:
        raise OperationError("capability.revoke requires a delegation_id")
    return revoke_delegation(delegation_id)


def _safe_agent_init(**extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"agent.init does not accept extra args: {sorted(extra)}")
    from .nostrhost.cli import _agent_init

    return _agent_init()


def _safe_agent_service(action: str = "", **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"agent.{action or 'service'} does not accept extra args: {sorted(extra)}")
    if action not in ("enable", "disable"):
        raise OperationError("agent.enable/disable requires an action")
    from .nostrhost.cli import _agent_service

    return _agent_service(action)


def _safe_agent_enable(**extra: Any) -> dict[str, Any]:
    return _safe_agent_service("enable", **extra)


def _safe_agent_disable(**extra: Any) -> dict[str, Any]:
    return _safe_agent_service("disable", **extra)


def _safe_agent_model_download(model_id: str = "", evaluation_only: bool = False, **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"agent.model.download does not accept extra args: {sorted(extra)}")
    from .nostrhost.cli import _agent_model_download

    return _agent_model_download(model_id, bool(evaluation_only))


def _safe_agent_model_select(model_id: str = "", **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"agent.model.select does not accept extra args: {sorted(extra)}")
    from .nostrhost.cli import _agent_model_select

    return _agent_model_select(model_id)


def _safe_agent_mode_set(level: str = "", confirm: bool = False, **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"agent.mode.set does not accept extra args: {sorted(extra)}")
    from .nostrhost.cli import _agent_mode_set

    return _agent_mode_set(level, bool(confirm))


def _safe_agent_export_run(cycle_id: str = "", **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"agent.export.run does not accept extra args: {sorted(extra)}")
    from .nostrhost.cli import _agent_export_run

    return _agent_export_run(cycle_id)


def _safe_agent_contribution_settings_set(
    dataset_repo: str = "", token: str | None = None, auto_submit: bool = False, **extra: Any
) -> dict[str, Any]:
    if extra:
        raise OperationError(f"agent.contribution.settings.set does not accept extra args: {sorted(extra)}")
    from .nostrhost.cli import _agent_contribution_settings_set

    return _agent_contribution_settings_set(dataset_repo, token, bool(auto_submit))


def _safe_agent_contribution_submit(candidate_file_id: str = "", **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"agent.contribution.submit does not accept extra args: {sorted(extra)}")
    from .nostrhost.cli import _agent_contribution_submit

    return _agent_contribution_submit(candidate_file_id)


def _safe_agent_contribution_share(cycle_id: str = "", **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"agent.contribution.share does not accept extra args: {sorted(extra)}")
    from .nostrhost.cli import _agent_contribution_share

    return _agent_contribution_share(cycle_id)


# The default registry: read-only tools plus write operations gated by scope
# + admin approval. Read tools are safe by construction and run un-gated
# (require_approval=False); every write carries an approval on top of the
# scope. The broadened native surface (app lifecycle, backup, user, firewall,
# diagnosis, system upgrade) lives in nostrhost/native_ops.py and is merged
# in below so the registry remains the single source of truth.
def _native_tools() -> dict[str, ToolSpec]:
    """The broadened native surface (MCP transition Phase 0).

    Imported lazily so the heavy handlers and their Pydantic models are only
    loaded when the registry is constructed, and so the module can import
    back from this registry without a cycle.
    """
    from .nostrhost.native_ops import NATIVE_TOOLS

    return NATIVE_TOOLS


TOOLS: dict[str, ToolSpec] = {
    "package.plan": ToolSpec(
        name="package.plan", handler=_safe_package_plan, scope=SCOPE_APPS_READ,
        require_approval=False, description="validate and plan a native package",
    ),
    "package.fetch_manifest": ToolSpec(
        name="package.fetch_manifest", handler=_safe_package_fetch_manifest, scope=SCOPE_APPS_READ,
        require_approval=False, description="shallow-clone a package.toml manifest from its repository",
    ),
    "package.reconcile": ToolSpec(
        name="package.reconcile", handler=_safe_package_reconcile, scope=SCOPE_APPS_WRITE,
        input_model=PackageReconcileArgs,
        description="apply an approved native package operation plan",
    ),
    "system.version": ToolSpec(
        name="system.version",
        handler=_safe_system_version,
        scope=SCOPE_SERVER_READ,
        require_approval=False,
        description="read-only OS/package version information",
    ),
    "app.list": ToolSpec(
        name="app.list",
        handler=_safe_app_list,
        scope=SCOPE_APPS_READ,
        require_approval=False,
        description="list installed applications",
    ),
    "app.remove": ToolSpec(
        name="app.remove",
        handler=_safe_app_remove,
        scope=SCOPE_APPS_REMOVE,
        input_model=AppRemoveArgs,
        description="remove one installed app (rollback reverse-action, write operation)",
    ),
    "service.status": ToolSpec(
        name="service.status",
        handler=_safe_service_status,
        scope=SCOPE_SERVICES_READ,
        require_approval=False, input_model=ServiceStatusArgs,
        description="status of running services",
    ),
    "service.restart": ToolSpec(
        name="service.restart",
        handler=_safe_service_restart,
        scope=SCOPE_SERVICES_RESTART,
        input_model=ServiceRestartArgs,
        description="restart one named service (write operation)",
    ),
    "service.control": ToolSpec(
        name="service.control",
        handler=_safe_service_control,
        scope=SCOPE_SERVICES_WRITE,
        input_model=ServiceControlArgs,
        description="start/stop/restart one named service (rollback reverse-action)",
    ),
    "rollback.apply": ToolSpec(
        name="rollback.apply",
        handler=_safe_rollback_apply,
        scope=SCOPE_STATE_WRITE,
        input_model=RollbackApplyArgs,
        description="execute an assisted rollback plan (write operation, admin-approval-gated)",
    ),
    "state.reconcile": ToolSpec(
        name="state.reconcile",
        handler=_safe_reconcile_apply,
        scope=SCOPE_STATE_WRITE,
        input_model=StateReconcileArgs,
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
        input_model=DomainAddArgs,
        description="register a native domain: plan DNS, apply, stand up Caddy routes, record state",
    ),
    "domain.remove": ToolSpec(
        name="domain.remove",
        handler=_safe_domain_remove,
        scope=SCOPE_DOMAINS_WRITE,
        input_model=DomainRemoveArgs,
        description="remove a native domain (blocks while apps use it; deletes owned DNS only)",
    ),
    "nsite.gateway.status": ToolSpec(
        name="nsite.gateway.status",
        handler=_safe_nsite_gateway_status,
        scope=SCOPE_NSITES_READ,
        require_approval=False,
        description="gateway status: enabled, mode, domain, service health, cache",
    ),
    "nsite.gateway.enable": ToolSpec(
        name="nsite.gateway.enable",
        handler=_safe_nsite_gateway_enable,
        scope=SCOPE_NSITES_ADMIN,
        input_model=GatewayArgs,
        risk=RISK_MEDIUM,
        reversibility=REVERSIBLE,
        description="enable the nsite gateway on a dedicated registered domain (Caddy route + unit + config)",
    ),
    "nsite.gateway.disable": ToolSpec(
        name="nsite.gateway.disable",
        handler=_safe_nsite_gateway_disable,
        scope=SCOPE_NSITES_ADMIN,
        input_model=GatewayDisableArgs,
        risk=RISK_MEDIUM,
        reversibility=REVERSIBLE,
        description="disable the nsite gateway: stop the unit, remove the Caddy route, keep state",
    ),
    "nsite.gateway.configure": ToolSpec(
        name="nsite.gateway.configure",
        handler=_safe_nsite_gateway_configure,
        scope=SCOPE_NSITES_ADMIN,
        input_model=GatewayArgs,
        risk=RISK_MEDIUM,
        reversibility=REVERSIBLE,
        description="update gateway config (relays, blossom servers, limits) and reload",
    ),
    "nsite.list": ToolSpec(
        name="nsite.list",
        handler=_safe_nsite_list,
        scope=SCOPE_NSITES_READ,
        require_approval=False,
        description="registered sites and the gateway mode",
    ),
    "nsite.inspect": ToolSpec(
        name="nsite.inspect",
        handler=_safe_nsite_inspect,
        scope=SCOPE_NSITES_READ,
        require_approval=False,
        input_model=SiteArgs,
        description="one registered site record (current manifest, hashes, relay/blob status)",
    ),
    "nsite.resolve": ToolSpec(
        name="nsite.resolve",
        handler=_safe_nsite_resolve,
        scope=SCOPE_NSITES_READ,
        require_approval=False,
        input_model=ResolveArgs,
        description="fetch the current manifest for a label/pubkey from public relays (read only, bounded)",
    ),
    "nsite.validate_manifest": ToolSpec(
        name="nsite.validate_manifest",
        handler=_safe_nsite_validate,
        scope=SCOPE_NSITES_READ,
        require_approval=False,
        input_model=ValidateManifestArgs,
        description="validate a candidate manifest event (kind, signature, tags, aggregate); no network",
    ),
    "nsite.reachability": ToolSpec(
        name="nsite.reachability",
        handler=_safe_nsite_reachability,
        scope=SCOPE_NSITES_READ,
        require_approval=False,
        input_model=ReachabilityArgs,
        description="relay/server reachability for a site (bounded probes)",
    ),
    "nsite.publish.plan": ToolSpec(
        name="nsite.publish.plan",
        handler=_safe_nsite_publish_plan,
        scope=SCOPE_NSITES_READ,
        require_approval=False,
        input_model=PublishPlanArgs,
        description="blob inventory to an unsigned manifest + plan_sha256 (D7); nothing is signed or broadcast",
    ),
    "nsite.register": ToolSpec(
        name="nsite.register",
        handler=_safe_nsite_register,
        scope=SCOPE_NSITES_ADMIN,
        input_model=SiteRegisterArgs,
        risk=RISK_LOW,
        reversibility=REVERSIBLE,
        description="add a hosted-mode allowlist entry",
    ),
    "nsite.unregister": ToolSpec(
        name="nsite.unregister",
        handler=_safe_nsite_unregister,
        scope=SCOPE_NSITES_ADMIN,
        input_model=SiteArgs,
        risk=RISK_LOW,
        reversibility=REVERSIBLE,
        description="remove a hosted-mode allowlist entry",
    ),
    "nsite.publish": ToolSpec(
        name="nsite.publish",
        handler=_safe_nsite_publish,
        scope=SCOPE_NSITES_PUBLISH,
        input_model=PublishArgs,
        risk=RISK_MEDIUM,
        reversibility=REVERSIBLE,
        description="verify a signed manifest (plan digest, signer, allowlist), broadcast to relays, record",
    ),
    "nsite.snapshot": ToolSpec(
        name="nsite.snapshot",
        handler=_safe_nsite_snapshot,
        scope=SCOPE_NSITES_PUBLISH,
        input_model=PublishArgs,
        risk=RISK_LOW,
        reversibility=REVERSIBLE,
        description="record a client-signed kind-5128 snapshot of the current manifest",
    ),
    "nsite.mirror": ToolSpec(
        name="nsite.mirror",
        handler=_safe_nsite_mirror,
        scope=SCOPE_NSITES_PUBLISH,
        input_model=MirrorArgs,
        risk=RISK_LOW,
        reversibility=REVERSIBLE,
        description="re-upload a site's missing blobs to the selected servers from the draft area (Phase 3b)",
    ),
    "nsite.domain.list": ToolSpec(
        name="nsite.domain.list",
        handler=_safe_nsite_domain_list,
        scope=SCOPE_NSITES_READ,
        require_approval=False,
        description="attached custom domains (Phase 4)",
    ),
    "nsite.domain.attach": ToolSpec(
        name="nsite.domain.attach",
        handler=_safe_nsite_domain_attach,
        scope=SCOPE_NSITES_ADMIN,
        required_scopes=(SCOPE_DOMAINS_WRITE,),
        input_model=DomainAttachArgs,
        risk=RISK_MEDIUM,
        reversibility=REVERSIBLE,
        description="attach a custom FQDN to a registered site (ownership proof via CNAME or TXT; adds the Caddy route + mapping)",
    ),
    "nsite.domain.detach": ToolSpec(
        name="nsite.domain.detach",
        handler=_safe_nsite_domain_detach,
        scope=SCOPE_NSITES_ADMIN,
        required_scopes=(SCOPE_DOMAINS_WRITE,),
        input_model=DomainDetachArgs,
        risk=RISK_MEDIUM,
        reversibility=REVERSIBLE,
        description="detach a custom FQDN (removes the Caddy route and the state marker only)",
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
        input_model=DnsApplyArgs,
        description="apply the DNS plan for a domain through its provider",
    ),
    "dns.verify": ToolSpec(
        name="dns.verify",
        handler=_safe_dns_verify,
        scope=SCOPE_DOMAINS_READ,
        require_approval=False,
        description="verify a domain's DNS records resolve",
    ),
    "dns.watch": ToolSpec(
        name="dns.watch",
        handler=_safe_dns_watch,
        scope=SCOPE_DOMAINS_READ,
        require_approval=False,
        description="DDNS watcher status: last-seen public IPs and dynamic-IP domains",
    ),
    "dns.subscribe": ToolSpec(
        name="dns.subscribe",
        handler=_safe_dns_subscribe,
        scope=SCOPE_DNS_WRITE,
        input_model=DnsSubscribeArgs,
        description="claim a nostr-native free hostname (identity-backed Dynette): sign the ownership claim with the operator key and provision its TSIG secret in the broker",
    ),
    "dns.subscriptions": ToolSpec(
        name="dns.subscriptions",
        handler=_safe_dns_subscriptions,
        scope=SCOPE_DOMAINS_READ,
        require_approval=False,
        description="list nostr-native free-hostname subscriptions (claims signed by the operator identity)",
    ),
    "dns.unsubscribe": ToolSpec(
        name="dns.unsubscribe",
        handler=_safe_dns_unsubscribe,
        scope=SCOPE_DNS_WRITE,
        input_model=DnsUnsubscribeArgs,
        description="release a nostr-native free-hostname subscription and drop its broker secret",
    ),
    "network.public_ip": ToolSpec(
        name="network.public_ip",
        handler=_safe_network_public_ip,
        scope=SCOPE_SERVER_READ,
        require_approval=False,
        description="current public IPv4/IPv6 address",
    ),
    "credential.set": ToolSpec(
        name="credential.set",
        handler=_safe_credential_set,
        scope=SCOPE_DNS_CREDENTIALS_WRITE,
        input_model=CredentialSetArgs,
        description="store a DNS provider token in the credential broker (secret:dns/<provider>/<name>)",
    ),
    "credential.remove": ToolSpec(
        name="credential.remove",
        handler=_safe_credential_remove,
        scope=SCOPE_DNS_CREDENTIALS_WRITE,
        input_model=CredentialRemoveArgs,
        description="remove a DNS provider token from the credential broker",
    ),
    "credential.list": ToolSpec(
        name="credential.list",
        handler=_safe_credential_list,
        scope=SCOPE_DNS_CREDENTIALS_READ,
        require_approval=False,
        description="list configured DNS credential references (names only, never values)",
    ),
    "identity.link": ToolSpec(
        name="identity.link",
        handler=_safe_identity_link,
        scope=SCOPE_IDENTITY_WRITE,
        input_model=IdentityLinkArgs,
        description="link a YunoHost account to an npub (publishes kind 31102 as the operator)",
    ),
    "identity.revoke": ToolSpec(
        name="identity.revoke",
        handler=_safe_identity_revoke,
        scope=SCOPE_IDENTITY_WRITE,
        input_model=IdentityRevokeArgs,
        description="revoke an npub identity link (publishes an enabled:false kind 31102)",
    ),
    "capability.grant": ToolSpec(
        name="capability.grant",
        handler=_safe_capability_grant,
        scope=SCOPE_CAPABILITY_WRITE,
        input_model=CapabilityGrantArgs,
        description="publish a kind-31100 capability grant for a subject pubkey (admin-only meta-op)",
    ),
    "capability.delegate": ToolSpec(
        name="capability.delegate",
        handler=_safe_capability_delegate,
        scope=SCOPE_CAPABILITY_WRITE,
        input_model=CapabilityDelegateArgs,
        description="publish a signed, server-scoped delegation (admin-only meta-op)",
    ),
    "capability.revoke": ToolSpec(
        name="capability.revoke",
        handler=_safe_capability_revoke,
        scope=SCOPE_CAPABILITY_WRITE,
        input_model=CapabilityRevokeArgs,
        description="publish a signed revocation for a delegation event (admin-only meta-op)",
    ),
    "agent.init": ToolSpec(
        name="agent.init",
        handler=_safe_agent_init,
        scope=SCOPE_AGENT_WRITE,
        input_model=_EmptyArgs,
        description="provision the resident agent (keys, service, config)",
    ),
    "agent.enable": ToolSpec(
        name="agent.enable",
        handler=_safe_agent_enable,
        scope=SCOPE_AGENT_WRITE,
        input_model=_EmptyArgs,
        description="start the resident agent service",
    ),
    "agent.disable": ToolSpec(
        name="agent.disable",
        handler=_safe_agent_disable,
        scope=SCOPE_AGENT_WRITE,
        input_model=_EmptyArgs,
        description="stop the resident agent service",
    ),
    "agent.model.download": ToolSpec(
        name="agent.model.download",
        handler=_safe_agent_model_download,
        scope=SCOPE_AGENT_WRITE,
        input_model=AgentModelDownloadArgs,
        description="download and register an agent model",
    ),
    "agent.model.select": ToolSpec(
        name="agent.model.select",
        handler=_safe_agent_model_select,
        scope=SCOPE_AGENT_WRITE,
        input_model=AgentModelSelectArgs,
        description="select the active agent model",
    ),
    "agent.mode.set": ToolSpec(
        name="agent.mode.set",
        handler=_safe_agent_mode_set,
        scope=SCOPE_AGENT_WRITE,
        input_model=AgentModeSetArgs,
        description="set the resident agent's operation mode",
    ),
    "agent.export.run": ToolSpec(
        name="agent.export.run",
        handler=_safe_agent_export_run,
        scope=SCOPE_AGENT_WRITE,
        input_model=AgentExportRunArgs,
        description="run a data export cycle for a completed agent cycle",
    ),
    "agent.contribution.settings.set": ToolSpec(
        name="agent.contribution.settings.set",
        handler=_safe_agent_contribution_settings_set,
        scope=SCOPE_AGENT_WRITE,
        input_model=AgentContributionSettingsSetArgs,
        description="set contribution settings (dataset repo, HF token, auto-submit)",
    ),
    "agent.contribution.submit": ToolSpec(
        name="agent.contribution.submit",
        handler=_safe_agent_contribution_submit,
        scope=SCOPE_AGENT_WRITE,
        input_model=AgentContributionSubmitArgs,
        description="submit one prepared candidate file to the community dataset",
    ),
    "agent.contribution.share": ToolSpec(
        name="agent.contribution.share",
        handler=_safe_agent_contribution_share,
        scope=SCOPE_AGENT_WRITE,
        input_model=AgentContributionShareArgs,
        description="redact and submit one completed agent cycle in a single call",
    ),
    **_native_tools(),
}


_APPLICATION_DATA_OPERATIONS = frozenset(
    {"app.install", "app.upgrade", "app.remove", "package.reconcile", "backup.create", "backup.restore"}
)
_EXTERNAL_PREFIXES = ("catalog.", "dns.", "nsite.")


def _complete_spec(spec: ToolSpec) -> ToolSpec:
    effect = spec.effect
    if not effect:
        if not spec.require_approval:
            effect = "read"
        elif spec.name.startswith("system.shutdown") or spec.name.startswith("system.reboot"):
            effect = "power"
        elif spec.reversibility == IRREVERSIBLE:
            effect = "destructive"
        elif spec.name.startswith(_EXTERNAL_PREFIXES):
            effect = "external_change"
        else:
            effect = "local_change"
    state_impact = spec.state_impact
    if spec.name in _APPLICATION_DATA_OPERATIONS:
        state_impact = "application_data"
    elif state_impact == "none" and effect in {"local_change", "destructive", "power"}:
        state_impact = "configuration"
    return replace(
        spec,
        input_model=spec.input_model or _EmptyArgs,
        result_model=spec.result_model or OperationResult,
        effect=effect,
        state_impact=state_impact,
    )


TOOLS = {name: _complete_spec(spec) for name, spec in TOOLS.items()}


def tool_spec(name: str) -> ToolSpec | None:
    """Look up a tool by name, or None for an unknown tool."""
    return TOOLS.get(name)


def known_tools() -> list[str]:
    return sorted(TOOLS)


def _operation_entries() -> list[dict[str, Any]]:
    return [
        {
            "name": spec.name,
            "contract_version": spec.contract_version,
            "scopes": list(spec.scopes),
            "approval": {"minimum": "admin" if spec.require_approval else "none", "policy_may_elevate": True},
            "risk": spec.risk,
            "reversibility": spec.reversibility,
            "effect": spec.effect,
            "state_impact": spec.state_impact,
            "description": spec.description,
            "input_schema": spec.input_schema(),
            "result_schema": spec.result_schema(),
            "verification_rule": spec.verification_rule,
            "sensitivity": {
                "input": list(spec.sensitive_input_paths),
                "result": list(spec.sensitive_result_paths),
                "untrusted_result": list(spec.untrusted_result_paths),
            },
        }
        for spec in sorted(TOOLS.values(), key=lambda item: item.name)
    ]


def validate_operation_registry() -> None:
    valid_effects = {"read", "local_change", "external_change", "destructive", "power"}
    valid_impacts = {"none", "configuration", "application_data", "identity"}
    for name, spec in TOOLS.items():
        if name != spec.name or spec.contract_version < 1:
            raise OperationError(f"invalid operation identity for {name!r}")
        if not spec.scopes or any(scope not in KNOWN_SCOPES for scope in spec.scopes):
            raise OperationError(f"invalid scopes for {name!r}")
        if spec.effect not in valid_effects or spec.state_impact not in valid_impacts:
            raise OperationError(f"invalid effect metadata for {name!r}")
        if spec.effect != "read" and not spec.require_approval:
            raise OperationError(f"mutating operation {name!r} must require approval")
        if not spec.input_schema() or not spec.result_schema():
            raise OperationError(f"operation {name!r} lacks input or result schema")


@lru_cache(maxsize=1)
def operation_catalog() -> dict[str, Any]:
    """Return the canonical, versioned operation contract document."""
    validate_operation_registry()
    entries = _operation_entries()
    canonical = json.dumps(
        {"schema_version": CATALOG_SCHEMA_VERSION, "operations": entries},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return {
        "schema_version": CATALOG_SCHEMA_VERSION,
        "digest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        "operations": entries,
    }


# --------------------------------------------------------------------------- #
# event authoring (each chain step is signed by the actor's own key)

def _derive_pubkey(sk: str) -> str:
    from nostr_sdk import Keys

    return Keys.parse(sk).public_key().to_hex()


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
    actor_pubkey: str | None = None,
) -> dict[str, Any]:
    """Build a kind-2200 request, optionally naming the authenticated actor."""
    if actor_pubkey is not None and not _is_hex64(actor_pubkey):
        raise OperationError("actor pubkey must be 64-hex")
    tags = [["p", target]] if target else []
    if actor_pubkey:
        tags.append(["actor", actor_pubkey.lower()])
    content = json.dumps(
        {"tool": tool, "args": args, "catalog_digest": operation_catalog()["digest"]},
        default=_json_default,
    )
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


def _validate_signed_nip46_decision(event: dict[str, Any], request_id: str, *, kind: int, label: str) -> dict[str, Any]:
    """Shared body of :func:`validate_signed_approval` and
    :func:`validate_signed_rejection` - only the expected chain kind and the
    error labelling differ between an approval and a rejection."""
    if event.get("kind") != kind or event.get("pubkey") is None:
        raise OperationError(f"NIP-46 signer returned a non-{label} event")
    tags = event.get("tags") or []
    if _e_tag(request_id)[0] not in tags:
        raise OperationError(f"NIP-46 {label} does not target the requested operation")
    if ["t", "nip46"] not in tags:
        raise OperationError(f"NIP-46 {label} is missing its audit marker")
    required = ("id", "sig", "created_at", "content")
    if any(key not in event for key in required) or not _is_hex64(str(event["id"])):
        raise OperationError("NIP-46 signer returned an incomplete event")
    serialized = json.dumps(
        [0, event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]],
        separators=(",", ":"), ensure_ascii=False,
    ).encode()
    if hashlib.sha256(serialized).hexdigest() != event["id"]:
        raise OperationError(f"NIP-46 {label} id does not match its contents")
    try:
        from nostr_sdk import Event
        if not Event.from_json(json.dumps(event)).verify():
            raise OperationError(f"NIP-46 {label} signature is invalid")
    except Exception as exc:  # noqa: BLE001 - normalize SDK parse/verification errors
        raise OperationError("NIP-46 signer returned an invalid key or signature encoding") from exc
    return event


def validate_signed_approval(event: dict[str, Any], request_id: str) -> dict[str, Any]:
    """Validate a remote-signed NIP-46 approval before it is published."""
    return _validate_signed_nip46_decision(event, request_id, kind=KIND_OPERATION_APPROVAL, label="approval")


def build_rejection(admin_sk: str, admin_pubkey: str, request_id: str, reason: str | None = None) -> dict[str, Any]:
    """Build (without publishing) a kind-2202 rejection for a request."""
    content = json.dumps({"reason": reason}, default=_json_default) if reason is not None else ""
    return _sign_event(admin_sk, admin_pubkey, KIND_OPERATION_REJECTION, content, _e_tag(request_id))


def build_rejection_template(admin_pubkey: str, request_id: str, reason: str | None = None) -> dict[str, Any]:
    """Build the unsigned NIP-46 rejection event passed to a remote signer.

    Mirrors :func:`build_approval_template` - see its docstring."""
    if not _is_hex64(admin_pubkey) or not _is_hex64(request_id):
        raise OperationError("rejection pubkey and request id must be 64-hex")
    content = json.dumps({"reason": reason}, default=_json_default) if reason is not None else ""
    return {
        "pubkey": admin_pubkey,
        "created_at": int(time.time()),
        "kind": KIND_OPERATION_REJECTION,
        "tags": _e_tag(request_id) + [["t", "nip46"]],
        "content": content,
    }


def validate_signed_rejection(event: dict[str, Any], request_id: str) -> dict[str, Any]:
    """Validate a remote-signed NIP-46 rejection before it is published."""
    return _validate_signed_nip46_decision(event, request_id, kind=KIND_OPERATION_REJECTION, label="rejection")


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
    content = json.dumps(
        {**extra, "ok": ok, "catalog_digest": operation_catalog()["digest"]},
        default=_json_default,
    )
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


def list_capabilities(
    *,
    admin_sk: str | None = None,
    control_relay: str | None = None,
    query: Callable[..., list[dict[str, Any]]] | None = None,
) -> list[dict[str, Any]]:
    """Read back the live kind-31100 capability grants from the control relay.

    Grants are parameterized-replaceable (NIP-33 ``d`` tag = subject
    pubkey) — a well-behaved relay keeps only the latest per subject, but a
    query can still surface stale copies from a store that doesn't prune,
    so this dedupes client-side by ``d`` tag on the newest ``created_at``.
    A grant published with an empty scope list is ``grant_capability``'s own
    revoke convention (see the admin UI's ``revokeCapability``), so it is
    filtered out here rather than shown as an active grant with no access.
    Best-effort like the audit reads: an unreachable relay yields ``[]``.
    """
    from .nostrhost.events import query_chain_events

    cfg = _operator_config(admin_sk, control_relay)
    fetch = query or query_chain_events
    events = fetch(cfg.control_relay, kinds=(KIND_CAPABILITY,), limit=500)
    latest: dict[str, dict[str, Any]] = {}
    for event in events:
        subject = next((t[1] for t in event.get("tags", []) if len(t) > 1 and t[0] == "d"), None)
        if not subject:
            continue
        current = latest.get(subject)
        if current is not None and (current.get("created_at") or 0) >= (event.get("created_at") or 0):
            continue
        latest[subject] = event

    grants: list[dict[str, Any]] = []
    for subject, event in latest.items():
        try:
            body = json.loads(event.get("content") or "{}")
        except json.JSONDecodeError:
            continue
        scopes = body.get("scopes")
        if not isinstance(scopes, list) or not scopes:
            continue  # empty scopes is a revoke, not an active grant
        grants.append(
            {
                "pubkey": subject,
                "type": body.get("type", "agent"),
                "scopes": sorted({str(s) for s in scopes if isinstance(s, str)}),
                "granted_at": event.get("created_at"),
                "event_id": event.get("id"),
            }
        )
    grants.sort(key=lambda g: g.get("granted_at") or 0, reverse=True)  # newest first
    return grants


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
# read side (used by the admin console's /package/operations* routes and
# bin/nostr-opctl status) - there is no separate operations database; the
# control relay's own event store is the source of truth, so listing
# operations means reading the chain back and replaying the state machine.

def _read_e_tag(event: dict[str, Any]) -> str | None:
    for tag in event.get("tags") or []:
        if tag and tag[0] == "e" and len(tag) > 1:
            return tag[1]
    return None


def fetch_chain_events(relay_url: str, *, kinds: tuple[int, ...] | None = None, timeout: float = 3.0) -> list[dict[str, Any]]:
    """REQ the chain kinds on the control relay; return the stored events.

    Handles the NIP-42 AUTH challenge (control kinds are protected by
    default), authenticating the connection as the operator - the same
    handshake ``bin/nostr-opctl status`` performs."""
    import secrets

    from websockets.sync.client import connect

    from .nostr_identity import _sign_auth_event, _wait_auth_ok, default_auth

    kinds = kinds or CHAIN_KINDS
    events: list[dict[str, Any]] = []
    with connect(relay_url) as ws:
        sub_id = "nostrhost-ops-" + secrets.token_hex(4)
        req = json.dumps(["REQ", sub_id, {"kinds": list(kinds)}])
        ws.send(req)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                msg = json.loads(ws.recv(timeout=0.5))
            except TimeoutError:
                continue
            if msg[0] == "AUTH":
                auth = default_auth()
                if auth is not None:
                    challenge = msg[1] if len(msg) > 1 else ""
                    auth_ev = _sign_auth_event(auth[0], auth[1], relay_url, challenge, sub_id)
                    ws.send(json.dumps(["AUTH", auth_ev]))
                    _wait_auth_ok(ws, auth_ev["id"], deadline)
                    ws.send(req)  # re-send the REQ now that the connection is authed
                continue
            if msg[0] == "EVENT":
                events.append(msg[2])
            elif msg[0] == "EOSE":
                break
    return events


def _operation_entry(chain: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Reduce one request's chain events (the 2200 request plus whatever
    2201-2204 follow-ons have landed) to a single summary entry, replaying
    the state machine in event order. Returns None for an orphaned follow-on
    event whose request isn't in this relay snapshot."""
    from .nostr_operations_state import InvalidTransition, next_state

    request_event = next((e for e in chain if e.get("kind") == KIND_OPERATION_REQUEST), None)
    if request_event is None:
        return None
    try:
        content = json.loads(request_event.get("content") or "{}")
    except json.JSONDecodeError:
        content = {}

    state = OpState.REQUESTED
    for event in sorted(chain, key=lambda e: e["created_at"]):
        if event["id"] == request_event["id"]:
            continue
        ok = True
        if event.get("kind") == KIND_EXECUTION_RESULT:
            try:
                ok = bool(json.loads(event.get("content") or "{}").get("ok", True))
            except json.JSONDecodeError:
                ok = True
        try:
            state = next_state(state, event["kind"], ok=ok)
        except InvalidTransition:
            continue  # ignore out-of-order/duplicate/invalid chain events

    return {
        "id": request_event["id"],
        "request_id": request_event["id"],
        "tool": content.get("tool"),
        "args": content.get("args"),
        "pubkey": request_event.get("pubkey"),
        "created_at": request_event.get("created_at"),
        "state": state.value.upper(),
    }


def list_operations(*, limit: int | None = None, control_relay: str | None = None) -> list[dict[str, Any]]:
    """Every operation on the control relay, newest request first."""
    relay = _control_relay(control_relay)
    events = fetch_chain_events(relay)
    by_request: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        request_id = event["id"] if event.get("kind") == KIND_OPERATION_REQUEST else _read_e_tag(event)
        if request_id is None:
            continue
        by_request.setdefault(request_id, []).append(event)

    entries = []
    for chain in by_request.values():
        entry = _operation_entry(chain)
        if entry is not None:
            entries.append(entry)
    entries.sort(key=lambda e: e["created_at"], reverse=True)
    return entries[:limit] if limit else entries


def get_operation(request_id: str, *, control_relay: str | None = None) -> dict[str, Any] | None:
    """One operation's current summary, or None if it isn't on the relay."""
    for entry in list_operations(control_relay=control_relay):
        if entry["request_id"] == request_id:
            return entry
    return None


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
    # An admin/operator request auto-approves in the engine (the requester is
    # the authority the approval step exists to ask), so it already reached a
    # terminal state and must not be handed a second approval - that would be
    # an illegal transition. Only a still-parked request needs the explicit
    # operator approval.
    if record.state == OpState.REQUESTED:
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
