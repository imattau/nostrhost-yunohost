"""Native ``nostrhost`` CLI.

The NostrHost administration CLI -- Typer commands over the native operation
surface.  No YunoHost/actionsmap compatibility: users are Nostr identities
(npubs), writes are the native resource-engine/control-plane tools, and
authorisation is capability-based.

Command groups:

    system      read-only system/package version info
    service     status / restart / control a service
    app         list / remove an installed app
    package     plan / reconcile a native package operation plan
    rollback    apply an assisted rollback plan
    state       apply a reconciliation plan
    identity    npub-based user identities (link / revoke / list / resolve)
    capability  grant / delegate / revoke capabilities to an npub
    agent       optional local agent lifecycle (init / status / enable / disable)
    postinstall first-run bootstrap / restore (new / restore / status)

The CLI runs as the authorized admin: read tools execute directly, and write
tools execute through their safe handlers here (the local admin is the
operator).  Remote agents route writes through the operation chain
(``nostr-opctl`` request/approve + ``nostr-operationsd``).  Keys and the
control relay are read from the operator config or overridden with
``--operator-sk`` / ``--admin-sk`` / ``--control-relay``.

Exit codes: 0 on success, 1 on any error, 2 on usage errors.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, Callable

import typer

from . import ui
from .core import NostrHostError
from yunohost.nostr_identity import (
    OPERATOR_CONFIG,
    IdentityError,
    _is_hex64,
    _npub,
    _parse_pubkey,
    _pubkey,
    _read_operator_config,
    link_identity,
    list_identities,
    list_identities_for_username,
    resolve_pubkey,
    resolve_username,
    revoke_identity,
)
from yunohost.nostr_operations import (
    OperationError,
    _safe_app_list,
    _safe_app_remove,
    _safe_credential_list,
    _safe_credential_remove,
    _safe_credential_set,
    _safe_dns_apply,
    _safe_dns_plan,
    _safe_dns_subscribe,
    _safe_dns_subscriptions,
    _safe_dns_unsubscribe,
    _safe_nsite_gateway_status,
    _safe_nsite_gateway_enable,
    _safe_nsite_gateway_disable,
    _safe_nsite_gateway_configure,
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
    _safe_nsite_domain_attach,
    _safe_nsite_domain_detach,
    _safe_nsite_domain_list,
    _safe_dns_verify,
    _safe_dns_watch,
    _safe_domain_add,
    _safe_domain_inspect,
    _safe_domain_list,
    _safe_domain_remove,
    _safe_network_public_ip,
    _safe_package_fetch_manifest,
    _safe_package_plan,
    _safe_package_reconcile,
    _safe_reconcile_apply,
    _safe_rollback_apply,
    _safe_service_control,
    _safe_service_restart,
    _safe_service_status,
    _safe_system_version,
    delegate_capability,
    grant_capability,
    revoke_delegation,
)
from yunohost.nostrhost import native_ops

EXIT_OK = 0
EXIT_ERR = 1

DESCRIPTION = (
    "NostrHost administration CLI: native tools, npub identities and "
    "capabilities. e.g. 'nostrhost system version', "
    "'nostrhost identity link alice npub1...', 'nostrhost service restart caddy'."
)

# Tool name -> safe handler (the ToolSpec registry is the source of truth).
_TOOL_HANDLERS: dict[str, Callable[..., Any]] = {
    "system.version": _safe_system_version,
    "service.status": _safe_service_status,
    "service.restart": _safe_service_restart,
    "service.control": _safe_service_control,
    "app.list": _safe_app_list,
    "app.remove": _safe_app_remove,
    "package.plan": _safe_package_plan,
    "package.fetch_manifest": _safe_package_fetch_manifest,
    "package.reconcile": _safe_package_reconcile,
    "rollback.apply": _safe_rollback_apply,
    "state.reconcile": _safe_reconcile_apply,
    "domain.list": _safe_domain_list,
    "domain.inspect": _safe_domain_inspect,
    "domain.add": _safe_domain_add,
    "domain.remove": _safe_domain_remove,
    "dns.plan": _safe_dns_plan,
    "dns.apply": _safe_dns_apply,
    "dns.verify": _safe_dns_verify,
    "dns.watch": _safe_dns_watch,
    "dns.subscribe": _safe_dns_subscribe,
    "dns.subscriptions": _safe_dns_subscriptions,
    "dns.unsubscribe": _safe_dns_unsubscribe,
    "nsite.gateway.status": _safe_nsite_gateway_status,
    "nsite.gateway.enable": _safe_nsite_gateway_enable,
    "nsite.gateway.disable": _safe_nsite_gateway_disable,
    "nsite.gateway.configure": _safe_nsite_gateway_configure,
    "nsite.list": _safe_nsite_list,
    "nsite.inspect": _safe_nsite_inspect,
    "nsite.mirror": _safe_nsite_mirror,
    "nsite.resolve": _safe_nsite_resolve,
    "nsite.validate_manifest": _safe_nsite_validate,
    "nsite.reachability": _safe_nsite_reachability,
    "nsite.publish.plan": _safe_nsite_publish_plan,
    "nsite.register": _safe_nsite_register,
    "nsite.unregister": _safe_nsite_unregister,
    "nsite.publish": _safe_nsite_publish,
    "nsite.snapshot": _safe_nsite_snapshot,
    "nsite.domain.attach": _safe_nsite_domain_attach,
    "nsite.domain.detach": _safe_nsite_domain_detach,
    "nsite.domain.list": _safe_nsite_domain_list,
    "network.public_ip": _safe_network_public_ip,
    "credential.set": _safe_credential_set,
    "credential.remove": _safe_credential_remove,
    "credential.list": _safe_credential_list,
    "system.status": native_ops._safe_system_status,
    "app.install": native_ops._safe_app_install,
    "app.upgrade": native_ops._safe_app_upgrade,
    "app.change_url": native_ops._safe_app_change_url,
    "app.config.read": native_ops._safe_app_config_read,
    "app.config.set": native_ops._safe_app_config_set,
    "backup.create": native_ops._safe_backup_create,
    "backup.info": native_ops._safe_backup_info,
    "backup.list": native_ops._safe_backup_list,
    "backup.restore": native_ops._safe_backup_restore,
    "user.list": native_ops._safe_user_list,
    "user.create": native_ops._safe_user_create,
    "user.delete": native_ops._safe_user_delete,
    "system.upgrade": native_ops._safe_system_upgrade,
    "firewall.list": native_ops._safe_firewall_list,
    "firewall.open": native_ops._safe_firewall_open,
    "firewall.close": native_ops._safe_firewall_close,
    "firewall.reload": native_ops._safe_firewall_reload,
    "diagnosis.run": native_ops._safe_diagnosis_run,
    "diagnosis.ignored": native_ops._safe_diagnosis_ignored,
    "diagnosis.ignore": native_ops._safe_diagnosis_ignore,
    "diagnosis.unignore": native_ops._safe_diagnosis_unignore,
    "catalog.list": native_ops._safe_catalog_list,
    "catalog.get": native_ops._safe_catalog_get,
    "catalog.publish": native_ops._safe_catalog_publish,
    "catalog.declare": native_ops._safe_catalog_declare,
    "catalog.verify": native_ops._safe_catalog_verify,
    "catalog.candidates": native_ops._safe_catalog_candidates,
    "catalog.attest": native_ops._safe_catalog_attest,
    "catalog.history": native_ops._safe_catalog_history,
    "catalog.trust": native_ops._safe_catalog_trust,
    "catalog.reverify": native_ops._safe_catalog_reverify,
    "catalog.profile.get": native_ops._safe_catalog_profile_get,
    "catalog.profile.set": native_ops._safe_catalog_profile_set,
    "catalog.announce": native_ops._safe_catalog_announce,
    "catalog.announcements": native_ops._safe_catalog_announcements,
    "updates.check": native_ops._safe_updates_check,
    "updates.refresh": native_ops._safe_updates_refresh,
    "system.migrations": native_ops._safe_system_migrations,
    "system.migrate": native_ops._safe_system_migrate,
    "service.history": native_ops._safe_service_history,
    "logs.read": native_ops._safe_logs_read,
    "logs.web": native_ops._safe_logs_web,
    "logs.problems": native_ops._safe_logs_problems,
    "backup.delete": native_ops._safe_backup_delete,
    "domain.cert.info": native_ops._safe_domain_cert_info,
    "domain.cert.install": native_ops._safe_domain_cert_install,
    "domain.primary.set": native_ops._safe_domain_primary_set,
    "nostr.connectivity.set": native_ops._safe_nostr_connectivity_set,
    "user.update": native_ops._safe_user_update,
    "user.group.list": native_ops._safe_user_group_list,
    "user.group.create": native_ops._safe_user_group_create,
    "user.group.update": native_ops._safe_user_group_update,
    "user.group.delete": native_ops._safe_user_group_delete,
    "user.permission.list": native_ops._safe_user_permission_list,
    "user.permission.info": native_ops._safe_user_permission_info,
    "user.permission.add": native_ops._safe_user_permission_add,
    "user.permission.remove": native_ops._safe_user_permission_remove,
    "user.permission.update": native_ops._safe_user_permission_update,
    "audit.list": native_ops._safe_audit_list,
    "audit.get": native_ops._safe_audit_get,
    "system.reboot": native_ops._safe_system_reboot,
    "system.shutdown": native_ops._safe_system_shutdown,
    "settings.list": native_ops._safe_settings_list,
    "settings.get": native_ops._safe_settings_get,
    "settings.set": native_ops._safe_settings_set,
    "settings.reset": native_ops._safe_settings_reset,
    "settings.reset_all": native_ops._safe_settings_reset_all,
}

VALID_SIGNER_TYPES = ("nip07", "nip46", "passkey", "unknown")


class _State:
    """Per-invocation global options shared with commands."""

    def __init__(self) -> None:
        self.output_as: str | None = None
        self.control_relay: str | None = None
        self.operator_sk: str | None = None
        self.admin_sk: str | None = None
        self.debug = False


def _print_error(exc: Exception) -> None:
    print(f"error: {exc}", file=sys.stderr)


def _load_json_file(path: str) -> Any:
    """Read a JSON file (a signed event or blob inventory) or raise."""
    try:
        import json

        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NostrHostError(f"cannot read JSON file {path}: {exc}") from exc


def _run_tool(name: str, args: dict[str, Any]) -> Any:
    handler = _TOOL_HANDLERS[name]
    return handler(**args)


# --------------------------------------------------------------------------- #
# native app lifecycle (ALPHA-PLAN Workstream 3)

PACKAGE_CACHE = Path("/var/cache/nostrhost/catalogue")
SYSTEM_BACKUP_PATHS = ("/etc", "/home", "/opt", "/var/www", "/var/lib/nostrhost")


def _coordinate_for(
    app_id: str,
    *,
    repository: str | None = None,
    revision: str | None = None,
    package_path: str | None = None,
    manifest_sha256: str | None = None,
) -> dict[str, Any] | None:
    """Resolve the catalogue coordinate for ``app_id`` (per-field overridable)."""
    try:
        from yunohost.nostr_catalog_provider import native_catalog_coordinate

        coordinate = native_catalog_coordinate(app_id) or {}
    except Exception:  # noqa: BLE001 - the catalogue is an optional source
        coordinate = {}
    for key, value in (
        ("repository", repository),
        ("revision", revision),
        ("package_path", package_path),
        ("manifest_sha256", manifest_sha256),
    ):
        if value:
            coordinate[key] = value
    return coordinate or None


def _load_package_data(source: Path | None, coordinate: dict[str, Any] | None) -> dict[str, Any]:
    """Return the resolved package.toml dict for an install/upgrade.

    ``--source`` may be a directory containing ``package_path`` (default
    ``package.toml``) or the manifest file itself. Without a local source the
    package is fetched from the coordinate's git repository at the pinned
    revision into the package cache."""
    import tomllib

    package_path = (coordinate or {}).get("package_path") or "package.toml"
    if source is not None:
        target = source / package_path if source.is_dir() else source
    else:
        coordinate = coordinate or {}
        repository = coordinate.get("repository")
        revision = coordinate.get("revision")
        if not repository or not revision:
            raise NostrHostError("no --source given and the catalogue coordinate lacks repository@revision")
        target = _fetch_catalogue_file(repository, revision, package_path)
    try:
        with target.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise NostrHostError(f"cannot load package {target}: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("app"), dict):
        raise NostrHostError(f"{target} is not a native package.toml (missing [app])")
    return raw


def _fetch_catalogue_file(repository: str, revision: str, package_path: str) -> Path:
    """Best-effort git checkout of ``repository@revision`` into the cache."""
    slug = hashlib.sha256(f"{repository}:{revision}".encode()).hexdigest()[:16]
    checkout = PACKAGE_CACHE / slug
    if not checkout.is_dir():
        PACKAGE_CACHE.mkdir(parents=True, exist_ok=True)
        temporary = checkout.with_suffix(".tmp")
        subprocess.run(["git", "clone", "--no-checkout", repository, str(temporary)], check=True, capture_output=True, text=True)
        temporary.rename(checkout)
    if not revision.startswith("refs/"):
        subprocess.run(["git", "-C", str(checkout), "checkout", "-q", revision], check=True, capture_output=True, text=True)
    return checkout / package_path


def _verify_package(package_data: dict[str, Any], coordinate: dict[str, Any] | None) -> None:
    """Refuse to plan a package whose canonical digest differs from the signed
    catalogue declaration's ``manifest_sha256``."""
    expected = (coordinate or {}).get("manifest_sha256")
    if not expected:
        return  # nothing to verify against
    from nostrhost.package_engine import _canonical_json

    actual = hashlib.sha256(_canonical_json(package_data)).hexdigest()
    if actual.lower() != str(expected).lower():
        raise NostrHostError(f"package manifest hash mismatch: expected {expected}, got {actual}")


def _apply_web_overrides(package_data: dict[str, Any], *, domain: str | None, path: str | None) -> dict[str, Any]:
    """Apply install-time ``[web].domain``/``[web].path`` overrides.

    Domain and path are install-time parameters (which host, which URL mount
    point) rather than part of the package's own signed content, so this
    must run on a copy of ``package_data`` and only *after* ``_verify_package``
    has checked the original against the catalogue's ``manifest_sha256`` —
    overriding them before verification would let an override silently
    forge what the catalogue actually signed. ``health.path`` is a separate
    literal field that packages conventionally set equal to ``web.path``
    (see nh-package-template's docs/new-package.md); keep it in sync so the
    health check still targets the right route after a ``--path`` override.
    """
    if domain is None and path is None:
        return package_data
    import copy

    package_data = copy.deepcopy(package_data)
    web = package_data.get("web")
    if not isinstance(web, dict):
        raise NostrHostError("--domain/--path given but the package declares no [web] resource")
    old_path = web.get("path")
    if domain is not None:
        web["domain"] = domain
    if path is not None:
        web["path"] = path
        health = package_data.get("health")
        if isinstance(health, dict) and health.get("path") == old_path:
            health["path"] = path
    return package_data


def _plan_envelope(package_data: dict[str, Any], coordinate: dict[str, Any] | None) -> dict[str, Any]:
    from nostrhost.package_engine import package_plan_envelope

    return package_plan_envelope(package_data, catalogue=coordinate)


def _run_lifecycle(tool: str, args: dict[str, Any], *, state: _State) -> dict[str, Any]:
    from yunohost.nostr_operations import run_signed_chain

    return run_signed_chain(
        tool,
        args,
        operator_sk=state.operator_sk,
        control_relay=state.control_relay,
    )


def _lifecycle_report(action: str, envelope: dict[str, Any], body: dict[str, Any], *, previous: str | None = None) -> dict[str, Any]:
    result = body.get("result") or {}
    rows = (result.get("results") if isinstance(result, dict) else None) or []
    health = next((row for row in rows if isinstance(row, dict) and row.get("operation") == "health.http.check"), None)
    changed = sum(1 for row in rows if isinstance(row, dict))
    report: dict[str, Any] = {
        "action": action,
        "package": envelope.get("package"),
        "plan_sha256": envelope.get("plan_sha256"),
        "operations": len(envelope.get("operations", [])),
        "applied": changed,
        "results": rows,
        "request_id": body.get("request_id"),
        "ok": bool(body.get("ok")),
    }
    if isinstance(result, dict) and result.get("restic_snapshot"):
        report["restic_snapshot"] = result["restic_snapshot"]
    if health is not None:
        report["health"] = health.get("result")
    if previous is not None:
        report["previous_version"] = previous
    return report


def _installed_manifest(app_id: str) -> dict[str, Any]:
    from nostrhost.native_providers import installed_package_manifest

    manifest = installed_package_manifest(app_id)
    if manifest is None:
        raise NostrHostError(f"{app_id} is not installed as a native app (no recorded manifest)")
    return manifest


def _iter_installed_manifests(state_dir: Path | None = None) -> list[tuple[str, dict[str, Any]]]:
    """Yield ``(app_id, manifest)`` for every installed native app.

    Reads the same ``*-manifest.json`` files ``installed_package_manifest``
    reads for a single app, one app at a time. Used by ``app
    reconcile-routes`` to replay every installed app's web route after Caddy
    (re)starts and drops its admin-API-pushed routes.
    """
    base = state_dir or Path("/var/lib/nostrhost/state/packages")
    results: list[tuple[str, dict[str, Any]]] = []
    if not base.is_dir():
        return results
    for candidate in sorted(base.glob("*-manifest.json")):
        app_id = candidate.name[: -len("-manifest.json")]
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        manifest = data.get("manifest") if isinstance(data, dict) else None
        if isinstance(manifest, dict):
            results.append((app_id, manifest))
    return results


def _removal_envelope(package_data: dict[str, Any]) -> dict[str, Any]:
    from nostrhost.package_engine import (
        PackageManifest,
        operation_plan_digest,
        plan_package_removal,
        validate_package,
    )

    package = validate_package(PackageManifest.parse_obj(package_data))
    operations = plan_package_removal(package)
    return {
        "schema": 1,
        "package": {"id": package.app.id, "version": package.app.version},
        "manifest_sha256": "",
        "plan_sha256": operation_plan_digest(operations),
        "operations": [operation.json_dict() for operation in operations],
    }


def _web_change_envelope(app_id: str, package_data: dict[str, Any], domain: str | None, path: str | None) -> dict[str, Any]:
    from nostrhost.package_engine import (
        PackageManifest,
        Operation,
        operation_plan_digest,
        validate_package,
    )

    package = validate_package(PackageManifest.parse_obj(package_data))
    if package.web is None:
        raise NostrHostError(f"{app_id} declares no web route to move")
    args = package.web.dict()
    if domain:
        args["domain"] = domain
    if path:
        args["path"] = path
    operation = Operation(
        name="web.route.ensure",
        resource=f"{app_id}:web",
        args={**args, "app": app_id},
        risk="medium",
        reverse="web.route.remove",
        summary=f"move {app_id} web route",
    )
    return {
        "schema": 1,
        "package": {"id": app_id, "version": package.app.version},
        "manifest_sha256": "",
        "plan_sha256": operation_plan_digest([operation]),
        "operations": [operation.json_dict()],
    }


def _restic_client() -> Any:
    from yunohost.nostr_restic import ResticClient, load_restic_config

    conf = load_restic_config()
    if conf is None:
        raise NostrHostError("restic is not configured (missing " + "/etc/nostrhost/restic.toml)")
    return ResticClient(repo=conf.repo, password=conf.password, binary=conf.binary, host=conf.host, tag=conf.tag, timeout=conf.timeout)


def _app_backup_paths(app_id: str) -> list[str]:
    from nostrhost.package_engine import PackageManifest, validate_package

    package = validate_package(PackageManifest.parse_obj(_installed_manifest(app_id)))
    if not package.backup or not package.backup.paths:
        raise NostrHostError(f"{app_id} declares no backup paths in its package.toml")
    return [str(path) for path in package.backup.paths]


# --------------------------------------------------------------------------- #
# native postinstall (ALPHA-PLAN Workstream 2)

POSTINSTALL_UNITS = [
    "caddy",
    "nostrhost-control",
    "nostr-identityd",
    "nostr-permissiond",
    "nostr-operationsd",
    "nostr-securityd",
    "nostr-ddnswatchd",
    "nostr-api",
    "nostr-portal-api",
    "nostrhost-certd.timer",
]

CADDY_BASE_DIR = "/etc/caddy"
CADDY_CONF_DIR = "/etc/caddy/conf.d"
CADDY_TEMPLATE_DIR = "/usr/share/yunohost/conf/caddy"
POLICY_CONFIG = "/etc/nostrhost/policy.toml"
RELAY_CONFIG = "/etc/nostrhost/relay.toml"
INSTALLED_MARKER = "/etc/yunohost/installed"
NOTIFY_CONFIG = os.environ.get("NOSTRHOST_NOTIFY_CONFIG", "/etc/nostrhost/notify.toml")
CATALOGUE_ENV = os.environ.get("NOSTRHOST_CATALOGUE_ENV", "/etc/nostrhost/catalogue.env")
KEYS_RECOVERY = os.environ.get("NOSTRHOST_KEYS_RECOVERY", "/etc/nostrhost/keys.recovery")
NOTIFY_STATE_DIR = os.environ.get("NOSTRHOST_NOTIFY_STATE_DIR", "/var/lib/nostrhost/state/notifications")
AGENT_CONFIG = "/etc/nostrhost-agent/config.json"
AGENT_STATE_DIR = "/var/lib/nostrhost-agent"
AGENT_BINARY = "/usr/bin/nostrhost-agent"
AGENT_SERVICE = "nostrhost-agent.service"
AGENT_MODEL_BINARY = "/usr/bin/nostrhost-agent-model"
AGENT_EXPORT_BINARY = "/usr/bin/nostrhost-agent-export"
AGENT_CONTRIBUTE_BINARY = "/usr/bin/nostrhost-agent-contribute"
AGENT_MODELS_DIR = "/var/lib/nostrhost-agent/models"
AGENT_RUNTIME_DIR = "/var/lib/nostrhost-agent/runtime"
AGENT_EXPORTS_DIR = "/var/lib/nostrhost-agent/exports"
AGENT_LLM_ENV = "/etc/nostrhost-agent/llm.env"
AGENT_LLM_SERVICE = "nostrhost-agent-llm.service"
AGENT_INFERENCE_HOST = "127.0.0.1"
AGENT_INFERENCE_PORT = 18080
AGENT_HF_TOKEN_PATH = "/etc/nostrhost-agent/hf_token"
# Shared with the resident daemon's own auto-submitter (agent/contribution_auto.go,
# same default path) so a cycle submitted either manually or automatically is never
# offered again through the other path.
AGENT_CONTRIBUTION_STATE_PATH = "/var/lib/nostrhost-agent/contribution-submitted.jsonl"
AGENT_MODE_LEVELS = ("observe", "assist", "maintain", "autonomous")


def _set_agent_relay_writer(pubkey: str, *, allowed: bool) -> bool:
    """Update the root-owned static relay writer list for the optional agent.

    The relay reconciles entries tagged ``agent`` on restart. Writer access
    permits event submission only; operation capabilities remain separate.
    """
    relay_path = Path(RELAY_CONFIG)
    if relay_path.is_symlink() or not relay_path.is_file():
        raise NostrHostError(f"control relay config is missing or unsafe: {relay_path}")
    raw = relay_path.read_text(encoding="utf-8")
    try:
        parsed = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise NostrHostError(f"control relay config is invalid TOML: {exc}") from exc
    keys = parsed.get("agent_pubkeys", [])
    if not isinstance(keys, list) or any(not isinstance(key, str) for key in keys):
        raise NostrHostError("control relay agent_pubkeys must be an array of public-key strings")
    updated = list(dict.fromkeys(keys))
    if allowed and pubkey not in updated:
        updated.append(pubkey)
    elif not allowed:
        if pubkey not in updated:
            return False
        updated = [key for key in updated if key != pubkey]
    else:
        return False
    replacement = "agent_pubkeys = " + json.dumps(updated, separators=(",", ":"))
    lines = raw.splitlines()
    section_start = next((i for i, line in enumerate(lines) if line.lstrip().startswith("[")), len(lines))
    key_line = next((i for i, line in enumerate(lines[:section_start]) if line.startswith("agent_pubkeys =")), None)
    if key_line is not None:
        lines[key_line] = replacement
    else:
        lines.insert(section_start, replacement)
    candidate = "\n".join(lines).rstrip() + "\n"
    try:
        tomllib.loads(candidate)
    except tomllib.TOMLDecodeError as exc:
        raise NostrHostError(f"updated control relay config is invalid TOML: {exc}") from exc
    mode = relay_path.stat().st_mode & 0o777
    temp_path = relay_path.with_name(relay_path.name + f".{os.getpid()}.tmp")
    fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(candidate)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, relay_path)
        os.chmod(relay_path, mode)
    except Exception:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise
    return True


def _agent_init() -> dict[str, Any]:
    """Write a dedicated Observe-mode agent config without enabling it or
    granting relay capabilities. Provisioning is explicitly operator initiated."""
    if os.geteuid() != 0:
        raise NostrHostError("agent init must be run as root")
    if not Path(INSTALLED_MARKER).exists():
        raise NostrHostError("NostrHost is not postinstalled; run `nostrhost postinstall new` first")
    config_path = Path(AGENT_CONFIG)
    if config_path.exists() or config_path.is_symlink():
        raise NostrHostError(f"{config_path} already exists; refusing to replace agent identity or policy")
    node = _read_operator_config()
    operator_sk = node.get("operator_sk")
    server_sk = node.get("server_sk") or operator_sk
    relay = node.get("control_relay") or os.environ.get("NOSTRHOST_CONTROL_RELAY") or "ws://127.0.0.1:4848"
    if not operator_sk or not server_sk:
        raise NostrHostError("NostrHost operator/server keys are missing from the root-only operator config")
    if not Path(AGENT_BINARY).exists():
        raise NostrHostError("nostrhost-agent is not installed; install the optional nostrhost-agent package first")

    config_path.parent.mkdir(parents=True, exist_ok=True)
    parent_stat = config_path.parent.lstat()
    if config_path.parent.is_symlink() or not config_path.parent.is_dir():
        raise NostrHostError("agent config directory must be a real directory")
    if parent_stat.st_uid != 0:
        os.chown(config_path.parent, 0, 0)
    os.chmod(config_path.parent, 0o750)
    agent_secret = secrets.token_hex(32)
    agent_pubkey = _pubkey(agent_secret)
    config = {
        "schema_version": 2,
        "relay": {
            "relay_url": relay,
            "agent_secret_key": agent_secret,
            "trusted_server_key": _pubkey(server_sk),
            "result_timeout": "2m",
        },
        "policy": {
            "level": "observe",
            "scopes": {"services.read": True},
        },
        # service.status is implemented by both the agent registry and the
        # current NostrHost control-plane ToolSpec registry.
        "observation_queries": [
            {"operation": "service.status"},
        ],
        "audit_path": str(Path(AGENT_STATE_DIR) / "audit.jsonl"),
        "interval": "6h",
        "run_immediately": True,
        "listen_for_events": True,
        "event_lookback": "5m",
    }
    temp_path = config_path.with_name(config_path.name + f".{os.getpid()}.tmp")
    fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(config, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, config_path)
        if config_path.stat().st_uid != 0:
            os.chown(config_path, 0, 0)
        os.chmod(config_path, 0o600)
    except Exception:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise
    return {
        "configured": True,
        "service_enabled": False,
        "policy": "observe",
        "config_path": str(config_path),
        "agent_pubkey": agent_pubkey,
        "agent_npub": _npub(agent_pubkey),
        "relay_scopes": ["services.read"],
        "next": (
            f"Review this agent identity; grant its read scope with `nostrhost capability grant {agent_pubkey} services.read --type agent`, "
            "then explicitly run `nostrhost agent enable`."
        ),
    }


def _agent_service(action: str) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise NostrHostError(f"agent {action} must be run as root")
    config_path = Path(AGENT_CONFIG)
    if action == "enable":
        if config_path.is_symlink() or not config_path.is_file():
            raise NostrHostError("agent config is missing or is not a regular file; run `nostrhost agent init` first")
        parent_stat = config_path.parent.stat()
        if config_path.parent.is_symlink() or parent_stat.st_uid != 0 or parent_stat.st_mode & 0o022:
            raise NostrHostError("agent config directory must be root-owned and not group/world writable")
        config_stat = config_path.stat()
        mode = config_stat.st_mode & 0o777
        if config_stat.st_uid != 0:
            raise NostrHostError("agent config must be owned by root")
        if mode & 0o077:
            raise NostrHostError("agent config must not be accessible to group or other users")
        validator = AGENT_BINARY
        if not Path(validator).exists():
            raise NostrHostError("nostrhost-agent is not installed")
        checked = subprocess.run(
            [validator, "--check-config", "--config", str(config_path)],
            capture_output=True, text=True, check=False,
        )
        if checked.returncode != 0:
            raise NostrHostError(checked.stderr.strip() or "agent configuration validation failed")
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
            agent_pubkey = _pubkey(config["relay"]["agent_secret_key"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise NostrHostError("agent config does not contain a valid relay identity") from exc
        if _set_agent_relay_writer(agent_pubkey, allowed=True):
            subprocess.run(["systemctl", "restart", "nostrhost-control.service"], check=True)
        subprocess.run(["systemctl", "enable", "--now", AGENT_SERVICE], check=True)
    elif action == "disable":
        subprocess.run(["systemctl", "disable", "--now", AGENT_SERVICE], check=True)
        if config_path.is_file() and not config_path.is_symlink():
            try:
                config = json.loads(config_path.read_text(encoding="utf-8"))
                agent_pubkey = _pubkey(config["relay"]["agent_secret_key"])
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise NostrHostError("agent config does not contain a valid relay identity") from exc
            if _set_agent_relay_writer(agent_pubkey, allowed=False):
                subprocess.run(["systemctl", "restart", "nostrhost-control.service"], check=True)
    return {"service": AGENT_SERVICE, "action": action, "config_path": str(config_path)}


def _agent_status() -> dict[str, Any]:
    config_path = Path(AGENT_CONFIG)
    enabled = subprocess.run(
        ["systemctl", "is-enabled", AGENT_SERVICE], capture_output=True, text=True, check=False,
    )
    active = subprocess.run(
        ["systemctl", "is-active", AGENT_SERVICE], capture_output=True, text=True, check=False,
    )
    return {
        "installed": Path(AGENT_BINARY).exists(),
        "configured": config_path.is_file() and not config_path.is_symlink(),
        "service_enabled": enabled.returncode == 0,
        "service_active": active.returncode == 0,
    }


def _run_agent_tool_raw(binary: str, args: list[str]) -> str:
    """Run one of the optional nostrhost-agent helper binaries and return its
    raw stdout. These tools are never invoked by the running daemon; only
    explicit root-side admin actions call them."""
    if not Path(binary).exists():
        raise NostrHostError(f"{binary} is not installed; install the optional nostrhost-agent package first")
    result = subprocess.run([binary, *args], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise NostrHostError(result.stderr.strip() or f"{binary} failed")
    return result.stdout


def _run_agent_tool(binary: str, args: list[str]) -> Any:
    """Like _run_agent_tool_raw, but parses the output as JSON -- only for
    subcommands that are documented to print a single JSON value."""
    stdout = _run_agent_tool_raw(binary, args)
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise NostrHostError(f"{binary} did not return valid JSON") from exc


def _read_agent_config() -> dict[str, Any]:
    config_path = Path(AGENT_CONFIG)
    if not config_path.is_file() or config_path.is_symlink():
        raise NostrHostError("agent is not configured; run `nostrhost agent init` first")
    try:
        return json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NostrHostError("agent config is missing or not valid JSON") from exc


def _write_agent_config(config: dict[str, Any]) -> None:
    config_path = Path(AGENT_CONFIG)
    temp_path = config_path.with_name(config_path.name + f".{os.getpid()}.tmp")
    fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(config, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, config_path)
        os.chown(config_path, 0, 0)
        os.chmod(config_path, 0o600)
    except Exception:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def _restart_agent_if_active() -> None:
    active = subprocess.run(["systemctl", "is-active", AGENT_SERVICE], capture_output=True, text=True, check=False)
    if active.returncode == 0:
        subprocess.run(["systemctl", "restart", AGENT_SERVICE], check=True)


def _ensure_dir(path: str, mode: int = 0o750) -> None:
    directory = Path(path)
    if directory.is_symlink():
        raise NostrHostError(f"{path} must be a real directory, not a symlink")
    directory.mkdir(parents=True, mode=mode, exist_ok=True)
    os.chown(directory, 0, 0)
    os.chmod(directory, mode)


def _agent_model_profile() -> Any:
    if os.geteuid() != 0:
        raise NostrHostError("agent model profile must be run as root")
    _ensure_dir(AGENT_MODELS_DIR, mode=0o755)
    return _run_agent_tool(AGENT_MODEL_BINARY, ["profile", "--models-dir", AGENT_MODELS_DIR])


def _agent_model_recommend() -> Any:
    if os.geteuid() != 0:
        raise NostrHostError("agent model recommend must be run as root")
    _ensure_dir(AGENT_MODELS_DIR, mode=0o755)
    return _run_agent_tool(AGENT_MODEL_BINARY, ["recommend", "--models-dir", AGENT_MODELS_DIR])


def _agent_model_download(model_id: str, evaluation_only: bool) -> Any:
    if os.geteuid() != 0:
        raise NostrHostError("agent model download must be run as root")
    if not model_id:
        raise NostrHostError("model_id is required")
    _ensure_dir(AGENT_MODELS_DIR, mode=0o755)
    args = ["download", "--models-dir", AGENT_MODELS_DIR, "--model-id", model_id]
    if evaluation_only:
        args.append("--evaluation-only")
    result = _run_agent_tool(AGENT_MODEL_BINARY, args)
    # The model weights are a public download, not a secret -- make them
    # readable by the unprivileged account that actually serves them.
    import pwd

    agent_user = pwd.getpwnam("nostrhost-agent")
    downloaded_path = Path(result["path"])
    os.chown(downloaded_path, agent_user.pw_uid, agent_user.pw_gid)
    os.chmod(downloaded_path, 0o644)
    return result


def _agent_runtime_ensure() -> Any:
    """Idempotent: fetches and unpacks the pinned llama.cpp CPU build only if
    it is not already present under AGENT_RUNTIME_DIR."""
    if os.geteuid() != 0:
        raise NostrHostError("agent runtime setup must be run as root")
    _ensure_dir(AGENT_RUNTIME_DIR, mode=0o755)
    status = _run_agent_tool(AGENT_MODEL_BINARY, ["runtime", "status", "--runtime-dir", AGENT_RUNTIME_DIR])
    if status.get("installed"):
        return status
    return _run_agent_tool(AGENT_MODEL_BINARY, ["runtime", "download", "--runtime-dir", AGENT_RUNTIME_DIR])


def _agent_model_select(model_id: str) -> dict[str, Any]:
    """Point the agent's inference config at a downloaded model and start the
    local llama.cpp server for it. Never changes the policy level."""
    if os.geteuid() != 0:
        raise NostrHostError("agent model select must be run as root")
    recommendation = None
    for entry in _agent_model_recommend().get("models", []):
        if entry["model"]["id"] == model_id:
            recommendation = entry["model"]
            break
    if recommendation is None:
        raise NostrHostError(f"unknown model id {model_id!r}")
    model_path = Path(AGENT_MODELS_DIR) / recommendation["filename"]
    if not model_path.is_file() or model_path.is_symlink():
        raise NostrHostError(f"model {model_id!r} is not downloaded yet")
    digest = hashlib.sha256(model_path.read_bytes()).hexdigest()
    if digest != recommendation["sha256"]:
        raise NostrHostError("downloaded model file no longer matches the catalog checksum")
    runtime = _agent_runtime_ensure()
    server_path = runtime.get("server_path")
    if not server_path or not Path(server_path).is_file():
        raise NostrHostError("local inference runtime is not installed correctly")
    runtime_dir = str(Path(server_path).parent)
    env_path = Path(AGENT_LLM_ENV)
    temp_path = env_path.with_name(env_path.name + f".{os.getpid()}.tmp")
    fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(f"MODEL_PATH={model_path}\n")
            stream.write(f"RUNTIME_SERVER_PATH={server_path}\n")
            stream.write(f"LD_LIBRARY_PATH={runtime_dir}\n")
        os.replace(temp_path, env_path)
        os.chown(env_path, 0, 0)
        os.chmod(env_path, 0o600)
    except Exception:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", AGENT_LLM_SERVICE], check=True)
    config = _read_agent_config()
    config["inference"] = {
        "base_url": f"http://{AGENT_INFERENCE_HOST}:{AGENT_INFERENCE_PORT}/v1",
        "model": model_id,
    }
    _write_agent_config(config)
    _restart_agent_if_active()
    return {
        "model_id": model_id,
        "deployment_eligible": recommendation["deployment_eligible"],
        "evaluation_status": recommendation["evaluation_status"],
        "llm_service": AGENT_LLM_SERVICE,
    }


def _agent_model_status() -> dict[str, Any]:
    config_path = Path(AGENT_CONFIG)
    selected_model = None
    if config_path.is_file() and not config_path.is_symlink():
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
            selected_model = (config.get("inference") or {}).get("model")
        except (OSError, json.JSONDecodeError):
            selected_model = None
    enabled = subprocess.run(["systemctl", "is-enabled", AGENT_LLM_SERVICE], capture_output=True, text=True, check=False)
    active = subprocess.run(["systemctl", "is-active", AGENT_LLM_SERVICE], capture_output=True, text=True, check=False)
    return {
        "selected_model": selected_model,
        "llm_service_enabled": enabled.returncode == 0,
        "llm_service_active": active.returncode == 0,
    }


def _agent_mode_get() -> dict[str, Any]:
    config = _read_agent_config()
    return {"level": (config.get("policy") or {}).get("level", "observe")}


def _agent_mode_set(level: str, confirm: bool) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise NostrHostError("agent mode must be set as root")
    if level not in AGENT_MODE_LEVELS:
        raise NostrHostError(f"level must be one of {', '.join(AGENT_MODE_LEVELS)}")
    if level in ("maintain", "autonomous") and not confirm:
        raise NostrHostError(
            "maintain/autonomous require an explicit confirm=true acknowledgement; "
            "the agent's own operation policy still gates every write behind approval, "
            "but this level changes what it is allowed to attempt"
        )
    config = _read_agent_config()
    config.setdefault("policy", {})["level"] = level
    _write_agent_config(config)
    _restart_agent_if_active()
    return {"level": level}


def _agent_submitted_cycle_ids() -> set[str]:
    """Cycle IDs already shared via either the manual review flow (marked by
    _agent_mark_cycle_submitted) or the daemon's own auto-submitter
    (contribution_auto.go), so neither path re-offers or re-sends them."""
    path = Path(AGENT_CONTRIBUTION_STATE_PATH)
    if not path.is_file() or path.is_symlink():
        return set()
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


def _agent_mark_cycle_submitted(cycle_id: str) -> None:
    if not cycle_id or cycle_id in _agent_submitted_cycle_ids():
        return
    path = Path(AGENT_CONTRIBUTION_STATE_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as stream:
        stream.write(cycle_id + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600)
    try:
        import pwd

        agent_user = pwd.getpwnam("nostrhost-agent")
        os.chown(path, agent_user.pw_uid, agent_user.pw_gid)
    except KeyError:
        pass


def _agent_export_list() -> Any:
    if os.geteuid() != 0:
        raise NostrHostError("agent export list must be run as root")
    journal = str(Path(AGENT_STATE_DIR) / "audit.jsonl")
    summaries = _run_agent_tool(AGENT_EXPORT_BINARY, ["--journal", journal, "--list"])
    submitted = _agent_submitted_cycle_ids()
    if not submitted:
        return summaries
    return [summary for summary in summaries if summary.get("cycle_id") not in submitted]


_CANDIDATE_ID_PATTERN = re.compile(r"^[a-f0-9-]{1,80}$")


def _agent_export_run(cycle_id: str) -> Any:
    if os.geteuid() != 0:
        raise NostrHostError("agent export must be run as root")
    if not cycle_id:
        raise NostrHostError("cycle_id is required")
    _ensure_dir(AGENT_EXPORTS_DIR, mode=0o700)
    journal = str(Path(AGENT_STATE_DIR) / "audit.jsonl")
    candidate_id = secrets.token_hex(16)
    output_path = Path(AGENT_EXPORTS_DIR) / f"{candidate_id}.json"
    _run_agent_tool_raw(AGENT_EXPORT_BINARY, ["--journal", journal, "--cycle-id", cycle_id, "--output", str(output_path)])
    # Recorded so a later submit can mark the *source cycle* as done -- the
    # candidate file itself is keyed by a random id, not the cycle id.
    cycle_ref_path = Path(AGENT_EXPORTS_DIR) / f"{candidate_id}.cycle_id"
    cycle_ref_path.write_text(cycle_id, encoding="utf-8")
    os.chmod(cycle_ref_path, 0o600)
    return json.loads(output_path.read_text(encoding="utf-8")) | {"candidate_file_id": candidate_id}


def _agent_export_get(candidate_file_id: str) -> Any:
    if not _CANDIDATE_ID_PATTERN.match(candidate_file_id or ""):
        raise NostrHostError("invalid candidate id")
    path = Path(AGENT_EXPORTS_DIR) / f"{candidate_file_id}.json"
    if not path.is_file() or path.is_symlink():
        raise NostrHostError("no prepared candidate with that id")
    return json.loads(path.read_text(encoding="utf-8"))


def _agent_contribution_settings_get() -> dict[str, Any]:
    dataset_repo = ""
    auto_submit = False
    try:
        config = _read_agent_config()
        contribution = config.get("contribution") or {}
        dataset_repo = str(contribution.get("dataset_repo", ""))
        # Go's ContributionFileConfig.Enabled *is* "the resident daemon
        # submits every completed cycle itself, with no click required" --
        # see agent/contribution_auto.go. Named "auto_submit" here so the
        # two very different meanings of "enabled" never collide in this
        # API. Neither this nor the manual per-cycle share below involves a
        # human reading the candidate first -- both rely on the same
        # client-side redaction plus the community repo's own CI
        # validation before anything merges.
        auto_submit = bool(contribution.get("enabled", False))
    except NostrHostError:
        pass
    token_configured = Path(AGENT_HF_TOKEN_PATH).is_file()
    return {
        "enabled": bool(dataset_repo) and token_configured,
        "auto_submit": auto_submit,
        "dataset_repo": dataset_repo,
        "token_configured": token_configured,
    }


def _agent_contribution_settings_set(dataset_repo: str, token: str | None, auto_submit: bool) -> dict[str, Any]:
    """Update the agent's Hugging Face contribution settings.

    ``dataset_repo``/``token`` control whether an operator can share a
    cycle themselves, one click at a time (the "enabled" field in the
    get() response, derived from these two rather than stored separately).
    ``auto_submit`` is a stronger, explicit opt-in: it flips the resident
    daemon's own ``contribution.enabled`` config so it submits every
    completed cycle itself, with no click needed -- see
    agent/contribution_auto.go. It can only be turned on once a repo and a
    token both exist. Both modes share the same redaction and the same
    downstream CI validation; neither involves a human on this host
    reading the candidate before it goes out.
    """
    if os.geteuid() != 0:
        raise NostrHostError("contribution settings must be set as root")
    token_will_exist = bool(token) or Path(AGENT_HF_TOKEN_PATH).is_file()
    if auto_submit and not (dataset_repo and token_will_exist):
        raise NostrHostError("dataset_repo and a saved Hugging Face token are both required before enabling automatic submission")
    if token:
        # The resident daemon (an unprivileged account) must be able to read
        # this directly for automatic submission -- root can always read it
        # regardless of ownership, so this doesn't weaken the manual path.
        import pwd

        agent_user = pwd.getpwnam("nostrhost-agent")
        token_path = Path(AGENT_HF_TOKEN_PATH)
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_temp = token_path.with_name(token_path.name + f".{os.getpid()}.tmp")
        fd = os.open(token_temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(token.strip() + "\n")
            os.replace(token_temp, token_path)
            os.chown(token_path, agent_user.pw_uid, agent_user.pw_gid)
            os.chmod(token_path, 0o600)
        except Exception:
            try:
                token_temp.unlink()
            except FileNotFoundError:
                pass
            raise
    config = _read_agent_config()
    config["contribution"] = {"enabled": auto_submit, "dataset_repo": dataset_repo}
    _write_agent_config(config)
    _restart_agent_if_active()
    return _agent_contribution_settings_get()


def _agent_contribution_submit(candidate_file_id: str) -> Any:
    if os.geteuid() != 0:
        raise NostrHostError("contribution submit must be run as root")
    settings = _agent_contribution_settings_get()
    if not settings["enabled"]:
        raise NostrHostError("Hugging Face sharing is not enabled; turn it on in agent settings first")
    if not settings["token_configured"]:
        raise NostrHostError("no Hugging Face token is configured")
    if not _CANDIDATE_ID_PATTERN.match(candidate_file_id or ""):
        raise NostrHostError("invalid candidate id")
    candidate_path = Path(AGENT_EXPORTS_DIR) / f"{candidate_file_id}.json"
    if not candidate_path.is_file() or candidate_path.is_symlink():
        raise NostrHostError("no prepared candidate with that id")
    result = _run_agent_tool(AGENT_CONTRIBUTE_BINARY, [
        "--candidate", str(candidate_path),
        "--token-file", AGENT_HF_TOKEN_PATH,
        "--repo", settings["dataset_repo"],
    ])
    cycle_ref_path = Path(AGENT_EXPORTS_DIR) / f"{candidate_file_id}.cycle_id"
    if cycle_ref_path.is_file() and not cycle_ref_path.is_symlink():
        _agent_mark_cycle_submitted(cycle_ref_path.read_text(encoding="utf-8").strip())
    return result


def _agent_contribution_share(cycle_id: str) -> Any:
    """Redacts and submits one completed cycle in a single step.

    There used to be a separate "prepare, then eyeball the JSON, then
    submit" flow, on the theory that a human reading the candidate before
    it left the host was the safety check. That job now belongs to the
    community contribution repo's own CI validation (schema/redaction
    re-check, append-only enforcement) ahead of an automatic merge -- a
    human on this host reading the file first was never a real gate and
    only ever applied to the manual path anyway, not to automatic
    submission. Manual and automatic submission differ only in who
    triggers each cycle's export+submit, not in whether either is
    reviewed.
    """
    if os.geteuid() != 0:
        raise NostrHostError("contribution share must be run as root")
    exported = _agent_export_run(cycle_id)
    return _agent_contribution_submit(exported["candidate_file_id"])


def _write_policy_toml(operator_npub: str) -> Path:
    """Write the editable shared host policy (defaults apply for unlisted
    keys; the ``[owner]`` block documents the operator identity)."""
    path = Path(POLICY_CONFIG)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Section headers quote the dotted key ([policy."apps.upgrade"]) so TOML
    # keeps it as one literal key; an unquoted `[policy.apps.upgrade]` parses
    # as a nested table that load_policy() cannot read.
    path.write_text(
        "# NostrHost shared host policy (nostrhost_policy.policy.rules).\n"
        "# Any [policy.<key>] section overrides the built-in default for that\n"
        "# key only; unlisted keys keep their built-in default. Owner\n"
        "# enforcement uses operator.toml's operator_pubkey; [owner] below is\n"
        "# the documented identity.\n"
        f'\n[owner]\nowner_npub = "{operator_npub}"\n'
        '\n[policy."apps.upgrade"]\n'
        'require_backup = true\nminimum_free_space = "2GB"\n'
        '\n[policy."apps.remove"]\n'
        'require_confirmation = true\nrequire_backup = true\nmax_backup_age = "24h"\n'
        '\n[policy."backups.restore"]\n'
        "require_confirmation = true\nrequire_owner_signature = true\n"
        '\n[policy."system.upgrade"]\n'
        "require_confirmation = true\nrequire_owner_signature = true\n"
        '\n[policy."firewall.write"]\n'
        "require_confirmation = true\nrequire_owner_signature = true\n"
    )
    os.chmod(path, 0o644)
    return path


def _render_caddy_base(domain: str) -> None:
    """Render the base Caddyfile + one per-domain snippet directly.

    The native path renders ``/etc/caddy`` from the shipped templates;
    regenconf's ``15-caddy`` category tracks the same files so later domain
    adds / drift detection keep working. Uses plain string substitution for
    ``{{ domain }}`` — the snippet's only variable."""
    Path(CADDY_BASE_DIR).mkdir(parents=True, exist_ok=True)
    Path(CADDY_CONF_DIR).mkdir(parents=True, exist_ok=True)
    template_dir = Path(CADDY_TEMPLATE_DIR)
    caddyfile = template_dir / "Caddyfile.template"
    domain_tpl = template_dir / "caddy_domain.conf"
    if not caddyfile.exists() or not domain_tpl.exists():
        raise NostrHostError(f"caddy templates not found in {CADDY_TEMPLATE_DIR}")
    Path(CADDY_BASE_DIR, "Caddyfile").write_text(caddyfile.read_text(encoding="utf-8"))
    conf = domain_tpl.read_text(encoding="utf-8").replace("{{ domain }}", domain)
    Path(CADDY_CONF_DIR, f"{domain}.conf").write_text(conf)


def _normalize_sk(value: str) -> str:
    """Accept a 64-hex secret key or an ``nsec1...`` bech32 key; return hex.

    Restore and the recovery-bundle loader accept either form so an operator
    recovering a node can paste the keys as the safe-keeping format (nsec1)
    or the on-disk hex form.
    """
    if _is_hex64(value):
        return value
    if value.startswith("nsec1"):
        from nostr_sdk import SecretKey

        return SecretKey.parse(value).to_hex()
    raise NostrHostError("secret key must be 64-hex or an nsec1... key")


def _render_notify_config(notifier_sk: str, relay: str) -> Path:
    """Render the nostrhost-notify service config from the generated key."""
    state_dir = Path(os.environ.get("NOSTRHOST_NOTIFY_STATE_DIR", NOTIFY_STATE_DIR))
    state_dir.mkdir(parents=True, exist_ok=True)
    path = Path(os.environ.get("NOSTRHOST_NOTIFY_CONFIG", NOTIFY_CONFIG))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "# nostrhost-notify native notification service (rendered by postinstall).\n"
        f'relay_url = "{relay}"\n'
        f'notifier_private_key = "{notifier_sk}"\n'
        f'recipients_path = "{state_dir}/recipients.toml"\n'
        f'policy_path = "{state_dir}/policy.toml"\n'
        f'state_path = "{state_dir}/state.json"\n'
    )
    os.chmod(path, 0o600)
    return path


def _render_catalogue_env(publisher_pubkey: str) -> Path:
    """Render the native catalogue synchroniser env (trusted publishers)."""
    from .connectivity import effective as effective_connectivity

    path = Path(os.environ.get("NOSTRHOST_CATALOGUE_ENV", CATALOGUE_ENV))
    path.parent.mkdir(parents=True, exist_ok=True)
    relay_targets = ["ws://127.0.0.1:4848", *effective_connectivity()["relays"]["catalogue"]]
    path.write_text(
        "# nostrhost-catalog synchroniser (rendered by postinstall).\n"
        f"NOSTRHOST_CATALOG_PUBLISHERS={publisher_pubkey}\n"
        f"NOSTRHOST_CATALOG_RELAYS={','.join(dict.fromkeys(relay_targets))}\n"
        "NOSTRHOST_CATALOG_STATE=/var/lib/nostrhost/catalogue.json\n"
    )
    os.chmod(path, 0o600)
    return path


def _recovery_bundle(boot: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Build the show-once recovery bundle: every node key as nsec1 + npubs."""
    from nostr_sdk import SecretKey

    keys = {k: SecretKey.parse(boot[k]).to_bech32() for k in ("operator_sk", "server_sk", "notice_sk", "publisher_sk", "notifier_sk")}
    npubs = {k: _npub(boot[k]) for k in ("operator_pubkey", "server_pubkey", "notice_pubkey", "publisher_pubkey", "notifier_pubkey")}
    return {"keys": keys, "npubs": npubs}


def _render_keys_recovery(boot: dict[str, Any]) -> Path:
    """Write the root-only keys.recovery bundle (durable safe-keeping copy)."""
    bundle = _recovery_bundle(boot)
    path = Path(os.environ.get("NOSTRHOST_KEYS_RECOVERY", KEYS_RECOVERY))
    path.parent.mkdir(parents=True, exist_ok=True)
    body = (
        "# nostrhost keys recovery bundle (root-only). Store offline.\n"
        "# WARNING: these are the node's full identity keys - losing them\n"
        "# loses the node, leaking them is takeover. Not in ngit state.\n"
        "[keys]\n"
        + "\n".join(f'{k} = "{v}"' for k, v in bundle["keys"].items())
        + "\n\n[npubs]\n"
        + "\n".join(f'{k} = "{v}"' for k, v in bundle["npubs"].items())
        + "\n"
    )
    path.write_text(body)
    os.chmod(path, 0o600)
    return path


def _load_keys_file(keys_file: Path) -> dict[str, str]:
    """Load the five secret keys from a keys.recovery bundle (hex or nsec1)."""
    import tomllib

    try:
        data = tomllib.loads(keys_file.read_text())
    except FileNotFoundError:
        raise NostrHostError(f"keys file not found: {keys_file}") from None
    except tomllib.TOMLDecodeError as exc:
        raise NostrHostError(f"keys file is not valid TOML: {keys_file} ({exc})") from None
    keys = data.get("keys")
    if not isinstance(keys, dict):
        raise NostrHostError(f"keys file {keys_file} has no [keys] table")
    required = ("operator_sk", "server_sk", "notice_sk", "publisher_sk", "notifier_sk")
    missing = [k for k in required if k not in keys]
    if missing:
        raise NostrHostError(f"keys file {keys_file} is missing: {', '.join(missing)}")
    return {k: _normalize_sk(str(keys[k])) for k in required}


RESTIC_CONFIG = os.environ.get("NOSTRHOST_RESTIC_CONFIG", "/etc/nostrhost/restic.toml")
RESTIC_REPO = "/var/lib/nostrhost/restic-repo"


def _provision_restic() -> Path:
    """Provision a default local Restic repo + config so the policy backup
    gate is satisfiable on a fresh node.

    Writes ``/etc/nostrhost/restic.toml`` (0600) pointing at a local repo
    under ``/var/lib/nostrhost/restic-repo`` with a freshly generated
    password, and initialises the repo if it does not exist yet. Operators
    may later point this at an external/remote repo; the local default keeps
    ``app install`` / ``app upgrade`` (which require a recent backup) working
    out of the box.
    """
    import secrets

    conf = Path(RESTIC_CONFIG)
    if conf.exists():
        return conf
    conf.parent.mkdir(parents=True, exist_ok=True)
    repo = Path(RESTIC_REPO)
    repo.mkdir(parents=True, exist_ok=True)
    password = secrets.token_urlsafe(32)
    conf.write_text(
        f'repo = "{repo}"\n'
        f'password = "{password}"\n'
        'paths = ["/etc", "/var/www", "/var/lib/nostrhost/state"]\n'
        'binary = "restic"\n'
        f'host = "{socket.gethostname()}"\n'
        'tag = "nostrhost"\n'
    )
    os.chmod(conf, 0o600)
    if not (repo / "config").exists():
        subprocess.run(
            ["restic", "-r", str(repo), "init"],
            input=f"{password}\n".encode(),
            capture_output=True,
            check=True,
        )
    return conf


def _trust_caddy_internal_ca() -> Path | None:
    """Add Caddy's internal root CA to the system trust store so package
    health checks against .test/local HTTPS routes verify.

    Caddy provisions ``/var/lib/caddy/pki/authorities/local/root.crt`` the
    first time it issues an internal certificate. Copy it into
    ``update-ca-certificates``'s store so httpx/requests trust it; return the
    target path (None when Caddy has not provisioned a root yet — e.g. no
    internal cert has been issued). Non-fatal on failure.
    """
    root = Path("/var/lib/caddy/pki/authorities/local/root.crt")
    if not root.exists():
        return None
    target = Path("/usr/local/share/ca-certificates/caddy-internal.crt")
    try:
        target.write_bytes(root.read_bytes())
        subprocess.run(["update-ca-certificates"], check=False, capture_output=True)
    except OSError:
        return None
    return target


def _systemctl(*args: str) -> None:
    subprocess.run(["systemctl", *args], check=False, capture_output=True, text=True)


def _enable_postinstall_daemons() -> list[str]:
    """daemon-reload + enable --now the native stack. Returns the units that
    did not reach an active/activating state (best-effort — surfaced in the
    summary, never fatal here)."""
    _systemctl("daemon-reload")
    failed: list[str] = []
    for unit in POSTINSTALL_UNITS:
        _systemctl("enable", unit)
        _systemctl("start", unit)
        res = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True)
        if res.stdout.strip() not in ("active", "activating"):
            failed.append(unit)
    return failed


def _prepare_node(domain: str, operator_npub: str) -> None:
    """Shared postinstall base configuration (both --new and --restore)."""
    Path("/var/lib/nostrhost").mkdir(parents=True, exist_ok=True)
    Path("/var/lib/caddy").mkdir(parents=True, exist_ok=True)
    Path("/var/log/caddy").mkdir(parents=True, exist_ok=True)
    _write_policy_toml(operator_npub)
    _render_caddy_base(domain)
    Path("/etc/yunohost/current_host").write_text(domain + "\n")
    _provision_portal_session_secret()


def _provision_portal_session_secret(path: str | Path | None = None) -> Path:
    """Ensure the portal session cookie secret exists.

    The portal-api mints/validates the ``nostrhost.portal`` session cookie with
    this AES-256 key; without it the single sign-in flow (portal login -> admin
    console) cannot work. The legacy YunoHost postinstall wizard wrote it;
    the native postinstall must too. 32 bytes exactly (AES-256-CBC key).
    """
    import secrets as _secrets

    secret_path = Path(path or "/etc/yunohost/.ssowat_cookie_secret")
    if secret_path.exists():
        return secret_path
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    secret_path.write_text(_secrets.token_urlsafe(24)[:32])
    secret_path.chmod(0o600)
    return secret_path


def _publish_initial_capability(operator_pubkey: str) -> dict[str, Any] | None:
    """Grant the operator the full scope set (published to the control relay
    as the operator; non-fatal when the relay is not yet up)."""
    from yunohost.nostr_operations import KNOWN_SCOPES, grant_capability

    try:
        return grant_capability(operator_pubkey, list(KNOWN_SCOPES), type_="admin")
    except Exception as exc:  # noqa: BLE001 - surfaced in the summary
        return {"error": str(exc)}


def _bootstrap_operator_account(
    domain: str,
    operator_pubkey: str,
    username: str = "nostrhost",
) -> dict[str, Any]:
    """Create the default ``nostrhost`` account and link the operator identity.

    Runs during postinstall (full root privileges, outside the identityd's
    locked-down namespace): creates the ``nostrhost`` YunoHost account
    (generated password — never used for login, the portal is passwordless)
    flagged as an admin, then publishes a kind-31102 identity event binding
    the operator pubkey to it. ``nostr-identityd`` materialises just the link
    (the account already exists). This is what makes the "sign in once" flow
    work out of the box: the operator logs in at the portal with their nsec
    and the admin console recognises them.
    """
    import secrets as _secrets

    from yunohost.user import user_list, user_create, user_group_list

    if username not in user_list()["users"]:
        password = _secrets.token_urlsafe(24) + "Aa1!"
        user_create(
            username=username,
            domain=domain,
            password=password,
            fullname="NostrHost operator",
            admin=True,
        )

    # user_create(admin=True) is supposed to land the operator in both
    # 'admins' and 'all_users' (yunohost.user.user_create -> user_group_update).
    # That used to be able to fail silently if the real /etc/group mutation
    # raised before the native store write (see accounts.add_real_user_to_group);
    # don't let a bootstrap that never actually happened report success.
    groups = user_group_list()["groups"]
    for required_group in ("admins", "all_users"):
        members = groups.get(required_group, {}).get("members", [])
        if username not in members:
            raise NostrHostError(
                f"postinstall bootstrap failed: '{username}' was not added to "
                f"the '{required_group}' group (expected after user_create "
                "with admin=True)"
            )

    event = link_identity(
        username,
        operator_pubkey,
        signer_type="nip07",
        label="operator",
        admin=True,
    )
    return {"username": username, "pubkey": operator_pubkey, "event": event.get("id")}


def _postinstall_new(domain: str | None, admin_npub: str | None, force: bool) -> dict[str, Any]:
    """Fresh bootstrap: generate the node identity, stand up the native stack
    and record state S0. This is the canonical first-run path (the legacy
    interactive tools_postinstall wizard is not involved)."""
    from yunohost.nostr_identity import _init_headless_yunohost, bootstrap_node
    from yunohost.nostr_state import (
        StateRepo,
        YunohostBackend,
        announce_state_repository,
        export_state,
        state_dir_from_env,
    )

    if os.geteuid() != 0:
        raise NostrHostError("postinstall must be run as root")
    if Path(INSTALLED_MARKER).exists() and not force:
        raise NostrHostError(
            f"{INSTALLED_MARKER} exists — the node is already postinstalled "
            "(pass --force to re-run)"
        )

    _init_headless_yunohost()
    domain = domain or socket.getfqdn()

    boot = bootstrap_node(admins=[admin_npub] if admin_npub else None, force=force, write_relay=RELAY_CONFIG)
    operator_npub = _npub(boot["operator_pubkey"])
    _prepare_node(domain, operator_npub)

    _render_notify_config(boot["notifier_sk"], boot["control_relay"])
    _render_catalogue_env(boot["publisher_pubkey"])
    recovery_path = _render_keys_recovery(boot)
    try:
        _provision_restic()
    except Exception as exc:  # noqa: BLE001 - non-fatal; surfaced in the summary
        restic_error = str(exc)
    else:
        restic_error = ""

    failed = _enable_postinstall_daemons()
    _trust_caddy_internal_ca()
    grant = _publish_initial_capability(boot["operator_pubkey"])
    operator_account = _bootstrap_operator_account(domain, boot["operator_pubkey"])

    repo = StateRepo(state_dir_from_env(), boot["server_pubkey"])
    tree = export_state(YunohostBackend())
    rev = repo.commit(tree, known_good=True, health="passed", message="initial state (postinstall --new)")

    announce: dict[str, Any] | str | None = None
    try:
        announce_state_repository()
        announce = "published"
    except Exception as exc:  # noqa: BLE001 - non-fatal
        announce = str(exc)

    bundle: dict[str, Any] | str | None = None
    try:
        from yunohost.nostr_state import publish_state_bundle

        publish_state_bundle()
        bundle = "published"
    except Exception as exc:  # noqa: BLE001 - non-fatal
        bundle = str(exc)

    Path(INSTALLED_MARKER).touch()

    return {
        "domain": domain,
        "operator_npub": operator_npub,
        "operator_pubkey": boot["operator_pubkey"],
        "server_npub": _npub(boot["server_pubkey"]),
        "publisher_npub": _npub(boot["publisher_pubkey"]),
        "notifier_npub": _npub(boot["notifier_pubkey"]),
        "control_relay": boot["control_relay"],
        "state_revision": rev[:16],
        "state_bundle": bundle,
        "policy_file": POLICY_CONFIG,
        "relay_config": RELAY_CONFIG,
        "notify_config": NOTIFY_CONFIG,
        "catalogue_env": CATALOGUE_ENV,
        "restic_config": RESTIC_CONFIG if not restic_error else f"error: {restic_error}",
        "keys_recovery": str(recovery_path),
        "recovery": _recovery_bundle(boot),
        "state_announcement": announce,
        "capability_grant": "ok" if isinstance(grant, dict) and "error" not in grant else str(grant or ""),
        "operator_account": operator_account.get("username", "error")
        if "error" not in operator_account
        else f"error: {operator_account['error']}",
        "daemons_failed": failed or "none",
        "note": "The operator key is linked to the default 'admin' account (portal "
        "login with the operator nsec). The recovery bundle above is shown ONCE - "
        "back it up offline (nsec1 keys). "
        "The optional agent remains unconfigured; install it separately, then run `nostrhost agent init`.",
        "agent": "optional agent not configured; no agent identity or relay grant was created",
    }


def _postinstall_restore(
    operator_sk: str,
    server_sk: str,
    notice_sk: str,
    publisher_sk: str,
    notifier_sk: str,
    domain: str | None,
    bundle: Path | None,
    state_relay: str | None,
    restic: str | None,
    force: bool,
    keys_file: Path | None = None,
) -> dict[str, Any]:
    """Restore a node from its state repository: recover the identity, restore
    the known-good state (bundle or discovered/cloned repo), restore the
    linked Restic data snapshot, reconcile, and stand the stack back up.

    All five node keys are required explicitly (or via ``--keys-file``) —
    they are never recovered from ngit state (secrets do not live there).
    """
    from yunohost.nostr_identity import _init_headless_yunohost, bootstrap_node
    from yunohost.nostr_operationsd import YnhExecutorBackend
    from yunohost.nostr_restic import ResticError, restic_client
    from yunohost.nostr_state import (
        StateRepo,
        YunohostBackend,
        announce_state_repository,
        apply_reconciliation_plan,
        clone_state_repository,
        export_state,
        state_dir_from_env,
    )

    if os.geteuid() != 0:
        raise NostrHostError("postinstall must be run as root")
    keys = _load_keys_file(keys_file) if keys_file is not None else {
        k: v for k, v in {
            "operator_sk": operator_sk,
            "server_sk": server_sk,
            "notice_sk": notice_sk,
            "publisher_sk": publisher_sk,
            "notifier_sk": notifier_sk,
        }.items() if v
    }
    missing = [k for k in ("operator_sk", "server_sk", "notice_sk", "publisher_sk", "notifier_sk") if k not in keys]
    if missing:
        raise NostrHostError(
            "restore requires every node key: --operator-sk, --server-sk, --notice-sk, "
            f"--publisher-sk, --notifier-sk (or --keys-file). Missing: {', '.join(missing)}"
        )
    operator_sk, server_sk = _normalize_sk(keys["operator_sk"]), _normalize_sk(keys["server_sk"])
    notice_sk, publisher_sk, notifier_sk = (
        _normalize_sk(keys["notice_sk"]),
        _normalize_sk(keys["publisher_sk"]),
        _normalize_sk(keys["notifier_sk"]),
    )
    if bundle is None and not state_relay:
        raise NostrHostError("restore needs a state source: --bundle PATH or --state-relay URL")
    if Path(INSTALLED_MARKER).exists() and not force:
        raise NostrHostError(
            f"{INSTALLED_MARKER} exists — the node is already postinstalled "
            "(pass --force to re-run)"
        )

    _init_headless_yunohost()
    domain = domain or socket.getfqdn()

    boot = bootstrap_node(
        operator_sk=operator_sk,
        server_sk=server_sk,
        notice_sk=notice_sk,
        publisher_sk=publisher_sk,
        notifier_sk=notifier_sk,
        force=force,
        write_relay=RELAY_CONFIG,
    )
    _prepare_node(domain, _npub(boot["operator_pubkey"]))
    _render_notify_config(boot["notifier_sk"], boot["control_relay"])
    _render_catalogue_env(boot["publisher_pubkey"])

    # restore the state repository
    state_dir = state_dir_from_env()
    if bundle is not None:
        StateRepo.verify_bundle(bundle)
        restored = StateRepo.restore_bundle(bundle, state_dir)
        repo = StateRepo(restored, boot["server_pubkey"])
        restored_from = f"bundle:{bundle}"
    else:
        assert state_relay is not None
        clone_state_repository(state_relay, server_pubkey=boot["server_pubkey"], destination=state_dir)
        repo = StateRepo(state_dir, boot["server_pubkey"])
        restored_from = f"relay:{state_relay}"

    target = repo.known_good_revision() or repo.revision()
    if not target:
        raise NostrHostError("restored state repository has no revisions to restore")

    manifest = repo.manifest_for(target)
    snapshot_id = restic or manifest.get("restic_snapshot") or ""
    data_restore: dict[str, Any] = {"snapshot": snapshot_id or "none"}
    if snapshot_id:
        try:
            restic_client().restore(snapshot_id, target=None)
            data_restore["status"] = "restored"
        except (ResticError, Exception) as exc:  # noqa: BLE001 - report, do not abort
            data_restore["status"] = "failed"
            data_restore["error"] = str(exc)

    failed = _enable_postinstall_daemons()
    _trust_caddy_internal_ca()
    grant = _publish_initial_capability(boot["operator_pubkey"])

    # reconcile: converge live state to the restored desired state (bounded)
    reconcile: dict[str, Any] = {"target": target[:16]}
    try:
        plan = repo.reconciliation_plan(export_state(YunohostBackend()))
        report = apply_reconciliation_plan(plan, backend=YnhExecutorBackend(), approve=True, repo=repo)
        reconcile["changes"] = sum(1 for row in report if row["status"] == "executed")
        reconcile["report"] = report
    except Exception as exc:  # noqa: BLE001 - report, do not abort
        reconcile["error"] = str(exc)

    announce: dict[str, Any] | str | None = None
    try:
        announce_state_repository()
        announce = "published"
    except Exception as exc:  # noqa: BLE001 - non-fatal
        announce = str(exc)

    bundle: dict[str, Any] | str | None = None
    try:
        from yunohost.nostr_state import publish_state_bundle

        publish_state_bundle()
        bundle = "published"
    except Exception as exc:  # noqa: BLE001 - non-fatal
        bundle = str(exc)

    rev = repo.commit(
        export_state(YunohostBackend()),
        known_good=False,
        health="passed",
        restic_snapshot=snapshot_id,
        message=f"post-restore reconcile from {restored_from}",
    )
    Path(INSTALLED_MARKER).touch()

    return {
        "domain": domain,
        "restored_from": restored_from,
        "operator_npub": _npub(boot["operator_pubkey"]),
        "operator_pubkey": boot["operator_pubkey"],
        "server_npub": _npub(boot["server_pubkey"]),
        "publisher_npub": _npub(boot["publisher_pubkey"]),
        "notifier_npub": _npub(boot["notifier_pubkey"]),
        "restored_revision": target[:16],
        "data_restore": data_restore,
        "reconcile": reconcile,
        "state_revision": rev[:16],
        "state_bundle": bundle,
        "policy_file": POLICY_CONFIG,
        "notify_config": NOTIFY_CONFIG,
        "catalogue_env": CATALOGUE_ENV,
        "state_announcement": announce,
        "capability_grant": "ok" if isinstance(grant, dict) and "error" not in grant else str(grant or ""),
        "daemons_failed": failed or "none",
        "agent": "optional agent not configured; no agent identity or relay grant was created",
    }


def _postinstall_status() -> dict[str, Any]:
    from yunohost.nostr_identity import is_bootstrapped
    from yunohost.nostr_state import StateRepo, state_dir_from_env

    bootstrapped = is_bootstrapped()
    state_dir = state_dir_from_env()
    revision = ""
    known_good = ""
    if bootstrapped and state_dir.exists():
        from yunohost.nostr_identity import _operator_config

        cfg = _operator_config()
        repo = StateRepo(state_dir, cfg.server_pubkey)
        revision = repo.revision()[:16] or ""
        known_good = repo.known_good_revision()[:16] or ""
    return {
        "installed": Path(INSTALLED_MARKER).exists(),
        "bootstrapped": bootstrapped,
        "operator_config": OPERATOR_CONFIG if bootstrapped else None,
        "state_revision": revision or None,
        "known_good": known_good or None,
    }


def build_app(*, prog: str = "nostrhost", state: _State | None = None) -> typer.Typer:
    app = typer.Typer(name=prog, help=DESCRIPTION, no_args_is_help=True)
    state = state or _State()

    @app.callback()
    def _root(
        output_as: str = typer.Option(None, "--output-as", help="Output result in another format (json/plain/none)"),
        debug: bool = typer.Option(False, "--debug", help="Enable debug output"),
        control_relay: str = typer.Option(None, "--control-relay", help="Nostr control relay URL"),
        operator_sk: str = typer.Option(None, "--operator-sk", help="operator secret key (hex)"),
        admin_sk: str = typer.Option(None, "--admin-sk", help="admin secret key (hex)"),
    ) -> None:
        state.output_as = output_as
        state.debug = debug
        state.control_relay = control_relay
        state.operator_sk = operator_sk
        state.admin_sk = admin_sk

    def _emit(result: Any, output_as: str | None = None) -> None:
        ui.format_result(result, output_as or state.output_as)

    def _guard(fn: Callable[[], Any], output_as: str | None = None) -> None:
        try:
            _emit(fn(), output_as)
        except (NostrHostError, OperationError, IdentityError) as exc:
            _print_error(exc)
            raise typer.Exit(EXIT_ERR)
        except Exception as exc:  # noqa: BLE001 - CLI is the last error boundary
            _print_error(exc)
            raise typer.Exit(EXIT_ERR)

    def _forward(tool: str, args: dict[str, Any], output_as: str | None = None) -> None:
        """Run a command whose entire body is a read-only forward to
        `_run_tool` with the command's own options passed straight through,
        under the same error handling as `_guard`. A command with any extra
        logic (building the args dict conditionally, calling `_run_lifecycle`,
        post-processing the result, ...) calls `_guard` directly instead."""
        _guard(lambda: _run_tool(tool, args), output_as)

    # -- system -------------------------------------------------------------

    system = typer.Typer(name="system", help="system information", no_args_is_help=True)

    @system.command("version")
    def system_version(output_as: str = typer.Option(None, "--output-as")) -> None:
        """Read-only OS/package version information."""
        _forward("system.version", {}, output_as)

    @system.command("regen-conf")
    def system_regen_conf(
        names: str = typer.Option("", "--names", help="comma-separated regenconf categories (default: all)"),
        force: bool = typer.Option(False, "--force", help="override manual modifications"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Regenerate system configuration files (regenconf categories).

        Used by the package upgrade path and available to operators; renders
        pending tracked config (base Caddyfile, per-domain snippets, and the
        YunoHost compatibility categories) from the current templates."""
        from yunohost.tools import tools_regen_conf

        def run() -> Any:
            from yunohost.nostr_identity import _init_headless_yunohost

            # tools_regen_conf drives YunoHost's operation logger, which
            # reads Moulinette.interface.type; the headless init registers
            # the CLI interface (moulinette itself was retired).
            _init_headless_yunohost()
            categories = [item.strip() for item in names.split(",") if item.strip()]
            return tools_regen_conf(names=categories, force=force)

        _guard(run, output_as)

    @system.command("migrations")
    def system_migrations(
        pending: bool = typer.Option(False, "--pending", help="only pending migrations"),
        done: bool = typer.Option(False, "--done", help="only done migrations"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """List known migrations (pending/done filters) and their recorded state."""
        _forward("system.migrations", {"pending": pending, "done": done}, output_as)

    @system.command("migrate")
    def system_migrate(
        targets: str = typer.Option("", "--targets", help="comma-separated migration ids (default: all pending)"),
        skip: bool = typer.Option(False, "--skip", help="skip the named migrations"),
        auto: bool = typer.Option(False, "--auto", help="run migrations non-interactively"),
        force_rerun: bool = typer.Option(False, "--force-rerun", help="force re-running already-run migrations"),
        accept_disclaimer: bool = typer.Option(False, "--accept-disclaimer", help="accept migration disclaimers"),
        skip_postmigrations: bool = typer.Option(False, "--skip-postmigrations", help="do not run post-migration hooks"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Run/skip/force-rerun YunoHost migrations (write op, owner co-signature)."""
        def run() -> Any:
            target_list = [item.strip() for item in targets.split(",") if item.strip()]
            body = _run_lifecycle(
                "system.migrate",
                {"targets": target_list, "skip": skip, "auto": auto, "force_rerun": force_rerun, "accept_disclaimer": accept_disclaimer, "skip_postmigrations": skip_postmigrations},
                state=state,
            )
            if not body.get("ok"):
                raise NostrHostError(f"system.migrate rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    # -- service ------------------------------------------------------------

    service = typer.Typer(name="service", help="service management", no_args_is_help=True)

    @service.command("status")
    def service_status(
        names: list[str] = typer.Argument(None, help="service names (default: all)"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Status of running services."""
        _forward("service.status", {"names": names} if names else {}, output_as)

    @service.command("restart")
    def service_restart(
        name: str = typer.Argument(..., help="service name"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Restart one named service (write operation)."""
        _forward("service.restart", {"name": name}, output_as)

    @service.command("control")
    def service_control(
        name: str = typer.Argument(..., help="service name"),
        action: str = typer.Argument(..., help="start | stop | restart"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Start/stop/restart one named service (write operation)."""
        _forward("service.control", {"name": name, "action": action}, output_as)

    @service.command("history")
    def service_history(
        names: list[str] = typer.Argument(..., help="service names"),
        lines: int = typer.Option(50, "--lines", help="journal lines for recent errors"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """systemd state + restart history for one or more services."""
        _forward("service.history", {"names": names, "lines": lines}, output_as)

    # -- app ----------------------------------------------------------------

    app_group = typer.Typer(name="app", help="application management", no_args_is_help=True)

    @app_group.command("list")
    def app_list(output_as: str = typer.Option(None, "--output-as")) -> None:
        """List installed applications."""
        _forward("app.list", {}, output_as)

    @app_group.command("install")
    def app_install(
        coordinate: str = typer.Argument(..., help="catalogue app id (coordinate)"),
        source: Path = typer.Option(None, "--source", help="local checkout/dir containing package.toml, or the file itself"),
        repository: str = typer.Option(None, "--repository", help="override the catalogue git repository"),
        revision: str = typer.Option(None, "--revision", help="override the catalogue git revision"),
        package_path: str = typer.Option(None, "--package-path", help="override the catalogue package.toml path"),
        manifest_sha256: str = typer.Option(None, "--manifest-sha256", help="override the expected manifest sha256"),
        domain: str = typer.Option(None, "--domain", help="install-time override for [web].domain"),
        path: str = typer.Option(None, "--path", help="install-time override for [web].path"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Install a native app through the signed operation chain.

        Resolves the catalogue coordinate, fetches and verifies package.toml
        (manifest_sha256), plans the resource-engine operations and runs them
        through the signed request -> policy -> approval -> execute chain.

        --domain/--path let one package.toml be installed on whichever domain
        and URL path the operator chooses, rather than the package hardcoding
        one — applied only after manifest_sha256 verification, so they can
        never be used to forge what the catalogue actually signed.
        """
        def run() -> Any:
            resolved = _coordinate_for(coordinate, repository=repository, revision=revision, package_path=package_path, manifest_sha256=manifest_sha256)
            package_data = _load_package_data(source, resolved)
            _verify_package(package_data, resolved)
            package_data = _apply_web_overrides(package_data, domain=domain, path=path)
            envelope = _plan_envelope(package_data, resolved)
            body = _run_lifecycle("package.reconcile", {"plan": envelope}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"install rejected: {body.get('reason') or body.get('state')}")
            return _lifecycle_report("installed", envelope, body)
        _guard(run, output_as)

    @app_group.command("upgrade")
    def app_upgrade(
        coordinate: str = typer.Argument(..., help="catalogue app id (coordinate)"),
        source: Path = typer.Option(None, "--source", help="local checkout/dir containing package.toml, or the file itself"),
        repository: str = typer.Option(None, "--repository", help="override the catalogue git repository"),
        revision: str = typer.Option(None, "--revision", help="override the catalogue git revision"),
        package_path: str = typer.Option(None, "--package-path", help="override the catalogue package.toml path"),
        manifest_sha256: str = typer.Option(None, "--manifest-sha256", help="override the expected manifest sha256"),
        domain: str = typer.Option(None, "--domain", help="override [web].domain for this upgrade (default: keep the currently installed domain)"),
        path: str = typer.Option(None, "--path", help="override [web].path for this upgrade (default: keep the currently installed path)"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Upgrade a native app to the resolved catalogue version.

        Conservative by construction: the resource engine re-applies only the
        operations whose current state no longer satisfies the new manifest,
        so data resources are left alone unless the manifest changes them.

        An upgrade never moves the app: package.toml is reloaded fresh from
        source on every upgrade, so without this, whatever [web].domain/path
        it happens to declare (a placeholder, or just a different value than
        what --domain/--path set at install time) would silently overwrite
        the live route. --domain/--path here default to the currently
        installed values; pass them explicitly only to combine an upgrade
        with a deliberate move (ordinary moves should use `app change-url`).
        """
        def run() -> Any:
            installed = _installed_manifest(coordinate)
            resolved = _coordinate_for(coordinate, repository=repository, revision=revision, package_path=package_path, manifest_sha256=manifest_sha256)
            package_data = _load_package_data(source, resolved)
            _verify_package(package_data, resolved)
            installed_web = installed.get("web") or {}
            package_data = _apply_web_overrides(
                package_data,
                domain=domain or installed_web.get("domain"),
                path=path or installed_web.get("path"),
            )
            from nostrhost.app_management import carry_forward_compatible_settings

            package_data = carry_forward_compatible_settings(installed, package_data)
            envelope = _plan_envelope(package_data, resolved)
            body = _run_lifecycle("package.reconcile", {"plan": envelope}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"upgrade rejected: {body.get('reason') or body.get('state')}")
            previous = (installed.get("app") or {}).get("version")
            return _lifecycle_report("upgraded", envelope, body, previous=previous)
        _guard(run, output_as)

    @app_group.command("remove")
    def app_remove(
        app: str = typer.Argument(..., help="app id"),
        purge: bool = typer.Option(False, "--purge", help="purge app data (legacy fallback only)"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Remove one installed app.

        Native apps are removed by reversing their recorded manifest through
        the signed chain (plan_package_removal); apps without a recorded
        native manifest fall back to the legacy removal tool.
        """
        def run() -> Any:
            from nostrhost.native_providers import installed_package_manifest

            manifest = installed_package_manifest(app)
            if manifest is None:
                return _run_tool("app.remove", {"app": app, "purge": purge})
            envelope = _removal_envelope(manifest)
            body = _run_lifecycle("package.reconcile", {"plan": envelope}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"removal rejected: {body.get('reason') or body.get('state')}")
            return _lifecycle_report("removed", envelope, body)
        _guard(run, output_as)

    @app_group.command("change-url")
    def app_change_url(
        app: str = typer.Argument(..., help="app id"),
        domain: str = typer.Option(None, "--domain", help="new domain"),
        path: str = typer.Option(None, "--path", help="new URL path (must start with '/')"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Move an app to a new domain and/or URL path (Caddy route update)."""
        def run() -> Any:
            if not domain and not path:
                raise NostrHostError("change-url requires --domain and/or --path")
            installed = _installed_manifest(app)
            envelope = _web_change_envelope(app, installed, domain, path)
            body = _run_lifecycle("package.reconcile", {"plan": envelope}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"change-url rejected: {body.get('reason') or body.get('state')}")
            return _lifecycle_report("change-url", envelope, body)
        _guard(run, output_as)

    @app_group.command("reconcile-routes")
    def app_reconcile_routes(output_as: str = typer.Option(None, "--output-as")) -> None:
        """Re-apply every installed native app's Caddy route (best-effort).

        Native web routes are pushed only through Caddy's admin API and are
        never written to disk, so any Caddy restart for any reason (a
        package upgrade that ships caddy.service and gets restarted by
        debhelper, a manual `systemctl restart caddy`, a crash-restart, a
        reboot) drops every installed native app back to the bare
        per-domain stub until something replays its route. This is that
        replay step, intended to run automatically via
        nostrhost-web-reconcile.service (After=caddy.service, wanted by
        caddy.service itself) rather than by hand.

        Reconciles each app's FULL stored manifest, not just its [web]
        resource: the resource engine already no-ops every operation whose
        current state still matches, so in practice this only re-applies
        what Caddy actually lost (route, permission, health check) — no
        riskier than re-running `app install` for every installed app.
        Failures are per-app and do not stop the rest from reconciling.
        """
        def run() -> Any:
            results: dict[str, Any] = {}
            for app_id, manifest in _iter_installed_manifests():
                if not isinstance(manifest.get("web"), dict):
                    continue  # nothing to reconcile for a routeless package
                try:
                    envelope = _plan_envelope(manifest, None)
                    body = _run_lifecycle("package.reconcile", {"plan": envelope}, state=state)
                    results[app_id] = {"ok": bool(body.get("ok")), "reason": body.get("reason") or body.get("state")}
                except Exception as exc:  # noqa: BLE001 - best-effort across every installed app
                    results[app_id] = {"ok": False, "error": str(exc)}
            return {"reconciled": results}
        _guard(run, output_as)

    @app_group.command("backup")
    def app_backup(
        app: str = typer.Argument(..., help="app id"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Back up an installed native app's declared paths (Restic snapshot)."""
        def run() -> Any:
            paths = _app_backup_paths(app)
            snapshot = _restic_client().snapshot(paths, tag=app)
            return {"app": app, "paths": paths, "snapshot": snapshot}
        _guard(run, output_as)

    @app_group.command("restore")
    def app_restore(
        app: str = typer.Argument(..., help="app id"),
        snapshot: str = typer.Argument(..., help="Restic snapshot id to restore"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Restore an installed native app's data from a Restic snapshot."""
        def run() -> Any:
            paths = _app_backup_paths(app)
            client = _restic_client()
            return {"app": app, "snapshot": snapshot, "paths": paths, "result": client.restore(snapshot, "/", include=paths)}
        _guard(run, output_as)

    # -- backup -----------------------------------------------------------

    backup = typer.Typer(name="backup", help="host backup (Restic + state)", no_args_is_help=True)

    @backup.command("create")
    def backup_create(output_as: str = typer.Option(None, "--output-as")) -> None:
        """Create a full host Restic snapshot (satisfies policy backup gates)."""
        def run() -> Any:
            client = _restic_client()
            snapshot = client.snapshot(list(SYSTEM_BACKUP_PATHS))
            return {"snapshot": snapshot, "paths": list(SYSTEM_BACKUP_PATHS)}
        _guard(run, output_as)

    @backup.command("list")
    def backup_list(output_as: str = typer.Option(None, "--output-as")) -> None:
        """List Restic snapshots on this host."""
        def run() -> Any:
            return {"snapshots": _restic_client().snapshots()}
        _guard(run, output_as)

    @backup.command("delete")
    def backup_delete(
        name: str = typer.Argument(..., help="local backup archive name to delete"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Delete one local backup archive (write op, owner co-signature)."""
        def run() -> Any:
            body = _run_lifecycle("backup.delete", {"name": name}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"backup.delete rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    # -- domain -------------------------------------------------------------

    domain = typer.Typer(name="domain", help="native domain management", no_args_is_help=True)

    @domain.command("list")
    def domain_list(output_as: str = typer.Option(None, "--output-as")) -> None:
        """List registered native domains."""
        _forward("domain.list", {}, output_as)

    @domain.command("inspect")
    def domain_inspect(
        name: str = typer.Argument(..., help="domain name"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Inspect a native domain: intent, desired/actual DNS, diff, routes."""
        _forward("domain.inspect", {"domain": name}, output_as)

    @domain.command("add")
    def domain_add(
        name: str = typer.Argument(..., help="domain name"),
        provider_type: str = typer.Option("manual", "--provider-type", help="dns provider (manual or cloudflare)"),
        provider_zone: str = typer.Option(None, "--provider-zone", help="override the authoritative zone"),
        credential: str = typer.Option(None, "--credential", help="secret:dns/<provider>/<name> credential ref (cloudflare)"),
        primary: bool = typer.Option(False, "--primary", help="mark as the primary domain"),
        ipv4: bool = typer.Option(True, "--ipv4/--no-ipv4", help="manage A records"),
        ipv6: bool = typer.Option(True, "--ipv6/--no-ipv6", help="manage AAAA records"),
        wildcard: bool = typer.Option(True, "--wildcard/--no-wildcard", help="manage wildcard A/AAAA records"),
        nip05: bool = typer.Option(False, "--nip05", help="serve .well-known/nostr.json on this domain"),
        caa: str = typer.Option(None, "--caa", help="CAA issuer(s), comma-separated (e.g. letsencrypt.org)"),
        apply_dns: bool = typer.Option(True, "--apply/--no-apply", help="apply the DNS plan (default: yes)"),
        verify: bool = typer.Option(True, "--verify/--no-verify", help="verify DNS after apply"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Register a native domain through the signed chain.

        Plans DNS for the domain, applies it via its provider, stands up
        Caddy (root site + optional NIP-05 route) and records state.
        """
        def run() -> Any:
            body = _run_lifecycle(
                "domain.add",
                {
                    "domain": name,
                    "provider_type": provider_type,
                    "provider_zone": provider_zone,
                    "credential": credential,
                    "primary": primary,
                    "ipv4": ipv4,
                    "ipv6": ipv6,
                    "wildcard": wildcard,
                    "nip05": nip05,
                    "tls_caa": [c.strip() for c in caa.split(",") if c.strip()] if caa else None,
                    "apply_dns": apply_dns,
                    "verify": verify,
                },
                state=state,
            )
            if not body.get("ok"):
                raise NostrHostError(f"domain.add rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @domain.command("remove")
    def domain_remove(
        name: str = typer.Argument(..., help="domain name"),
        force: bool = typer.Option(False, "--force", help="remove even if apps still use it"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Remove a native domain through the signed chain.

        Blocks while native apps still use the domain; deletes only
        NostrHost-owned DNS records and drops the Caddy routes.
        """
        def run() -> Any:
            body = _run_lifecycle("domain.remove", {"domain": name, "force": force}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"domain.remove rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @domain.command("cert-info")
    def domain_cert_info(
        name: str = typer.Argument(..., help="domain name"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Read-only certificate status for an already-registered domain."""
        _forward("domain.cert.info", {"domain": name}, output_as)

    @domain.command("cert-install")
    def domain_cert_install(
        name: str = typer.Argument(..., help="domain name"),
        letsencrypt: bool = typer.Option(True, "--letsencrypt/--self-signed", help="request a real Let's Encrypt certificate"),
        staging: bool = typer.Option(False, "--staging", help="rejected: this YunoHost has no ACME staging endpoint"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Issue/renew a certificate for an already-registered domain (write op)."""
        def run() -> Any:
            body = _run_lifecycle("domain.cert.install", {"domain": name, "letsencrypt": letsencrypt, "staging": staging}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"domain.cert.install rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    # -- dns ----------------------------------------------------------------

    dns = typer.Typer(name="dns", help="native DNS reconciliation", no_args_is_help=True)

    @dns.command("plan")
    def dns_plan(
        name: str = typer.Argument(..., help="domain name"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Compute the desired-vs-actual DNS plan for a domain (no changes)."""
        _forward("dns.plan", {"domain": name}, output_as)

    @dns.command("apply")
    def dns_apply(
        name: str = typer.Argument(..., help="domain name"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Apply the DNS plan for a domain through its provider (write op)."""
        def run() -> Any:
            body = _run_lifecycle("dns.apply", {"domain": name}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"dns.apply rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @dns.command("verify")
    def dns_verify(
        name: str = typer.Argument(..., help="domain name"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Verify a domain's DNS records resolve."""
        _forward("dns.verify", {"domain": name}, output_as)

    @dns.command("watch")
    def dns_watch(output_as: str = typer.Option(None, "--output-as")) -> None:
        """DDNS watcher status: last-seen public IPs and dynamic domains."""
        _forward("dns.watch", {}, output_as)

    @dns.command("subscribe")
    def dns_subscribe(
        hostname: str = typer.Argument(..., help="free hostname to claim, a <label> under nohost.me / noho.st / ynh.fr"),
        secret: str = typer.Option(None, "--secret", help="TSIG secret to provision (default: generated)"),
        rotate: bool = typer.Option(False, "--rotate", help="regenerate the TSIG secret on re-subscribe"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Claim a nostr-native free hostname: the operator identity signs the
        ownership claim and the TSIG secret goes into the credential broker."""
        def run() -> Any:
            body = _run_lifecycle("dns.subscribe", {"hostname": hostname, "secret": secret, "rotate": rotate}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"dns.subscribe rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            result = body.get("result") or body
            return {
                "hostname": result.get("hostname"),
                "zone": result.get("zone"),
                "pubkey": result.get("pubkey"),
                "claim_id": result.get("claim_id"),
                "secret_ref": result.get("secret_ref"),
                "next": result.get("next"),
            }
        _guard(run, output_as)

    @dns.command("subscriptions")
    def dns_subscriptions(output_as: str = typer.Option(None, "--output-as")) -> None:
        """List nostr-native free-hostname subscriptions (identity claims)."""
        _forward("dns.subscriptions", {}, output_as)

    @dns.command("unsubscribe")
    def dns_unsubscribe(
        hostname: str = typer.Argument(..., help="free hostname to release"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Release a nostr-native free-hostname subscription and drop its
        broker secret."""
        def run() -> Any:
            body = _run_lifecycle("dns.unsubscribe", {"hostname": hostname}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"dns.unsubscribe rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            result = body.get("result") or body
            return {"hostname": result.get("hostname"), "secret_ref": result.get("secret_ref"), "unsubscribed": result.get("unsubscribed")}
        _guard(run, output_as)

    # -- catalogue -----------------------------------------------------------

    catalog = typer.Typer(name="catalog", help="native catalogue (trusted projection + publish)", no_args_is_help=True)

    @catalog.command("list")
    def catalog_list(output_as: str = typer.Option(None, "--output-as")) -> None:
        """List the trusted native catalogue projection."""
        _forward("catalog.list", {}, output_as)

    @catalog.command("get")
    def catalog_get(
        app_id: str = typer.Argument(..., help="app id to resolve"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Resolve one app from the trusted projection."""
        _forward("catalog.get", {"app_id": app_id}, output_as)

    @catalog.command("publish")
    def catalog_publish(
        app_id: str = typer.Argument(..., help="app id to re-declare under the node's publisher key"),
        relays: str = typer.Option("ws://127.0.0.1:4848", "--relays", help="comma-separated relay URLs"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Publish a catalogue declaration for a trusted app (signed with the node publisher key)."""
        def run() -> Any:
            body = _run_lifecycle("catalog.publish", {"app_id": app_id, "relays": relays}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"catalog.publish rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @catalog.command("verify")
    def catalog_verify(
        event: str = typer.Argument(..., help="JSON Nostr declaration event to verify"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Verify a catalogue declaration event (id, signature, schema, trusted publisher)."""
        _forward("catalog.verify", {"event_or_naddr": event}, output_as)

    # -- updates ------------------------------------------------------------

    updates = typer.Typer(name="updates", help="update metadata (check + refresh)", no_args_is_help=True)

    @updates.command("check")
    def updates_check(output_as: str = typer.Option(None, "--output-as")) -> None:
        """Pending app/system updates, from cache only (no network refresh)."""
        _forward("updates.check", {}, output_as)

    @updates.command("refresh")
    def updates_refresh(
        target: str = typer.Option("apps", "--target", help="apps | system | all"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Refresh cached update metadata (apt cache, app catalog sources)."""
        _forward("updates.refresh", {"target": target}, output_as)

    # -- nsites ------------------------------------------------------------

    nsite = typer.Typer(name="nsite", help="NIP-5A nsite gateway (Phase 1)", no_args_is_help=True)

    @nsite.command("status")
    def nsite_status(output_as: str = typer.Option(None, "--output-as")) -> None:
        """Gateway status: enabled, mode, domain, service health."""
        _forward("nsite.gateway.status", {}, output_as)

    @nsite.command("enable")
    def nsite_enable(
        domain: str = typer.Argument(..., help="registered gateway domain (D2)"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Enable the nsite gateway on a dedicated registered domain."""
        def run() -> Any:
            body = _run_lifecycle("nsite.gateway.enable", {"domain": domain}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"nsite.gateway.enable rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @nsite.command("disable")
    def nsite_disable(output_as: str = typer.Option(None, "--output-as")) -> None:
        """Disable the nsite gateway: stop the unit, remove the Caddy route."""
        def run() -> Any:
            body = _run_lifecycle("nsite.gateway.disable", {}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"nsite.gateway.disable rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @nsite.command("configure")
    def nsite_configure(
        domain: str = typer.Argument(..., help="registered gateway domain (D2)"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Update the nsite gateway config and reload."""
        def run() -> Any:
            body = _run_lifecycle("nsite.gateway.configure", {"domain": domain}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"nsite.gateway.configure rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @nsite.command("list")
    def nsite_list(output_as: str = typer.Option(None, "--output-as")) -> None:
        """Registered sites and the gateway mode."""
        _forward("nsite.list", {}, output_as)

    @nsite.command("inspect")
    def nsite_inspect(
        pubkey: str = typer.Argument(..., help="site owner pubkey (hex or npub)"),
        d: str = typer.Option("", "--d", help="named-site d tag (empty for root)"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """One registered site record."""
        _forward("nsite.inspect", {"pubkey": pubkey, "d": d}, output_as)

    @nsite.command("register")
    def nsite_register(
        pubkey: str = typer.Argument(..., help="site owner pubkey (hex or npub)"),
        kind: int = typer.Option(15128, "--kind", help="15128 (root) or 35128 (named)"),
        d: str = typer.Option("", "--d", help="named-site d tag (empty for root)"),
        title: str = typer.Option("", "--title"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Add a hosted-mode allowlist entry."""
        def run() -> Any:
            body = _run_lifecycle("nsite.register", {"pubkey": pubkey, "kind": kind, "d": d, "title": title}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"nsite.register rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @nsite.command("unregister")
    def nsite_unregister(
        pubkey: str = typer.Argument(..., help="site owner pubkey (hex or npub)"),
        d: str = typer.Option("", "--d", help="named-site d tag (empty for root)"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Remove a hosted-mode allowlist entry."""
        def run() -> Any:
            body = _run_lifecycle("nsite.unregister", {"pubkey": pubkey, "d": d}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"nsite.unregister rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @nsite.command("validate")
    def nsite_validate(
        event_file: str = typer.Argument(..., help="path to a signed manifest JSON"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Validate a candidate manifest event; no network."""
        def run() -> Any:
            return _run_tool("nsite.validate_manifest", {"event": _load_json_file(event_file)})
        _guard(run, output_as)

    @nsite.command("resolve")
    def nsite_resolve(
        label: str = typer.Argument("", help="site label (npub1…, v+50 base36, 50 base36 + d)"),
        pubkey: str = typer.Option("", "--pubkey", help="author pubkey (hex or npub)"),
        d: str = typer.Option("", "--d", help="named-site d tag"),
        relays: str = typer.Option("", "--relays", help="comma-separated lookup relays"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Fetch the current manifest from public relays (read only, bounded)."""
        _guard(
            lambda: _run_tool(
                "nsite.resolve",
                {"label": label, "pubkey": pubkey, "d": d,
                 "relays": [r for r in relays.split(",") if r] or None},
            ),
            output_as,
        )

    @nsite.command("reachability")
    def nsite_reachability(
        relays: str = typer.Option("", "--relays", help="comma-separated relay URLs"),
        servers: str = typer.Option("", "--servers", help="comma-separated blossom server URLs"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Probe relay/server reachability (bounded)."""
        _guard(
            lambda: _run_tool(
                "nsite.reachability",
                {"relays": [r for r in relays.split(",") if r] or None,
                 "servers": [s for s in servers.split(",") if s] or None},
            ),
            output_as,
        )

    @nsite.command("publish-plan")
    def nsite_publish_plan(
        pubkey: str = typer.Argument(..., help="site owner pubkey (hex or npub)"),
        inventory: str = typer.Argument(None, help="path to a JSON blob inventory (omit to use --site)"),
        kind: int = typer.Option(15128, "--kind", help="15128 (root) or 35128 (named)"),
        d: str = typer.Option("", "--d", help="named-site d tag (empty for root)"),
        site: str = typer.Option("", "--site", help="Phase 3b: read the inventory from the server-side draft area"),
        servers: str = typer.Option("", "--servers", help="comma-separated blossom servers"),
        relays: str = typer.Option("", "--relays", help="comma-separated publish relays"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Build the unsigned manifest + plan_sha256 from a blob inventory (or a draft site)."""
        def run() -> Any:
            return _run_tool(
                "nsite.publish.plan",
                {
                    "pubkey": pubkey,
                    "kind": kind,
                    "d": d,
                    "items": _load_json_file(inventory) if inventory else None,
                    "site": site,
                    "servers": [r for r in servers.split(",") if r] or None,
                    "relays": [r for r in relays.split(",") if r] or None,
                },
            )
        _guard(run, output_as)

    @nsite.command("publish")
    def nsite_publish(
        signed_event: str = typer.Argument(..., help="path to the signed manifest JSON"),
        plan: str = typer.Argument(..., help="the plan_sha256 from nsite publish-plan"),
        relays: str = typer.Option("", "--relays", help="comma-separated publish relays"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Verify a signed manifest, broadcast to relays, record the site."""
        def run() -> Any:
            body = _run_lifecycle(
                "nsite.publish",
                {"event": _load_json_file(signed_event), "plan_sha256": plan,
                 "relays": [r for r in relays.split(",") if r] or None},
                state=state,
            )
            if not body.get("ok"):
                raise NostrHostError(f"nsite.publish rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @nsite.command("snapshot")
    def nsite_snapshot(
        signed_event: str = typer.Argument(..., help="path to the signed kind-5128 snapshot JSON"),
        plan: str = typer.Argument("", help="plan/aggregate digest binding"),
        relays: str = typer.Option("", "--relays", help="comma-separated publish relays"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Record a client-signed kind-5128 snapshot of the current manifest."""
        def run() -> Any:
            body = _run_lifecycle(
                "nsite.snapshot",
                {"event": _load_json_file(signed_event), "plan_sha256": plan,
                 "relays": [r for r in relays.split(",") if r] or None},
                state=state,
            )
            if not body.get("ok"):
                raise NostrHostError(f"nsite.snapshot rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @nsite.command("mirror")
    def nsite_mirror(
        pubkey: str = typer.Argument(..., help="site owner pubkey (hex or npub)"),
        d: str = typer.Option("", "--d", help="named-site d tag (empty for root)"),
        servers: str = typer.Option(..., "--servers", help="comma-separated blossom servers"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Re-upload a site's missing blobs to the selected servers from the draft area."""
        def run() -> Any:
            body = _run_lifecycle(
                "nsite.mirror",
                {"pubkey": pubkey, "d": d, "servers": [s for s in servers.split(",") if s]},
                state=state,
            )
            if not body.get("ok"):
                raise NostrHostError(f"nsite.mirror rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @nsite.command("domain-attach")
    def nsite_domain_attach(
        fqdn: str = typer.Argument(..., help="custom FQDN to attach (e.g. example.com)"),
        pubkey: str = typer.Argument(..., help="site owner pubkey (hex or npub)"),
        d: str = typer.Option("", "--d", help="named-site d tag (empty for root)"),
        method: str = typer.Option("cname", "--method", help="ownership proof: cname | txt"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Attach a custom FQDN to a registered site (Phase 4; ownership proof)."""
        def run() -> Any:
            body = _run_lifecycle(
                "nsite.domain.attach",
                {"fqdn": fqdn, "pubkey": pubkey, "d": d, "method": method, "verify": True},
                state=state,
            )
            if not body.get("ok"):
                raise NostrHostError(f"nsite.domain.attach rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @nsite.command("domain-detach")
    def nsite_domain_detach(
        fqdn: str = typer.Argument(..., help="attached custom FQDN to detach"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Detach a custom FQDN: removes the route and the state marker only."""
        def run() -> Any:
            body = _run_lifecycle(
                "nsite.domain.detach",
                {"fqdn": fqdn},
                state=state,
            )
            if not body.get("ok"):
                raise NostrHostError(f"nsite.domain.detach rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @nsite.command("domain-list")
    def nsite_domain_list(output_as: str = typer.Option(None, "--output-as")) -> None:
        """List attached custom domains."""
        _forward("nsite.domain.list", {}, output_as)

    # -- logs ---------------------------------------------------------------

    logs = typer.Typer(name="logs", help="host logs (journal + nginx)", no_args_is_help=True)

    @logs.command("read")
    def logs_read(
        units: list[str] = typer.Argument(..., help="allowlisted journal units (kernel/ssh/fail2ban/nginx/systemd…)"),
        since: str = typer.Option(None, "--since", help="ISO-8601 or relative (e.g. -24h)"),
        until: str = typer.Option(None, "--until", help="ISO-8601 or relative"),
        priority: str = typer.Option(None, "--priority", help="syslog priority or range (e.g. err..emerg)"),
        grep: str = typer.Option(None, "--grep", help="text/regex filter"),
        lines: int = typer.Option(200, "--lines", help="max entries"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Query a deliberately allowlisted set of system journals."""
        _forward("logs.read", {"units": units, "since": since, "until": until, "priority": priority, "grep": grep, "lines": lines}, output_as)

    @logs.command("web")
    def logs_web(
        host: str = typer.Option(None, "--host", help="filter by client host"),
        path: str = typer.Option(None, "--path", help="filter by URL path"),
        status: int = typer.Option(None, "--status", help="filter by HTTP status"),
        since: str = typer.Option(None, "--since", help="ISO-8601 or relative (e.g. -24h)"),
        until: str = typer.Option(None, "--until", help="ISO-8601 or relative"),
        lines: int = typer.Option(200, "--lines", help="max entries"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Read bounded, structured Nginx access/error log records."""
        _forward("logs.web", {"host": host, "path": path, "status": status, "since": since, "until": until, "lines": lines}, output_as)

    @logs.command("problems")
    def logs_problems(
        host: str = typer.Option(None, "--host", help="filter by client host"),
        path: str = typer.Option(None, "--path", help="filter by URL path"),
        status: int = typer.Option(None, "--status", help="filter by HTTP status"),
        code: str = typer.Option(None, "--code", help="filter by error code"),
        kind: str = typer.Option(None, "--kind", help="filter by kind (auth/api_error/operation/unhandled/render/portal/http)"),
        source: str = typer.Option(None, "--source", help="filter by source (api/portal)"),
        request_id: str = typer.Option(None, "--request-id", help="filter by correlation request id"),
        since: str = typer.Option(None, "--since", help="ISO-8601 or relative (e.g. -24h)"),
        until: str = typer.Option(None, "--until", help="ISO-8601 or relative"),
        lines: int = typer.Option(200, "--lines", help="max entries"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Read bounded, structured server problem records (4xx/5xx + unhandled)."""
        _forward(
            "logs.problems",
            {"host": host, "path": path, "status": status, "code": code, "kind": kind, "source": source, "request_id": request_id, "since": since, "until": until, "lines": lines},
            output_as,
        )

    # -- user ---------------------------------------------------------------

    user = typer.Typer(name="user", help="user, group and permission management", no_args_is_help=True)

    @user.command("list")
    def user_list(output_as: str = typer.Option(None, "--output-as")) -> None:
        """List YunoHost user accounts."""
        _forward("user.list", {}, output_as)

    @user.command("create")
    def user_create(
        username: str = typer.Argument(..., help="username"),
        domain: str = typer.Argument(..., help="domain"),
        password: str = typer.Option(..., "--password", help="account password"),
        fullname: str = typer.Option(..., "--fullname", help="full display name"),
        mailbox_quota: str = typer.Option("0", "--mailbox-quota", help="mailbox quota (0 = unlimited)"),
        admin: bool = typer.Option(False, "--admin", help="also grant webadmin/SSH access (owner co-signature)"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Create a YunoHost user account/mailbox (write op)."""
        def run() -> Any:
            body = _run_lifecycle("user.create", {"username": username, "domain": domain, "password": password, "fullname": fullname, "mailbox_quota": mailbox_quota, "admin": admin}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"user.create rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @user.command("update")
    def user_update(
        username: str = typer.Argument(..., help="username"),
        mail: str = typer.Option(None, "--mail", help="new primary email"),
        change_password: str = typer.Option(None, "--password", help="new password"),
        add_mailforward: str = typer.Option(None, "--add-mailforward", help="comma-separated forward addresses to add"),
        remove_mailforward: str = typer.Option(None, "--remove-mailforward", help="comma-separated forward addresses to remove"),
        add_mailalias: str = typer.Option(None, "--add-mailalias", help="comma-separated aliases to add"),
        remove_mailalias: str = typer.Option(None, "--remove-mailalias", help="comma-separated aliases to remove"),
        mailbox_quota: str = typer.Option(None, "--mailbox-quota", help="new mailbox quota"),
        fullname: str = typer.Option(None, "--fullname", help="new full name"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Update an existing user (only the fields passed change; write op)."""
        def run() -> Any:
            args = {"username": username}
            for key, value in (
                ("mail", mail), ("change_password", change_password),
                ("add_mailforward", [i.strip() for i in add_mailforward.split(",")] if add_mailforward else None),
                ("remove_mailforward", [i.strip() for i in remove_mailforward.split(",")] if remove_mailforward else None),
                ("add_mailalias", [i.strip() for i in add_mailalias.split(",")] if add_mailalias else None),
                ("remove_mailalias", [i.strip() for i in remove_mailalias.split(",")] if remove_mailalias else None),
                ("mailbox_quota", mailbox_quota), ("fullname", fullname),
            ):
                if value is not None:
                    args[key] = value
            body = _run_lifecycle("user.update", args, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"user.update rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @user.command("delete")
    def user_delete(
        username: str = typer.Argument(..., help="username"),
        purge: bool = typer.Option(False, "--purge", help="also purge the home directory"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Delete a YunoHost user account (write op, owner co-signature)."""
        def run() -> Any:
            body = _run_lifecycle("user.delete", {"username": username, "purge": purge}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"user.delete rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    user_group = typer.Typer(name="group", help="user group management", no_args_is_help=True)

    @user_group.command("list")
    def user_group_list(output_as: str = typer.Option(None, "--output-as")) -> None:
        """List YunoHost user groups and their members."""
        _forward("user.group.list", {}, output_as)

    @user_group.command("create")
    def user_group_create(
        groupname: str = typer.Argument(..., help="group name"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Create a new user group (write op)."""
        def run() -> Any:
            body = _run_lifecycle("user.group.create", {"groupname": groupname}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"user.group.create rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @user_group.command("update")
    def user_group_update(
        groupname: str = typer.Argument(..., help="group name"),
        add: str = typer.Option(None, "--add", help="comma-separated usernames to add"),
        remove: str = typer.Option(None, "--remove", help="comma-separated usernames to remove"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Add/remove usernames from a group (write op; 'admins' needs owner co-signature)."""
        def run() -> Any:
            args = {"groupname": groupname}
            if add is not None:
                args["add"] = [i.strip() for i in add.split(",") if i.strip()]
            if remove is not None:
                args["remove"] = [i.strip() for i in remove.split(",") if i.strip()]
            body = _run_lifecycle("user.group.update", args, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"user.group.update rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @user_group.command("delete")
    def user_group_delete(
        groupname: str = typer.Argument(..., help="group name"),
        force: bool = typer.Option(False, "--force", help="delete even if it is a primary group"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Delete a user group and its permission grants (write op, owner co-signature)."""
        def run() -> Any:
            body = _run_lifecycle("user.group.delete", {"groupname": groupname, "force": force}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"user.group.delete rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    user_permission = typer.Typer(name="permission", help="app/system permission management", no_args_is_help=True)

    @user_permission.command("list")
    def user_permission_list(output_as: str = typer.Option(None, "--output-as")) -> None:
        """List app/system permissions and allowed users/groups."""
        _forward("user.permission.list", {}, output_as)

    @user_permission.command("info")
    def user_permission_info(
        permission: str = typer.Argument(..., help="permission name (e.g. myapp.main)"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """One permission's full info."""
        _forward("user.permission.info", {"permission": permission}, output_as)

    @user_permission.command("add")
    def user_permission_add(
        permission: str = typer.Argument(..., help="permission name (e.g. myapp.main)"),
        names: list[str] = typer.Argument(..., help="usernames/groups to grant"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Grant users/groups access to an app permission (write op, owner co-signature)."""
        def run() -> Any:
            body = _run_lifecycle("user.permission.add", {"permission": permission, "names": names}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"user.permission.add rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @user_permission.command("remove")
    def user_permission_remove(
        permission: str = typer.Argument(..., help="permission name (e.g. myapp.main)"),
        names: list[str] = typer.Argument(..., help="usernames/groups to revoke"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Revoke users/groups access to an app permission (write op, owner co-signature)."""
        def run() -> Any:
            body = _run_lifecycle("user.permission.remove", {"permission": permission, "names": names}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"user.permission.remove rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @user_permission.command("update")
    def user_permission_update(
        permission: str = typer.Argument(..., help="permission name (e.g. myapp.main)"),
        label: str = typer.Option(None, "--label", help="new display label"),
        show_tile: bool = typer.Option(None, "--show-tile/--hide-tile", help="show/hide the SSO dashboard tile"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Update a permission's label/tile visibility (write op, owner co-signature)."""
        def run() -> Any:
            args = {"permission": permission}
            if label is not None:
                args["label"] = label
            if show_tile is not None:
                args["show_tile"] = show_tile
            body = _run_lifecycle("user.permission.update", args, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"user.permission.update rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @user_permission.command("grant-nostr")
    def user_permission_grant_nostr(
        permission: str = typer.Argument(..., help="permission name (e.g. myapp.main)"),
        pubkeys: list[str] = typer.Argument(..., help="member pubkeys/npubs (replaces the full NIP-51 membership for this permission)"),
        public: bool = typer.Option(False, "--public", help="mark the permission visitor-accessible"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Grant NIP-51 (kind 30000) access to an app permission (roadmap §25 phase 2).

        Publishes as the operator; nostr-permissiond projects it into the
        permission map alongside (not replacing) any LDAP-granted access.
        """
        def run() -> Any:
            from nostrhost.nip51_permissions import author_permission_grant

            return author_permission_grant(
                permission,
                pubkeys,
                public=public,
                operator_sk=state.operator_sk,
                control_relay=state.control_relay,
            )
        _guard(run, output_as)

    @user_permission.command("clear-nostr")
    def user_permission_clear_nostr(
        permission: str = typer.Argument(..., help="permission name (e.g. myapp.main)"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Clear NIP-51-sourced access to a permission (LDAP-granted access, if any, is unaffected)."""
        def run() -> Any:
            from nostrhost.nip51_permissions import author_permission_clear

            return author_permission_clear(
                permission,
                operator_sk=state.operator_sk,
                control_relay=state.control_relay,
            )
        _guard(run, output_as)

    user.add_typer(user_group, name="group")
    user.add_typer(user_permission, name="permission")

    # -- audit ---------------------------------------------------------------

    audit = typer.Typer(name="audit", help="signed operation-chain audit trail", no_args_is_help=True)

    @audit.command("list")
    def audit_list(
        limit: int = typer.Option(None, "--limit", help="max entries, newest first"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """List signed operation-chain audit entries (owner co-signature per call)."""
        def run() -> Any:
            body = _run_lifecycle("audit.list", {"limit": limit} if limit is not None else {}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"audit.list rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    @audit.command("get")
    def audit_get(
        audit_id: str = typer.Argument(..., help="event id or request id"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Fetch one audit entry (owner co-signature per call)."""
        def run() -> Any:
            body = _run_lifecycle("audit.get", {"audit_id": audit_id}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"audit.get rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            return body.get("result") or body
        _guard(run, output_as)

    # -- network ------------------------------------------------------------

    network = typer.Typer(name="network", help="network facts", no_args_is_help=True)

    @network.command("public-ip")
    def network_public_ip(output_as: str = typer.Option(None, "--output-as")) -> None:
        """Current public IPv4/IPv6 address."""
        _forward("network.public_ip", {}, output_as)

    # -- credential ----------------------------------------------------------

    credential = typer.Typer(name="credential", help="DNS provider credential broker", no_args_is_help=True)

    @credential.command("set")
    def credential_set(
        provider: str = typer.Argument(..., help="dns provider (cloudflare)"),
        name: str = typer.Argument(..., help="credential name"),
        value: str = typer.Option(..., "--value", help="provider token (stored root-0600; never echoed)"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Store a DNS provider token: secret:dns/<provider>/<name>."""
        def run() -> Any:
            body = _run_lifecycle("credential.set", {"provider": provider, "name": name, "value": value}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"credential.set rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            result = body.get("result") or body
            return {"ref": result.get("ref"), "path": result.get("path"), "set": True}
        _guard(run, output_as)

    @credential.command("remove")
    def credential_remove(
        provider: str = typer.Argument(..., help="dns provider"),
        name: str = typer.Argument(..., help="credential name"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Remove a DNS provider token."""
        def run() -> Any:
            body = _run_lifecycle("credential.remove", {"provider": provider, "name": name}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"credential.remove rejected: {body.get('reason') or body.get('error') or body.get('state')}")
            result = body.get("result") or body
            return {"ref": result.get("ref"), "removed": result.get("removed")}
        _guard(run, output_as)

    @credential.command("list")
    def credential_list(provider: str = typer.Option(None, "--provider", help="filter by provider"), output_as: str = typer.Option(None, "--output-as")) -> None:
        """List configured DNS credential references (names only)."""
        _forward("credential.list", {"provider": provider}, output_as)

    # -- package ------------------------------------------------------------

    package = typer.Typer(name="package", help="native package planning", no_args_is_help=True)

    @package.command("plan")
    def package_plan(
        package_file: Path = typer.Argument(..., help="package manifest JSON"),
        catalogue_file: Path = typer.Option(None, "--catalogue-file", help="catalogue provenance JSON"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Validate and plan a native package."""
        def run() -> Any:
            package = json.loads(package_file.read_text(encoding="utf-8"))
            catalogue = json.loads(catalogue_file.read_text(encoding="utf-8")) if catalogue_file else None
            return _run_tool("package.plan", {"package": package, "catalogue": catalogue})
        _guard(run, output_as)

    @package.command("reconcile")
    def package_reconcile(
        plan_file: Path = typer.Argument(..., help="plan envelope JSON"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Apply an approved native package operation plan (write operation)."""
        def run() -> Any:
            plan = json.loads(plan_file.read_text(encoding="utf-8"))
            return _run_tool("package.reconcile", {"plan": plan})
        _guard(run, output_as)

    # -- rollback / state ---------------------------------------------------

    rollback = typer.Typer(name="rollback", help="assisted rollback", no_args_is_help=True)

    @rollback.command("apply")
    def rollback_apply(
        plan_file: Path = typer.Argument(..., help="rollback plan JSON"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Execute an assisted rollback plan (write operation)."""
        def run() -> Any:
            plan = json.loads(plan_file.read_text(encoding="utf-8"))
            return _run_tool("rollback.apply", {"plan": plan})
        _guard(run, output_as)

    state_group = typer.Typer(name="state", help="state reconciliation", no_args_is_help=True)

    @state_group.command("reconcile")
    def state_reconcile(
        plan_file: Path = typer.Argument(..., help="reconciliation plan JSON"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Apply an approved, bounded reconciliation plan (write operation)."""
        def run() -> Any:
            plan = json.loads(plan_file.read_text(encoding="utf-8"))
            return _run_tool("state.reconcile", {"plan": plan})
        _guard(run, output_as)

    # -- identity (npub user model) ------------------------------------------

    identity = typer.Typer(name="identity", help="npub identities (the NostrHost user model)", no_args_is_help=True)

    @identity.command("link")
    def identity_link(
        username: str = typer.Argument(..., help="account username to bind"),
        pubkey_or_npub: str = typer.Argument(..., help="pubkey (64-hex) or npub"),
        signer_type: str = typer.Option("unknown", "--signer-type", help=f"one of {', '.join(VALID_SIGNER_TYPES)}"),
        label: str = typer.Option(None, "--label", help="human label for the identity"),
        disabled: bool = typer.Option(False, "--disabled", help="link as disabled"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Link an npub to an account (publishes kind 31102 as the operator)."""
        def run() -> Any:
            return link_identity(
                username,
                pubkey_or_npub,
                operator_sk=state.operator_sk,
                control_relay=state.control_relay,
                signer_type=signer_type,
                label=label,
                enabled=not disabled,
            )
        _guard(run, output_as)

    @identity.command("revoke")
    def identity_revoke(
        pubkey_or_npub: str = typer.Argument(..., help="pubkey (64-hex) or npub"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Revoke an identity (publishes enabled:false)."""
        def run() -> Any:
            return revoke_identity(
                pubkey_or_npub,
                operator_sk=state.operator_sk,
                control_relay=state.control_relay,
            )
        _guard(run, output_as)

    @identity.command("list")
    def identity_list(
        username: str = typer.Option(None, "--username", help="list identities for one account"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """List identities (optionally for one username)."""
        def run() -> Any:
            if username:
                return [_identity_dict(i) for i in list_identities_for_username(username)]
            return [_identity_dict(i) for i in list_identities()]
        _guard(run, output_as)

    @identity.command("resolve")
    def identity_resolve(
        pubkey_or_npub_or_username: str = typer.Argument(..., help="pubkey, npub, or username"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Resolve a pubkey/npub to its account, or list identities of a username."""
        def run() -> Any:
            value = pubkey_or_npub_or_username
            if _parse_pubkey is not None and (value.startswith("npub1") or (len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value))):
                identity = resolve_pubkey(_parse_pubkey(value))
                return _identity_dict(identity) if identity else None
            return [_identity_dict(i) for i in resolve_username(value)]
        _guard(run, output_as)

    # -- capability ----------------------------------------------------------

    capability = typer.Typer(name="capability", help="npub capabilities", no_args_is_help=True)

    @capability.command("grant")
    def capability_grant(
        pubkey: str = typer.Argument(..., help="subject pubkey (64-hex)"),
        scopes: list[str] = typer.Argument(..., help="scopes, e.g. apps.read services.write"),
        type_: str = typer.Option("agent", "--type", help="agent | admin"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Grant capabilities to an npub (publishes kind 31100 as admin)."""
        def run() -> Any:
            return grant_capability(
                pubkey,
                scopes,
                type_=type_,
                admin_sk=state.admin_sk,
                control_relay=state.control_relay,
            )
        _guard(run, output_as)

    # -- optional local agent ------------------------------------------------

    agent = typer.Typer(name="agent", help="optional resident agent lifecycle", no_args_is_help=True)

    @agent.command("init")
    def agent_init(output_as: str = typer.Option(None, "--output-as")) -> None:
        """Create a separate Observe-mode agent identity and private config.

        Does not grant relay capabilities or enable/start the service.
        """
        _guard(_agent_init, output_as)

    @agent.command("status")
    def agent_status(output_as: str = typer.Option(None, "--output-as")) -> None:
        """Show whether the optional agent is installed, configured and running."""
        _guard(_agent_status, output_as)

    @agent.command("enable")
    def agent_enable(output_as: str = typer.Option(None, "--output-as")) -> None:
        """Validate the private config and explicitly enable/start the agent."""
        _guard(lambda: _agent_service("enable"), output_as)

    @agent.command("disable")
    def agent_disable(output_as: str = typer.Option(None, "--output-as")) -> None:
        """Stop and disable the optional agent service."""
        _guard(lambda: _agent_service("disable"), output_as)

    @capability.command("delegate")
    def capability_delegate(
        pubkey: str = typer.Argument(..., help="delegate pubkey (64-hex)"),
        scopes: list[str] = typer.Argument(..., help="scopes, e.g. apps.read"),
        expires_at: int = typer.Option(..., "--expires-at", help="expiry as Unix timestamp"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Publish a signed, expiring delegation to an npub."""
        def run() -> Any:
            return delegate_capability(
                pubkey,
                scopes,
                expires_at,
                delegator_sk=state.operator_sk,
                control_relay=state.control_relay,
            )
        _guard(run, output_as)

    @capability.command("revoke")
    def capability_revoke(
        delegation_id: str = typer.Argument(..., help="delegation event id"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Revoke a delegation event."""
        def run() -> Any:
            return revoke_delegation(
                delegation_id,
                delegator_sk=state.operator_sk,
                control_relay=state.control_relay,
            )
        _guard(run, output_as)

    # -- MCP endpoint (Caddy route + CA trust) --------------------------------

    mcp = typer.Typer(name="mcp", help="MCP endpoint setup (nostrhost-mcp behind Caddy)", no_args_is_help=True)

    @mcp.command("route")
    def mcp_route(
        domain: str = typer.Argument(..., help="domain to serve the MCP endpoint on, e.g. mcp.example.com"),
        port: int = typer.Option(None, "--port", help="local nostrhost-mcp --http port (default: 8930)"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Route DOMAIN to a local nostrhost-mcp (serve --http), reusing the
        same Caddy admin-API mechanism every native web resource uses. The
        domain must already resolve/have a certificate the way any other
        NostrHost domain does (see `nostrhost domain add`); this only adds
        the MCP app's route on top of it. Safe to re-run to change the port."""
        from .mcp_endpoint import DEFAULT_PORT, configure_route

        def run() -> Any:
            route_id = configure_route(domain, port=port or DEFAULT_PORT)
            return {"route_id": route_id, "domain": domain, "port": port or DEFAULT_PORT}
        _guard(run, output_as)

    @mcp.command("remove-route")
    def mcp_remove_route(
        domain: str = typer.Argument(..., help="domain the MCP endpoint was routed on"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Remove the MCP endpoint's Caddy route and forget its configuration."""
        from .mcp_endpoint import remove_route

        def run() -> Any:
            remove_route(domain)
            return {"domain": domain, "removed": True}
        _guard(run, output_as)

    @mcp.command("status")
    def mcp_status(output_as: str = typer.Option(None, "--output-as")) -> None:
        """Show the configured MCP endpoint (domain/port), if any."""
        from .mcp_endpoint import read_endpoint_config

        def run() -> Any:
            config = read_endpoint_config()
            return config or {"configured": False}
        _guard(run, output_as)

    @mcp.command("export-ca")
    def mcp_export_ca(
        output: Path = typer.Option(None, "--output", "-o", help="write the bundle here instead of stdout"),
    ) -> None:
        """Export a CA bundle (system CAs + Caddy's internal root, if used)
        for a remote MCP client to trust this node's TLS certificate.

        Only needed when the MCP domain uses Caddy's internal CA (a lab/test
        domain, `tls internal`) rather than a public ACME certificate — a
        public ACME certificate needs no client-side trust change at all."""
        from .mcp_endpoint import export_ca_bundle

        bundle = export_ca_bundle()
        if bundle is None:
            _print_error(
                "this node has no Caddy internal CA (/var/lib/caddy/pki/authorities/local/root.crt) — "
                "if the MCP domain uses a public ACME certificate, no client-side trust change is needed"
            )
            raise typer.Exit(EXIT_ERR)
        if output:
            output.write_bytes(bundle)
        else:
            typer.echo(bundle.decode("utf-8", errors="replace"), nl=False)

    # -- operation chain ---------------------------------------------------------

    op_group = typer.Typer(name="op", help="operation chain (follow/status)", no_args_is_help=True)

    @op_group.command("follow")
    def op_follow(
        request_id: str = typer.Argument(..., help="operation request id"),
        timeout: float = typer.Option(60.0, "--timeout", help="seconds to keep waiting"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Stream an operation's progress/result events until it finishes."""
        def run() -> None:
            for event in _stream_events(request_id, state.control_relay, timeout):
                _render_operation_event(event, output_as or state.output_as)
        _guard(run, output_as)

    @op_group.command("status")
    def op_status(
        request_id: str = typer.Argument(..., help="operation request id"),
        timeout: float = typer.Option(5.0, "--timeout", help="seconds to wait for the result"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Print the latest chain event for an operation."""
        def run() -> None:
            last = None
            for event in _stream_events(request_id, state.control_relay, timeout):
                _render_operation_event(event, output_as or state.output_as)
                last = event
            if last is None:
                print(f"{request_id[:16]} … no chain events (pending or unknown)")
        _guard(run, output_as)

    # -- postinstall --------------------------------------------------------

    postinstall = typer.Typer(name="postinstall", help="first-run bootstrap / restore", no_args_is_help=True)

    @postinstall.command("new")
    def postinstall_new(
        domain: str = typer.Option(None, "--domain", help="primary domain (default: hostname)"),
        admin_npub: str = typer.Option(None, "--admin-npub", help="operator admin npub (default: the generated operator)"),
        force: bool = typer.Option(False, "--force", help="re-run even if /etc/yunohost/installed exists"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Bootstrap a fresh node: generate the identity, stand up the native
        stack (relay, daemons, Caddy) and record state S0."""
        _guard(lambda: _postinstall_new(domain, admin_npub, force), output_as)

    @postinstall.command("restore")
    def postinstall_restore(
        operator_sk: str = typer.Option(None, "--operator-sk", help="recovered admin secret key (64-hex or nsec1)"),
        server_sk: str = typer.Option(None, "--server-sk", help="recovered server key (64-hex or nsec1)"),
        notice_sk: str = typer.Option(None, "--notice-sk", help="recovered portal notice key"),
        publisher_sk: str = typer.Option(None, "--publisher-sk", help="recovered catalogue publisher key"),
        notifier_sk: str = typer.Option(None, "--notifier-sk", help="recovered notification service key"),
        keys_file: Path = typer.Option(None, "--keys-file", help="recovery bundle from postinstall --new (keys.recovery)"),
        domain: str = typer.Option(None, "--domain", help="primary domain (default: hostname)"),
        bundle: Path = typer.Option(None, "--bundle", help="state-replica bundle to restore (nostrhost-state replicate)"),
        state_relay: str = typer.Option(None, "--state-relay", help="relay to discover the kind-30617 state repo on"),
        restic: str = typer.Option(None, "--restic", help="override the restic snapshot id"),
        force: bool = typer.Option(False, "--force", help="re-run even if /etc/yunohost/installed exists"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Restore a node: recover identity + state, restore the linked Restic
        snapshot, reconcile and stand the stack back up. Every node key is
        required (explicit flags or --keys-file)."""
        _guard(
            lambda: _postinstall_restore(
                operator_sk or "", server_sk or "", notice_sk or "", publisher_sk or "", notifier_sk or "",
                domain, bundle, state_relay, restic, force,
                keys_file=keys_file,
            ),
            output_as,
        )

    @postinstall.command("status")
    def postinstall_status(output_as: str = typer.Option(None, "--output-as")) -> None:
        """Show bootstrap / postinstall state."""
        _guard(_postinstall_status, output_as)

    for group in (system, service, app_group, package, rollback, state_group, identity, capability, agent, mcp, op_group, postinstall, backup, domain, dns, nsite, catalog, updates, logs, user, audit, network, credential):
        app.add_typer(group, name=group.info.name)

    return app


# --------------------------------------------------------------------------- #
# operation chain subscription

def _stream_events(request_id: str, relay: str | None, timeout: float):
    from . import events as events_module

    return events_module.stream_operation_events(
        request_id,
        relay_url=relay or "ws://127.0.0.1:4848",
        timeout=timeout,
    )


def _render_operation_event(event: dict[str, Any], output_as: str | None) -> None:
    """Print one chain event: JSON when requested, else a short human line."""
    kind = int(event.get("kind", 0))
    if output_as == "json":
        print(json.dumps(event, default=str))
        return
    request_id = next(
        (tag[1] for tag in event.get("tags") or [] if len(tag) >= 2 and tag[0] == "e"),
        event.get("id", ""),
    )[:16]
    if kind == 2203:
        print(f"{request_id} … started")
    elif kind == 2205:
        try:
            body = json.loads(event.get("content") or "{}")
        except (TypeError, json.JSONDecodeError):
            body = {}
        pct = f" {body['progress'] * 100:.0f}%" if "progress" in body else ""
        print(f"{request_id} … [{body.get('stage', '?')}]{pct}{' ' + body['message'] if body.get('message') else ''}")
    elif kind == 2204:
        try:
            body = json.loads(event.get("content") or "{}")
        except (TypeError, json.JSONDecodeError):
            body = {}
        print(f"{request_id} … {'done: ok' if body.get('ok') else 'failed'}"
              + (f" ({body.get('error')})" if body.get("error") else ""))
    else:
        print(f"{request_id} … kind {kind}")


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


def run(argv: list[str], *, app: typer.Typer | None = None, state: _State | None = None) -> int:
    """Run the CLI against ``argv`` (injectable for tests)."""
    from typer.testing import CliRunner

    if app is None:
        app = build_app(state=state)
    result = CliRunner().invoke(app, argv)
    return result.exit_code


def main(argv: list[str] | None = None) -> int:
    """Programmatic entry point used by ``bin/nostrhost``."""
    app = build_app()
    if argv is None:
        argv = sys.argv[1:]
    try:
        app(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_ERR
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover - exercised through bin/nostrhost
    raise SystemExit(main())
