"""Broadened native safe-tool surface for the operation registry.

These are the *safe* wrappers the executor (nostr_operationsd) runs, one per
ToolSpec in ``NATIVE_TOOLS``. Each is bounded by construction: strict named
arguments (a Pydantic input model carries the JSON Schema that drives
generated MCP/Admin interfaces), no passthrough, single-target where
relevant, and it calls the fork's own decorated functions lazily so importing
this module stays light (MCP transition Phase 0 / docs/MCP-TRANSITION.md §6).

Imported lazily by ``yunohost.nostr_operations._native_tools()``; the reverse
import here is safe because the registry module is fully defined before it
constructs ``TOOLS``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from yunohost.nostr_operations import (
    OperationError,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    REVERSIBLE,
    REVERSIBLE_WITH_PLAN,
    IRREVERSIBLE,
    SCOPE_APPS_CONFIG_READ,
    SCOPE_APPS_CONFIG_WRITE,
    SCOPE_APPS_INSTALL,
    SCOPE_APPS_UPGRADE,
    SCOPE_AUDIT_READ,
    SCOPE_BACKUPS_CREATE,
    SCOPE_BACKUPS_DELETE,
    SCOPE_BACKUPS_READ,
    SCOPE_BACKUPS_RESTORE,
    SCOPE_DIAGNOSIS_READ,
    SCOPE_FIREWALL_READ,
    SCOPE_FIREWALL_WRITE,
    SCOPE_LOGS_READ,
    SCOPE_SERVER_READ,
    SCOPE_SYSTEM_MIGRATE,
    SCOPE_SYSTEM_UPDATE,
    SCOPE_SYSTEM_UPGRADE,
    SCOPE_USERS_DELETE,
    SCOPE_USERS_READ,
    SCOPE_USERS_WRITE,
    SCOPE_CATALOG_READ,
    SCOPE_CATALOG_VERIFY,
    SCOPE_CATALOG_PUBLISH,
    SCOPE_DOMAINS_READ,
    SCOPE_DOMAINS_WRITE,
    SCOPE_SERVICES_READ,
    KIND_CAPABILITY,
    ToolSpec,
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SystemStatusArgs(_Strict):
    pass


class AppInstallArgs(_Strict):
    app: str
    label: str | None = None
    args: str | None = None
    force: bool = False
    no_remove_on_failure: bool = False


class AppUpgradeArgs(_Strict):
    app: str
    force: bool = False
    no_safety_backup: bool = False


class AppChangeUrlArgs(_Strict):
    app: str
    domain: str
    path: str


class AppConfigReadArgs(_Strict):
    app: str
    key: str = ""
    full: bool = False


class AppConfigSetArgs(_Strict):
    app: str
    key: str
    value: Any = None


class BackupCreateArgs(_Strict):
    name: str | None = None
    description: str | None = None
    apps: list[str] = Field(default_factory=list)
    system: list[str] = Field(default_factory=list)
    output_directory: str | None = None


class BackupListArgs(_Strict):
    with_info: bool = False


class BackupRestoreArgs(_Strict):
    name: str
    apps: list[str] = Field(default_factory=list)
    system: list[str] = Field(default_factory=list)
    force: bool = False


class UserListArgs(_Strict):
    pass


class UserCreateArgs(_Strict):
    username: str
    domain: str
    password: str
    fullname: str
    mailbox_quota: str = "0"
    admin: bool = False


class UserDeleteArgs(_Strict):
    username: str
    purge: bool = False
    force: bool = False


class SystemUpgradeArgs(_Strict):
    target: Literal["apps", "system"] = "system"


class FirewallListArgs(_Strict):
    raw: bool = False
    protocol: Literal["tcp", "udp"] = "tcp"
    forwarded: bool = False


class FirewallOpenArgs(_Strict):
    port: str
    protocol: Literal["tcp", "udp"]
    comment: str = "opened via native operation"
    upnp: bool = False


class FirewallCloseArgs(_Strict):
    port: str
    protocol: Literal["tcp", "udp"]
    upnp_only: bool = False


class FirewallReloadArgs(_Strict):
    skip_upnp: bool = False


class DiagnosisRunArgs(_Strict):
    categories: list[str] = Field(default_factory=list)
    force: bool = False


class CatalogListArgs(_Strict):
    pass


class CatalogGetArgs(_Strict):
    app_id: str = Field(..., description="the app id to resolve from the trusted projection")


class CatalogPublishArgs(_Strict):
    app_id: str = Field(..., description="the app id to re-declare and publish under the node's publisher key")
    relays: str = Field(
        default="ws://127.0.0.1:4848",
        description="comma-separated relay ws:// or wss:// URLs to publish the declaration to",
    )


class UpdatesCheckArgs(_Strict):
    pass


class UpdatesRefreshArgs(_Strict):
    target: Literal["apps", "system", "all"] = "apps"


class SystemMigrationsArgs(_Strict):
    pending: bool = False
    done: bool = False


class SystemMigrateArgs(_Strict):
    targets: list[str] = Field(default_factory=list)
    skip: bool = False
    auto: bool = False
    force_rerun: bool = False
    accept_disclaimer: bool = False
    skip_postmigrations: bool = False


class ServiceHistoryArgs(_Strict):
    names: list[str] = Field(..., description="service names to report state + restart history for")
    lines: int = 50


class LogsReadArgs(_Strict):
    units: list[str] = Field(..., description="allowlisted journal units to query")
    since: str | None = None
    until: str | None = None
    priority: str | None = None
    grep: str | None = None
    lines: int = 200


class LogsWebArgs(_Strict):
    host: str | None = None
    path: str | None = None
    status: int | None = None
    since: str | None = None
    until: str | None = None
    lines: int = 200


class BackupDeleteArgs(_Strict):
    name: str = Field(..., description="local backup archive name to delete")


class DomainCertInfoArgs(_Strict):
    domain: str = Field(..., description="already-registered domain to report certificate status for")


class DomainCertInstallArgs(_Strict):
    domain: str = Field(..., description="already-registered domain to issue/renew a certificate for")
    letsencrypt: bool = True
    staging: bool = False


class UserUpdateArgs(_Strict):
    username: str
    mail: str | None = None
    change_password: str | None = None
    add_mailforward: list[str] | None = None
    remove_mailforward: list[str] | None = None
    add_mailalias: list[str] | None = None
    remove_mailalias: list[str] | None = None
    mailbox_quota: str | None = None
    fullname: str | None = None


class UserGroupListArgs(_Strict):
    pass


class UserGroupCreateArgs(_Strict):
    groupname: str
    gid: str | None = None


class UserGroupUpdateArgs(_Strict):
    groupname: str
    add: list[str] | None = None
    remove: list[str] | None = None


class UserGroupDeleteArgs(_Strict):
    groupname: str
    force: bool = False


class UserPermissionListArgs(_Strict):
    full: bool = False


class UserPermissionInfoArgs(_Strict):
    permission: str


class UserPermissionAddArgs(_Strict):
    permission: str
    names: list[str] = Field(..., description="usernames/groups to grant")
    protected: bool | None = None


class UserPermissionRemoveArgs(_Strict):
    permission: str
    names: list[str] = Field(..., description="usernames/groups to revoke")


class UserPermissionUpdateArgs(_Strict):
    permission: str
    label: str | None = None
    show_tile: bool | None = None
    protected: bool | None = None


class CatalogVerifyArgs(_Strict):
    event_or_naddr: str = Field(..., description="a JSON Nostr declaration event to verify (naddr input is not yet supported)")


class AuditListArgs(_Strict):
    limit: int | None = Field(default=None, description="max entries to return, newest first")


class AuditGetArgs(_Strict):
    audit_id: str = Field(..., description="event id or request id of the chain entry to fetch")


# --------------------------------------------------------------------------- #
# handlers

def _safe_system_status(**args: Any) -> dict[str, Any]:
    """Read-only host snapshot: versions, platform, load average."""
    if args:
        raise OperationError(f"system.status does not accept extra args: {sorted(args)}")
    import os
    import platform

    from yunohost.tools import tools_versions

    try:
        load = os.getloadavg()
    except OSError:
        load = None
    return {
        "versions": tools_versions(),
        "platform": platform.platform(),
        "hostname": platform.node(),
        "loadavg": [round(x, 2) for x in load] if load else None,
    }


def _safe_app_install(app: str = "", label: str | None = None, args: str | None = None, force: bool = False, no_remove_on_failure: bool = False, **extra: Any) -> dict[str, Any]:
    app = str(app or "").strip()
    if extra:
        raise OperationError(f"app.install does not accept extra args: {sorted(extra)}")
    if not app:
        raise OperationError("app.install requires a non-empty 'app'")
    from yunohost.app import app_install

    app_install(app=app, label=label, args=args, force=bool(force), no_remove_on_failure=bool(no_remove_on_failure))
    return {"app": app}


def _safe_app_upgrade(app: str = "", force: bool = False, no_safety_backup: bool = False, **extra: Any) -> dict[str, Any]:
    app = str(app or "").strip()
    if extra:
        raise OperationError(f"app.upgrade does not accept extra args: {sorted(extra)}")
    if not app:
        raise OperationError("app.upgrade requires a non-empty 'app'")
    from yunohost.app import app_upgrade

    result = app_upgrade(app=app, force=bool(force), no_safety_backup=bool(no_safety_backup))
    return {"app": app, "result": result}


def _safe_app_change_url(app: str = "", domain: str = "", path: str = "", **extra: Any) -> dict[str, Any]:
    app = str(app or "").strip()
    domain = str(domain or "").strip()
    path = str(path or "").strip()
    if extra:
        raise OperationError(f"app.change_url does not accept extra args: {sorted(extra)}")
    if not app or not domain or not path:
        raise OperationError("app.change_url requires 'app', 'domain' and 'path'")
    from yunohost.app import app_change_url

    app_change_url(app=app, domain=domain, path=path)
    return {"app": app, "domain": domain, "path": path}


def _safe_app_config_read(app: str = "", key: str = "", full: bool = False, **extra: Any) -> dict[str, Any]:
    app = str(app or "").strip()
    if extra:
        raise OperationError(f"app.config.read does not accept extra args: {sorted(extra)}")
    if not app:
        raise OperationError("app.config.read requires a non-empty 'app'")
    from yunohost.app import app_config_get

    return app_config_get(app=app, key=key, full=bool(full))


def _safe_app_config_set(app: str = "", key: str = "", value: Any = None, **extra: Any) -> dict[str, Any]:
    app = str(app or "").strip()
    key = str(key or "").strip()
    if extra:
        raise OperationError(f"app.config.set does not accept extra args: {sorted(extra)}")
    if not app or not key:
        raise OperationError("app.config.set requires 'app' and 'key'")
    from yunohost.app import app_config_set

    app_config_set(app=app, key=key, value=value)
    return {"app": app, "key": key}


def _safe_backup_create(name: str | None = None, description: str | None = None, apps: list[str] | None = None, system: list[str] | None = None, output_directory: str | None = None, **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"backup.create does not accept extra args: {sorted(extra)}")
    apps = apps or []
    system = system or []
    from yunohost.backup import backup_create

    backup_create(name=name, description=description, apps=apps, system=system, output_directory=output_directory)
    return {"name": name, "apps": apps, "system": system}


def _safe_backup_list(with_info: bool = False, **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"backup.list does not accept extra args: {sorted(extra)}")
    from yunohost.backup import backup_list

    return backup_list(with_info=bool(with_info))


def _safe_backup_restore(name: str = "", apps: list[str] | None = None, system: list[str] | None = None, force: bool = False, **extra: Any) -> dict[str, Any]:
    name = str(name or "").strip()
    if extra:
        raise OperationError(f"backup.restore does not accept extra args: {sorted(extra)}")
    if not name:
        raise OperationError("backup.restore requires a non-empty 'name'")
    apps = apps or []
    system = system or []
    from yunohost.backup import backup_restore

    backup_restore(name=name, apps=apps, system=system, force=bool(force))
    return {"name": name, "apps": apps, "system": system}


def _safe_user_list(**extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"user.list does not accept extra args: {sorted(extra)}")
    from yunohost.user import user_list

    return user_list()


def _safe_user_create(username: str = "", domain: str = "", password: str = "", fullname: str = "", mailbox_quota: str = "0", admin: bool = False, **extra: Any) -> dict[str, Any]:
    username = str(username or "").strip()
    domain = str(domain or "").strip()
    fullname = str(fullname or "").strip()
    if extra:
        raise OperationError(f"user.create does not accept extra args: {sorted(extra)}")
    if not username or not domain or not password or not fullname:
        raise OperationError("user.create requires 'username', 'domain', 'password' and 'fullname'")
    from yunohost.user import user_create

    user_create(username=username, domain=domain, password=password, fullname=fullname, mailbox_quota=mailbox_quota or "0", admin=bool(admin))
    return {"username": username, "domain": domain, "admin": bool(admin)}


def _safe_user_delete(username: str = "", purge: bool = False, force: bool = False, **extra: Any) -> dict[str, Any]:
    username = str(username or "").strip()
    if extra:
        raise OperationError(f"user.delete does not accept extra args: {sorted(extra)}")
    if not username:
        raise OperationError("user.delete requires a non-empty 'username'")
    from yunohost.user import user_delete

    user_delete(username=username, purge=bool(purge), force=bool(force))
    return {"username": username, "purge": bool(purge)}


def _safe_system_upgrade(target: str = "system", **extra: Any) -> dict[str, Any]:
    target = str(target or "").strip()
    if extra:
        raise OperationError(f"system.upgrade does not accept extra args: {sorted(extra)}")
    if target not in ("apps", "system"):
        raise OperationError("system.upgrade target must be 'apps' or 'system'")
    from yunohost.tools import tools_upgrade

    tools_upgrade(target=target)
    return {"target": target}


def _safe_firewall_list(raw: bool = False, protocol: str = "tcp", forwarded: bool = False, **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"firewall.list does not accept extra args: {sorted(extra)}")
    if protocol not in ("tcp", "udp"):
        raise OperationError("firewall.list protocol must be 'tcp' or 'udp'")
    from yunohost.firewall import firewall_list

    return firewall_list(raw=bool(raw), protocol=protocol, forwarded=bool(forwarded))


def _safe_firewall_open(port: str = "", protocol: str = "", comment: str = "opened via native operation", upnp: bool = False, **extra: Any) -> dict[str, Any]:
    port = str(port or "").strip()
    protocol = str(protocol or "").strip()
    if extra:
        raise OperationError(f"firewall.open does not accept extra args: {sorted(extra)}")
    if not port or protocol not in ("tcp", "udp"):
        raise OperationError("firewall.open requires a 'port' and a 'protocol' of tcp or udp")
    from yunohost.firewall import firewall_open

    firewall_open(port=port, protocol=protocol, comment=comment or "opened via native operation", upnp=bool(upnp))
    return {"port": port, "protocol": protocol}


def _safe_firewall_close(port: str = "", protocol: str = "", upnp_only: bool = False, **extra: Any) -> dict[str, Any]:
    port = str(port or "").strip()
    protocol = str(protocol or "").strip()
    if extra:
        raise OperationError(f"firewall.close does not accept extra args: {sorted(extra)}")
    if not port or protocol not in ("tcp", "udp"):
        raise OperationError("firewall.close requires a 'port' and a 'protocol' of tcp or udp")
    from yunohost.firewall import firewall_close

    firewall_close(port=port, protocol=protocol, upnp_only=bool(upnp_only))
    return {"port": port, "protocol": protocol}


def _safe_firewall_reload(skip_upnp: bool = False, **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"firewall.reload does not accept extra args: {sorted(extra)}")
    from yunohost.firewall import firewall_reload

    firewall_reload(skip_upnp=bool(skip_upnp))
    return {"reloaded": True}


def _safe_diagnosis_run(categories: list[str] | None = None, force: bool = False, **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"diagnosis.run does not accept extra args: {sorted(extra)}")
    categories = categories or []
    from yunohost.diagnosis import diagnosis_run, diagnosis_show

    diagnosis_run(categories=categories, force=bool(force))
    try:
        return diagnosis_show(categories=categories)
    except Exception:  # noqa: BLE001 - a missing cache is an empty report, not an error
        return {}


# --------------------------------------------------------------------------- #
# catalogue surface (MCP transition Phase 5) — the native catalog.* tools.

CATALOG_BIN = os.environ.get("NOSTRHOST_CATALOG_BIN", "/usr/bin/nostrhost-catalog")
CATALOG_STATE = os.environ.get("NOSTRHOST_CATALOG_STATE", "/var/lib/nostrhost/catalogue.json")


def _trusted_publishers() -> str:
    """Comma-separated trusted publisher pubkeys: catalogue.env first, else the
    node's own publisher key (operator.toml)."""
    env_path = Path(os.environ.get("NOSTRHOST_CATALOGUE_ENV", "/etc/nostrhost/catalogue.env"))
    try:
        for line in env_path.read_text().splitlines():
            if line.startswith("NOSTRHOST_CATALOG_PUBLISHERS="):
                return line.split("=", 1)[1].strip()
    except OSError:
        pass
    from yunohost.nostr_identity import _operator_config

    return _operator_config().publisher_pubkey


def _catalog_cli(subcommand: list[str], stdin_data: bytes | None = None) -> dict[str, Any]:
    """Run the native catalogue CLI and parse its JSON stdout."""
    import subprocess

    cmd = [CATALOG_BIN, "--publishers", _trusted_publishers(), "--state", CATALOG_STATE, *subcommand]
    try:
        proc = subprocess.run(cmd, input=stdin_data, capture_output=True, timeout=60)
    except FileNotFoundError:
        raise OperationError(f"catalogue CLI not found: {CATALOG_BIN} (install the nostrhost-catalog package)") from None
    except subprocess.TimeoutExpired:
        raise OperationError("catalogue CLI timed out") from None
    if proc.returncode != 0:
        raise OperationError(f"catalogue CLI failed: {proc.stderr.decode(errors='replace').strip() or 'exit ' + str(proc.returncode)}")
    try:
        return json.loads(proc.stdout.decode() or "{}")
    except json.JSONDecodeError:
        return {"raw": proc.stdout.decode(errors="replace").strip()}


def _safe_catalog_list(**args: Any) -> dict[str, Any]:
    if args:
        raise OperationError(f"catalog.list does not accept extra args: {sorted(args)}")
    return _catalog_cli(["list"])


def _safe_catalog_get(app_id: str = "", **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"catalog.get does not accept extra args: {sorted(extra)}")
    if not app_id:
        raise OperationError("catalog.get requires an app_id")
    return _catalog_cli(["get", app_id])


def _safe_catalog_publish(app_id: str = "", relays: str = "", **extra: Any) -> dict[str, Any]:
    """Re-declare a trusted app under the node's own catalogue publisher key.

    The declaration is built from the local trusted projection's package
    coordinate, signed with the node's publisher key (operator.toml), pushed
    to the configured relays, and ingested back into the local projection so
    the change is visible immediately without waiting for a sync round-trip.
    """
    if extra:
        raise OperationError(f"catalog.publish does not accept extra args: {sorted(extra)}")
    if not app_id:
        raise OperationError("catalog.publish requires an app_id")

    from yunohost.nostr_catalog_provider import native_catalog_coordinate
    from yunohost.nostr_identity import _operator_config, _sign_event

    coordinate = native_catalog_coordinate(app_id)
    if not coordinate:
        raise OperationError(f"app {app_id!r} is not in the trusted native catalogue projection")
    manifest = coordinate.get("manifest_sha256") or ""
    content = coordinate.get("content_sha256") or ""
    commit = coordinate.get("revision") or ""
    for label, value in (("manifest", manifest), ("content", content), ("commit", commit)):
        if len(value) < 40:
            raise OperationError(f"catalogue coordinate for {app_id!r} lacks a valid {label} hash")

    tags = [
        ["d", coordinate["app_id"]],
        ["platform", "yunohost"],
        ["repository", coordinate["repository"]],
        ["version", coordinate.get("version") or "0"],
        ["commit", commit],
        ["manifest", f"sha256:{manifest}"],
        ["content", f"sha256:{content}"],
    ]
    package_path = coordinate.get("package_path")
    if package_path:
        tags.append(["package", package_path])
    archs = coordinate.get("architectures") or []
    if archs:
        tags.append(["category", "app"])
    content_json = json.dumps({"name": coordinate.get("version") or app_id, "architectures": archs}, separators=(",", ":"))

    cfg = _operator_config()
    event = _sign_event(cfg.publisher_sk, cfg.publisher_pubkey, 32267, content_json, tags)

    result = _catalog_cli(["publish", "--relay", relays or "ws://127.0.0.1:4848"], json.dumps(event).encode())
    ingest = _catalog_cli(["ingest"], json.dumps(event).encode())
    return {
        "app_id": app_id,
        "publisher_pubkey": cfg.publisher_pubkey,
        "event_id": event["id"],
        "published": result,
        "ingested": ingest,
    }


# --------------------------------------------------------------------------- #
# updates / migrations

def _safe_updates_check(**args: Any) -> dict[str, Any]:
    """Pending app/system updates, from cache only (no network refresh)."""
    if args:
        raise OperationError(f"updates.check does not accept extra args: {sorted(args)}")
    from yunohost.nostr_identity import _init_headless_yunohost
    from yunohost.tools import tools_update_norefresh

    _init_headless_yunohost()
    return tools_update_norefresh()


def _safe_updates_refresh(target: str = "apps", **extra: Any) -> dict[str, Any]:
    """Refresh cached update metadata (apt cache, app catalog sources)."""
    if extra:
        raise OperationError(f"updates.refresh does not accept extra args: {sorted(extra)}")
    if target not in ("apps", "system", "all"):
        raise OperationError("updates.refresh target must be 'apps', 'system' or 'all'")
    from yunohost.nostr_identity import _init_headless_yunohost
    from yunohost.tools import tools_update

    _init_headless_yunohost()
    result = tools_update(target=target)
    return {"target": target, **result}


def _safe_system_migrations(pending: bool = False, done: bool = False, **extra: Any) -> dict[str, Any]:
    """List known migrations (pending/done filters) and their recorded state."""
    if extra:
        raise OperationError(f"system.migrations does not accept extra args: {sorted(extra)}")
    from yunohost.tools import tools_migrations_list, tools_migrations_state

    listing = tools_migrations_list(pending=bool(pending), done=bool(done))
    return {
        "migrations": listing.get("migrations", []),
        "state": tools_migrations_state().get("migrations", {}),
    }


def _safe_system_migrate(
    targets: list[str] | None = None,
    skip: bool = False,
    auto: bool = False,
    force_rerun: bool = False,
    accept_disclaimer: bool = False,
    skip_postmigrations: bool = False,
    **extra: Any,
) -> dict[str, Any]:
    if extra:
        raise OperationError(f"system.migrate does not accept extra args: {sorted(extra)}")
    targets = targets or []
    from yunohost.tools import tools_migrations_run, tools_migrations_state

    tools_migrations_run(
        targets=targets,
        skip=bool(skip),
        auto=bool(auto),
        force_rerun=bool(force_rerun),
        accept_disclaimer=bool(accept_disclaimer),
        skip_postmigrations=bool(skip_postmigrations),
    )
    return {"targets": targets, "state": tools_migrations_state().get("migrations", {})}


# --------------------------------------------------------------------------- #
# service history + host logs (logs.read / logs.web / service.history)

JOURNALCTL_BIN = os.environ.get("NOSTRHOST_JOURNALCTL_BIN", "journalctl")
CADDY_LOG_DIR = os.environ.get("NOSTRHOST_CADDY_LOG_DIR", "/var/log/caddy")

# The journal surface is deliberately allowlisted: host-level incident evidence
# (kernel, OOM, SSH, fail2ban, systemd) plus the NostrHost-native services
# (Caddy web server, the nostr API daemons and the control-plane services) —
# never an arbitrary unit reader.
_INTROSPECTION_JOURNAL_UNITS = frozenset(
    {
        "caddy",
        "nostr-api",
        "nostr-portal-api",
        "nostr-operationsd",
        "nostr-identityd",
        "nostr-certd",
        "nostrhost-control",
        "nostrhost-catalog",
        "ssh",
        "sshd",
        "fail2ban",
        "nftables",
        "kernel",
        "systemd",
        "systemd-oomd",
        "systemd-logind",
    }
)

_JOURNAL_PRIORITY_NAMES = {
    "0": "emerg",
    "1": "alert",
    "2": "crit",
    "3": "err",
    "4": "warning",
    "5": "notice",
    "6": "info",
    "7": "debug",
}


def _normalize_journal_entry(raw: dict[str, Any], *, default_service: str) -> dict[str, Any]:
    """One ``journalctl -o json`` record -> {timestamp, service, priority,
    message}. __REALTIME_TIMESTAMP is microseconds-since-epoch as a decimal
    string; PRIORITY is a syslog number 0-7; MESSAGE is normally a string but
    non-UTF8 content arrives as a byte array. Messages pass through the policy
    text redactor so a service's own journal output can't leak secrets."""
    import datetime as _dt

    from nostrhost_policy.redaction import redact_text

    timestamp = raw.get("__REALTIME_TIMESTAMP")
    if timestamp is not None:
        try:
            timestamp = _dt.datetime.fromtimestamp(int(timestamp) / 1_000_000, tz=_dt.timezone.utc).isoformat()
        except (ValueError, OverflowError):
            timestamp = None

    message = raw.get("MESSAGE", "")
    if isinstance(message, list):
        message = bytes(message).decode("utf-8", errors="replace")
    if isinstance(message, str):
        message = redact_text(message)

    return {
        "timestamp": timestamp,
        "service": raw.get("_SYSTEMD_UNIT", default_service),
        "priority": _JOURNAL_PRIORITY_NAMES.get(str(raw.get("PRIORITY")), raw.get("PRIORITY")),
        "message": message,
    }


def _journalctl(unit: str, *, since: str | None, until: str | None, priority: str | None, grep: str | None, lines: int) -> list[dict[str, Any]]:
    """Bounded journalctl query for one unit; returns normalized entries."""
    import subprocess

    args = [JOURNALCTL_BIN, "--no-pager", "-o", "json", "-n", str(lines)]
    args += ["-k"] if unit == "kernel" else ["-u", unit]
    if since:
        args += ["--since", since]
    if until:
        args += ["--until", until]
    if priority:
        args += ["-p", priority]
    if grep:
        args += ["--grep", grep]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired as exc:
        raise OperationError("journalctl timed out") from exc
    if proc.returncode != 0:
        return []
    entries: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        entries.append(_normalize_journal_entry(raw, default_service=unit))
    return entries


def _safe_logs_read(
    units: list[str] | None = None,
    since: str | None = None,
    until: str | None = None,
    priority: str | None = None,
    grep: str | None = None,
    lines: int = 200,
    **extra: Any,
) -> dict[str, Any]:
    """Query a deliberately allowlisted set of system journals (logs.read)."""
    if extra:
        raise OperationError(f"logs.read does not accept extra args: {sorted(extra)}")
    units = units or []
    if not units:
        raise OperationError("logs.read requires at least one 'units' entry")
    unknown = sorted(set(units) - _INTROSPECTION_JOURNAL_UNITS)
    if unknown:
        raise OperationError(f"journal units are not allowlisted: {', '.join(unknown)}")
    capped = max(1, min(lines, 2000))
    entries: list[dict[str, Any]] = []
    for unit in units:
        entries.extend(_journalctl(unit, since=since, until=until, priority=priority, grep=grep, lines=capped))
    entries.sort(key=lambda entry: entry.get("timestamp") or "")
    return {"units": units, "entries": entries[-capped:]}


def _parse_introspection_time(value: str | None) -> Any:
    import datetime as _dt

    if value is None:
        return None
    if value == "now":
        return _dt.datetime.now(_dt.timezone.utc)
    import re as _re

    relative = _re.fullmatch(r"-(\d+)([smhdw])", value)
    if relative:
        amount, unit = int(relative.group(1)), relative.group(2)
        seconds = amount * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]
        return _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(seconds=seconds)
    try:
        parsed = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OperationError("time bounds must be ISO-8601 or a relative value such as -24h") from exc
    return parsed.replace(tzinfo=parsed.tzinfo or _dt.timezone.utc).astimezone(_dt.timezone.utc)


def _tail_file_lines(path: Path, lines: int, *, max_bytes: int = 2_000_000) -> list[str]:
    """Read only a bounded tail of a text log without loading its whole file."""
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        end = handle.tell()
        start = max(0, end - max_bytes)
        handle.seek(start)
        data = handle.read(end - start)
    if start:
        data = data[data.find(b"\n") + 1 :]
    return data.decode("utf-8", errors="replace").splitlines()[-lines:]


def _parse_caddy_log_line(line: str, filename: str) -> dict[str, Any] | None:
    """Normalize one Caddy access-log line (JSON, Caddyfile ``format json``).

    The native web server is Caddy, which logs a JSON object per request to
    /var/log/caddy/access.log (conf/caddy/Caddyfile.template): an access entry
    has ``logger`` ``http.log.access`` and a ``request`` object; error entries
    carry ``level: error``. Returns a normalized dict or None for a blank
    line; message text passes through the policy redactor.
    """
    import datetime as _dt
    from urllib.parse import urlsplit

    from nostrhost_policy.redaction import redact_text

    try:
        raw = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        message = redact_text(line.strip())
        return {"kind": "raw", "file": filename, "message": message[:4000]}
    if not isinstance(raw, dict):
        return {"kind": "raw", "file": filename, "message": redact_text(str(raw))[:4000]}

    ts = raw.get("ts")
    timestamp = None
    if isinstance(ts, (int, float)):
        timestamp = _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).isoformat()
    req = raw.get("request")
    if not isinstance(req, dict):
        req = {}
    uri = req.get("uri") or ""
    path = None
    if uri:
        path = urlsplit(uri).path or uri
    level = raw.get("level", "info")
    status = raw.get("status")
    logger = raw.get("logger", "")
    is_access = logger.endswith(".access") or (
        not logger.endswith(".error") and level != "error"
    )
    base = {
        "file": filename,
        "source_timestamp": ts,
        "timestamp": timestamp,
        "status": status if isinstance(status, int) else None,
    }
    if is_access:
        return {
            "kind": "access",
            **base,
            "remote_addr": req.get("remote_ip") or req.get("client_ip"),
            "method": req.get("method"),
            "host": req.get("host"),
            "path": path,
            "bytes": raw.get("size") if isinstance(raw.get("size"), int) else None,
            "duration": raw.get("duration") if isinstance(raw.get("duration"), (int, float)) else None,
        }
    return {
        "kind": "error",
        **base,
        "level": level,
        "message": redact_text(str(raw.get("msg") or raw.get("error") or ""))[:4000],
    }


def _safe_logs_web(
    host: str | None = None,
    path: str | None = None,
    status: int | None = None,
    since: str | None = None,
    until: str | None = None,
    lines: int = 200,
    **extra: Any,
) -> dict[str, Any]:
    """Read bounded, structured Caddy access/error log records (logs.web)."""
    if extra:
        raise OperationError(f"logs.web does not accept extra args: {sorted(extra)}")
    if host is not None and (not host or len(host) > 253):
        raise OperationError("host must be a bounded non-empty hostname")
    if path is not None and (not path.startswith("/") or len(path) > 4096):
        raise OperationError("path must be an absolute bounded URL path")
    if status is not None and not 100 <= status <= 599:
        raise OperationError("status must be an HTTP status code")
    lower_bound = _parse_introspection_time(since)
    upper_bound = _parse_introspection_time(until)
    if lower_bound and upper_bound and lower_bound > upper_bound:
        raise OperationError("since must not be later than until")
    lower_ts = lower_bound.timestamp() if lower_bound else None
    upper_ts = upper_bound.timestamp() if upper_bound else None
    capped = max(1, min(lines, 2000))
    log_dir = Path(os.environ.get("NOSTRHOST_CADDY_LOG_DIR", CADDY_LOG_DIR))
    if not log_dir.is_dir():
        return {"log_dir": str(log_dir), "entries": [], "warning": "Caddy log directory is unavailable"}
    files = [
        item
        for item in sorted(log_dir.iterdir())
        if item.is_file() and not item.is_symlink()
        and (item.name.endswith(".log") or ".log." in item.name)
        and not item.name.endswith(".gz")
    ]
    entries: list[dict[str, Any]] = []
    for file in files:
        try:
            raw_lines = _tail_file_lines(file, capped)
        except (OSError, UnicodeError):
            continue
        for raw_line in raw_lines:
            entry = _parse_caddy_log_line(raw_line, file.name)
            if entry is None:
                continue
            ts = entry.pop("source_timestamp", None)
            if isinstance(ts, (int, float)):
                if lower_ts is not None and ts < lower_ts:
                    continue
                if upper_ts is not None and ts > upper_ts:
                    continue
            elif lower_ts is not None or upper_ts is not None:
                continue
            if status is not None and entry.get("status") != status:
                continue
            if host is not None and host.lower() not in str(entry.get("host") or entry.get("remote_addr") or entry.get("file", "")).lower():
                continue
            if path is not None and entry.get("path") != path:
                continue
            entries.append(entry)
    return {"log_dir": str(log_dir), "entries": entries[-capped:]}


def _safe_service_history(names: list[str] | None = None, lines: int = 50, **extra: Any) -> dict[str, Any]:
    """systemd state + restart history for one or more YunoHost-managed services."""
    import subprocess

    if extra:
        raise OperationError(f"service.history does not accept extra args: {sorted(extra)}")
    names = names or []
    if not names:
        raise OperationError("service.history requires at least one 'names' entry")
    from yunohost.service import _get_services

    known = _get_services()
    for name in names:
        if name not in known:
            raise OperationError(f"unknown service {name!r}")
    services: dict[str, Any] = {}
    for name in names:
        props: dict[str, str] = {}
        try:
            proc = subprocess.run(
                ["systemctl", "show", name, "--property", "Id,LoadState,ActiveState,SubState,Result,MainPID,ExecMainCode,ExecMainStatus,NRestarts,ActiveEnterTimestamp,InactiveExitTimestamp,FragmentPath"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            for line in proc.stdout.splitlines():
                if "=" in line:
                    key, _, value = line.partition("=")
                    props[key] = value
        except (FileNotFoundError, subprocess.TimeoutExpired):
            props = {}
        services[name] = {
            "status": props.get("ActiveState"),
            "substate": props.get("SubState"),
            "result": props.get("Result"),
            "main_pid": props.get("MainPID"),
            "exit_code": props.get("ExecMainCode"),
            "exit_status": props.get("ExecMainStatus"),
            "restart_count": props.get("NRestarts"),
            "active_since": props.get("ActiveEnterTimestamp"),
            "inactive_since": props.get("InactiveExitTimestamp"),
            "unit_file": props.get("FragmentPath"),
            "recent_errors": _journalctl(name, since=None, until=None, priority="err..emerg", grep=None, lines=max(1, lines)),
        }
    return {"services": services}


# --------------------------------------------------------------------------- #
# backup.delete / domain.cert.* / user.* / groups / permissions

def _safe_backup_delete(name: str = "", **extra: Any) -> dict[str, Any]:
    name = str(name or "").strip()
    if extra:
        raise OperationError(f"backup.delete does not accept extra args: {sorted(extra)}")
    if not name:
        raise OperationError("backup.delete requires a non-empty 'name'")
    if any(c in name for c in ("/", "\\")) or name in (".", ".."):
        raise OperationError(f"invalid backup archive name {name!r}")
    from yunohost.backup import backup_delete

    backup_delete(name=name)
    return {"name": name, "deleted": True}


def _safe_domain_cert_info(domain: str = "", **extra: Any) -> dict[str, Any]:
    domain = str(domain or "").strip()
    if extra:
        raise OperationError(f"domain.cert.info does not accept extra args: {sorted(extra)}")
    if not domain:
        raise OperationError("domain.cert.info requires a 'domain'")
    from yunohost.certificate import certificate_status

    certs = (certificate_status([domain], full=True) or {}).get("certificates") or {}
    return {"domain": domain, "certificate": certs.get(domain)}


def _safe_domain_cert_install(domain: str = "", letsencrypt: bool = True, staging: bool = False, **extra: Any) -> dict[str, Any]:
    domain = str(domain or "").strip()
    if extra:
        raise OperationError(f"domain.cert.install does not accept extra args: {sorted(extra)}")
    if not domain:
        raise OperationError("domain.cert.install requires a 'domain'")
    if staging:
        raise OperationError("staging certificates are not supported: this YunoHost has no ACME staging endpoint configured")
    from yunohost.certificate import certificate_install, certificate_status

    acme_error = None
    try:
        certificate_install(domain_list=[domain], force=True, self_signed=not bool(letsencrypt))
    except Exception as exc:  # noqa: BLE001 - surface ACME failure via acme_error + reconciled status
        acme_error = str(exc)
    certs = (certificate_status([domain], full=True) or {}).get("certificates") or {}
    return {
        "domain": domain,
        "requested": "letsencrypt" if letsencrypt else "selfsigned",
        "acme_error": acme_error,
        "certificate": certs.get(domain),
    }


def _safe_user_update(
    username: str = "",
    mail: str | None = None,
    change_password: str | None = None,
    add_mailforward: list[str] | None = None,
    remove_mailforward: list[str] | None = None,
    add_mailalias: list[str] | None = None,
    remove_mailalias: list[str] | None = None,
    mailbox_quota: str | None = None,
    fullname: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    username = str(username or "").strip()
    if extra:
        raise OperationError(f"user.update does not accept extra args: {sorted(extra)}")
    if not username:
        raise OperationError("user.update requires a non-empty 'username'")
    from yunohost.user import user_update

    user_update(
        username=username,
        mail=mail,
        change_password=change_password,
        add_mailforward=add_mailforward,
        remove_mailforward=remove_mailforward,
        add_mailalias=add_mailalias,
        remove_mailalias=remove_mailalias,
        mailbox_quota=mailbox_quota,
        fullname=fullname,
    )
    return {"username": username}


def _safe_user_group_list(**args: Any) -> dict[str, Any]:
    if args:
        raise OperationError(f"user.group.list does not accept extra args: {sorted(args)}")
    from yunohost.user import user_group_list

    return user_group_list()


def _safe_user_group_create(groupname: str = "", gid: str | None = None, **extra: Any) -> dict[str, Any]:
    groupname = str(groupname or "").strip()
    if extra:
        raise OperationError(f"user.group.create does not accept extra args: {sorted(extra)}")
    if not groupname:
        raise OperationError("user.group.create requires a non-empty 'groupname'")
    from yunohost.user import user_group_create

    user_group_create(groupname=groupname, gid=gid)
    return {"groupname": groupname}


def _safe_user_group_update(groupname: str = "", add: list[str] | None = None, remove: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    groupname = str(groupname or "").strip()
    if extra:
        raise OperationError(f"user.group.update does not accept extra args: {sorted(extra)}")
    if not groupname:
        raise OperationError("user.group.update requires a non-empty 'groupname'")
    from yunohost.user import user_group_update

    user_group_update(groupname=groupname, add=add, remove=remove)
    return {"groupname": groupname}


def _safe_user_group_delete(groupname: str = "", force: bool = False, **extra: Any) -> dict[str, Any]:
    groupname = str(groupname or "").strip()
    if extra:
        raise OperationError(f"user.group.delete does not accept extra args: {sorted(extra)}")
    if not groupname:
        raise OperationError("user.group.delete requires a non-empty 'groupname'")
    from yunohost.user import user_group_delete

    user_group_delete(groupname=groupname, force=bool(force))
    return {"groupname": groupname}


def _safe_user_permission_list(full: bool = False, **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"user.permission.list does not accept extra args: {sorted(extra)}")
    from yunohost.user import user_permission_list

    return user_permission_list(full=bool(full))


def _safe_user_permission_info(permission: str = "", **extra: Any) -> dict[str, Any]:
    permission = str(permission or "").strip()
    if extra:
        raise OperationError(f"user.permission.info does not accept extra args: {sorted(extra)}")
    if not permission:
        raise OperationError("user.permission.info requires a non-empty 'permission'")
    from yunohost.user import user_permission_info

    return user_permission_info(permission=permission)


def _safe_user_permission_add(permission: str = "", names: list[str] | None = None, protected: bool | None = None, **extra: Any) -> dict[str, Any]:
    permission = str(permission or "").strip()
    if extra:
        raise OperationError(f"user.permission.add does not accept extra args: {sorted(extra)}")
    if not permission:
        raise OperationError("user.permission.add requires a non-empty 'permission'")
    names = names or []
    if not names:
        raise OperationError("user.permission.add requires a non-empty 'names'")
    from yunohost.user import user_permission_add

    result = user_permission_add(permission=permission, names=names, protected=protected)
    return {"permission": permission, "result": result}


def _safe_user_permission_remove(permission: str = "", names: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    permission = str(permission or "").strip()
    if extra:
        raise OperationError(f"user.permission.remove does not accept extra args: {sorted(extra)}")
    if not permission:
        raise OperationError("user.permission.remove requires a non-empty 'permission'")
    names = names or []
    if not names:
        raise OperationError("user.permission.remove requires a non-empty 'names'")
    from yunohost.user import user_permission_remove

    result = user_permission_remove(permission=permission, names=names)
    return {"permission": permission, "result": result}


def _safe_user_permission_update(permission: str = "", label: str | None = None, show_tile: bool | None = None, protected: bool | None = None, **extra: Any) -> dict[str, Any]:
    permission = str(permission or "").strip()
    if extra:
        raise OperationError(f"user.permission.update does not accept extra args: {sorted(extra)}")
    if not permission:
        raise OperationError("user.permission.update requires a non-empty 'permission'")
    if protected is not None:
        raise OperationError("user.permission.update does not accept 'protected'; set it via user.permission.add/remove")
    from yunohost.user import user_permission_update

    result = user_permission_update(permission=permission, label=label, show_tile=show_tile)
    return {"permission": permission, "result": result}


# --------------------------------------------------------------------------- #
# catalogue verify

def _verify_catalog_event(event: dict[str, Any]) -> dict[str, Any]:
    """Verify a declaration event: id, signature, kind/tag schema, and that the
    signer is a trusted catalogue publisher. Mirrors the checks the Go CLI's
    ingest/sync apply (internal/protocol/types.go + trust policy)."""
    import hashlib
    import re as _re

    from nostr_sdk import Event

    required = ("pubkey", "created_at", "kind", "tags", "content", "id", "sig")
    if not isinstance(event, dict) or not all(k in event for k in required):
        raise OperationError("event must be a JSON Nostr event object")

    pubkey = str(event["pubkey"])
    if not _re.fullmatch(r"[0-9a-f]{64}", pubkey):
        raise OperationError("event pubkey must be 64 lowercase hex")

    kind = event["kind"]
    if kind not in (32267, 30078):
        raise OperationError(f"event kind {kind} is not a catalogue declaration (expected 32267 or 30078)")

    tags = event["tags"]
    if not isinstance(tags, list) or not all(isinstance(t, list) and len(t) >= 2 for t in tags):
        raise OperationError("event tags must be a list of string arrays")
    tag_map: dict[str, list[str]] = {}
    for t in tags:
        tag_map.setdefault(str(t[0]), []).append(str(t[1]))
    for single in ("d", "version", "commit", "manifest", "content"):
        if len(tag_map.get(single, [])) != 1:
            raise OperationError(f"event must carry exactly one '{single}' tag")
    if not (tag_map.get("platform") or tag_map.get("platforms")):
        raise OperationError("event must carry a 'platform' or 'platforms' tag")
    if not (tag_map.get("repository") or tag_map.get("repo")):
        raise OperationError("event must carry a 'repository' or 'repo' tag")

    if not _re.fullmatch(r"[a-z0-9][a-z0-9_-]*", tag_map["d"][0]):
        raise OperationError("app id 'd' tag is invalid")
    platforms = tag_map.get("platform", []) + tag_map.get("platforms", [])
    if any(p not in ("yunohost", "linux") for p in platforms):
        raise OperationError("platform must be 'yunohost' or 'linux'")
    repos = tag_map.get("repository", []) + tag_map.get("repo", [])
    if any(not _re.fullmatch(r"https://[^/\s]+/[^/\s]+", r) for r in repos):
        raise OperationError("repository must be an HTTPS URL with a path")
    if not _re.fullmatch(r"[0-9a-f]{40,64}", tag_map["commit"][0]):
        raise OperationError("commit must be 40-64 lowercase hex")
    if not _re.fullmatch(r"sha256:[0-9a-f]{64}", tag_map["manifest"][0]):
        raise OperationError("manifest must be sha256:<64 hex>")
    if not _re.fullmatch(r"sha256:[0-9a-f]{64}", tag_map["content"][0]):
        raise OperationError("content must be sha256:<64 hex>")
    content = event["content"]
    try:
        json.loads(content) if isinstance(content, str) else content
    except (json.JSONDecodeError, TypeError):
        raise OperationError("event content must be a JSON object") from None

    serialized = json.dumps([0, pubkey, event["created_at"], kind, tags, content], separators=(",", ":"), ensure_ascii=False).encode()
    if hashlib.sha256(serialized).hexdigest() != event["id"]:
        raise OperationError("event id does not match its canonical serialization")
    try:
        parsed = Event.from_json(json.dumps(event))
    except Exception as exc:  # noqa: BLE001 - normalize SDK parse/verification errors
        raise OperationError("event signature is invalid") from exc
    if not parsed.verify_signature():
        raise OperationError("event signature is invalid")

    trusted = [p.strip() for p in _trusted_publishers().split(",") if p.strip()]
    if pubkey not in trusted:
        raise OperationError(f"event publisher {pubkey[:16]}… is not a trusted catalogue publisher")

    return {
        "app_id": tag_map["d"][0],
        "kind": kind,
        "publisher": pubkey,
        "event_id": event["id"],
        "valid": True,
    }


def _safe_catalog_verify(event_or_naddr: str = "", **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"catalog.verify does not accept extra args: {sorted(extra)}")
    raw = str(event_or_naddr or "").strip()
    if not raw:
        raise OperationError("catalog.verify requires an 'event_or_naddr'")
    if raw.startswith("naddr"):
        raise OperationError("catalog.verify does not yet support naddr; pass the JSON declaration event (no nip19 decoder is installed)")
    try:
        event = json.loads(raw)
    except json.JSONDecodeError:
        raise OperationError("catalog.verify expects a JSON Nostr declaration event")
    return _verify_catalog_event(event)


# --------------------------------------------------------------------------- #
# audit (the signed operation chain on the control relay)

AUDIT_CHAIN_KINDS = (2200, 2201, 2202, 2203, 2204, 2205, 31100, 27236, 27237)
AUDIT_MAX_SCAN = 5000
# The relay REQ ``limit`` counts events across all requested kinds, so a flat
# limit is dominated by the per-operation 2203/2204 pairs and hides the 2200
# requests the audit is meant to surface. Fetch a wider window and trim after
# the newest-first sort instead.
AUDIT_LIST_WINDOW = 400


def _audit_events(kinds: tuple[int, ...] | None = None, limit: int = 100, since: int | None = None) -> list[dict[str, Any]]:
    """Durable audit: the signed operation chain on the control relay."""
    from yunohost.nostr_identity import _operator_config
    from yunohost.nostr_operations import KIND_OPERATION_REQUEST
    from yunohost.nostrhost.events import _e_tag, query_chain_events

    cfg = _operator_config()
    events = query_chain_events(cfg.control_relay, kinds=kinds or AUDIT_CHAIN_KINDS, limit=limit, since=since)
    entries: list[dict[str, Any]] = []
    for event in events:
        content = event.get("content", "")
        try:
            parsed = json.loads(content) if isinstance(content, str) else content
        except (json.JSONDecodeError, TypeError):
            parsed = None
        tool = None
        if isinstance(parsed, dict):
            tool = parsed.get("tool")
        if tool is None and event.get("kind") == KIND_CAPABILITY:
            tool = "capability.grant"
        # A kind-2200 request carries no ``e`` tag: its own id IS the request
        # id (approvals/results reference it via ``#e``).
        request_id = event.get("id") if event.get("kind") == KIND_OPERATION_REQUEST else _e_tag(event)
        entries.append(
            {
                "id": event.get("id"),
                "kind": event.get("kind"),
                "pubkey": event.get("pubkey"),
                "created_at": event.get("created_at"),
                "request_id": request_id,
                "tool": tool,
            }
        )
    entries.sort(key=lambda entry: entry.get("created_at") or 0, reverse=True)  # newest first
    return entries


def _safe_audit_list(limit: int | None = None, **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"audit.list does not accept extra args: {sorted(extra)}")
    limit = limit or 100
    return {"entries": _audit_operations(limit=limit)}


def _audit_operations(limit: int = 100) -> list[dict[str, Any]]:
    """One audit entry per operation: the kind-2200 request with its terminal
    state, plus standalone capability/delegation events.

    A flat raw-event view is dominated by each operation's 2203/2204 tail and
    hides the requests the audit is meant to surface, so the chain is grouped
    by request id (a 2200 request's own id) and the outcome derived from the
    latest chained event (2202 -> REJECTED, 2204.ok -> SUCCEEDED/FAILED, 2203
    -> EXECUTING, 2201 -> APPROVED, else REQUESTED)."""
    from yunohost.nostr_operations import (
        KIND_OPERATION_REQUEST,
        KIND_OPERATION_APPROVAL,
        KIND_OPERATION_REJECTION,
        KIND_EXECUTION_STARTED,
        KIND_EXECUTION_RESULT,
    )

    events = _audit_events(limit=max(limit, AUDIT_LIST_WINDOW))
    chain_kinds = {
        KIND_OPERATION_REQUEST,
        KIND_OPERATION_APPROVAL,
        KIND_OPERATION_REJECTION,
        KIND_EXECUTION_STARTED,
        KIND_EXECUTION_RESULT,
    }
    ops: dict[str, dict[str, Any]] = {}
    standalone: list[dict[str, Any]] = []
    for event in events:
        rid = event.get("request_id")
        if event.get("kind") in chain_kinds and rid:
            ops.setdefault(rid, {"events": []})["events"].append(event)
        else:
            standalone.append(event)

    entries: list[dict[str, Any]] = []
    for rid, op in ops.items():
        tail = sorted(op["events"], key=lambda x: x.get("created_at") or 0)
        req = next((x for x in tail if x["kind"] == KIND_OPERATION_REQUEST), None)
        latest = tail[-1]
        state = "REQUESTED"
        if any(x["kind"] == KIND_OPERATION_REJECTION for x in tail):
            state = "REJECTED"
        elif latest["kind"] == KIND_EXECUTION_RESULT:
            ok = None
            content = latest.get("content", "{}")
            try:
                parsed = json.loads(content) if isinstance(content, str) else content
                ok = bool(parsed.get("ok")) if isinstance(parsed, dict) else None
            except (json.JSONDecodeError, TypeError):
                ok = None
            state = "SUCCEEDED" if ok else ("FAILED" if ok is False else "EXECUTING")
        elif latest["kind"] == KIND_EXECUTION_STARTED:
            state = "EXECUTING"
        elif any(x["kind"] == KIND_OPERATION_APPROVAL for x in tail):
            state = "APPROVED"
        anchor = req or latest
        entries.append(
            {
                "id": anchor.get("id"),
                "kind": KIND_OPERATION_REQUEST,
                "request_id": rid,
                "tool": req.get("tool") if req else None,
                "pubkey": anchor.get("pubkey"),
                "created_at": anchor.get("created_at"),
                "state": state,
            }
        )
    entries.extend(standalone)
    entries.sort(key=lambda entry: entry.get("created_at") or 0, reverse=True)  # newest first
    return entries[:limit]


def _safe_audit_get(audit_id: str = "", **extra: Any) -> dict[str, Any]:
    audit_id = str(audit_id or "").strip()
    if extra:
        raise OperationError(f"audit.get does not accept extra args: {sorted(extra)}")
    if not audit_id:
        raise OperationError("audit.get requires an 'audit_id'")
    for entry in _audit_operations(limit=AUDIT_MAX_SCAN):
        if entry["id"] == audit_id or entry["request_id"] == audit_id:
            return entry
    raise OperationError(f"audit entry {audit_id!r} not found")


# --------------------------------------------------------------------------- #
# registry merge (consumed by yunohost.nostr_operations.TOOLS)

NATIVE_TOOLS: dict[str, ToolSpec] = {
    "system.status": ToolSpec(
        name="system.status", handler=_safe_system_status, scope=SCOPE_SERVER_READ,
        require_approval=False, input_model=SystemStatusArgs,
        description="read-only host snapshot: versions, platform, load average",
    ),
    "app.install": ToolSpec(
        name="app.install", handler=_safe_app_install, scope=SCOPE_APPS_INSTALL,
        input_model=AppInstallArgs, risk=RISK_HIGH, reversibility=REVERSIBLE_WITH_PLAN,
        description="install one app from the legacy catalogue (native packages use package.plan/reconcile)",
    ),
    "app.upgrade": ToolSpec(
        name="app.upgrade", handler=_safe_app_upgrade, scope=SCOPE_APPS_UPGRADE,
        input_model=AppUpgradeArgs, risk=RISK_HIGH, reversibility=REVERSIBLE_WITH_PLAN,
        description="upgrade one installed app",
    ),
    "app.change_url": ToolSpec(
        name="app.change_url", handler=_safe_app_change_url, scope=SCOPE_APPS_UPGRADE,
        input_model=AppChangeUrlArgs, risk=RISK_MEDIUM, reversibility=REVERSIBLE,
        description="move one installed app to a new domain/path in place",
    ),
    "app.config.read": ToolSpec(
        name="app.config.read", handler=_safe_app_config_read, scope=SCOPE_APPS_CONFIG_READ,
        require_approval=False, input_model=AppConfigReadArgs,
        description="read one installed app's config-panel schema and values",
    ),
    "app.config.set": ToolSpec(
        name="app.config.set", handler=_safe_app_config_set, scope=SCOPE_APPS_CONFIG_WRITE,
        input_model=AppConfigSetArgs, risk=RISK_MEDIUM, reversibility=REVERSIBLE,
        description="set one config-panel option on an installed app",
    ),
    "backup.create": ToolSpec(
        name="backup.create", handler=_safe_backup_create, scope=SCOPE_BACKUPS_CREATE,
        input_model=BackupCreateArgs, risk=RISK_MEDIUM, reversibility=REVERSIBLE,
        description="create a local backup archive (apps/system)",
    ),
    "backup.list": ToolSpec(
        name="backup.list", handler=_safe_backup_list, scope=SCOPE_BACKUPS_READ,
        require_approval=False, input_model=BackupListArgs,
        description="list local backup archives",
    ),
    "backup.restore": ToolSpec(
        name="backup.restore", handler=_safe_backup_restore, scope=SCOPE_BACKUPS_RESTORE,
        input_model=BackupRestoreArgs, risk=RISK_HIGH, reversibility=REVERSIBLE_WITH_PLAN,
        description="restore a local backup archive (admin + owner co-signature)",
    ),
    "user.list": ToolSpec(
        name="user.list", handler=_safe_user_list, scope=SCOPE_USERS_READ,
        require_approval=False, input_model=UserListArgs,
        description="list YunoHost user accounts",
    ),
    "user.create": ToolSpec(
        name="user.create", handler=_safe_user_create, scope=SCOPE_USERS_WRITE,
        input_model=UserCreateArgs, risk=RISK_MEDIUM, reversibility=REVERSIBLE,
        description="create a YunoHost user account/mailbox",
    ),
    "user.delete": ToolSpec(
        name="user.delete", handler=_safe_user_delete, scope=SCOPE_USERS_DELETE,
        input_model=UserDeleteArgs, risk=RISK_HIGH, reversibility=IRREVERSIBLE,
        description="delete a YunoHost user account (owner co-signature)",
    ),
    "system.upgrade": ToolSpec(
        name="system.upgrade", handler=_safe_system_upgrade, scope=SCOPE_SYSTEM_UPGRADE,
        input_model=SystemUpgradeArgs, risk=RISK_HIGH, reversibility=REVERSIBLE_WITH_PLAN,
        description="upgrade system (or apps) packages (admin + owner co-signature)",
    ),
    "firewall.list": ToolSpec(
        name="firewall.list", handler=_safe_firewall_list, scope=SCOPE_FIREWALL_READ,
        require_approval=False, input_model=FirewallListArgs,
        description="list firewall rules (tcp/udp, forwarded, raw)",
    ),
    "firewall.open": ToolSpec(
        name="firewall.open", handler=_safe_firewall_open, scope=SCOPE_FIREWALL_WRITE,
        input_model=FirewallOpenArgs, risk=RISK_HIGH, reversibility=REVERSIBLE,
        description="open a firewall port (admin + owner co-signature)",
    ),
    "firewall.close": ToolSpec(
        name="firewall.close", handler=_safe_firewall_close, scope=SCOPE_FIREWALL_WRITE,
        input_model=FirewallCloseArgs, risk=RISK_HIGH, reversibility=REVERSIBLE,
        description="close a firewall port (admin + owner co-signature)",
    ),
    "firewall.reload": ToolSpec(
        name="firewall.reload", handler=_safe_firewall_reload, scope=SCOPE_FIREWALL_WRITE,
        input_model=FirewallReloadArgs, risk=RISK_HIGH, reversibility=REVERSIBLE,
        description="re-apply the current firewall rule set (admin + owner co-signature)",
    ),
    "diagnosis.run": ToolSpec(
        name="diagnosis.run", handler=_safe_diagnosis_run, scope=SCOPE_DIAGNOSIS_READ,
        require_approval=False, input_model=DiagnosisRunArgs,
        description="run YunoHost diagnosis categories and return the cached report",
    ),
    "catalog.list": ToolSpec(
        name="catalog.list", handler=_safe_catalog_list, scope=SCOPE_CATALOG_READ,
        require_approval=False, input_model=CatalogListArgs,
        description="list the trusted native catalogue projection (synced from the control relay)",
    ),
    "catalog.get": ToolSpec(
        name="catalog.get", handler=_safe_catalog_get, scope=SCOPE_CATALOG_READ,
        require_approval=False, input_model=CatalogGetArgs,
        description="resolve one app from the trusted native catalogue projection",
    ),
    "catalog.publish": ToolSpec(
        name="catalog.publish", handler=_safe_catalog_publish, scope=SCOPE_CATALOG_PUBLISH,
        input_model=CatalogPublishArgs, risk=RISK_MEDIUM, reversibility=REVERSIBLE,
        description="re-declare a trusted app under the node's catalogue publisher key and publish it (admin approval)",
    ),
    "updates.check": ToolSpec(
        name="updates.check", handler=_safe_updates_check, scope=SCOPE_SYSTEM_UPDATE,
        require_approval=False, input_model=UpdatesCheckArgs,
        description="pending app/system updates, from cache only (no network refresh)",
    ),
    "updates.refresh": ToolSpec(
        name="updates.refresh", handler=_safe_updates_refresh, scope=SCOPE_SYSTEM_UPDATE,
        require_approval=False, input_model=UpdatesRefreshArgs,
        description="refresh cached update metadata (apt cache, app catalog sources)",
    ),
    "system.migrations": ToolSpec(
        name="system.migrations", handler=_safe_system_migrations, scope=SCOPE_SYSTEM_UPDATE,
        require_approval=False, input_model=SystemMigrationsArgs,
        description="list known migrations (pending/done filters) and their recorded state",
    ),
    "system.migrate": ToolSpec(
        name="system.migrate", handler=_safe_system_migrate, scope=SCOPE_SYSTEM_MIGRATE,
        input_model=SystemMigrateArgs, risk=RISK_HIGH, reversibility=IRREVERSIBLE,
        description="run/skip/force-rerun YunoHost migrations (admin + owner co-signature)",
    ),
    "service.history": ToolSpec(
        name="service.history", handler=_safe_service_history, scope=SCOPE_SERVICES_READ,
        require_approval=False, input_model=ServiceHistoryArgs,
        description="systemd state + restart history for one or more services",
    ),
    "logs.read": ToolSpec(
        name="logs.read", handler=_safe_logs_read, scope=SCOPE_LOGS_READ,
        require_approval=False, input_model=LogsReadArgs,
        description="query a deliberately allowlisted set of host journals (kernel/ssh/fail2ban/systemd/caddy/nostr daemons)",
    ),
    "logs.web": ToolSpec(
        name="logs.web", handler=_safe_logs_web, scope=SCOPE_LOGS_READ,
        require_approval=False, input_model=LogsWebArgs,
        description="read bounded, structured Caddy access/error log records (/var/log/caddy/access.log)",
    ),
    "backup.delete": ToolSpec(
        name="backup.delete", handler=_safe_backup_delete, scope=SCOPE_BACKUPS_DELETE,
        input_model=BackupDeleteArgs, risk=RISK_HIGH, reversibility=IRREVERSIBLE,
        description="delete one local backup archive (admin + owner co-signature)",
    ),
    "domain.cert.info": ToolSpec(
        name="domain.cert.info", handler=_safe_domain_cert_info, scope=SCOPE_DOMAINS_READ,
        require_approval=False, input_model=DomainCertInfoArgs,
        description="read-only certificate status for an already-registered domain",
    ),
    "domain.cert.install": ToolSpec(
        name="domain.cert.install", handler=_safe_domain_cert_install, scope=SCOPE_DOMAINS_WRITE,
        input_model=DomainCertInstallArgs, risk=RISK_MEDIUM, reversibility=REVERSIBLE,
        description="issue/renew a certificate for an already-registered domain (admin confirmation)",
    ),
    "user.update": ToolSpec(
        name="user.update", handler=_safe_user_update, scope=SCOPE_USERS_WRITE,
        input_model=UserUpdateArgs, risk=RISK_MEDIUM, reversibility=REVERSIBLE,
        description="update an existing user's mail/password/quota/fullname (only fields passed change)",
    ),
    "user.group.list": ToolSpec(
        name="user.group.list", handler=_safe_user_group_list, scope=SCOPE_USERS_READ,
        require_approval=False, input_model=UserGroupListArgs,
        description="list YunoHost user groups and their members",
    ),
    "user.group.create": ToolSpec(
        name="user.group.create", handler=_safe_user_group_create, scope=SCOPE_USERS_WRITE,
        input_model=UserGroupCreateArgs, risk=RISK_MEDIUM, reversibility=REVERSIBLE,
        description="create a new user group",
    ),
    "user.group.update": ToolSpec(
        name="user.group.update", handler=_safe_user_group_update, scope=SCOPE_USERS_WRITE,
        input_model=UserGroupUpdateArgs, risk=RISK_MEDIUM, reversibility=REVERSIBLE,
        description="add/remove usernames from a group (the 'admins' group carries owner co-signature)",
    ),
    "user.group.delete": ToolSpec(
        name="user.group.delete", handler=_safe_user_group_delete, scope=SCOPE_USERS_DELETE,
        input_model=UserGroupDeleteArgs, risk=RISK_HIGH, reversibility=IRREVERSIBLE,
        description="delete a user group and its permission grants (owner co-signature)",
    ),
    "user.permission.list": ToolSpec(
        name="user.permission.list", handler=_safe_user_permission_list, scope=SCOPE_USERS_READ,
        require_approval=False, input_model=UserPermissionListArgs,
        description="list app/system permissions and allowed users/groups",
    ),
    "user.permission.info": ToolSpec(
        name="user.permission.info", handler=_safe_user_permission_info, scope=SCOPE_USERS_READ,
        require_approval=False, input_model=UserPermissionInfoArgs,
        description="one permission's full info (allowed users/groups, label, show_tile, protected, URLs)",
    ),
    "user.permission.add": ToolSpec(
        name="user.permission.add", handler=_safe_user_permission_add, scope=SCOPE_USERS_WRITE,
        input_model=UserPermissionAddArgs, risk=RISK_MEDIUM, reversibility=REVERSIBLE,
        description="grant users/groups access to an app permission (owner co-signature)",
    ),
    "user.permission.remove": ToolSpec(
        name="user.permission.remove", handler=_safe_user_permission_remove, scope=SCOPE_USERS_WRITE,
        input_model=UserPermissionRemoveArgs, risk=RISK_MEDIUM, reversibility=REVERSIBLE,
        description="revoke users/groups access to an app permission (owner co-signature)",
    ),
    "user.permission.update": ToolSpec(
        name="user.permission.update", handler=_safe_user_permission_update, scope=SCOPE_USERS_WRITE,
        input_model=UserPermissionUpdateArgs, risk=RISK_MEDIUM, reversibility=REVERSIBLE,
        description="update a permission's label/tile visibility, not membership (owner co-signature)",
    ),
    "catalog.verify": ToolSpec(
        name="catalog.verify", handler=_safe_catalog_verify, scope=SCOPE_CATALOG_VERIFY,
        require_approval=False, input_model=CatalogVerifyArgs,
        description="verify a catalogue declaration event: id, signature, schema and trusted publisher",
    ),
    "audit.list": ToolSpec(
        name="audit.list", handler=_safe_audit_list, scope=SCOPE_AUDIT_READ,
        input_model=AuditListArgs, risk=RISK_LOW, reversibility=REVERSIBLE,
        description="list signed operation-chain audit entries (one per operation, with terminal state), newest first (owner co-signature per call)",
    ),
    "audit.get": ToolSpec(
        name="audit.get", handler=_safe_audit_get, scope=SCOPE_AUDIT_READ,
        input_model=AuditGetArgs, risk=RISK_LOW, reversibility=REVERSIBLE,
        description="fetch one audit entry by request id (the kind-2200 id) or event id (owner co-signature per call)",
    ),
}
