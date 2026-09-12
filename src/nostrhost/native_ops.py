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

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from yunohost.nostr_operations import (
    OperationError,
    RISK_HIGH,
    RISK_MEDIUM,
    REVERSIBLE,
    REVERSIBLE_WITH_PLAN,
    IRREVERSIBLE,
    SCOPE_APPS_CONFIG_READ,
    SCOPE_APPS_CONFIG_WRITE,
    SCOPE_APPS_INSTALL,
    SCOPE_APPS_UPGRADE,
    SCOPE_BACKUPS_CREATE,
    SCOPE_BACKUPS_READ,
    SCOPE_BACKUPS_RESTORE,
    SCOPE_DIAGNOSIS_READ,
    SCOPE_FIREWALL_READ,
    SCOPE_FIREWALL_WRITE,
    SCOPE_SERVER_READ,
    SCOPE_SYSTEM_UPGRADE,
    SCOPE_USERS_DELETE,
    SCOPE_USERS_READ,
    SCOPE_USERS_WRITE,
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
}
