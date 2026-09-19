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

import datetime as _dt
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

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
    SCOPE_BACKUPS_WRITE,
    SCOPE_DIAGNOSIS_READ,
    SCOPE_DIAGNOSIS_WRITE,
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
    SCOPE_SYSTEM_POWER,
    SCOPE_SETTINGS_READ,
    SCOPE_SETTINGS_WRITE,
    KIND_CAPABILITY,
    ToolSpec,
    _Strict,
)


def _catalog_relay_arg(explicit: str = "") -> str:
    """Resolve public catalogue relays while retaining the private local target."""
    if explicit.strip():
        return explicit.strip()
    from nostrhost.connectivity import effective

    targets = ["ws://127.0.0.1:4848", *effective()["relays"]["catalogue"]]
    return ",".join(dict.fromkeys(targets))


class SystemStatusArgs(_Strict):
    pass


class ProjectionStatusArgs(_Strict):
    name: str | None = None


class ServiceStatusArgs(_Strict):
    pass


class ListReadArgs(_Strict):
    family: str


class ListPublishArgs(_Strict):
    family: str
    values: list[str] | None = None
    settings: dict[str, Any] | None = None
    public: bool = False


class PolicyReadArgs(_Strict):
    family: str


class PolicyPublishArgs(_Strict):
    family: str
    document: dict[str, Any]
    revision: int = 1


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
    tag: str = ""
    paths: list[str] = Field(default_factory=list, description="paths to snapshot; empty uses the configured restic paths")
    host: str = ""


class BackupListArgs(_Strict):
    tag: str = ""
    host: str = ""


class BackupInfoArgs(_Strict):
    snapshot: str = Field(description="snapshot id or unique prefix")


class BackupRestoreArgs(_Strict):
    snapshot: str = Field(description="snapshot id or unique prefix to restore")
    target: str = Field(default="", description="restore target base directory; empty uses the configured restore_target")
    include: list[str] = Field(default_factory=list, description="optional paths within the snapshot to restore")


class BackupDeleteArgs(_Strict):
    snapshot: str = Field(default="", description="snapshot id(s) to forget (comma/space separated)")
    apply_retention: bool = Field(default=False, description="apply the configured retention policy instead of named snapshots")
    prune: bool = True


class BackupCheckArgs(_Strict):
    pass


class BackupStatsArgs(_Strict):
    pass


class BackupPolicyReadArgs(_Strict):
    pass


class BackupScheduleArgs(_Strict):
    pass


class BackupPolicySetArgs(_Strict):
    retention: dict[str, int] | None = Field(default=None, description="keep_last/keep_daily/keep_weekly/keep_monthly/keep_yearly counts")
    schedule_enabled: bool | None = None
    schedule_calendar: str | None = Field(default=None, description="systemd OnCalendar value, e.g. 'daily'")


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
    full: bool = Field(
        default=False,
        description="keep timestamp/cached_for and per-item meta/ignored fields (needed to build an ignore filter)",
    )


class DiagnosisIgnoredArgs(_Strict):
    pass


class DiagnosisIgnoreArgs(_Strict):
    filter: list[str] = Field(
        description="[category, 'key1=value1', 'key2=value2', ...] — the category to ignore, optionally narrowed by criteria matching an existing issue"
    )


class DiagnosisUnignoreArgs(_Strict):
    filter: list[str] = Field(description="the same [category, 'key=value', ...] filter previously passed to diagnosis.ignore")


class CatalogListArgs(_Strict):
    pass


class CatalogGetArgs(_Strict):
    app_id: str = Field(..., description="the app id to resolve from the trusted projection")


class CatalogPublishArgs(_Strict):
    app_id: str = Field(..., description="the app id to re-declare and publish under the node's publisher key")
    relays: str = Field(
        default="",
        description="comma-separated relay ws:// or wss:// URLs to publish the declaration to",
    )


class CatalogDeclareArgs(_Strict):
    package: dict[str, Any] = Field(..., description="a native package manifest, the same object sent to package.plan")
    repository: str = Field(..., description="a URL where this exact manifest content is published, for provenance")
    relays: str = Field(
        default="",
        description="comma-separated relay ws:// or wss:// URLs to publish the declaration to",
    )


class CatalogCandidatesArgs(_Strict):
    pass


class CatalogAttestArgs(_Strict):
    app_id: str = Field(..., description="the app id being endorsed")
    publisher: str = Field(..., description="the declaration publisher's hex pubkey being endorsed")
    claim: Literal["recommend", "tested"] = Field(..., description="the endorsement claim")
    comment: str = Field(default="", description="an optional free-text comment attached to the endorsement")
    relays: str = Field(
        default="",
        description="comma-separated relay ws:// or wss:// URLs to publish the endorsement to",
    )


class CatalogHistoryArgs(_Strict):
    pass


class CatalogTrustArgs(_Strict):
    attestation_policy: Literal["off", "prefer", "require"] = Field(
        default="off", description="the CI-attestation policy mode to evaluate every declaration against"
    )
    min_attestations: int = Field(default=0, ge=0, description="minimum acceptable attestations to count a revision verified (0 = default of 1)")
    required_checks: list[str] = Field(default_factory=list, description="required CI check names; empty means any overall pass result is acceptable")
    trusted_verifiers: list[str] = Field(default_factory=list, description="trusted attestation verifier keys; empty means trust any verifier")


class CatalogReverifyArgs(_Strict):
    app_id: str = Field(..., description="the app id to independently re-check against its declared repository and commit")


class CatalogProfileGetArgs(_Strict):
    pass


class CatalogProfileSetArgs(_Strict):
    name: str = Field(default="", description="the catalogue publisher's display name")
    about: str = Field(default="", description="a short bio for the catalogue publisher")
    picture: str = Field(default="", description="a picture URL for the catalogue publisher")
    nip05: str = Field(default="", description="a NIP-05 identifier for the catalogue publisher")
    website: str = Field(default="", description="a website URL for the catalogue publisher")
    relays: str = Field(
        default="",
        description="comma-separated relay ws:// or wss:// URLs to publish the profile to",
    )


class CatalogAnnounceArgs(_Strict):
    app_id: str = Field(..., description="the app id to announce, must be one of this node's own published declarations")
    relays: str = Field(
        default="",
        description="comma-separated relay ws:// or wss:// URLs to publish the announcement to",
    )


class CatalogAnnouncementsArgs(_Strict):
    pass


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


class SystemRebootArgs(_Strict):
    pass


class SystemShutdownArgs(_Strict):
    pass


class SettingsListArgs(_Strict):
    full: bool = False


class SettingsGetArgs(_Strict):
    key: str
    full: bool = False
    export: bool = False


class SettingsSetArgs(_Strict):
    key: str
    value: Any = None


class SettingsResetArgs(_Strict):
    key: str


class SettingsResetAllArgs(_Strict):
    pass


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


class LogsProblemsArgs(_Strict):
    host: str | None = None
    path: str | None = None
    status: int | None = None
    code: str | None = None
    kind: str | None = None
    source: str | None = None
    request_id: str | None = None
    since: str | None = None
    until: str | None = None
    lines: int = 200


class DomainCertInfoArgs(_Strict):
    domain: str = Field(..., description="already-registered domain to report certificate status for")


class DomainCertInstallArgs(_Strict):
    domain: str = Field(..., description="already-registered domain to issue/renew a certificate for")
    letsencrypt: bool = True
    staging: bool = False


class DomainPrimarySetArgs(_Strict):
    domain: str
    plan_sha256: str


class NostrConnectivitySetArgs(_Strict):
    configuration: dict[str, Any]
    plan_sha256: str


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

def _safe_projection_status(**args: Any) -> dict[str, Any]:
    """Read-only projection health: applied revision, freshness, quarantine.

    Reads the durable cursor files under /var/lib/nostrhost/projections (WP2),
    so it works cross-process without calling into the daemons.
    """
    name = args.pop("name", None)
    if args:
        raise OperationError(f"projection.status does not accept extra args: {sorted(args)}")
    from yunohost.nostr_projector import read_status_dir

    rows = read_status_dir()
    if name is not None:
        rows = [row for row in rows if row["name"] == name]
    return {"projections": rows}


def _safe_service_config_status(**args: Any) -> dict[str, Any]:
    """Read-only WP7 service-config provenance + drift for every generated file.

    Compares each rendered service config against its ``.source.json`` sidecar
    so manual edits are detected without touching the daemons.
    """
    if args:
        raise OperationError(f"service.config.status does not accept extra args: {sorted(args)}")
    from yunohost.nostrhost.service_projection import check_all_drift

    files = check_all_drift()
    return {"service_configs": files, "drifted": [row["name"] for row in files if row["drifted"]]}


_LIST_FAMILIES = {
    "trusted-publishers",
    "approved-repositories",
    "blocked-relays",
    "blocked-site-owners",
    "preferred-relays",
    "portal-settings",
}


def _safe_list_read(**args: Any) -> dict[str, Any]:
    """Read the effective view of one WP4 list/preference family."""
    family = str(args.pop("family", "")).strip()
    if args:
        raise OperationError(f"list.read does not accept extra args: {sorted(args)}")
    if family not in _LIST_FAMILIES:
        raise OperationError(f"unknown list family: {family}")
    from nostrhost import list_projection as lp

    if family == "trusted-publishers":
        return {"family": family, "entries": lp.trusted_publishers()}
    if family == "approved-repositories":
        return {"family": family, "entries": lp.approved_repositories()}
    if family == "blocked-relays":
        return {"family": family, "entries": lp.blocked_relays()}
    if family == "blocked-site-owners":
        return {"family": family, "entries": lp.blocked_site_owners()}
    if family == "preferred-relays":
        return {"family": family, "entries": lp.preferred_relays()}
    return {"family": family, "settings": lp.portal_settings()}


def _safe_list_publish(**args: Any) -> dict[str, Any]:
    """Publish an operator-authored host list / settings document (WP4).

    Only the operator-owned families are publishable here; the per-user
    preference family is self-service on the portal and is deliberately not
    reachable through the operator chain, so this tool can never act on a
    user's behalf.
    """
    family = str(args.pop("family", "")).strip()
    values = args.pop("values", None)
    settings = args.pop("settings", None)
    args.pop("public", None)
    if args:
        raise OperationError(f"list.publish does not accept extra args: {sorted(args)}")
    from nostrhost import list_projection as lp

    if family == "trusted-publishers":
        event = lp.import_trusted_publishers([str(v) for v in (values or [])])
    elif family == "approved-repositories":
        event = lp.import_approved_repositories([str(v) for v in (values or [])])
    elif family in ("blocked-relays", "blocked-site-owners"):
        from nostrhost.nsites import blocklist

        if family == "blocked-site-owners":
            result = blocklist.publish_blocklist([str(v) for v in (values or [])])
        else:
            result = _publish_url_list(10006, [str(v) for v in (values or [])])
        return {"family": family, "result": result}
    elif family == "portal-settings":
        result = _publish_settings(30078, "nostrhost:portal-settings", dict(settings or {}))
        return {"family": family, "result": result}
    else:
        raise OperationError(f"list family is not operator-publishable: {family}")
    return {"family": family, "event_id": event["id"]}


def _safe_policy_read(**args: Any) -> dict[str, Any]:
    """Read the effective folded view of one WP6 policy family."""
    family = str(args.pop("family", "")).strip()
    if args:
        raise OperationError(f"policy.read does not accept extra args: {sorted(args)}")
    from nostrhost import policy_projection as pp

    if family == pp.NOTIFICATION_RULES:
        return {"family": family, "document": pp.notification_rules()}
    if family == pp.RESTIC_POLICY:
        return {"family": family, "document": pp.restic_policy()}
    if family == pp.HOST_POLICY:
        return {"family": family, "document": pp.host_policy()}
    raise OperationError(f"unknown policy family: {family}")


def _safe_policy_publish(**args: Any) -> dict[str, Any]:
    """Publish an operator-authored kind-31101 policy declaration (WP6).

    The document carries only desired, non-secret state; Restic repo URL +
    password and provider tokens are never part of a policy document.
    """
    family = str(args.pop("family", "")).strip()
    document = args.pop("document", None)
    revision = int(args.pop("revision", 1))
    if args:
        raise OperationError(f"policy.publish does not accept extra args: {sorted(args)}")
    if not isinstance(document, dict):
        raise OperationError("policy.publish requires a document object")
    from nostrhost import policy_projection as pp

    if family == pp.NOTIFICATION_RULES:
        spec = pp.spec_for_name(pp.NOTIFICATION_RULES)
    elif family == pp.RESTIC_POLICY:
        spec = pp.spec_for_name(pp.RESTIC_POLICY)
    elif family == pp.HOST_POLICY:
        spec = pp.spec_for_name(pp.HOST_POLICY)
    else:
        raise OperationError(f"unknown policy family: {family}")
    event = pp.publish_policy_document(spec, document, revision=revision)
    return {"family": family, "event_id": event["id"]}


def _publish_url_list(kind: int, urls: list[str]) -> dict[str, Any]:
    from yunohost.nostr_identity import _operator_config, _sign_event, publish_to_relay

    cfg = _operator_config(None, None)
    event = _sign_event(cfg.operator_sk, cfg.operator_pubkey, kind, "", [["r", url] for url in sorted(set(urls))])
    publish_to_relay(cfg.control_relay, event)
    return {"event_id": event["id"], "urls": sorted(set(urls))}


def _publish_settings(kind: int, coordinate: str, settings: dict[str, Any]) -> dict[str, Any]:
    import json as _json

    from yunohost.nostr_identity import _operator_config, _sign_event, publish_to_relay

    cfg = _operator_config(None, None)
    event = _sign_event(cfg.operator_sk, cfg.operator_pubkey, kind, _json.dumps(settings), [["d", coordinate]])
    publish_to_relay(cfg.control_relay, event)
    return {"event_id": event["id"], "coordinate": coordinate}


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


def _restic() -> Any:
    """The configured Restic client, or an OperationError when unset.

    Restic is the data-recovery system (§7.4): the backup.* tools operate on
    Restic snapshots, not the retired YunoHost archive format."""
    from yunohost.nostr_restic import ResticError, restic_client

    try:
        return restic_client()
    except ResticError as exc:
        raise OperationError(str(exc)) from exc


def _restic_config() -> Any:
    from yunohost.nostr_restic import load_restic_config

    conf = load_restic_config()
    if conf is None:
        raise OperationError("restic is not configured (missing /etc/nostrhost/restic.toml)")
    return conf


def _safe_backup_create(tag: str = "", paths: list[str] | None = None, host: str = "", **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"backup.create does not accept extra args: {sorted(extra)}")
    client = _restic()
    targets = [str(p) for p in (paths or [])]
    if not targets:
        targets = list(_restic_config().paths)
    snapshot = client.snapshot(targets, tag=str(tag or "").strip() or None, host=str(host or "").strip() or None)
    return {"snapshot": snapshot, "paths": targets}


def _safe_backup_list(tag: str = "", host: str = "", **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"backup.list does not accept extra args: {sorted(extra)}")
    return {"snapshots": _restic().snapshots(tag=str(tag or "").strip() or None, host=str(host or "").strip() or None)}


def _safe_backup_info(snapshot: str = "", **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"backup.info does not accept extra args: {sorted(extra)}")
    sid = str(snapshot or "").strip()
    if not sid:
        raise OperationError("backup.info requires a non-empty 'snapshot'")
    for snap in _restic().snapshots():
        if str(snap.get("id", "")) == sid or str(snap.get("short_id", "")) == sid or str(snap.get("id", "")).startswith(sid):
            return snap
    raise OperationError(f"no snapshot matching {sid!r}")


def _safe_backup_restore(snapshot: str = "", target: str = "", include: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"backup.restore does not accept extra args: {sorted(extra)}")
    sid = str(snapshot or "").strip()
    if not sid:
        raise OperationError("backup.restore requires a non-empty 'snapshot'")
    conf = _restic_config()
    dest = str(target or "").strip() or conf.restore_target
    result = _restic().restore(sid, dest, include=[str(p) for p in (include or [])])
    return {"snapshot": sid, "target": dest, "include": [str(p) for p in (include or [])], "result": result}


def _safe_backup_check(**extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"backup.check does not accept extra args: {sorted(extra)}")
    return _restic().check()


def _safe_backup_stats(**extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"backup.stats does not accept extra args: {sorted(extra)}")
    return {"stats": _restic().stats()}


def _safe_backup_policy_read(**extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"backup.policy.read does not accept extra args: {sorted(extra)}")
    conf = _restic_config()
    # repo is a location, never the password: safe to surface to an admin.
    return {
        "retention": conf.retention,
        "schedule": {"enabled": conf.schedule_enabled, "calendar": conf.schedule_calendar},
        "repo": conf.repo,
        "paths": list(conf.paths),
        "host": conf.host,
        "tag": conf.tag,
    }


def _safe_backup_schedule(**extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"backup.schedule does not accept extra args: {sorted(extra)}")
    conf = _restic_config()
    timer: dict[str, Any] = {}
    try:
        res = subprocess.run(
            ["systemctl", "show", "nostrhost-backup.timer",
             "--property", "Id,LoadState,ActiveState,SubState,LastTriggerUSec,NextElapseUSecRealtime"],
            capture_output=True, text=True, timeout=10,
        )
        for line in res.stdout.splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                timer[key.strip()] = value.strip()
    except (OSError, subprocess.SubprocessError) as exc:  # noqa: BLE001 - best-effort status
        timer = {"error": str(exc)}
    return {
        "enabled": conf.schedule_enabled,
        "calendar": conf.schedule_calendar,
        "active_state": timer.get("ActiveState", "unknown"),
        "sub_state": timer.get("SubState", ""),
        "last_trigger": timer.get("LastTriggerUSec", ""),
        "next_elapse": timer.get("NextElapseUSecRealtime", ""),
    }


def _safe_backup_policy_set(
    retention: dict[str, int] | None = None,
    schedule_enabled: bool | None = None,
    schedule_calendar: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    if extra:
        raise OperationError(f"backup.policy.set does not accept extra args: {sorted(extra)}")
    from yunohost.nostr_restic import load_restic_config, write_restic_policy

    # WP6: the desired Restic policy is now a kind-31101 document; the file is
    # the rendered compatibility output the projector keeps current. Publish
    # the document first so an event always records the operator's intent,
    # then write the rendered file immediately (the daemon may not have folded
    # the event yet) and keep the timer drop-in in sync.
    from nostrhost import policy_projection as pp

    try:
        current = load_restic_config()
        doc = {
            "paths": list(current.paths) if current is not None else [],
            "retention": {str(k): int(v) for k, v in (retention or {}).items() if v}
            if retention is not None
            else (dict(current.retention) if current is not None else {}),
            "schedule": {
                "enabled": schedule_enabled if schedule_enabled is not None else (current.schedule_enabled if current is not None else False),
                "calendar": str(schedule_calendar or "") or (current.schedule_calendar if current is not None else "daily"),
            },
        }
        try:
            spec = pp.spec_for_name(pp.RESTIC_POLICY)
            pp.publish_policy_document(spec, doc)
        except Exception:  # noqa: BLE001 - an offline relay must not fail policy.set
            logger = __import__("logging").getLogger("nostr-native-ops")
            logger.warning("backup.policy.set: failed to publish 31101 restic-policy; continuing with file write")
    except Exception:  # noqa: BLE001 - config may be absent; fall through to the file path
        pass

    conf = write_restic_policy(
        retention=retention,
        schedule_enabled=schedule_enabled,
        schedule_calendar=schedule_calendar,
    )
    if schedule_calendar:
        try:
            dropin = Path("/etc/systemd/system/nostrhost-backup.timer.d/calendar.conf")
            dropin.parent.mkdir(parents=True, exist_ok=True)
            dropin.write_text(f"[Timer]\nOnCalendar=\nOnCalendar={schedule_calendar}\n")
            subprocess.run(["systemctl", "daemon-reload"], capture_output=True, text=True, timeout=30, check=False)
        except (OSError, subprocess.SubprocessError):  # noqa: BLE001 - best-effort
            pass
    if schedule_enabled is not None:
        action = "enable" if schedule_enabled else "disable"
        try:
            subprocess.run(
                ["systemctl", action, "--now", "nostrhost-backup.timer"],
                capture_output=True, text=True, timeout=30, check=False,
            )
        except (OSError, subprocess.SubprocessError):  # noqa: BLE001 - unit may not exist in tests
            pass
    return {
        "retention": conf.retention,
        "schedule": {"enabled": conf.schedule_enabled, "calendar": conf.schedule_calendar},
    }


def _safe_user_list(**extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"user.list does not accept extra args: {sorted(extra)}")
    from yunohost.user import user_list

    return user_list(fields=["username", "fullname", "mail", "mailbox-quota", "groups"])


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


def _safe_diagnosis_run(categories: list[str] | None = None, force: bool = False, full: bool = False, **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"diagnosis.run does not accept extra args: {sorted(extra)}")
    categories = categories or []
    # diagnosis_run is decorated with yunohost.log's ActionLogger, which reads
    # Moulinette.interface.type. The nostr-*d daemons initialise the headless
    # interface at startup; the HTTP API / MCP processes do not, so without
    # this every diagnosis.run raised AttributeError: 'NoneType' object has no
    # attribute 'type' -> 500. Idempotent (no-op once the interface is set).
    from yunohost.nostr_identity import _init_headless_yunohost

    _init_headless_yunohost()
    from yunohost.diagnosis import diagnosis_run, diagnosis_show

    diagnosis_run(categories=categories, force=bool(force))
    try:
        return diagnosis_show(categories=categories, full=bool(full))
    except Exception:  # noqa: BLE001 - a missing cache is an empty report, not an error
        return {}


def _safe_diagnosis_ignored(**extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"diagnosis.ignored does not accept extra args: {sorted(extra)}")
    from yunohost.diagnosis import diagnosis_ignore

    return diagnosis_ignore(filter=[], list=True)


def _safe_diagnosis_ignore(filter: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    filter = filter or []
    if extra:
        raise OperationError(f"diagnosis.ignore does not accept extra args: {sorted(extra)}")
    if not filter:
        raise OperationError("diagnosis.ignore requires a non-empty 'filter'")
    from yunohost.diagnosis import diagnosis_ignore

    diagnosis_ignore(filter=filter, list=False)
    return {"filter": filter, "ignored": True}


def _safe_diagnosis_unignore(filter: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    filter = filter or []
    if extra:
        raise OperationError(f"diagnosis.unignore does not accept extra args: {sorted(extra)}")
    if not filter:
        raise OperationError("diagnosis.unignore requires a non-empty 'filter'")
    from yunohost.diagnosis import diagnosis_unignore

    diagnosis_unignore(filter=filter)
    return {"filter": filter, "unignored": True}


# --------------------------------------------------------------------------- #
# catalogue surface (MCP transition Phase 5) — the native catalog.* tools.

CATALOG_BIN = os.environ.get("NOSTRHOST_CATALOG_BIN", "/usr/bin/nostrhost-catalog")
CATALOG_STATE = os.environ.get("NOSTRHOST_CATALOG_STATE", "/var/lib/nostrhost/catalogue.json")


def _trusted_publishers() -> str:
    """Comma-separated trusted publisher pubkeys.

    WP4: the authoritative source is the ``trusted-publishers`` people-set
    projected into ``/etc/nostrhost/lists.json`` (and rendered into
    ``catalogue.env``). For compatibility this still prefers an explicit
    ``catalogue.env`` value, then the projected set, then the node's own
    publisher key (operator.toml) — so effective trust is unchanged through
    the cutover.
    """
    env_path = Path(os.environ.get("NOSTRHOST_CATALOGUE_ENV", "/etc/nostrhost/catalogue.env"))
    try:
        for line in env_path.read_text().splitlines():
            if line.startswith("NOSTRHOST_CATALOG_PUBLISHERS="):
                value = line.split("=", 1)[1].strip()
                if value:
                    return value
    except OSError:
        pass
    try:
        from nostrhost.list_projection import trusted_publishers

        projected = trusted_publishers()
        if projected:
            return ",".join(projected)
    except Exception:  # noqa: BLE001 - projection is best-effort; fall back to the operator key
        pass
    from yunohost.nostr_identity import _operator_config

    return _operator_config().publisher_pubkey


def _catalog_cli(subcommand: list[str], stdin_data: bytes | None = None, extra_flags: list[str] | None = None) -> dict[str, Any]:
    """Run the native catalogue CLI and parse its JSON stdout.

    extra_flags are inserted before the subcommand name - the Go CLI's flag
    package stops parsing flags at the first positional argument, so a flag
    like --app-id or --attestation-policy that a specific subcommand reads
    must precede it, not follow it.
    """
    import subprocess

    cmd = [CATALOG_BIN, "--publishers", _trusted_publishers(), "--state", CATALOG_STATE, *(extra_flags or []), *subcommand]
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

    result = _catalog_cli(["--relay", _catalog_relay_arg(relays), "publish"], json.dumps(event).encode())
    ingest = _catalog_cli(["ingest"], json.dumps(event).encode())
    return {
        "app_id": app_id,
        "publisher_pubkey": cfg.publisher_pubkey,
        "event_id": event["id"],
        "published": result,
        "ingested": ingest,
    }


def _safe_catalog_declare(package: dict[str, Any] | None = None, repository: str = "", relays: str = "", **extra: Any) -> dict[str, Any]:
    """Declare a brand-new app in the catalogue from an authored native
    package manifest - the missing link between the package-authoring
    screen's "review plan" and actually getting the package installable by
    anyone else.

    Unlike catalog.publish (which re-declares an *existing* trusted
    catalogue entry), this builds a fresh kind-32267 declaration from a
    manifest that has never been declared before. It reuses package.plan's
    own validation and its exact manifest_sha256 (package_plan_envelope's
    canonical-JSON hash) as the authoritative provenance hash, so a
    declaration can never drift from what package.plan would compute for
    the same manifest.

    This does not (yet) independently re-clone `repository` to confirm the
    manifest actually lives there the way catalog.reverify does for
    YunoHost-style git packages - the Go catalogue library's repository
    verification assumes a manifest.toml layout, not this project's native
    JSON package schema. `repository` is provenance the admin asserts, not
    yet independently checked; commit/manifest/content hashes are all the
    manifest's own content hash, since a native package has no separate
    build artifact distinct from its manifest.
    """
    if extra:
        raise OperationError(f"catalog.declare does not accept extra args: {sorted(extra)}")
    if not isinstance(package, dict):
        raise OperationError("catalog.declare requires a package object")
    if not repository:
        raise OperationError("catalog.declare requires a repository URL where this exact manifest is published")

    from nostrhost.package_engine import package_plan_envelope

    try:
        envelope = package_plan_envelope(package)
    except (TypeError, ValueError) as exc:
        raise OperationError(f"invalid native package: {exc}") from exc

    app_id = envelope["package"]["id"]
    version = envelope["package"]["version"]
    manifest_hash = envelope["manifest_sha256"]

    from yunohost.nostr_identity import _operator_config, _sign_event

    cfg = _operator_config()
    tags = [
        ["d", app_id],
        # Native NostrHost packages are generic Linux packages, not YunoHost
        # apps; the catalogue protocol only accepts "yunohost" or "linux"
        # (libs/nostrhost-catalog/internal/protocol/types.go ParseAppDeclaration),
        # so declaring "native" made every native declaration fail to ingest.
        ["platform", "linux"],
        ["repository", repository],
        ["version", version],
        ["commit", manifest_hash],
        ["manifest", f"sha256:{manifest_hash}"],
        ["content", f"sha256:{manifest_hash}"],
    ]
    content_json = json.dumps({"name": app_id}, separators=(",", ":"))
    event = _sign_event(cfg.publisher_sk, cfg.publisher_pubkey, 32267, content_json, tags)

    result = _catalog_cli(["--relay", _catalog_relay_arg(relays), "publish"], json.dumps(event).encode())
    ingest = _catalog_cli(["ingest"], json.dumps(event).encode())
    return {
        "app_id": app_id,
        "publisher_pubkey": cfg.publisher_pubkey,
        "event_id": event["id"],
        "published": result,
        "ingested": ingest,
    }


# --------------------------------------------------------------------------- #
# catalogue admin page (Phase 6) — endorsements, trust dashboard, on-demand
# reverification, publisher profile, and release announcements. Every event
# built here is signed with the node's publisher key the same way
# catalog.publish already is (_sign_event, never leaving this process), then
# handed to the catalogue CLI's kind-agnostic "publish" subcommand for pure
# transport - the CLI itself never accepts a private key. WP5: all history /
# profile / announcement reads are relay-derived (no local JSON ledgers).

def _catalog_own_events(kinds: tuple[int, ...]) -> list[dict[str, Any]]:
    """Every event this node's catalogue publisher key authored, read from the
    control relay (WP5: the relay is authoritative; there is no local ledger).

    Bounded pagination so a large history is not silently truncated."""
    from yunohost.nostr_identity import _operator_config
    from yunohost.nostrhost.events import query_chain_events

    cfg = _operator_config()
    try:
        return query_chain_events(
            cfg.control_relay, kinds=kinds, authors=(cfg.publisher_pubkey,), limit=5000, page_all=True
        )
    except Exception:  # noqa: BLE001 - a relay hiccup must not break the admin page
        return []


def _catalog_endorsements() -> list[dict[str, Any]]:
    """This node's own kind-30079 curator endorsements, newest first."""
    records: list[dict[str, Any]] = []
    for event in _catalog_own_events((30079,)):
        tags = {t[0]: t[1] for t in event.get("tags") or [] if len(t) >= 2}
        parts = str(tags.get("a") or "").split(":")
        records.append(
            {
                "app_id": parts[2] if len(parts) >= 3 else "",
                "publisher": parts[1] if len(parts) >= 2 else "",
                "claim": tags.get("claim", ""),
                "comment": event.get("content", ""),
                "event_id": event.get("id"),
                "created_at": event.get("created_at"),
            }
        )
    records.sort(key=lambda record: record.get("created_at") or 0, reverse=True)
    return records


def _catalog_announcements_from_relay() -> list[dict[str, Any]]:
    """This node's own kind-1 announcement notes, newest first."""
    records: list[dict[str, Any]] = []
    for event in _catalog_own_events((1,)):
        tags = {t[0]: t[1] for t in event.get("tags") or [] if len(t) >= 2}
        coordinate = str(tags.get("a") or "")
        app_id = coordinate.split(":")[2] if coordinate.count(":") >= 2 else ""
        records.append(
            {
                "app_id": app_id,
                "version": tags.get("version", ""),
                "event_id": event.get("id"),
                "created_at": event.get("created_at"),
            }
        )
    records.sort(key=lambda record: record.get("created_at") or 0, reverse=True)
    return records


def _catalog_profile_from_relay() -> dict[str, Any]:
    """This node's newest kind-0 catalogue publisher profile content."""
    events = _catalog_own_events((0,))
    if not events:
        return {}
    newest = max(events, key=lambda e: (int(e.get("created_at") or 0), str(e.get("id") or "")))
    try:
        parsed = json.loads(newest.get("content") or "{}")
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


# --------------------------------------------------------------------------- #
# catalogue history / profile / announcements are read from the control relay
# (WP5) - see _catalog_own_events / _catalog_endorsements /
# _catalog_announcements_from_relay / _catalog_profile_from_relay above.


def _catalog_entries() -> list[dict[str, Any]]:
    listing = _catalog_cli(["list"])
    entries = listing.get("entries") if isinstance(listing, dict) else listing
    return entries if isinstance(entries, list) else []


def _safe_catalog_candidates(**args: Any) -> dict[str, Any]:
    """Installed apps declared by a publisher other than this node, that this
    node has not already endorsed - the attest screen's candidate list."""
    if args:
        raise OperationError(f"catalog.candidates does not accept extra args: {sorted(args)}")

    from yunohost.nostr_identity import _operator_config

    from .cli import _TOOL_HANDLERS

    self_pubkey = _operator_config().publisher_pubkey
    installed = _TOOL_HANDLERS["app.list"]().get("apps", {})
    if not isinstance(installed, dict):
        installed = {}
    attested = {
        (record.get("app_id"), record.get("publisher"))
        for record in _catalog_endorsements()
    }

    candidates = []
    for entry in _catalog_entries():
        declaration = entry.get("declaration") if isinstance(entry, dict) else None
        if not isinstance(declaration, dict):
            continue
        app_id = declaration.get("AppID")
        publisher = declaration.get("Publisher")
        if not app_id or not publisher or publisher == self_pubkey:
            continue
        if app_id not in installed:
            continue
        if (app_id, publisher) in attested:
            continue
        candidates.append(
            {
                "app_id": app_id,
                "publisher": publisher,
                "version": declaration.get("Version"),
                "name": declaration.get("Name") or app_id,
            }
        )
    return {"candidates": candidates}


def _safe_catalog_attest(
    app_id: str = "", publisher: str = "", claim: str = "", comment: str = "", relays: str = "", **extra: Any
) -> dict[str, Any]:
    """Publish a kind-30079 curator endorsement for another publisher's
    declaration, mirroring internal/curation.Build's exact tag/content shape
    so the Go catalogue library can parse events built here."""
    if extra:
        raise OperationError(f"catalog.attest does not accept extra args: {sorted(extra)}")
    if not app_id or not publisher:
        raise OperationError("catalog.attest requires an app_id and publisher")
    if claim not in ("recommend", "tested"):
        raise OperationError("catalog.attest claim must be recommend or tested")

    from yunohost.nostr_identity import _operator_config, _sign_event

    cfg = _operator_config()
    if publisher == cfg.publisher_pubkey:
        raise OperationError("catalog.attest cannot endorse this node's own declaration")
    tags = [["a", f"32267:{publisher}:{app_id}"], ["claim", claim]]
    event = _sign_event(cfg.publisher_sk, cfg.publisher_pubkey, 30079, comment, tags)

    result = _catalog_cli(["--relay", _catalog_relay_arg(relays), "publish"], json.dumps(event).encode())
    # WP5: no local ledger — the kind-30079 event is addressable
    # (d=app_id:publisher), so a re-endorsement is an ordinary replaceable
    # event and the relay is the read source.
    return {"app_id": app_id, "publisher": publisher, "event_id": event["id"], "published": result}


def _safe_catalog_history(**args: Any) -> dict[str, Any]:
    """Every endorsement this node has published, most recent first."""
    if args:
        raise OperationError(f"catalog.history does not accept extra args: {sorted(args)}")
    return {"history": _catalog_endorsements()}


def _safe_catalog_trust(
    attestation_policy: str = "off",
    min_attestations: int = 0,
    required_checks: list[str] | None = None,
    trusted_verifiers: list[str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Every accepted declaration's trust picture under the given CI-attestation
    policy: what this node has verified, what CI-backed attestations exist for
    its exact revision, and what the policy decides as a result."""
    if extra:
        raise OperationError(f"catalog.trust does not accept extra args: {sorted(extra)}")
    extra_flags = ["--attestation-policy", attestation_policy]
    if min_attestations:
        extra_flags += ["--min-attestations", str(min_attestations)]
    if required_checks:
        extra_flags += ["--required-checks", ",".join(required_checks)]
    if trusted_verifiers:
        extra_flags += ["--trusted-verifiers", ",".join(trusted_verifiers)]
    result = _catalog_cli(["trust"], extra_flags=extra_flags)
    entries = result if isinstance(result, list) else result.get("raw", [])
    return {"entries": entries if isinstance(entries, list) else []}


def _safe_catalog_reverify(app_id: str = "", **extra: Any) -> dict[str, Any]:
    """Independently re-check one accepted declaration on demand: re-clone its
    repository at the declared commit and recompute both hashes, rather than
    trusting whatever was true at ingestion time."""
    if extra:
        raise OperationError(f"catalog.reverify does not accept extra args: {sorted(extra)}")
    if not app_id:
        raise OperationError("catalog.reverify requires an app_id")
    return _catalog_cli(["reverify"], extra_flags=["--app-id", app_id])


def _safe_catalog_profile_get(**args: Any) -> dict[str, Any]:
    """This node's last-published kind-0 catalogue publisher profile, from a
    local cache - a missing cache means nothing has been published yet
    through this admin page, not an error."""
    if args:
        raise OperationError(f"catalog.profile.get does not accept extra args: {sorted(args)}")
    from yunohost.nostr_identity import _operator_config

    return {"profile": _catalog_profile_from_relay(), "self_publisher": _operator_config().publisher_pubkey}


def _safe_catalog_profile_set(
    name: str = "", about: str = "", picture: str = "", nip05: str = "", website: str = "", relays: str = "", **extra: Any
) -> dict[str, Any]:
    """Publish a kind-0 profile for the catalogue publisher key, so it
    resolves to a real, followable account instead of an opaque hex string."""
    if extra:
        raise OperationError(f"catalog.profile.set does not accept extra args: {sorted(extra)}")

    from yunohost.nostr_identity import _operator_config, _sign_event

    profile = {
        key: value
        for key, value in {"name": name, "about": about, "picture": picture, "nip05": nip05, "website": website}.items()
        if value
    }
    cfg = _operator_config()
    content = json.dumps(profile, separators=(",", ":"))
    event = _sign_event(cfg.publisher_sk, cfg.publisher_pubkey, 0, content, [])

    result = _catalog_cli(["--relay", _catalog_relay_arg(relays), "publish"], json.dumps(event).encode())
    published = isinstance(result, dict) and any(not item.get("error") for item in result.get("relays", []))
    # WP5: no local cache — the kind-0 profile is a replaceable event and is
    # read back from the relay (see _catalog_profile_from_relay).
    return {"event_id": event["id"], "published": result, "published_any": bool(published)}


def _safe_catalog_announce(app_id: str = "", relays: str = "", **extra: Any) -> dict[str, Any]:
    """Publish a kind-1 text note announcing a release, so it shows up in an
    ordinary Nostr feed instead of only as an unrendered replaceable event -
    only for a declaration this node itself published, and only once per
    revision (deduped against the same ledger a future automated --announce
    publish flow would share)."""
    if extra:
        raise OperationError(f"catalog.announce does not accept extra args: {sorted(extra)}")
    if not app_id:
        raise OperationError("catalog.announce requires an app_id")

    from yunohost.nostr_identity import _operator_config, _sign_event

    cfg = _operator_config()
    declaration = _catalog_cli(["get", app_id])
    if declaration.get("Publisher") != cfg.publisher_pubkey:
        raise OperationError("catalog.announce can only announce this node's own declarations")
    commit = declaration.get("Commit") or ""
    version = declaration.get("Version") or ""
    # WP5: idempotency is checked against the relay, not a local ledger. A note
    # carries a `version` tag (and, for legacy notes, the short commit in its
    # content), so a re-announce of the same revision is refused.
    if any(
        record.get("app_id") == app_id and record.get("version") == version
        for record in _catalog_announcements_from_relay()
    ):
        raise OperationError(f"app {app_id!r} version {version!r} was already announced")

    repository = declaration.get("Repository") or ""
    name = declaration.get("Name") or app_id
    short_commit = commit[:7] if commit else ""
    # No nostr: naddr link is embedded here - this codebase does not carry a
    # nip19 encoder (see catalog.verify's own naddr note), and the "a" tag
    # below already gives clients a resolvable address for the declaration.
    content = f"\U0001f4e6 {name} {version} published\n{repository}@{short_commit}".rstrip()
    tags = [["a", f"32267:{cfg.publisher_pubkey}:{app_id}"], ["r", repository], ["version", version]]
    event = _sign_event(cfg.publisher_sk, cfg.publisher_pubkey, 1, content, tags)

    result = _catalog_cli(["--relay", _catalog_relay_arg(relays), "publish"], json.dumps(event).encode())
    return {"app_id": app_id, "event_id": event["id"], "published": result}


def _safe_catalog_announcements(**args: Any) -> dict[str, Any]:
    """Every announcement note this node has published, most recent first."""
    if args:
        raise OperationError(f"catalog.announcements does not accept extra args: {sorted(args)}")
    return {"announcements": _catalog_announcements_from_relay()}


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


def _safe_system_reboot(**extra: Any) -> dict[str, Any]:
    """Reboot the host. Always forced: the owner co-signature on this
    operation's signed chain is the confirmation, replacing the interactive
    CLI prompt tools_reboot() would otherwise show."""
    if extra:
        raise OperationError(f"system.reboot does not accept extra args: {sorted(extra)}")
    from yunohost.tools import tools_reboot

    tools_reboot(force=True)
    return {"rebooting": True}


def _safe_system_shutdown(**extra: Any) -> dict[str, Any]:
    """Power off the host. Always forced, for the same reason as
    system.reboot above."""
    if extra:
        raise OperationError(f"system.shutdown does not accept extra args: {sorted(extra)}")
    from yunohost.tools import tools_shutdown

    tools_shutdown(force=True)
    return {"shutting_down": True}


def _safe_settings_list(full: bool = False, **extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"settings.list does not accept extra args: {sorted(extra)}")
    from yunohost.settings import settings_list

    return {"settings": settings_list(full=bool(full))}


def _safe_settings_get(key: str = "", full: bool = False, export: bool = False, **extra: Any) -> dict[str, Any]:
    key = str(key or "").strip()
    if extra:
        raise OperationError(f"settings.get does not accept extra args: {sorted(extra)}")
    if not key:
        raise OperationError("settings.get requires a non-empty 'key'")
    if full and export:
        raise OperationError("settings.get 'full' and 'export' are mutually exclusive")
    from yunohost.settings import settings_get

    return {"key": key, "value": settings_get(key=key, full=bool(full), export=bool(export))}


def _safe_settings_set(key: str = "", value: Any = None, **extra: Any) -> dict[str, Any]:
    key = str(key or "").strip()
    if extra:
        raise OperationError(f"settings.set does not accept extra args: {sorted(extra)}")
    if not key:
        raise OperationError("settings.set requires a non-empty 'key'")
    from yunohost.settings import settings_set

    settings_set(key=key, value=value)
    return {"key": key, "value": value}


def _safe_settings_reset(key: str = "", **extra: Any) -> dict[str, Any]:
    key = str(key or "").strip()
    if extra:
        raise OperationError(f"settings.reset does not accept extra args: {sorted(extra)}")
    if not key:
        raise OperationError("settings.reset requires a non-empty 'key'")
    from yunohost.settings import settings_get, settings_reset

    settings_reset(key=key)
    return {"key": key, "value": settings_get(key=key)}


def _safe_settings_reset_all(**extra: Any) -> dict[str, Any]:
    if extra:
        raise OperationError(f"settings.reset_all does not accept extra args: {sorted(extra)}")
    from yunohost.settings import settings_list, settings_reset_all

    settings_reset_all()
    return {"settings": settings_list()}


# --------------------------------------------------------------------------- #
# service history + host logs (logs.read / logs.web / service.history)

JOURNALCTL_BIN = os.environ.get("NOSTRHOST_JOURNALCTL_BIN", "journalctl")
CADDY_LOG_DIR = os.environ.get("NOSTRHOST_CADDY_LOG_DIR", "/var/log/caddy")
PROBLEMS_LOG = os.environ.get("NOSTRHOST_PROBLEMS_LOG", "/var/log/nostrhost/problems.log")

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
        "nostr-permissiond",
        "nostr-securityd",
        "nostr-ddnswatchd",
        "nostrhost-control",
        "nostrhost-catalog",
        "nostrhost-certd",
        "nostrhost-notify",
        "nostrhost-nsite",
        "nostrhost-mcp",
        "nostrhost-agent",
        "nostrhost-agent-llm",
        "nostrhost-web-reconcile",
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


def _safe_logs_problems(
    host: str | None = None,
    path: str | None = None,
    status: int | None = None,
    code: str | None = None,
    kind: str | None = None,
    source: str | None = None,
    request_id: str | None = None,
    since: str | None = None,
    until: str | None = None,
    lines: int = 200,
    **extra: Any,
) -> dict[str, Any]:
    """Read bounded, structured server problem records (logs.problems).

    /var/log/nostrhost/problems.log (written by the api/portal-api error
    boundaries) holds one JSON record per 4xx/5xx response and per unhandled
    exception, with request context (method, route, status, error code, actor,
    request id, duration) and the traceback for server errors.
    """
    if extra:
        raise OperationError(f"logs.problems does not accept extra args: {sorted(extra)}")
    if host is not None and (not host or len(host) > 253):
        raise OperationError("host must be a bounded non-empty hostname")
    if path is not None and (not path.startswith("/") or len(path) > 4096):
        raise OperationError("path must be an absolute bounded URL path")
    if status is not None and not 100 <= status <= 599:
        raise OperationError("status must be an HTTP status code")
    if code is not None and (not code or len(code) > 256):
        raise OperationError("code must be a bounded non-empty error code")
    if request_id is not None and len(request_id) > 128:
        raise OperationError("request_id must be a bounded value")
    lower_bound = _parse_introspection_time(since)
    upper_bound = _parse_introspection_time(until)
    if lower_bound and upper_bound and lower_bound > upper_bound:
        raise OperationError("since must not be later than until")
    lower_ts = lower_bound.timestamp() if lower_bound else None
    upper_ts = upper_bound.timestamp() if upper_bound else None
    capped = max(1, min(lines, 2000))
    log_path = Path(os.environ.get("NOSTRHOST_PROBLEMS_LOG", PROBLEMS_LOG))
    if not log_path.is_file():
        return {"log_file": str(log_path), "entries": [], "warning": "problem log is unavailable"}
    entries: list[dict[str, Any]] = []
    for raw_line in _tail_file_lines(log_path, capped):
        try:
            entry = json.loads(raw_line)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(entry, dict):
            continue
        ts = entry.get("ts")
        if isinstance(ts, str):
            try:
                parsed = _dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=_dt.timezone.utc)
                ts_epoch = parsed.timestamp()
            except ValueError:
                ts_epoch = None
            if ts_epoch is not None:
                if lower_ts is not None and ts_epoch < lower_ts:
                    continue
                if upper_ts is not None and ts_epoch > upper_ts:
                    continue
            elif lower_ts is not None or upper_ts is not None:
                continue
        elif lower_ts is not None or upper_ts is not None:
            continue
        if status is not None and entry.get("status") != status:
            continue
        if code is not None and entry.get("code") != code:
            continue
        if kind is not None and entry.get("kind") != kind:
            continue
        if source is not None and entry.get("source") != source:
            continue
        if request_id is not None and entry.get("request_id") != request_id:
            continue
        if host is not None and host.lower() not in str(entry.get("host") or entry.get("remote") or "").lower():
            continue
        if path is not None and entry.get("path") != path:
            continue
        entries.append(entry)
    return {"log_file": str(log_path), "entries": entries[-capped:]}


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

def _safe_backup_delete(
    snapshot: str = "",
    apply_retention: bool = False,
    prune: bool = True,
    **extra: Any,
) -> dict[str, Any]:
    if extra:
        raise OperationError(f"backup.delete does not accept extra args: {sorted(extra)}")
    ids = [part for part in str(snapshot or "").replace(",", " ").split() if part]
    if not ids and not apply_retention:
        raise OperationError("backup.delete requires a 'snapshot' id or apply_retention=true")
    client = _restic()
    result = client.forget(
        policy=client.retention if apply_retention else {},
        prune=bool(prune),
        snapshot_ids=ids or None,
    )
    return {
        "deleted": ids,
        "apply_retention": bool(apply_retention),
        "pruned": bool(prune),
        "result": result,
    }


def _safe_domain_cert_info(domain: str = "", **extra: Any) -> dict[str, Any]:
    domain = str(domain or "").strip()
    if extra:
        raise OperationError(f"domain.cert.info does not accept extra args: {sorted(extra)}")
    if not domain:
        raise OperationError("domain.cert.info requires a 'domain'")
    from yunohost.certificate import certificate_status
    from yunohost.utils.error import YunohostError

    try:
        certs = (certificate_status([domain], full=True) or {}).get("certificates") or {}
    except YunohostError as exc:
        # Caddy has not provisioned/exported a certificate for the domain yet.
        return {"domain": domain, "certificate": None, "error": str(exc)}
    return {"domain": domain, "certificate": certs.get(domain)}


def _safe_domain_cert_install(domain: str = "", letsencrypt: bool = True, staging: bool = False, **extra: Any) -> dict[str, Any]:
    domain = str(domain or "").strip()
    if extra:
        raise OperationError(f"domain.cert.install does not accept extra args: {sorted(extra)}")
    if not domain:
        raise OperationError("domain.cert.install requires a 'domain'")
    if staging:
        raise OperationError("staging certificates are not supported: Caddy owns ACME and uses its configured CA")
    from yunohost.certificate import certificate_install, certificate_status
    from yunohost.utils.error import YunohostError

    # Caddy is the platform TLS layer and provisions/renews automatically: the
    # op ensures the domain's Caddy site exists and exports the resulting cert.
    # There is no separate self-signed-vs-ACME choice here (Caddy's policy
    # decides per domain), so `letsencrypt` only annotates the result.
    acme_error = None
    try:
        certificate_install(domain_list=[domain], force=True, no_checks=True)
    except Exception as exc:  # noqa: BLE001 - surface ACME failure via acme_error + reconciled status
        acme_error = str(exc)
    try:
        certs = (certificate_status([domain], full=True) or {}).get("certificates") or {}
    except YunohostError:
        certs = {}
    return {
        "domain": domain,
        "requested": "letsencrypt" if letsencrypt else "selfsigned",
        "acme_error": acme_error,
        "certificate": certs.get(domain),
    }


def _safe_domain_primary_set(domain: str = "", plan_sha256: str = "", **extra: Any) -> dict[str, Any]:
    if extra or not domain or not plan_sha256:
        raise OperationError("domain.primary.set requires a domain and reviewed plan fingerprint")
    from nostrhost.domains.primary import apply_primary, plan_primary

    current_plan = plan_primary(domain)
    if current_plan["plan_sha256"] != plan_sha256:
        raise OperationError("domain state changed after review; create and approve a fresh plan")

    return apply_primary(domain)


def _safe_nostr_connectivity_set(
    configuration: dict[str, Any] | None = None,
    plan_sha256: str = "",
    **extra: Any,
) -> dict[str, Any]:
    if extra or not isinstance(configuration, dict) or not plan_sha256:
        raise OperationError("nostr.connectivity.set requires configuration and a reviewed plan fingerprint")
    from nostrhost.connectivity import apply_config, plan_config

    current_plan = plan_config(configuration)
    if current_plan["plan_sha256"] != plan_sha256:
        raise OperationError("Nostr network settings changed after review; create and approve a fresh plan")

    return apply_config(configuration)


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


def _audit_raw_events(
    kinds: tuple[int, ...] | None = None,
    limit: int = 100,
    since: int | None = None,
    *,
    page_all: bool = False,
) -> list[dict[str, Any]]:
    """Raw signed chain events from the control relay (tags/content intact).

    ``page_all`` walks the whole history with ``until`` (WP5) so a chain
    larger than the relay's single-REQ cap cannot silently drop older events.
    """
    from yunohost.nostr_identity import _operator_config
    from yunohost.nostrhost.events import query_chain_events

    cfg = _operator_config()
    return query_chain_events(
        cfg.control_relay, kinds=kinds or AUDIT_CHAIN_KINDS, limit=limit, since=since, page_all=page_all
    )


def _audit_events(
    kinds: tuple[int, ...] | None = None,
    limit: int = 100,
    since: int | None = None,
    *,
    page_all: bool = False,
) -> list[dict[str, Any]]:
    """Normalized audit view: one row per raw chain event with the resolved
    request id and tool (used by ``audit.events``-style callers)."""
    from yunohost.nostr_operations import KIND_OPERATION_REQUEST
    from yunohost.nostrhost.events import _e_tag

    events = _audit_raw_events(kinds=kinds, limit=limit, since=since, page_all=page_all)
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

    WP5: the per-operation state reduction is delegated to the single
    authoritative fold, ``nostr_operations._operation_entry`` (same-second
    chain-position tie-break, strict state machine, illegal-result ->
    FAILED), rather than the divergent ad-hoc logic that used to live here —
    so ``audit.list`` and ``/package/operations`` can never disagree. The
    chain is read with bounded pagination so an older terminal result is not
    silently omitted. Each entry also carries the read-side signer/link
    validation (``validated``/``anomalies``)."""
    from yunohost.nostr_operations import KIND_CAPABILITY, KIND_OPERATION_REQUEST, _operation_entry
    from yunohost.nostrhost.events import _e_tag

    events = _audit_raw_events(limit=AUDIT_MAX_SCAN, page_all=True)
    by_request: dict[str, list[dict[str, Any]]] = {}
    standalone: list[dict[str, Any]] = []
    for event in events:
        if event.get("kind") == KIND_OPERATION_REQUEST:
            by_request.setdefault(event["id"], []).append(event)
        else:
            rid = _e_tag(event)
            if rid:
                by_request.setdefault(rid, []).append(event)
            else:
                standalone.append(event)

    admins, server_pubkey = _audit_authority()
    entries: list[dict[str, Any]] = []
    for chain in by_request.values():
        entry = _operation_entry(chain, admins=admins, server_pubkey=server_pubkey)
        if entry is None:
            # Orphaned follow-ons (their request is older than the window):
            # surface the raw events rather than discarding them.
            standalone.extend(chain)
            continue
        entries.append(entry)
    for item in standalone:
        item.setdefault("request_id", None)
        item.setdefault("validated", True)
        item.setdefault("anomalies", [])
        if item.get("kind") == KIND_CAPABILITY and item.get("tool") is None:
            item["tool"] = "capability.grant"
    entries.extend(standalone)
    entries.sort(key=lambda entry: entry.get("created_at") or 0, reverse=True)  # newest first
    return entries[:limit]


def _audit_authority() -> tuple[tuple[str, ...], str | None]:
    """Admins + server pubkey for read-side chain validation (best-effort)."""
    try:
        from yunohost.nostr_identity import _operator_config

        cfg = _operator_config()
        return tuple(cfg.admins), cfg.server_pubkey
    except Exception:  # noqa: BLE001 - audit read must survive an unbootstrapped node
        return (), None


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
    "projection.status": ToolSpec(
        name="projection.status", handler=_safe_projection_status, scope=SCOPE_SERVER_READ,
        require_approval=False, input_model=ProjectionStatusArgs,
        description="projection health: applied revision, freshness, quarantine (WP2)",
    ),
    "service.config.status": ToolSpec(
        name="service.config.status", handler=_safe_service_config_status, scope=SCOPE_SERVER_READ,
        require_approval=False, input_model=ServiceStatusArgs,
        description="generated service-config provenance + drift vs the rendered digest (WP7)",
    ),
    "list.read": ToolSpec(
        name="list.read", handler=_safe_list_read, scope=SCOPE_SERVER_READ,
        require_approval=False, input_model=ListReadArgs,
        description="read the effective view of a NIP-51/NIP-78 list or settings family (WP4)",
    ),
    "list.publish": ToolSpec(
        name="list.publish", handler=_safe_list_publish, scope=SCOPE_SETTINGS_WRITE,
        input_model=ListPublishArgs, risk=RISK_MEDIUM, reversibility=REVERSIBLE,
        description="publish an operator-authored host list or settings document (WP4)",
    ),
    "policy.read": ToolSpec(
        name="policy.read", handler=_safe_policy_read, scope=SCOPE_SERVER_READ,
        require_approval=False, input_model=PolicyReadArgs,
        description="read the effective view of a kind-31101 policy family (WP6)",
    ),
    "policy.publish": ToolSpec(
        name="policy.publish", handler=_safe_policy_publish, scope=SCOPE_SETTINGS_WRITE,
        input_model=PolicyPublishArgs, risk=RISK_MEDIUM, reversibility=REVERSIBLE,
        description="publish an operator-authored kind-31101 policy declaration (WP6)",
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
        description="create a Restic data snapshot (configured paths by default)",
    ),
    "backup.list": ToolSpec(
        name="backup.list", handler=_safe_backup_list, scope=SCOPE_BACKUPS_READ,
        require_approval=False, input_model=BackupListArgs,
        description="list Restic restore points (snapshots)",
    ),
    "backup.info": ToolSpec(
        name="backup.info", handler=_safe_backup_info, scope=SCOPE_BACKUPS_READ,
        require_approval=False, input_model=BackupInfoArgs,
        description="details for one Restic snapshot",
    ),
    "backup.restore": ToolSpec(
        name="backup.restore", handler=_safe_backup_restore, scope=SCOPE_BACKUPS_RESTORE,
        input_model=BackupRestoreArgs, risk=RISK_HIGH, reversibility=REVERSIBLE_WITH_PLAN,
        description="restore a Restic snapshot (admin confirmation)",
    ),
    "backup.check": ToolSpec(
        name="backup.check", handler=_safe_backup_check, scope=SCOPE_BACKUPS_READ,
        require_approval=False, input_model=BackupCheckArgs,
        description="verify Restic repository integrity",
    ),
    "backup.stats": ToolSpec(
        name="backup.stats", handler=_safe_backup_stats, scope=SCOPE_BACKUPS_READ,
        require_approval=False, input_model=BackupStatsArgs,
        description="Restic repository size/growth statistics",
    ),
    "backup.policy.read": ToolSpec(
        name="backup.policy.read", handler=_safe_backup_policy_read, scope=SCOPE_BACKUPS_READ,
        require_approval=False, input_model=BackupPolicyReadArgs,
        description="Restic retention policy, schedule and repository location",
    ),
    "backup.schedule": ToolSpec(
        name="backup.schedule", handler=_safe_backup_schedule, scope=SCOPE_BACKUPS_READ,
        require_approval=False, input_model=BackupScheduleArgs,
        description="scheduled-backup timer state (active, last run, next run)",
    ),
    "backup.policy.set": ToolSpec(
        name="backup.policy.set", handler=_safe_backup_policy_set, scope=SCOPE_BACKUPS_WRITE,
        input_model=BackupPolicySetArgs, risk=RISK_MEDIUM, reversibility=REVERSIBLE,
        description="set Restic retention policy and scheduled-backup cadence",
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
    "diagnosis.ignored": ToolSpec(
        name="diagnosis.ignored", handler=_safe_diagnosis_ignored, scope=SCOPE_DIAGNOSIS_READ,
        require_approval=False, input_model=DiagnosisIgnoredArgs,
        description="list currently configured diagnosis ignore filters, by category",
    ),
    "diagnosis.ignore": ToolSpec(
        name="diagnosis.ignore", handler=_safe_diagnosis_ignore, scope=SCOPE_DIAGNOSIS_WRITE,
        input_model=DiagnosisIgnoreArgs, risk=RISK_LOW, reversibility=REVERSIBLE,
        description="add a diagnosis ignore filter (admin + owner co-signature)",
    ),
    "diagnosis.unignore": ToolSpec(
        name="diagnosis.unignore", handler=_safe_diagnosis_unignore, scope=SCOPE_DIAGNOSIS_WRITE,
        input_model=DiagnosisUnignoreArgs, risk=RISK_LOW, reversibility=REVERSIBLE,
        description="remove a diagnosis ignore filter (admin + owner co-signature)",
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
    "catalog.declare": ToolSpec(
        name="catalog.declare", handler=_safe_catalog_declare, scope=SCOPE_CATALOG_PUBLISH,
        input_model=CatalogDeclareArgs, risk=RISK_MEDIUM, reversibility=REVERSIBLE,
        description="declare a new app in the catalogue from an authored native package manifest (admin approval)",
    ),
    "catalog.candidates": ToolSpec(
        name="catalog.candidates", handler=_safe_catalog_candidates, scope=SCOPE_CATALOG_READ,
        require_approval=False, input_model=CatalogCandidatesArgs,
        description="installed apps declared by another publisher this node has not yet endorsed",
    ),
    "catalog.attest": ToolSpec(
        name="catalog.attest", handler=_safe_catalog_attest, scope=SCOPE_CATALOG_PUBLISH,
        input_model=CatalogAttestArgs, risk=RISK_MEDIUM, reversibility=REVERSIBLE,
        description="publish a curator endorsement (recommend/tested) for another publisher's declaration (admin approval)",
    ),
    "catalog.history": ToolSpec(
        name="catalog.history", handler=_safe_catalog_history, scope=SCOPE_CATALOG_READ,
        require_approval=False, input_model=CatalogHistoryArgs,
        description="every endorsement this node has published, most recent first",
    ),
    "catalog.trust": ToolSpec(
        name="catalog.trust", handler=_safe_catalog_trust, scope=SCOPE_CATALOG_READ,
        require_approval=False, input_model=CatalogTrustArgs,
        description="every accepted declaration's CI-attestation trust status under a given policy",
    ),
    "catalog.reverify": ToolSpec(
        name="catalog.reverify", handler=_safe_catalog_reverify, scope=SCOPE_CATALOG_VERIFY,
        require_approval=False, input_model=CatalogReverifyArgs,
        description="independently re-check one accepted declaration against its repository and commit",
    ),
    "catalog.profile.get": ToolSpec(
        name="catalog.profile.get", handler=_safe_catalog_profile_get, scope=SCOPE_CATALOG_READ,
        require_approval=False, input_model=CatalogProfileGetArgs,
        description="this node's last-published catalogue publisher profile",
    ),
    "catalog.profile.set": ToolSpec(
        name="catalog.profile.set", handler=_safe_catalog_profile_set, scope=SCOPE_CATALOG_PUBLISH,
        input_model=CatalogProfileSetArgs, risk=RISK_LOW, reversibility=REVERSIBLE,
        description="publish a kind-0 profile for the catalogue publisher key (admin approval)",
    ),
    "catalog.announce": ToolSpec(
        name="catalog.announce", handler=_safe_catalog_announce, scope=SCOPE_CATALOG_PUBLISH,
        input_model=CatalogAnnounceArgs, risk=RISK_LOW, reversibility=REVERSIBLE,
        description="publish a release announcement note for one of this node's own declarations (admin approval)",
    ),
    "catalog.announcements": ToolSpec(
        name="catalog.announcements", handler=_safe_catalog_announcements, scope=SCOPE_CATALOG_READ,
        require_approval=False, input_model=CatalogAnnouncementsArgs,
        description="every release announcement this node has published, most recent first",
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
    "logs.problems": ToolSpec(
        name="logs.problems", handler=_safe_logs_problems, scope=SCOPE_LOGS_READ,
        require_approval=False, input_model=LogsProblemsArgs,
        description="read bounded, structured server problem records (/var/log/nostrhost/problems.log: every 4xx/5xx and unhandled exception with route, error code, actor, request id and traceback)",
    ),
    "backup.delete": ToolSpec(
        name="backup.delete", handler=_safe_backup_delete, scope=SCOPE_BACKUPS_DELETE,
        input_model=BackupDeleteArgs, risk=RISK_HIGH, reversibility=IRREVERSIBLE,
        description="forget Restic snapshots or apply the retention policy (admin confirmation)",
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
    "domain.primary.set": ToolSpec(
        name="domain.primary.set", handler=_safe_domain_primary_set, scope=SCOPE_DOMAINS_WRITE,
        input_model=DomainPrimarySetArgs, risk=RISK_HIGH, reversibility=REVERSIBLE_WITH_PLAN,
        description="change the server address and primary administration domain",
    ),
    "nostr.connectivity.set": ToolSpec(
        name="nostr.connectivity.set", handler=_safe_nostr_connectivity_set, scope=SCOPE_SETTINGS_WRITE,
        input_model=NostrConnectivitySetArgs, risk=RISK_MEDIUM, reversibility=REVERSIBLE,
        description="set public Nostr relay and Blossom defaults",
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
    "system.reboot": ToolSpec(
        name="system.reboot", handler=_safe_system_reboot, scope=SCOPE_SYSTEM_POWER,
        input_model=SystemRebootArgs, risk=RISK_HIGH, reversibility=REVERSIBLE_WITH_PLAN,
        description="reboot the host (admin + owner co-signature)",
    ),
    "system.shutdown": ToolSpec(
        name="system.shutdown", handler=_safe_system_shutdown, scope=SCOPE_SYSTEM_POWER,
        input_model=SystemShutdownArgs, risk=RISK_HIGH, reversibility=IRREVERSIBLE,
        description="power off the host; requires an out-of-band power-on to recover (admin + owner co-signature)",
    ),
    "settings.list": ToolSpec(
        name="settings.list", handler=_safe_settings_list, scope=SCOPE_SETTINGS_READ,
        require_approval=False, input_model=SettingsListArgs,
        description="list global YunoHost settings and their current values",
    ),
    "settings.get": ToolSpec(
        name="settings.get", handler=_safe_settings_get, scope=SCOPE_SETTINGS_READ,
        require_approval=False, input_model=SettingsGetArgs,
        description="get one global YunoHost setting by key",
    ),
    "settings.set": ToolSpec(
        name="settings.set", handler=_safe_settings_set, scope=SCOPE_SETTINGS_WRITE,
        input_model=SettingsSetArgs, risk=RISK_MEDIUM, reversibility=REVERSIBLE,
        description="set one global YunoHost setting (admin + owner co-signature)",
    ),
    "settings.reset": ToolSpec(
        name="settings.reset", handler=_safe_settings_reset, scope=SCOPE_SETTINGS_WRITE,
        input_model=SettingsResetArgs, risk=RISK_MEDIUM, reversibility=REVERSIBLE,
        description="reset one global YunoHost setting to its default (admin + owner co-signature)",
    ),
    "settings.reset_all": ToolSpec(
        name="settings.reset_all", handler=_safe_settings_reset_all, scope=SCOPE_SETTINGS_WRITE,
        input_model=SettingsResetAllArgs, risk=RISK_HIGH, reversibility=REVERSIBLE_WITH_PLAN,
        description="reset all global YunoHost settings to their defaults (admin + owner co-signature)",
    ),
}
