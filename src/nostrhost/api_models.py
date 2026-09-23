"""Typed request models for the native admin API (A1 typed API contracts).

Every model mirrors the exact field names, defaults and coercion rules the
legacy ``body.get(...)`` handlers applied, so adopting these models changes no
wire shape. Unknown keys are rejected (``extra="forbid"``) only where the
legacy handler validated an exact key set; elsewhere ``extra="ignore"``
preserves the tolerant behaviour. Request bodies are parsed by
``nostrhost.api._body`` from the same ``request.state.body_bytes`` cache the
NIP-98 signature binds to, so payload binding is unchanged.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _Tolerant(BaseModel):
    """Models that ignore unknown keys (the legacy default)."""

    model_config = ConfigDict(extra="ignore")


class _Strict(BaseModel):
    """Models that forbid unknown keys (legacy ``set(body) != {...}``)."""

    model_config = ConfigDict(extra="forbid")


# -- system -------------------------------------------------------------------

class UpdatesRefreshBody(_Tolerant):
    target: str = "apps"


class UpdatesApplyBody(_Tolerant):
    target: str = "system"


class MigrateBody(_Tolerant):
    """Pass-through of the whole body to ``system.migrate``."""


# -- domain / dns -------------------------------------------------------------

class DomainAddBody(_Tolerant):
    domain: str = ""
    provider_type: str = "manual"
    provider_zone: str | None = None
    credential: str | None = None
    primary: bool = False
    ipv4: bool = True
    ipv6: bool = True
    wildcard: bool = True
    nip05: bool = False
    tls_caa: list[str] | None = None
    apply_dns: bool = True
    verify: bool = True


class DomainRemoveBody(_Tolerant):
    domain: str = ""
    force: bool = False


class DnsApplyBody(_Tolerant):
    domain: str = ""


class DnsSubscribeBody(_Tolerant):
    hostname: str = ""
    secret: str | None = None
    rotate: bool = False


class DnsUnsubscribeBody(_Tolerant):
    hostname: str = ""


class CredentialSetBody(_Tolerant):
    provider: str = ""
    name: str = ""
    value: str = ""


class CredentialRemoveBody(_Tolerant):
    provider: str = ""
    name: str = ""


class DomainPrimaryPlanBody(_Strict):
    domain: str


class DomainPrimaryApplyBody(_Strict):
    domain: str
    plan_sha256: str


# -- nsite gateway ------------------------------------------------------------

class NsiteGatewayBody(_Tolerant):
    domain: str = ""
    lookup_relays: list[str] | None = None
    extra_relays: list[str] | None = None
    fallback_servers: list[str] | None = None
    allow_http: bool = False
    max_blob_bytes: int | None = None
    cache_quota_bytes: int | None = None


class NsiteBlossomBody(_Tolerant):
    """Local Blossom server (Phase 5, D4) enable/configure body."""

    listen: str = ""
    data_dir: str = ""
    quota_bytes: int | None = None
    max_blob_bytes: int | None = None
    retention_days: int | None = None
    allow_pubkeys: list[str] | None = None


# -- nsite sites / publishing -------------------------------------------------

class NsiteValidateBody(_Tolerant):
    event: Any = None


class NsiteReachabilityBody(_Tolerant):
    relays: list[str] | None = None
    servers: list[str] | None = None
    timeout: float = 5.0


class NsitePublishPlanBody(_Tolerant):
    pubkey: str = ""
    kind: int = 15128
    d: str = ""
    items: list[dict[str, str]] | None = None
    site: str = ""
    servers: list[str] | None = None
    relays: list[str] | None = None
    copy_of: str = ""
    app: str = ""
    npk: bool = False
    npk_version: str = "0.1.0"


class NsiteRegisterBody(_Tolerant):
    pubkey: str = ""
    kind: int = 15128
    d: str = ""
    title: str = ""


class NsiteUnregisterBody(_Tolerant):
    pubkey: str = ""
    d: str = ""


class NsiteBlockAddBody(_Tolerant):
    pubkey: str = ""


class NsiteBlockRemoveBody(_Tolerant):
    pubkey: str = ""


class NsiteBlockSetBody(_Tolerant):
    pubkeys: list[str] = Field(default_factory=list)


class NsitePublishBody(_Tolerant):
    event: Any = None
    plan_sha256: str = ""
    relays: list[str] | None = None
    npk_release_event: Any = None
    npk_sha256: str = ""


class NsiteSnapshotBody(_Tolerant):
    event: Any = None
    plan_sha256: str = ""
    relays: list[str] | None = None


class NsiteMirrorBody(_Tolerant):
    pubkey: str = ""
    d: str = ""
    servers: list[str] = Field(default_factory=list)


class NsiteDomainAttachBody(_Tolerant):
    fqdn: str = ""
    pubkey: str = ""
    d: str = ""
    method: str = "cname"
    verify: bool = True


class NsiteDomainDetachBody(_Tolerant):
    fqdn: str = ""


class NsiteCollectionValidateBody(_Tolerant):
    event: dict[str, Any] = Field(default_factory=dict)


class NsiteCollectionPlanBody(_Tolerant):
    pubkey: str = ""
    d: str = ""
    title: str = ""
    description: str = ""
    image: str = ""
    entries: Any = None
    relays: list[str] | None = None
    copy_of: str = ""


class NsiteCollectionPublishBody(_Tolerant):
    event: dict[str, Any] = Field(default_factory=dict)
    plan_sha256: str = ""
    relays: list[str] | None = None


# -- backup -------------------------------------------------------------------

class BackupCreateBody(_Tolerant):
    tag: str = ""
    paths: list[str] = Field(default_factory=list)
    host: str = ""


class BackupRestoreBody(_Tolerant):
    snapshot: str = ""
    target: str = ""
    include: list[str] = Field(default_factory=list)


class BackupDeleteBody(_Tolerant):
    snapshot: str = ""
    apply_retention: bool = False
    prune: bool = True


class BackupPolicySetBody(_Tolerant):
    retention: dict[str, int] | None = None
    schedule_enabled: bool | None = None
    schedule_calendar: str | None = None


# -- state / recovery ---------------------------------------------------------

class StateRollbackPlanBody(_Tolerant):
    from_ref: str = Field(default="", alias="from")
    to_ref: str = Field(default="", alias="to")
    restic_snapshot: str = ""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class RollbackApplyBody(_Tolerant):
    plan: Any = None


class StateReconcileBody(_Tolerant):
    plan: Any = None


class StatePublishBody(_Tolerant):
    snapshot_only: bool = False
    relays: list[str] = Field(default_factory=list)


# -- diagnosis ----------------------------------------------------------------

class DiagnosisRunBody(_Tolerant):
    categories: list[str] = Field(default_factory=list)
    force: bool = False
    full: bool = False


class DiagnosisIgnoreBody(_Tolerant):
    filter: list[str] = Field(default_factory=list)


class DiagnosisUnignoreBody(_Tolerant):
    filter: list[str] = Field(default_factory=list)


# -- firewall -----------------------------------------------------------------

class FirewallOpenBody(_Tolerant):
    port: str = ""
    protocol: str = ""
    comment: str = "opened via native operation"
    upnp: bool = False


class FirewallCloseBody(_Tolerant):
    port: str = ""
    protocol: str = ""
    upnp_only: bool = False


class FirewallReloadBody(_Tolerant):
    skip_upnp: bool = False


# -- service ------------------------------------------------------------------

class ServiceRestartBody(_Tolerant):
    name: str = ""


class ServiceControlBody(_Tolerant):
    name: str = ""
    action: str = ""


# -- agent --------------------------------------------------------------------

class AgentModelDownloadBody(_Tolerant):
    model_id: str = ""
    evaluation_only: bool = False


class AgentModelSelectBody(_Tolerant):
    model_id: str = ""


class AgentModeSetBody(_Tolerant):
    level: str = ""
    confirm: bool = False


class AgentExportRunBody(_Tolerant):
    cycle_id: str = ""


class AgentContributionSettingsSetBody(_Tolerant):
    dataset_repo: str = ""
    token: str | None = None
    auto_submit: bool = False


class AgentContributionSubmitBody(_Tolerant):
    candidate_file_id: str = ""


class AgentContributionShareBody(_Tolerant):
    cycle_id: str = ""


# -- catalog ------------------------------------------------------------------

class CatalogAttestBody(_Tolerant):
    app_id: str = ""
    publisher: str = ""
    claim: str = ""
    comment: str = ""
    relays: str = ""


class CatalogProfileSetBody(_Tolerant):
    name: str = ""
    about: str = ""
    picture: str = ""
    nip05: str = ""
    website: str = ""
    relays: str = ""


class CatalogAnnounceBody(_Tolerant):
    app_id: str = ""
    relays: str = ""


# -- app ----------------------------------------------------------------------

class LifecyclePlanBody(_Strict):
    """Bodies accepted by ``.../{app_id}/install|upgrade|remove/plan``."""

    model_config = ConfigDict(extra="forbid")


class LifecycleApplyBody(_Strict):
    plan_sha256: str


class AppRemoveBody(_Tolerant):
    app: str = ""
    purge: bool = False


class AppSettingsPlanBody(_Strict):
    values: dict[str, Any]


class AppSettingsApplyBody(_Strict):
    values: dict[str, Any]
    plan_sha256: str


class AppChangeUrlPlanBody(_Strict):
    domain: str
    path: str


class AppChangeUrlApplyBody(_Strict):
    domain: str
    path: str
    plan_sha256: str


# -- user ---------------------------------------------------------------------

class UserCreateBody(_Tolerant):
    username: str = ""
    domain: str = ""
    password: str = ""
    fullname: str = ""
    mailbox_quota: str = "0"
    admin: bool = False


class UserUpdateBody(_Tolerant):
    username: str = ""
    mail: str | None = None
    change_password: str | None = None
    add_mailforward: Any = None
    remove_mailforward: Any = None
    add_mailalias: Any = None
    remove_mailalias: Any = None
    mailbox_quota: Any = None
    fullname: Any = None


class UserDeleteBody(_Tolerant):
    username: str = ""
    purge: bool = False
    force: bool = False


class UserGroupCreateBody(_Tolerant):
    groupname: str = ""
    gid: str | None = None


class UserGroupUpdateBody(_Tolerant):
    groupname: str = ""
    add: list[str] | None = None
    remove: list[str] | None = None


class UserGroupDeleteBody(_Tolerant):
    groupname: str = ""
    force: bool = False


class UserPermissionAddBody(_Tolerant):
    permission: str = ""
    names: list[str] = Field(default_factory=list)


class UserPermissionRemoveBody(_Tolerant):
    permission: str = ""
    names: list[str] = Field(default_factory=list)


class UserPermissionUpdateBody(_Tolerant):
    permission: str = ""
    label: str | None = None
    show_tile: bool | None = None


# -- settings -----------------------------------------------------------------

class SettingsSetBody(_Tolerant):
    key: str = ""
    value: Any = None


class SettingsResetBody(_Tolerant):
    key: str = ""


# -- connectivity -------------------------------------------------------------

class ConnectivityCheckBody(_Strict):
    relays: list[str]
    blossom_servers: list[str]


class ConnectivityPlanBody(_Strict):
    configuration: dict[str, Any]


class ConnectivityApplyBody(_Strict):
    configuration: dict[str, Any]
    plan_sha256: str


# -- WP7 service configs ------------------------------------------------------

class ServiceConfigsReconcileBody(_Tolerant):
    names: list[str] | None = None


# -- package ------------------------------------------------------------------

class PackagePlanBody(_Tolerant):
    package: Any = None
    catalogue: Any = None
    domain: str | None = None
    path: str | None = None




class PackageReconcileBody(_Tolerant):
    plan: Any = None


# -- identity -----------------------------------------------------------------

class IdentityLinkBody(_Tolerant):
    username: str = ""
    pubkey_or_npub: str = ""
    signer_type: str = "unknown"
    label: str | None = None
    enabled: bool = True


class IdentityRevokeBody(_Tolerant):
    pubkey_or_npub: str = ""


# -- capability ---------------------------------------------------------------

class CapabilityGrantBody(_Tolerant):
    pubkey: str = ""
    scopes: list[str] = Field(default_factory=list)
    type_: str = Field(default="agent", alias="type")

    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class CapabilityDelegateBody(_Tolerant):
    pubkey: str = ""
    scopes: list[str] = Field(default_factory=list)
    expires_at: int = 0


class CapabilityRevokeBody(_Tolerant):
    delegation_id: str = ""


# -- mcp endpoint -------------------------------------------------------------

class McpEndpointConfigureBody(_Tolerant):
    domain: str | None = None


# -- operations approval chain ------------------------------------------------

class OperationDecisionBody(_Tolerant):
    event: dict[str, Any] | None = None
    note: str | None = None
    reason: str | None = None


# -- notify signers -----------------------------------------------------------

class NotifySignersRegisterBody(_Tolerant):
    bunker_uri: str = ""
    label: str | None = None


class NotifySignersPairStartBody(_Tolerant):
    relays: list[str] | None = None
    label: str | None = None
