"""ToolSpec handlers for the nsites gateway lifecycle (Phase 1, task 1.4).

Each handler is a thin call into :class:`NsiteService`; the OperationEngine
invokes them via ``ToolSpec.handler``. Input models are pydantic v2 (the
registry's ``ToolSpec.validate_args`` uses v2 ``model_validate``/schema).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..core import NostrHostError
from .models import GatewayBlossom, GatewayConfig, GatewayLimits, GatewayNpk, GatewayRelays
from .service import NsiteError, NsiteService


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GatewayArgs(_Strict):
    """Shared arguments for nsite.gateway.enable/configure."""

    domain: str = Field(description="the registered gateway domain (D2)")
    mode: Literal["hosted", "open"] = Field(
        default="hosted",
        description="hosted (allowlisted) or open (any decodable label; requires the operator's ACME DNS-01 token)",
    )
    lookup_relays: list[str] | None = Field(
        None, description="override the default NIP-65 lookup relays (D5)"
    )
    extra_relays: list[str] | None = Field(
        None, description="extra relays to resolve site manifests from"
    )
    fallback_servers: list[str] | None = Field(
        None, description="fallback Blossom servers when a manifest has no hints (D4)"
    )
    allow_http: bool = False
    npk_enabled: bool = Field(
        False, description="serve sites from their publisher's npack release bundle when available (Phase 3)"
    )
    max_blob_bytes: int | None = Field(
        None, description="per-blob cap in bytes (default 32 MiB, max 128 MiB)"
    )
    cache_quota_bytes: int | None = Field(
        None, description="blob cache quota in bytes (default 2 GiB)"
    )


class GatewayDisableArgs(_Strict):
    """nsite.gateway.disable takes no arguments (the registry requires every
    approval-gated tool to advertise an input model)."""

    confirm: bool = Field(True, description="acknowledge disabling the gateway")


class BlossomLocalArgs(_Strict):
    """Shared arguments for nsite.blossom.enable/configure (Phase 5, D4)."""

    listen: str = Field(
        "127.0.0.1:8197", description="loopback-only listener (host:port)"
    )
    data_dir: str = Field(
        "/var/lib/nostrhost-nsite/blossom",
        description="content-addressed blob directory",
    )
    quota_bytes: int = Field(
        1073741824, description="total store quota in bytes (default 1 GiB)"
    )
    max_blob_bytes: int = Field(
        33554432, description="per-blob cap in bytes (default 32 MiB, max 128 MiB)"
    )
    retention_days: int = Field(
        30, description="blob retention in days (0 = keep forever)"
    )
    allow_pubkeys: list[str] = Field(
        default_factory=list,
        description="admit uploads signed by exactly these pubkeys (empty = any valid kind-24242 auth)",
    )


class BlossomDisableArgs(_Strict):
    """nsite.blossom.disable takes no arguments (the registry requires every
    approval-gated tool to advertise an input model)."""

    confirm: bool = Field(True, description="acknowledge disabling the local Blossom server")


class SiteArgs(_Strict):
    """Shared arguments for nsite.register / nsite.inspect / nsite.unregister."""

    pubkey: str = Field(description="the site owner pubkey (hex or npub)")
    d: str = Field(default="", description="named-site d tag (empty for root sites)")


class SiteRegisterArgs(SiteArgs):
    kind: int = Field(15128, description="15128 (root) or 35128 (named)")
    title: str = Field(default="", description="human-readable site title")


class ValidateManifestArgs(_Strict):
    event: dict = Field(description="the signed (or unsigned) manifest event")


class PublishPlanArgs(_Strict):
    pubkey: str = Field(description="the site owner pubkey (hex or npub)")
    kind: int = Field(15128, description="15128 (root) or 35128 (named)")
    d: str = Field(default="", description="named-site d tag (empty for root sites)")
    items: list[dict[str, str]] | None = Field(
        None, description='blob inventory: [{"path": "/index.html", "sha256": "<64 hex>"}]'
    )
    site: str = Field(
        default="",
        description="Phase 3b: read the inventory from the server-side draft area instead of items",
    )
    servers: list[str] | None = Field(None, description="Blossom server hints")
    relays: list[str] | None = Field(None, description="publish relays (defaults to host list)")
    copy_of: str = Field(
        default="",
        description="Phase 5: copy the site at 'kind:pubkey:d' — the plan carries a (parent) and A (origin) tags",
    )
    app: str = Field(
        default="",
        description="Phase 5: the 'kind:pubkey:d' address of the kind-32267 catalogue app this site links to — the plan carries an app tag",
    )
    npk: bool = Field(
        default=False,
        description="Phase 3c: also pack the site draft into a deterministic .npk and return the release template",
    )
    npk_version: str = Field(
        default="0.1.0", description="SemVer version for the npk release (default 0.1.0)"
    )


class MirrorArgs(_Strict):
    """nsite.mirror: re-upload a site's missing blobs to selected servers."""

    pubkey: str = Field(description="the site owner pubkey (hex or npub)")
    d: str = Field(default="", description="named-site d tag (empty for root sites)")
    servers: list[str] = Field(description="Blossom servers to mirror onto")


class DomainAttachArgs(_Strict):
    """nsite.domain.attach: attach a custom FQDN to a registered site.

    Requires ``nsites.admin`` + ``domains.write`` (Phase 4, plan §5.3).
    """

    fqdn: str = Field(description="the custom FQDN to attach (e.g. example.com)")
    pubkey: str = Field(description="the site owner pubkey (hex or npub)")
    d: str = Field(default="", description="named-site d tag (empty for root sites)")
    method: str = Field(
        default="cname",
        description="ownership proof: 'cname' to the gateway domain, or 'txt' under _nostrhost-site.<fqdn>",
    )
    verify: bool = Field(
        default=True, description="require the live DNS ownership proof (disable only for controlled tests)"
    )


class DomainDetachArgs(_Strict):
    """nsite.domain.detach: remove an attached custom FQDN's route + marker."""

    fqdn: str = Field(description="the attached custom FQDN to detach")


class PublishArgs(_Strict):
    event: dict = Field(description="the signed manifest event to verify/broadcast/record")
    plan_sha256: str = Field(description="the plan digest from nsite.publish.plan")
    relays: list[str] | None = Field(None, description="publish relays (must match the plan)")
    npk_release_event: dict | None = Field(
        None, description="Phase 3c: the signed kind-9900 release event to verify, upload and broadcast"
    )
    npk_sha256: str = Field(
        default="", description="Phase 3c: the artifact sha256 the release commits to"
    )


class ResolveArgs(_Strict):
    label: str = Field(default="", description="a site label (npub1…, v+50 base36, or 50 base36 + d)")
    pubkey: str = Field(default="", description="author pubkey (hex or npub)")
    d: str = Field(default="", description="named-site d tag")
    relays: list[str] | None = Field(None, description="lookup relays to query")
    limit: int = Field(5, description="max relays to query (bounded)")
    timeout: float = Field(8.0, description="per-relay timeout seconds (bounded)")


class ReachabilityArgs(_Strict):
    relays: list[str] | None = Field(None, description="relay URLs to probe")
    servers: list[str] | None = Field(None, description="Blossom server URLs to probe")
    timeout: float = Field(5.0, description="per-target timeout seconds")


class DiscoverArgs(_Strict):
    refresh: bool = Field(False, description="bypass the 5-minute result cache and force a live relay scan")


class BlockPubkeyArgs(_Strict):
    pubkey: str = Field(description="the site owner pubkey (hex or npub) to block/unblock")


class BlockSetArgs(_Strict):
    pubkeys: list[str] = Field(default_factory=list, description="the full blocked pubkey set (replaces the mute list)")


class CollectionValidateArgs(_Strict):
    event: dict = Field(description="the signed (or unsigned) collection event")


class CollectionPlanArgs(_Strict):
    pubkey: str = Field(description="the curator pubkey (hex or npub)")
    d: str = Field(description="the collection d identifier (1-64 [a-zA-Z0-9_-])")
    title: str = Field(default="", description="collection title (max 120 chars)")
    description: str = Field(default="", description="collection description (max 500 chars)")
    image: str = Field(default="", description="optional https cover image URL")
    entries: list[dict[str, str]] | None = Field(
        None,
        description='ordered entries: [{"kind": "live-root"|"live-named"|"pinned", "ref": "<coordinate|event id>", "relay": "<optional wss hint>"}]',
    )
    relays: list[str] | None = Field(None, description="publication relays (defaults to host list)")
    copy_of: str = Field(
        default="",
        description="save a copy: the 30004:<pubkey>:<d> source to re-sign under this identity",
    )


class CollectionPublishArgs(_Strict):
    event: dict = Field(description="the signed collection event to verify/broadcast")
    plan_sha256: str = Field(description="the plan digest from nsite.collection.publish.plan")
    relays: list[str] | None = Field(None, description="publish relays (must match the plan)")


class CollectionResolveArgs(_Strict):
    coordinate: str = Field(description="a 30004:<pubkey>:<d> collection coordinate")
    relays: list[str] | None = Field(None, description="lookup relays to query")
    limit: int = Field(5, description="max relays to query (bounded)")
    timeout: float = Field(8.0, description="per-relay timeout seconds (bounded)")


class CollectionDiscoverArgs(_Strict):
    refresh: bool = Field(False, description="bypass the 5-minute result cache and force a live relay scan")


def _safe_nsite_discover(**args: Any) -> dict[str, Any]:
    extra = {k: v for k, v in args.items() if k != "refresh"}
    if extra:
        raise NostrHostError(f"nsite.discover does not accept extra args: {sorted(extra)}")
    try:
        return _service().discover(refresh=bool(args.get("refresh", False)))
    except NsiteError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_nsite_block_list(**args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.block.list does not accept extra args: {sorted(args)}")
    from .blocklist import current_blocklist

    try:
        pubkeys = current_blocklist()
    except Exception as exc:  # noqa: BLE001
        raise NostrHostError(f"could not read the blocklist: {exc}") from exc
    return {"pubkeys": pubkeys, "count": len(pubkeys)}


def _safe_nsite_block_set(pubkeys: list[str] | None = None, **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.block.set does not accept extra args: {sorted(args)}")
    from .blocklist import publish_blocklist

    try:
        return publish_blocklist(pubkeys or [])
    except Exception as exc:  # noqa: BLE001
        raise NostrHostError(f"could not publish the blocklist: {exc}") from exc


def _safe_nsite_block_add(pubkey: str = "", **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.block.add does not accept extra args: {sorted(args)}")
    if not pubkey:
        raise NostrHostError("nsite.block.add requires a pubkey")
    from yunohost.nostr_identity import _parse_pubkey
    from .blocklist import _current_block, publish_blocklist

    try:
        target = _parse_pubkey(pubkey)
        current, latest_created_at = _current_block()
        pubkeys = sorted({*current, target})
        return publish_blocklist(pubkeys, latest_created_at=latest_created_at)
    except Exception as exc:  # noqa: BLE001
        raise NostrHostError(f"could not publish the blocklist: {exc}") from exc


def _safe_nsite_block_remove(pubkey: str = "", **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.block.remove does not accept extra args: {sorted(args)}")
    if not pubkey:
        raise NostrHostError("nsite.block.remove requires a pubkey")
    from yunohost.nostr_identity import _parse_pubkey
    from .blocklist import _current_block, publish_blocklist

    try:
        target = _parse_pubkey(pubkey)
        current, latest_created_at = _current_block()
        pubkeys = sorted(p for p in current if p != target)
        return publish_blocklist(pubkeys, latest_created_at=latest_created_at)
    except Exception as exc:  # noqa: BLE001
        raise NostrHostError(f"could not publish the blocklist: {exc}") from exc


def _service() -> NsiteService:
    return NsiteService()


def _config(args: dict[str, Any]) -> GatewayConfig:
    base = GatewayConfig(domain=args["domain"], mode=args.get("mode", "hosted"))
    if args.get("lookup_relays") is not None:
        base.relays = GatewayRelays(lookup=args["lookup_relays"])
    if args.get("extra_relays") is not None:
        base.relays.extra = args["extra_relays"]
    if args.get("fallback_servers") is not None:
        base.blossom = GatewayBlossom(fallback_servers=args["fallback_servers"])
    base.blossom.allow_http = bool(args.get("allow_http", False))
    base.npk = GatewayNpk(enabled=bool(args.get("npk_enabled", False)))
    if args.get("max_blob_bytes") is not None:
        base.limits = GatewayLimits(max_blob_bytes=args["max_blob_bytes"])
    if args.get("cache_quota_bytes") is not None:
        base.limits = GatewayLimits(cache_quota_bytes=args["cache_quota_bytes"])
    return base


def _safe_gateway_status(**args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError("nsite.gateway.status takes no arguments")
    return _service().gateway_status()


def _safe_gateway_enable(**args: Any) -> dict[str, Any]:
    if not args.get("domain"):
        raise NostrHostError("nsite.gateway.enable requires a domain")
    try:
        return _service().enable(_config(args))
    except NsiteError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_gateway_disable(**args: Any) -> dict[str, Any]:
    if set(args) - {"confirm"}:
        raise NostrHostError("nsite.gateway.disable takes only confirm")
    return _service().disable()


def _safe_gateway_configure(**args: Any) -> dict[str, Any]:
    if not args.get("domain"):
        raise NostrHostError("nsite.gateway.configure requires a domain")
    try:
        return _service().configure(_config(args))
    except NsiteError as exc:
        raise NostrHostError(str(exc)) from exc


def _local_model(args: dict[str, Any]):
    from .models import GatewayBlossomLocal

    return GatewayBlossomLocal(**args)


def _safe_blossom_status(**args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError("nsite.blossom.status takes no arguments")
    return _service().blossom_status()


def _safe_blossom_enable(**args: Any) -> dict[str, Any]:
    try:
        return _service().blossom_enable(_local_model(args))
    except NsiteError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_blossom_configure(**args: Any) -> dict[str, Any]:
    try:
        return _service().blossom_configure(_local_model(args))
    except NsiteError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_blossom_disable(**args: Any) -> dict[str, Any]:
    if set(args) - {"confirm"}:
        raise NostrHostError("nsite.blossom.disable takes only confirm")
    try:
        return _service().blossom_disable()
    except NsiteError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_nsite_list(**args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError("nsite.list takes no arguments")
    return _service().site_list()


def _safe_nsite_inspect(pubkey: str = "", d: str = "", **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.inspect does not accept extra args: {sorted(args)}")
    try:
        return _service().site_inspect(pubkey, d=d)
    except NsiteError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_nsite_register(pubkey: str = "", kind: int = 15128, d: str = "", title: str = "", **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.register does not accept extra args: {sorted(args)}")
    try:
        return _service().site_register(pubkey, kind=kind, d=d, title=title)
    except NsiteError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_nsite_unregister(pubkey: str = "", d: str = "", **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.unregister does not accept extra args: {sorted(args)}")
    try:
        return _service().site_unregister(pubkey, d=d)
    except NsiteError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_nsite_validate(event: dict | None = None, **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.validate_manifest does not accept extra args: {sorted(args)}")
    if not event:
        raise NostrHostError("nsite.validate_manifest requires an event")
    return _service().validate_manifest(event)


def _safe_nsite_publish_plan(pubkey: str = "", kind: int = 15128, d: str = "", items: list | None = None, site: str = "", servers: list | None = None, relays: list | None = None, copy_of: str = "", app: str = "", npk: bool = False, npk_version: str = "0.1.0", **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.publish.plan does not accept extra args: {sorted(args)}")
    try:
        return _service().publish_plan(pubkey, kind=kind, d=d, items=items, site=site, servers=servers, relays=relays, copy_of=copy_of, app=app, npk=npk, npk_version=npk_version)
    except NsiteError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_nsite_mirror(pubkey: str = "", d: str = "", servers: list | None = None, **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.mirror does not accept extra args: {sorted(args)}")
    try:
        return _service().mirror(pubkey, d=d, servers=servers)
    except NsiteError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_nsite_domain_list(**args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.domain.list does not accept extra args: {sorted(args)}")
    return _service().domain_list()


def _safe_nsite_domain_attach(fqdn: str = "", pubkey: str = "", d: str = "", method: str = "cname", verify: bool = True, **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.domain.attach does not accept extra args: {sorted(args)}")
    if not fqdn:
        raise NostrHostError("nsite.domain.attach requires an fqdn")
    if not pubkey:
        raise NostrHostError("nsite.domain.attach requires a pubkey")
    try:
        return _service().domain_attach(fqdn, pubkey, d=d, method=method, verify=verify)
    except NsiteError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_nsite_domain_detach(fqdn: str = "", **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.domain.detach does not accept extra args: {sorted(args)}")
    if not fqdn:
        raise NostrHostError("nsite.domain.detach requires an fqdn")
    try:
        return _service().domain_detach(fqdn)
    except NsiteError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_nsite_publish(event: dict | None = None, plan_sha256: str = "", relays: list | None = None, npk_release_event: dict | None = None, npk_sha256: str = "", **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.publish does not accept extra args: {sorted(args)}")
    if not event:
        raise NostrHostError("nsite.publish requires a signed event")
    try:
        return _service().publish(event, plan_sha256=plan_sha256, relays=relays, npk_release_event=npk_release_event, npk_sha256=npk_sha256)
    except NsiteError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_nsite_snapshot(event: dict | None = None, plan_sha256: str = "", relays: list | None = None, **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.snapshot does not accept extra args: {sorted(args)}")
    if not event:
        raise NostrHostError("nsite.snapshot requires a signed event")
    try:
        return _service().snapshot(event, plan_sha256=plan_sha256, relays=relays)
    except NsiteError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_nsite_resolve(label: str = "", pubkey: str = "", d: str = "", relays: list | None = None, limit: int = 5, timeout: float = 8.0, **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.resolve does not accept extra args: {sorted(args)}")
    try:
        return _service().resolve(label=label, pubkey=pubkey, d=d, relays=relays, limit=limit, timeout=timeout)
    except NsiteError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_nsite_reachability(relays: list | None = None, servers: list | None = None, timeout: float = 5.0, **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.reachability does not accept extra args: {sorted(args)}")
    return _service().reachability(relays=relays, servers=servers, timeout=timeout)


def _safe_nsite_collection_validate(event: dict | None = None, **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.collection.validate does not accept extra args: {sorted(args)}")
    if not event:
        raise NostrHostError("nsite.collection.validate requires an event")
    return _service().collection_validate(event)


def _safe_nsite_collection_plan(pubkey: str = "", d: str = "", title: str = "", description: str = "", image: str = "", entries: list | None = None, relays: list | None = None, copy_of: str = "", **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.collection.publish.plan does not accept extra args: {sorted(args)}")
    if not pubkey:
        raise NostrHostError("nsite.collection.publish.plan requires a pubkey")
    try:
        return _service().collection_publish_plan(
            pubkey, d=d, title=title, description=description, image=image,
            entries=entries, relays=relays, copy_of=copy_of,
        )
    except NsiteError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_nsite_collection_publish(event: dict | None = None, plan_sha256: str = "", relays: list | None = None, **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.collection.publish does not accept extra args: {sorted(args)}")
    if not event:
        raise NostrHostError("nsite.collection.publish requires a signed event")
    try:
        return _service().collection_publish(event, plan_sha256=plan_sha256, relays=relays)
    except NsiteError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_nsite_collection_resolve(coordinate: str = "", relays: list | None = None, limit: int = 5, timeout: float = 8.0, **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.collection.get does not accept extra args: {sorted(args)}")
    if not coordinate:
        raise NostrHostError("nsite.collection.get requires a coordinate")
    try:
        return _service().collection_resolve(coordinate, relays=relays, limit=limit, timeout=timeout)
    except NsiteError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_nsite_collection_discover(refresh: bool = False, **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.collection.discover does not accept extra args: {sorted(args)}")
    return _service().collection_discover(refresh=bool(refresh))
