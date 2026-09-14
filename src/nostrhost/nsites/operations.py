"""ToolSpec handlers for the nsites gateway lifecycle (Phase 1, task 1.4).

Each handler is a thin call into :class:`NsiteService`; the OperationEngine
invokes them via ``ToolSpec.handler``. Input models are pydantic v2 (the
registry's ``ToolSpec.validate_args`` uses v2 ``model_validate``/schema).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..core import NostrHostError
from .models import GatewayBlossom, GatewayConfig, GatewayLimits, GatewayRelays
from .service import NsiteError, NsiteService


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GatewayArgs(_Strict):
    """Shared arguments for nsite.gateway.enable/configure."""

    domain: str = Field(description="the registered gateway domain (D2)")
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


class MirrorArgs(_Strict):
    """nsite.mirror: re-upload a site's missing blobs to selected servers."""

    pubkey: str = Field(description="the site owner pubkey (hex or npub)")
    d: str = Field(default="", description="named-site d tag (empty for root sites)")
    servers: list[str] = Field(description="Blossom servers to mirror onto")


class PublishArgs(_Strict):
    event: dict = Field(description="the signed manifest event to verify/broadcast/record")
    plan_sha256: str = Field(description="the plan digest from nsite.publish.plan")
    relays: list[str] | None = Field(None, description="publish relays (must match the plan)")


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


def _service() -> NsiteService:
    return NsiteService()


def _config(args: dict[str, Any]) -> GatewayConfig:
    base = GatewayConfig(domain=args["domain"])
    if args.get("lookup_relays") is not None:
        base.relays = GatewayRelays(lookup=args["lookup_relays"])
    if args.get("extra_relays") is not None:
        base.relays.extra = args["extra_relays"]
    if args.get("fallback_servers") is not None:
        base.blossom = GatewayBlossom(fallback_servers=args["fallback_servers"])
    base.blossom.allow_http = bool(args.get("allow_http", False))
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


def _safe_nsite_publish_plan(pubkey: str = "", kind: int = 15128, d: str = "", items: list | None = None, site: str = "", servers: list | None = None, relays: list | None = None, **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.publish.plan does not accept extra args: {sorted(args)}")
    try:
        return _service().publish_plan(pubkey, kind=kind, d=d, items=items, site=site, servers=servers, relays=relays)
    except NsiteError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_nsite_mirror(pubkey: str = "", d: str = "", servers: list | None = None, **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.mirror does not accept extra args: {sorted(args)}")
    try:
        return _service().mirror(pubkey, d=d, servers=servers)
    except NsiteError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_nsite_publish(event: dict | None = None, plan_sha256: str = "", relays: list | None = None, **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError(f"nsite.publish does not accept extra args: {sorted(args)}")
    if not event:
        raise NostrHostError("nsite.publish requires a signed event")
    try:
        return _service().publish(event, plan_sha256=plan_sha256, relays=relays)
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
