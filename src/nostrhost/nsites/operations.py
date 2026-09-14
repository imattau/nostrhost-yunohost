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
