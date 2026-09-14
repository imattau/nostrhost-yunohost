"""Nsites gateway/site intent models (Phase 1, task 1.4).

Follows the domain models' pydantic v1 style. These describe the *intent*
stored in ngit state (``state/nsites/``) and the gateway config rendered to
``/etc/nostrhost/nsite.toml`` (implementation plan §3.2/§4.3).
"""

from __future__ import annotations

from typing import Literal

try:
    from pydantic.v1 import BaseModel, Field
except ImportError:  # pragma: no cover - plain pydantic for local dev
    from pydantic import BaseModel, Field


class GatewayRelays(BaseModel):
    """Relay selection for resolution and publishing (D5)."""

    lookup: list[str] = Field(
        default_factory=lambda: ["wss://purplepag.es", "wss://user.kindpag.es"]
    )
    extra: list[str] = Field(default_factory=list)
    manifest_ttl_seconds: int = 300
    negative_ttl_seconds: int = 60


class GatewayBlossom(BaseModel):
    """External Blossom servers for blob resolution (D4)."""

    fallback_servers: list[str] = Field(
        default_factory=lambda: ["https://blossom.primal.net", "https://blossom.band"]
    )
    allow_http: bool = False


class GatewayLimits(BaseModel):
    """Hosted-mode defaults (implementation plan §4.4)."""

    max_blob_bytes: int = 33554432  # 32 MiB
    fetch_timeout_seconds: int = 20
    fetch_concurrency: int = 8
    max_redirects: int = 3
    cache_quota_bytes: int = 2147483648  # 2 GiB
    max_paths_per_manifest: int = 5000
    requests_per_second: int = 50
    requests_burst: int = 200


class GatewayConfig(BaseModel):
    """What the gateway is supposed to do on this host.

    ``enabled`` is derived state (enable/disable), not part of the toml; the
    rest maps 1:1 onto ``/etc/nostrhost/nsite.toml``. Sites are not stored
    here — site registration (Phase 3) writes ``state/nsites/sites/*.json``.
    """

    domain: str = ""
    mode: Literal["hosted"] = "hosted"  # "open" is deferred to Phase 5 (D3)
    public_listen: str = "127.0.0.1:8195"
    internal_listen: str = "127.0.0.1:8196"
    cache_path: str = "/var/cache/nostrhost-nsite"
    relays: GatewayRelays = Field(default_factory=GatewayRelays)
    blossom: GatewayBlossom = Field(default_factory=GatewayBlossom)
    limits: GatewayLimits = Field(default_factory=GatewayLimits)

    def to_toml(self) -> str:
        """Render the gateway config as ``nsite.toml`` (§4.3)."""
        lines = [
            f'domain = "{self.domain}"',
            f'mode = "{self.mode}"',
            f'public_listen = "{self.public_listen}"',
            f'internal_listen = "{self.internal_listen}"',
            f'cache_path = "{self.cache_path}"',
            "",
            "[relays]",
            "lookup = " + _str_list(self.relays.lookup),
            "extra = " + _str_list(self.relays.extra),
            f"manifest_ttl_seconds = {self.relays.manifest_ttl_seconds}",
            f"negative_ttl_seconds = {self.relays.negative_ttl_seconds}",
            "",
            "[blossom]",
            "fallback_servers = " + _str_list(self.blossom.fallback_servers),
            f"allow_http = {str(self.blossom.allow_http).lower()}",
            "",
            "[limits]",
            f"max_blob_bytes = {self.limits.max_blob_bytes}",
            f"fetch_timeout_seconds = {self.limits.fetch_timeout_seconds}",
            f"fetch_concurrency = {self.limits.fetch_concurrency}",
            f"max_redirects = {self.limits.max_redirects}",
            f"cache_quota_bytes = {self.limits.cache_quota_bytes}",
            f"max_paths_per_manifest = {self.limits.max_paths_per_manifest}",
            f"requests_per_second = {self.limits.requests_per_second}",
            f"requests_burst = {self.limits.requests_burst}",
            "",
        ]
        return "\n".join(lines)


class SiteRecord(BaseModel):
    """A hosted-mode allowlist entry (rendered into nsite.toml §sites)."""

    pubkey: str
    kind: int = 15128  # 15128 root | 35128 named
    d: str = ""
    title: str = ""
    last_event_id: str = ""
    aggregate_hash: str = ""
    servers: list[str] = Field(default_factory=list)
    relays: list[str] = Field(default_factory=list)
    provenance: dict[str, str] = Field(default_factory=dict)


class PublishItem(BaseModel):
    """One blob in a publish plan: path and its content sha256."""

    path: str
    sha256: str


class PublishPlan(BaseModel):
    """The unsigned manifest a user is about to sign (D7).

    Built by ``nsite.publish.plan``, never persisted: the plan digest
    ``plan_sha256`` binds the manifest *content* (kind, ``d``, path tags)
    so ``nsite.publish`` can reject a signed event whose digest does not
    match what was planned (stale-plan rejection).
    """

    pubkey: str
    kind: int = 15128  # 15128 root | 35128 named
    d: str = ""
    items: list[PublishItem] = Field(default_factory=list)
    servers: list[str] = Field(default_factory=list)
    relays: list[str] = Field(default_factory=list)
    unsigned_event: dict = Field(default_factory=dict)
    plan_sha256: str = ""


class PublishRequest(BaseModel):
    """A signed manifest + the plan digest it was built from (D7)."""

    event: dict
    plan_sha256: str = ""


def _str_list(values: list[str]) -> str:
    return "[" + ", ".join(f'"{v}"' for v in values) + "]"
