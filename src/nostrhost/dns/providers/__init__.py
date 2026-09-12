"""DNS provider adapters (W4).

A provider is the only thing that talks to a DNS service. It resolves
credentials internally (via the ``secret:` reference on
``DnsProviderResource``) so operators/agents never see tokens.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from ..models import DnsProviderCapabilities, DnsProviderResource, DnsRecord


class DnsProvider(Protocol):
    """The full-zone surface a provider implements (``full_zone=True``).

    Dynamic-IP-only providers (``capabilities.full_zone is False``) instead
    implement :meth:`push_records` and do not offer the record CRUD surface;
    the domain service routes them through the point-to-point push path.
    """

    capabilities: DnsProviderCapabilities

    def discover_zone(self, domain: str) -> str:
        """Return the authoritative zone that must be reconciled for ``domain``."""
        ...

    def list_records(self, zone: str) -> list[DnsRecord]:
        """All records the provider currently has for ``zone``.

        Records NostrHost created carry their ``owner`` (via the local
        ownership mirror); external records keep a foreign/non-owned owner.
        """
        ...

    def create_record(self, record: DnsRecord) -> str:
        """Create one record; returns a stable provider record id."""
        ...

    def update_record(self, provider_id: str, record: DnsRecord) -> None:
        """Replace the record identified by ``provider_id``."""
        ...

    def delete_record(self, provider_id: str) -> None:
        """Delete the record identified by ``provider_id``."""
        ...

    def verify_record(self, record: DnsRecord) -> dict:
        """Best-effort propagation/resolution check for ``record``."""
        ...


def provider_capabilities(provider_type: str) -> DnsProviderCapabilities:
    """The default capabilities a provider type advertises.

    Kept in one place so the domain resource state, the built provider and
    the capability-model consumers all agree on what a provider can do.
    """
    defaults: dict[str, dict] = {
        "manual": {"dynamic_ip": True, "full_zone": True, "wildcard": True, "txt": True, "caa": True},
        "cloudflare": {"dynamic_ip": True, "full_zone": True, "wildcard": True, "txt": True, "caa": True},
        "desec": {"dynamic_ip": True, "full_zone": True, "wildcard": True, "txt": True, "caa": True},
        "duckdns": {"dynamic_ip": True, "full_zone": False, "wildcard": False, "txt": True, "caa": False},
        "dynu": {"dynamic_ip": True, "full_zone": False, "wildcard": False, "txt": False, "caa": False},
        "dynette": {"dynamic_ip": True, "full_zone": False, "wildcard": False, "txt": False, "caa": False},
    }
    if provider_type not in defaults:
        raise ValueError(f"unknown DNS provider {provider_type!r}")
    return DnsProviderCapabilities(**defaults[provider_type])


def build_provider(resource: DnsProviderResource, state_dir: Path) -> Any:
    """Instantiate a provider from its resource declaration.

    Returns a full-zone provider (``capabilities.full_zone``) or a
    dynamic-IP-only provider (``push_records``) depending on ``resource.type``;
    consumers branch on ``provider.capabilities``.
    """
    from .manual import ManualProvider

    if resource.type == "manual":
        return ManualProvider(zone=resource.zone or "", state_dir=state_dir)
    if resource.type == "cloudflare":
        from .cloudflare import CloudflareProvider

        return CloudflareProvider(
            credential=resource.credential,
            zone=resource.zone or "",
            state_dir=state_dir,
        )
    if resource.type == "duckdns":
        from .duckdns import DuckDnsProvider

        return DuckDnsProvider(
            credential=resource.credential,
            zone=resource.zone or "",
            state_dir=state_dir,
        )
    if resource.type == "dynu":
        from .dynu import DynuProvider

        return DynuProvider(
            credential=resource.credential,
            zone=resource.zone or "",
            state_dir=state_dir,
        )
    if resource.type == "desec":
        from .desec import DesecProvider

        return DesecProvider(
            credential=resource.credential,
            zone=resource.zone or "",
            state_dir=state_dir,
        )
    if resource.type == "dynette":
        from .dynette import DynetteProvider

        return DynetteProvider(
            credential=resource.credential,
            zone=resource.zone or "",
            state_dir=state_dir,
        )
    raise ValueError(f"DNS provider {resource.type!r} is not implemented yet")
