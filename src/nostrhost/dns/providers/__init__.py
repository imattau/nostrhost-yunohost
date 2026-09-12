"""DNS provider adapters (W4).

A provider is the only thing that talks to a DNS service. It resolves
credentials internally (via the ``secret:` reference on
``DnsProviderResource``) so operators/agents never see tokens.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from ..models import DnsProviderCapabilities, DnsProviderResource, DnsRecord


class DnsProvider(Protocol):
    """The minimal surface every provider implements."""

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


def build_provider(resource: DnsProviderResource, state_dir: Path) -> DnsProvider:
    """Instantiate a provider from its resource declaration.

    ``credential`` is resolved by the provider itself (currently only the
    manual provider exists; Cloudflare lands in W4 Phase B).
    """
    from .manual import ManualProvider

    if resource.type == "manual":
        return ManualProvider(zone=resource.zone or "", state_dir=state_dir)
    raise ValueError(f"DNS provider {resource.type!r} is not implemented yet")
