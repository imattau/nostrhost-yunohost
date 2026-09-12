"""ManualProvider: NostrHost-owned zone state on disk.

The manual provider is both the default and a faithful stand-in for real
providers: the zone's records live in the DNS state dir, so create/update/
delete are idempotent and ownership-bounded exactly like a real provider's
API calls would be. ``verify_record`` does a best-effort resolution check
through the system resolver.
"""

from __future__ import annotations

import socket
from pathlib import Path

from .. import ownership
from ..models import DnsProviderCapabilities, DnsRecord


class ManualProvider:
    """A provider that owns a single zone, persisted under the state dir."""

    resource_type = "dns.manual"

    capabilities = DnsProviderCapabilities(
        dynamic_ip=True, full_zone=True, wildcard=True, txt=True, caa=True
    )

    def __init__(self, *, zone: str, state_dir: Path) -> None:
        self.zone = zone
        self.state_dir = state_dir

    def discover_zone(self, domain: str) -> str:
        return self.zone or domain

    def list_records(self, zone: str) -> list[DnsRecord]:
        return ownership.owned_records(self.state_dir, zone)

    def create_record(self, record: DnsRecord) -> str:
        record_id = ownership.create_record_entry(self.state_dir, record)
        ownership.set_zone_provider(self.state_dir, record.zone, "manual")
        return record_id

    def update_record(self, provider_id: str, record: DnsRecord) -> None:
        ownership.update_record_entry(self.state_dir, provider_id, record)

    def delete_record(self, provider_id: str) -> None:
        ownership.delete_record_entry(self.state_dir, self.zone, provider_id)

    def verify_record(self, record: DnsRecord) -> dict:
        """Best-effort resolution check via the system resolver.

        A/AAAA use ``socket.getaddrinfo``; other types try the ``dig``
        helper when available and otherwise report ``unchecked``.
        """
        fqdn = record.fqdn()
        if record.type in ("A", "AAAA"):
            try:
                infos = socket.getaddrinfo(fqdn, None)
            except socket.gaierror as exc:
                return {"record": record.fingerprint(), "verified": False, "error": str(exc)}
            values = {info[4][0] for info in infos}
            return {"record": record.fingerprint(), "verified": record.value in values, "resolved": sorted(values)}
        try:
            from yunohost.utils.dns import dig

            answers = dig(fqdn, record.type)
        except Exception:  # noqa: BLE001 - dig is best-effort
            return {"record": record.fingerprint(), "verified": None, "note": "unchecked (dig unavailable)"}
        return {"record": record.fingerprint(), "verified": record.value in answers, "answers": answers}
