"""Desired-record computation for a DomainResource (W4).

The planner is the only place that decides which records a domain wants;
providers and registrars stay out of it entirely.
"""

from __future__ import annotations

from typing import Iterable

from ..dns.models import DnsRecord
from .models import DomainResource

_SPECIAL_USE_TLDS = frozenset({"local", "test", "invalid", "localhost", "onion", "example", "internal"})


def discover_zone(domain: str, *, provider_zone: str | None = None, registered: Iterable[str] = ()) -> str:
    """Find the authoritative zone that must be reconciled for ``domain``.

    Order of preference:
      1. an explicit ``provider.zone`` on the resource;
      2. the longest registered native domain that is ``domain`` or a parent
         (so ``sub.example.com`` reconciles against ``example.com``);
      3. a heuristic: the last two labels, or the last three for a known
         special-use TLD, else the whole name.
    """
    if provider_zone:
        return provider_zone.rstrip(".")
    registered = sorted({d.rstrip(".") for d in registered if d}, key=len, reverse=True)
    for candidate in registered:
        if domain == candidate or domain.endswith("." + candidate):
            return candidate
    labels = domain.split(".")
    if len(labels) <= 2:
        return domain
    if labels[-1] in _SPECIAL_USE_TLDS:
        return ".".join(labels[-2:])
    return ".".join(labels[-2:])


def desired_records(domain: DomainResource, *, ipv4: str | None = None, ipv6: str | None = None) -> list[DnsRecord]:
    """The records NostrHost wants for this domain.

    Native default: A/AAAA (apex + optional wildcard) and any explicitly
    configured CAA issuers. No mail records unless an app declares them
    (W4 Phase B). NIP-05 needs no DNS record — it is served over HTTPS.
    """
    zone = domain.name
    records: list[DnsRecord] = []

    if domain.exposure.ipv4 and ipv4:
        records.append(DnsRecord(zone=zone, name="@", type="A", value=ipv4, owner="nostrhost"))
        if domain.exposure.wildcard:
            records.append(DnsRecord(zone=zone, name="*", type="A", value=ipv4, owner="nostrhost"))
    if domain.exposure.ipv6 and ipv6:
        records.append(DnsRecord(zone=zone, name="@", type="AAAA", value=ipv6, owner="nostrhost"))
        if domain.exposure.wildcard:
            records.append(DnsRecord(zone=zone, name="*", type="AAAA", value=ipv6, owner="nostrhost"))

    for issuer in domain.tls.caa:
        records.append(DnsRecord(zone=zone, name="@", type="CAA", value=f'0 issue "{issuer}"', owner="nostrhost"))

    return records
