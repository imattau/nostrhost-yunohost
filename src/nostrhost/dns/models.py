"""Typed DNS resource models (W4).

Mirrors the package-engine model style: pydantic v1 when bundled (the
runtime ships pydantic v2 with its v1 compat module), plain pydantic
otherwise.
"""

from __future__ import annotations

import re
from typing import Literal

try:
    from pydantic.v1 import BaseModel, Field, validator
except ImportError:  # pragma: no cover - plain pydantic for local dev
    from pydantic import BaseModel, Field, validator

DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "TXT", "SRV", "CAA", "NS", "MX")

PROVIDER_TYPES = ("manual", "cloudflare")


class DnsProviderCapabilities(BaseModel):
    """What a provider can represent natively.

    ``dynamic_ip``  -- supports point-to-point updates when the public WAN
        address changes (no full-zone replace needed).
    ``full_zone``   -- can enumerate and reconcile the whole zone.
    ``wildcard``    -- can create ``*`` records.
    ``txt``         -- can create TXT records (SPF/DKIM/NIP-05 ownership).
    ``caa``         -- can create CAA records.
    """

    dynamic_ip: bool = False
    full_zone: bool = True
    wildcard: bool = True
    txt: bool = True
    caa: bool = True


class DnsProviderResource(BaseModel):
    """A reference to a DNS provider + its credential reference.

    ``credential`` is a ``secret:dns/<provider>/<name>`` reference resolved
    by the provider internally — agents/operators never see the token.
    """

    type: str = "manual"
    zone: str | None = None
    credential: str | None = None
    capabilities: DnsProviderCapabilities = Field(default_factory=DnsProviderCapabilities)

    @validator("type")
    def known_provider(cls, value: str) -> str:
        if value not in PROVIDER_TYPES:
            raise ValueError(f"unknown DNS provider {value!r}")
        return value

    @validator("credential")
    def reference_form(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith("secret:"):
            raise ValueError("credential must be a 'secret:dns/<provider>/<name>' reference")
        return value


class DnsRecord(BaseModel):
    """One desired/actual DNS record.

    ``name`` is relative to ``zone`` (``@`` for the apex). ``owner`` bounds
    every mutation: only records owned by the declaring resource are ever
    created/updated/deleted by NostrHost; everything else in the zone is
    preserved.
    """

    zone: str
    name: str = "@"
    type: str
    value: str
    ttl: int = 3600
    owner: str = "nostrhost"

    @validator("type")
    def known_type(cls, value: str) -> str:
        if value not in DNS_RECORD_TYPES:
            raise ValueError(f"unsupported DNS record type {value!r}")
        return value

    @validator("name")
    def sane_name(cls, value: str) -> str:
        if value == "@":
            return value
        if not re.fullmatch(r"[a-zA-Z0-9*_.-]+", value):
            raise ValueError(f"invalid DNS record name {value!r}")
        return value

    def fqdn(self) -> str:
        """Fully-qualified name (apex => the zone itself)."""
        if self.name in ("@", ""):
            return self.zone
        return f"{self.name}.{self.zone}"

    def is_on_domain(self, domain: str) -> bool:
        """True when this record's fqdn is ``domain`` or a subdomain of it."""
        fqdn = self.fqdn().rstrip(".")
        domain = domain.rstrip(".")
        return fqdn == domain or fqdn.endswith("." + domain)

    def fingerprint(self) -> str:
        """Stable identity used as the provider record id / diff key."""
        return f"{self.type} {self.fqdn()} = {self.value}"

    def diff_key(self) -> tuple[str, str, str]:
        return (self.zone, self.name, self.type)


class DnsChange(BaseModel):
    """One step of a reconciliation plan."""

    action: Literal["create", "update", "delete", "keep"]
    record: DnsRecord
    provider_id: str | None = None
    note: str = ""


class DnsPlan(BaseModel):
    """A full desired-vs-actual reconciliation for one zone."""

    zone: str
    changes: list[DnsChange] = Field(default_factory=list)
    preserved: list[DnsRecord] = Field(default_factory=list)

    def summarize(self) -> dict[str, int]:
        counts: dict[str, int] = {"create": 0, "update": 0, "delete": 0, "keep": 0}
        for change in self.changes:
            counts[change.action] = counts.get(change.action, 0) + 1
        counts["preserved"] = len(self.preserved)
        return counts
