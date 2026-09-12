"""Domain intent models (W4)."""

from __future__ import annotations

import re
from typing import Literal

try:
    from pydantic.v1 import BaseModel, Field, validator
except ImportError:  # pragma: no cover - plain pydantic for local dev
    from pydantic import BaseModel, Field, validator

from ..dns.models import DnsProviderResource


class DomainExposure(BaseModel):
    """Which address records NostrHost should keep for the domain."""

    ipv4: bool = True
    ipv6: bool = True
    wildcard: bool = True


class DomainTls(BaseModel):
    """TLS policy. ``automatic`` means Caddy owns provisioning (HTTP-01 via
    its ACME/fallback policy); CAA records are only generated when an issuer
    is explicitly listed (never hard-wired to Let's Encrypt)."""

    mode: Literal["automatic"] = "automatic"
    caa: list[str] = Field(default_factory=list)


class DomainNostr(BaseModel):
    """Nostr-native identity features on the domain."""

    nip05: bool = False


class DomainResource(BaseModel):
    """What a NostrHost domain is supposed to do.

    The provider is a ``DnsProviderResource`` reference; NostrHost never
    needs to know registrar/provider API details.
    """

    name: str
    primary: bool = False
    provider: DnsProviderResource = Field(default_factory=lambda: DnsProviderResource(type="manual"))
    exposure: DomainExposure = Field(default_factory=DomainExposure)
    tls: DomainTls = Field(default_factory=DomainTls)
    nostr: DomainNostr = Field(default_factory=DomainNostr)

    @validator("name")
    def valid_hostname(cls, value: str) -> str:
        value = value.strip().lower().rstrip(".")
        if not _VALID_HOSTNAME_RE.fullmatch(value):
            raise ValueError(f"invalid domain name {value!r}")
        tld = value.rsplit(".", 1)[-1]
        if tld.isdigit():
            raise ValueError(f"invalid domain name {value!r} (numeric TLD)")
        return value

    @validator("name")
    def no_trailing_dot(cls, value: str) -> str:
        return value.rstrip(".")


_VALID_HOSTNAME_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def is_valid_hostname(value: str) -> bool:
    try:
        DomainResource(name=value)
        return True
    except Exception:  # noqa: BLE001 - validation check
        return False
