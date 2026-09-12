"""ToolSpec handlers for the native domain/DNS plane (W4).

Each handler is a thin call into :class:`DomainService` with live
dependencies; the OperationEngine invokes them via ``ToolSpec.handler``.
"""

from __future__ import annotations

from typing import Any

from ..core import NostrHostError
from .models import DomainResource
from .service import DomainError, DomainService


def _service() -> DomainService:
    return DomainService()


def _safe_domain_list(**args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError("domain.list takes no arguments")
    return _service().list_domains()


def _safe_domain_inspect(domain: str = "", **args: Any) -> dict[str, Any]:
    if args or not domain:
        raise NostrHostError("domain.inspect requires a domain")
    try:
        return _service().inspect(domain)
    except DomainError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_domain_add(
    domain: str = "",
    provider_type: str = "manual",
    provider_zone: str | None = None,
    primary: bool = False,
    ipv4: bool = True,
    ipv6: bool = True,
    wildcard: bool = True,
    nip05: bool = False,
    tls_caa: list[str] | None = None,
    apply_dns: bool = True,
    verify: bool = True,
    **args: Any,
) -> dict[str, Any]:
    if args or not domain:
        raise NostrHostError("domain.add requires a domain name")
    from ..dns.models import DnsProviderResource, DnsProviderCapabilities
    from .models import DomainExposure, DomainNostr, DomainTls

    try:
        resource = DomainResource(
            name=domain,
            primary=primary,
            provider=DnsProviderResource(type=provider_type, zone=provider_zone, capabilities=DnsProviderCapabilities()),
            exposure=DomainExposure(ipv4=ipv4, ipv6=ipv6, wildcard=wildcard),
            tls=DomainTls(caa=list(tls_caa or [])),
            nostr=DomainNostr(nip05=nip05),
        )
        return _service().add(resource, apply_dns=apply_dns, verify=verify)
    except DomainError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_domain_remove(domain: str = "", force: bool = False, **args: Any) -> dict[str, Any]:
    if args or not domain:
        raise NostrHostError("domain.remove requires a domain")
    try:
        return _service().remove(domain, force=force)
    except DomainError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_dns_plan(domain: str = "", **args: Any) -> dict[str, Any]:
    if args or not domain:
        raise NostrHostError("dns.plan requires a domain")
    try:
        return _service().dns_plan(domain)
    except DomainError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_dns_apply(domain: str = "", **args: Any) -> dict[str, Any]:
    if args or not domain:
        raise NostrHostError("dns.apply requires a domain")
    try:
        return _service().dns_apply(domain)
    except DomainError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_dns_verify(domain: str = "", **args: Any) -> dict[str, Any]:
    if args or not domain:
        raise NostrHostError("dns.verify requires a domain")
    try:
        return _service().dns_verify(domain)
    except DomainError as exc:
        raise NostrHostError(str(exc)) from exc


def _safe_network_public_ip(**args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError("network.public_ip takes no arguments")
    service = _service()
    return {"ipv4": service.public_ipv4(), "ipv6": service.public_ipv6()}
