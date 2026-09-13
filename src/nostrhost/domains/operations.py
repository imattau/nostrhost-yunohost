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


def _dynette_legacy_key(domain: str) -> Any:
    """The legacy Dynette TSIG key file for ``domain``, if any (compat conditional)."""
    from ..dns.providers.dynette import find_tsig_key

    return find_tsig_key(domain)


def _dynette_available(domain: str) -> bool:
    """Whether ``domain`` can be a Dynette host without a credential ref:
    either a legacy TSIG key file or an identity-backed free-hostname
    subscription (its default broker ref exists)."""
    if _dynette_legacy_key(domain) is not None:
        return True
    from ..credentials import exists

    return exists(f"secret:dns/dynette/{domain}")


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
    credential: str | None = None,
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
    from ..dns.models import DnsProviderResource
    from ..dns.providers import provider_capabilities
    from .models import DomainExposure, DomainNostr, DomainTls

    if provider_type != "manual" and not credential:
        # Dynette is the legacy-DDNS compat case: the TSIG key may already
        # exist from a `yunohost dyndns subscribe` OR the host may have been
        # claimed the nostr-native way (`nostrhost dns subscribe`, identity-
        # backed: the operator signed the ownership claim and the broker
        # holds the secret at secret:dns/dynette/<domain>). In both cases no
        # credential ref is required then (the provider resolves the secret
        # itself).
        if provider_type != "dynette" or not _dynette_available(domain):
            raise NostrHostError(
                f"domain.add with the {provider_type} provider requires a --credential secret:dns/{provider_type}/<name> reference"
            )
    elif provider_type != "manual":
        from ..credentials import resolve as resolve_credential

        resolve_credential(credential or "")  # fails fast on a missing/typo'd ref

    try:
        resource = DomainResource(
            name=domain,
            primary=primary,
            provider=DnsProviderResource(type=provider_type, zone=provider_zone, credential=credential, capabilities=provider_capabilities(provider_type)),
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


def _safe_dns_watch(**args: Any) -> dict[str, Any]:
    """DDNS watcher status: last-seen public addresses, last update and the
    dynamic-IP domains the watcher would reconcile."""
    if args:
        raise NostrHostError("dns.watch takes no arguments")
    from ..network.ddns import WatchState

    service = _service()
    state = WatchState(state_dir=service.state_dir)
    return {
        "ipv4": state.last_ipv4,
        "ipv6": state.last_ipv6,
        "last_update": state.last_update,
        "dynamic_domains": service.dynamic_domains(),
        "state": str(state.path),
    }


def _safe_network_public_ip(**args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError("network.public_ip takes no arguments")
    service = _service()
    return {"ipv4": service.public_ipv4(), "ipv6": service.public_ipv6()}


# -- credential broker ------------------------------------------------------ #

def _safe_credential_set(provider: str = "", name: str = "", value: str = "", **args: Any) -> dict[str, Any]:
    if args or not provider or not name:
        raise NostrHostError("credential.set requires a provider and a name")
    from ..credentials import set_secret

    return set_secret(f"secret:dns/{provider}/{name}", value)


def _safe_credential_remove(provider: str = "", name: str = "", **args: Any) -> dict[str, Any]:
    if args or not provider or not name:
        raise NostrHostError("credential.remove requires a provider and a name")
    from ..credentials import remove_secret

    return remove_secret(f"secret:dns/{provider}/{name}")


def _safe_credential_list(provider: str | None = None, **args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError("credential.list accepts only an optional provider")
    from ..credentials import list_secrets

    return {"credentials": list_secrets(provider)}


# -- nostr-native free hostname (identity-backed Dynette) ------------------- #

def _safe_dns_subscribe(hostname: str = "", secret: str | None = None, rotate: bool = False, **args: Any) -> dict[str, Any]:
    if args or not hostname:
        raise NostrHostError("dns.subscribe requires a hostname (a <label> under nohost.me / noho.st / ynh.fr)")
    from ..dns.freehost import subscribe

    try:
        return subscribe(_service().state_dir, hostname, secret=secret, rotate=rotate)
    except NostrHostError:
        raise
    except Exception as exc:
        raise NostrHostError(f"dns.subscribe failed: {exc}") from exc


def _safe_dns_subscriptions(**args: Any) -> dict[str, Any]:
    if args:
        raise NostrHostError("dns.subscriptions takes no arguments")
    from ..dns.freehost import list_subscriptions

    return {"subscriptions": list_subscriptions(_service().state_dir)}


def _safe_dns_unsubscribe(hostname: str = "", **args: Any) -> dict[str, Any]:
    if args or not hostname:
        raise NostrHostError("dns.unsubscribe requires a hostname")
    from ..dns.freehost import unsubscribe

    try:
        return unsubscribe(_service().state_dir, hostname)
    except NostrHostError:
        raise
    except Exception as exc:
        raise NostrHostError(f"dns.unsubscribe failed: {exc}") from exc
