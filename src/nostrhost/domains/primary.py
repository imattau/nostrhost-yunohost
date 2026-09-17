"""Reviewed primary server-address changes for native domains."""

from __future__ import annotations

import hashlib
import json
import socket
import ssl
from pathlib import Path
from typing import Any

from .service import DomainError, DomainService, load_domain, native_domain_names, save_domain


def _legacy_primary() -> str:
    try:
        from yunohost.domain import _get_maindomain

        return _get_maindomain()
    except Exception:  # noqa: BLE001 - native test/install environments may not have current_host
        try:
            return Path("/etc/yunohost/current_host").read_text(encoding="utf-8").strip()
        except OSError:
            return ""


def current_primary(service: DomainService | None = None) -> str:
    service = service or DomainService()
    flagged = []
    for name in native_domain_names(service.state_dir):
        resource = load_domain(service.state_dir, name)
        if resource is not None and resource.primary:
            flagged.append(name)
    return flagged[0] if len(flagged) == 1 else _legacy_primary()


def _certificate_readiness(domain: str) -> dict[str, Any]:
    """Verify that the public HTTPS endpoint presents a valid cert for domain."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3.0) as connection:
            with context.wrap_socket(connection, server_hostname=domain) as secure:
                certificate = secure.getpeercert()
        return {
            "ready": True,
            "expires": certificate.get("notAfter", ""),
        }
    except (OSError, ssl.SSLError, ValueError) as exc:
        return {
            "ready": False,
            "reason": f"HTTPS certificate is not ready for {domain}: {exc}",
        }


def primary_status(service: DomainService | None = None) -> dict[str, Any]:
    service = service or DomainService()
    current = current_primary(service)
    candidates: list[dict[str, Any]] = []
    for name in native_domain_names(service.state_dir):
        if name == current:
            continue
        ready = True
        reasons: list[str] = []
        try:
            inspected = service.inspect(name)
            drift = inspected.get("drift") or {}
            if drift.get("in_sync") is False:
                ready = False
                reasons.append("DNS changes still need to be applied")
        except Exception as exc:  # noqa: BLE001 - report candidate readiness instead of failing the list
            ready = False
            reasons.append(str(exc))
        certificate_check = getattr(service, "certificate_readiness", _certificate_readiness)(name)
        if not certificate_check["ready"]:
            ready = False
            reasons.append(certificate_check["reason"])
        candidates.append(
            {
                "domain": name,
                "ready": ready,
                "reasons": reasons,
                "certificate": certificate_check,
            }
        )
    return {"current": current, "candidates": candidates}


def plan_primary(domain: str, service: DomainService | None = None) -> dict[str, Any]:
    service = service or DomainService()
    status = primary_status(service)
    current = status["current"]
    if not domain or domain == current:
        raise DomainError("choose a different registered domain")
    candidate = next((item for item in status["candidates"] if item["domain"] == domain), None)
    if candidate is None:
        raise DomainError(f"domain {domain} is not registered")
    if not candidate["ready"]:
        raise DomainError(f"domain {domain} is not ready: {'; '.join(candidate['reasons'])}")
    registry = {
        name: resource.dict()
        for name in native_domain_names(service.state_dir)
        if (resource := load_domain(service.state_dir, name)) is not None
    }
    route_state: dict[str, bool] = {}
    if service.caddy is not None and hasattr(service.caddy, "get_route"):
        for name in registry:
            for tag in ("admin", "sso", "portalapi", "native-api"):
                route_id = f"nostrhost-{tag}:{name}"
                route_state[route_id] = service.caddy.get_route(route_id) is not None

    envelope: dict[str, Any] = {
        "action": "domain.primary.set",
        "risk": "high",
        "reversibility": "reversible-with-plan",
        "current_domain": current,
        "target_domain": domain,
        "old_admin_url": f"https://{current}/nostrhost/admin/" if current else "",
        "new_admin_url": f"https://{domain}/nostrhost/admin/",
        "new_portal_url": f"https://{domain}/nostrhost/sso/",
        "changes": [
            "Change the server hostname and primary address",
            "Regenerate server configuration and administrator mail aliases",
            "Move the protected administration API to the new address",
        ],
        "unchanged": ["Installed application addresses", "Nsite custom domains", "The previous registered domain"],
        "sign_in_again": True,
        "readiness": candidate,
        "registry": registry,
        "route_state": route_state,
    }
    payload = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    envelope["plan_sha256"] = hashlib.sha256(payload).hexdigest()
    return envelope


def apply_primary(domain: str, service: DomainService | None = None) -> dict[str, Any]:
    service = service or DomainService()
    from yunohost.nostr_identity import _init_headless_yunohost

    # domain_main_domain is wrapped by @is_unit_operation(); its OperationLogger
    # reads Moulinette.interface.type. The native MCP/API processes never mount a
    # CLI/API interface, so the headless init (same one nostr-identityd /
    # nostr-operationsd / nostr-permissiond run) must happen here or the
    # decorated call crashes with "'NoneType' object has no attribute 'type'".
    _init_headless_yunohost()
    old_domain = current_primary(service)
    resources = {
        name: load_domain(service.state_dir, name)
        for name in native_domain_names(service.state_dir)
    }
    if domain not in resources or resources[domain] is None:
        raise DomainError(f"domain {domain} is not registered")

    try:
        from yunohost.domain import domain_main_domain

        domain_main_domain(new_main_domain=domain)
        for name, resource in resources.items():
            if resource is None:
                continue
            resource.primary = name == domain
            save_domain(service.state_dir, resource)
        for name in resources:
            service._ensure_portal_routes(name)
    except Exception as exc:  # noqa: BLE001 - best-effort transaction rollback
        for resource in resources.values():
            if resource is not None:
                save_domain(service.state_dir, resource)
        if old_domain and old_domain != domain:
            try:
                from yunohost.domain import domain_main_domain

                domain_main_domain(new_main_domain=old_domain)
            except Exception:
                pass
        for name in resources:
            try:
                service._ensure_portal_routes(name)
            except Exception:
                pass
        raise DomainError(f"server address change failed and was rolled back: {exc}") from exc

    return {
        "action": "domain.primary.set",
        "old_domain": old_domain,
        "new_domain": domain,
        "admin_url": f"https://{domain}/nostrhost/admin/",
        "portal_url": f"https://{domain}/nostrhost/sso/",
        "sign_in_again": True,
        "ok": True,
    }
