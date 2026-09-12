"""Native domain lifecycle service (W4).

``DomainService`` owns the normal flow for ``domain.add`` / ``domain.remove``
and the read-only ``list`` / ``inspect`` plus the ``dns.plan|apply|verify``
entry points. All live dependencies (state dir, Caddy client, public-IP
probes, provider factory) are injectable for tests.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Callable

from ..dns import reconciler
from ..dns.models import DnsProviderResource, DnsRecord
from ..dns.providers import build_provider
from .models import DomainResource


def domain_state_dir(state_dir: Path) -> Path:
    # Distinct from the legacy ``state/domains`` section the state recorder
    # re-renders from LDAP (export_state -> StateRepo._render rmtree's it),
    # so native domains live in their own directory that nothing clobbers.
    return state_dir / "domains-native"


def domain_state_path(state_dir: Path, name: str) -> Path:
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", name)
    return domain_state_dir(state_dir) / f"{safe}.json"


def load_domain(state_dir: Path, name: str) -> DomainResource | None:
    path = domain_state_path(state_dir, name)
    if not path.is_file():
        return None
    try:
        return DomainResource(**json.loads(path.read_text(encoding="utf-8")))
    except Exception:  # noqa: BLE001 - a broken state file is a listing warning
        return None


def save_domain(state_dir: Path, domain: DomainResource) -> Path:
    path = domain_state_path(state_dir, domain.name)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(domain.dict(), indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o640)
    temporary.replace(path)
    return path


def unlink_domain(state_dir: Path, name: str) -> bool:
    path = domain_state_path(state_dir, name)
    if not path.is_file():
        return False
    path.unlink()
    return True


def native_domain_names(state_dir: Path | None = None) -> list[str]:
    """All registered native domain names (the parallel registry).

    Consumed by the legacy permission validation path so native domains are
    accepted without any LDAP virtualdomain entry (W4: no LDAP).
    """
    try:
        state_dir = state_dir or _default_state_dir()
    except Exception:  # noqa: BLE001
        state_dir = state_dir or Path("/var/lib/nostrhost/state")
    names: list[str] = []
    base = domain_state_dir(state_dir)
    if not base.is_dir():
        return names
    for path in sorted(base.glob("*.json")):
        names.append(path.stem)
    return names


def native_domain_registry(state_dir: Path | None = None) -> dict[str, dict[str, Any]]:
    """Registered native domains as plain dicts (for inspect/registry use)."""
    registry: dict[str, dict[str, Any]] = {}
    for name in native_domain_names(state_dir):
        domain = load_domain(state_dir or _default_state_dir(), name)
        if domain is not None:
            registry[name] = domain.dict()
    return registry


def _default_state_dir() -> Path:
    try:
        from yunohost.nostr_state import state_dir_from_env

        return state_dir_from_env()
    except Exception:  # noqa: BLE001
        return Path(os.environ.get("NOSTRHOST_STATE_DIR", "/var/lib/nostrhost/state"))


def _public_ip(protocol: int) -> str | None:
    try:
        from yunohost.utils.network import get_public_ip

        return get_public_ip(protocol)  # type: ignore[arg-type]
    except Exception:  # noqa: BLE001 - public IP probing is best-effort
        return None


_LIVE = object()


class DomainService:
    """The native domain lifecycle, dependency-injectable."""

    def __init__(
        self,
        *,
        state_dir: Path | None = None,
        caddy: Any = _LIVE,
        public_ipv4: Callable[[], str | None] | None = None,
        public_ipv6: Callable[[], str | None] | None = None,
        provider_factory: Callable[[DnsProviderResource, Path], Any] | None = None,
    ) -> None:
        self.state_dir = state_dir or _default_state_dir()
        self.caddy = _live_caddy() if caddy is _LIVE else caddy
        self.public_ipv4 = public_ipv4 or (lambda: _public_ip(4))
        self.public_ipv6 = public_ipv6 or (lambda: _public_ip(6))
        self.provider_factory = provider_factory or build_provider

    # -- registry ---------------------------------------------------------- #

    def list_domains(self) -> dict[str, Any]:
        return {"domains": native_domain_names(self.state_dir)}

    def inspect(self, name: str) -> dict[str, Any]:
        domain = self._require(name)
        zone = self._zone_for(domain)
        provider = self._provider(domain, zone)
        desired = self._desired(domain)
        actual = provider.list_records(zone)
        plan = reconciler.build_plan(desired, actual)
        return {
            "domain": domain.dict(),
            "zone": zone,
            "provider": {"type": domain.provider.type, "zone": zone, "credential": domain.provider.credential},
            "desired": [r.dict() for r in desired],
            "actual": [r.dict() for r in actual],
            "plan": {"summary": plan.summarize(), "changes": [c.dict() for c in plan.changes], "preserved": [r.dict() for r in plan.preserved]},
            "drift": self._drift_report(plan),
            "state": str(domain_state_path(self.state_dir, name)),
        }

    # -- lifecycle --------------------------------------------------------- #

    def add(self, domain: DomainResource, *, apply_dns: bool = True, verify: bool = True) -> dict[str, Any]:
        """Register a domain: plan DNS, apply it, stand up Caddy routes and
        persist semantic state."""
        if load_domain(self.state_dir, domain.name) is not None:
            raise DomainError(f"domain {domain.name} is already registered")
        zone = self._zone_for(domain)
        provider = self._provider(domain, zone)
        desired = self._desired(domain)
        actual = provider.list_records(zone)
        plan = reconciler.build_plan(desired, actual)

        applied: list[dict[str, Any]] = []
        if apply_dns:
            applied = reconciler.apply_plan(plan, provider)

        routes: dict[str, Any] = {"domain_site": self._ensure_domain_site(domain.name)}
        if domain.nostr.nip05:
            routes["nip05"] = self._ensure_nip05_route(domain.name)
        routes["portal"] = self._ensure_portal_routes(domain.name)

        save_domain(self.state_dir, domain)

        verification: list[dict[str, Any]] = []
        if verify and apply_dns:
            verification = reconciler.verify_plan(desired, provider)

        return {
            "action": "domain.add",
            "domain": domain.name,
            "zone": zone,
            "provider": domain.provider.type,
            "dns_plan": {"summary": plan.summarize(), "changes": [c.dict() for c in plan.changes], "preserved": [r.dict() for r in plan.preserved]},
            "applied": applied,
            "routes": routes,
            "verify": verification,
            "state": str(domain_state_path(self.state_dir, domain.name)),
            "ok": True,
        }

    def remove(self, name: str, *, force: bool = False) -> dict[str, Any]:
        """Remove a domain: block if apps still use it, delete only
        NostrHost-owned records, drop Caddy routes, unregister state."""
        domain = self._require(name)
        dependents = self._dependents(domain.name)
        if dependents and not force:
            raise DomainError(f"domain {name} is still used by: {', '.join(sorted(dependents))}")

        zone = self._zone_for(domain)
        provider = self._provider(domain, zone)
        owned = [r for r in provider.list_records(zone) if r.is_on_domain(domain.name) and _owned(r)]
        deleted: list[dict[str, Any]] = []
        for record in owned:
            provider.delete_record(record.fingerprint())
            deleted.append({"action": "delete", "record": record.fingerprint(), "type": record.type, "name": record.fqdn()})

        if self.caddy is not None:
            self.caddy.remove_domain_site(domain.name)
            try:
                self.caddy.remove_nip05_route(domain.name)
            except Exception:  # noqa: BLE001 - nip05 route may not exist
                pass
            try:
                self.caddy.remove_portal_routes(domain.name)
            except Exception:  # noqa: BLE001 - portal routes may not exist
                pass

        unlink_domain(self.state_dir, domain.name)

        return {
            "action": "domain.remove",
            "domain": domain.name,
            "zone": zone,
            "deleted": deleted,
            "unregistered": True,
            "ok": True,
        }

    # -- dns.* entry points ------------------------------------------------ #

    def dns_plan(self, name: str) -> dict[str, Any]:
        domain = self._require(name)
        zone = self._zone_for(domain)
        provider = self._provider(domain, zone)
        desired = self._desired(domain)
        actual = provider.list_records(zone)
        plan = reconciler.build_plan(desired, actual)
        return {
            "domain": name,
            "zone": zone,
            "plan": {"summary": plan.summarize(), "changes": [c.dict() for c in plan.changes], "preserved": [r.dict() for r in plan.preserved]},
            "drift": self._drift_report(plan),
        }

    def _drift_report(self, plan: Any) -> dict[str, Any]:
        """Drift report-vs-reconcile summary: what would change and why."""
        summary = plan.summarize()
        report: dict[str, Any] = {"in_sync": summary["create"] == 0 and summary["update"] == 0 and summary["delete"] == 0}
        report["summary"] = summary
        for action in ("create", "update", "delete"):
            report[f"to_{action}"] = [c.record.fingerprint() for c in plan.changes if c.action == action]
        report["preserved"] = [r.fingerprint() for r in plan.preserved]
        return report

    def dns_apply(self, name: str) -> dict[str, Any]:
        domain = self._require(name)
        zone = self._zone_for(domain)
        provider = self._provider(domain, zone)
        desired = self._desired(domain)
        actual = provider.list_records(zone)
        plan = reconciler.build_plan(desired, actual)
        applied = reconciler.apply_plan(plan, provider)
        return {"domain": name, "zone": zone, "applied": applied, "ok": True}

    def dns_reconcile_app(self, app_id: str, domain: str, *, exclude_app: bool = False) -> dict[str, Any]:
        """Reconcile a domain after an app's ``[dns.*]`` records changed.

        Used by the package engine's ``dns.records.ensure`` / ``.remove``
        lifecycle steps. ``dns.records.remove`` runs before the app manifest
        is deleted (plan removal reverses in reverse order), so it passes
        ``exclude_app=True`` to drop the departing app's records from the
        desired set — the reconciler then deletes exactly its owned records.
        The domain must be registered as a native domain (app records are
        enforced through the domain's provider).
        """
        self._require(domain)
        return self._dns_apply_named(domain, exclude_app=app_id if exclude_app else None)

    def _dns_apply_named(self, name: str, *, exclude_app: str | None = None) -> dict[str, Any]:
        domain = self._require(name)
        zone = self._zone_for(domain)
        provider = self._provider(domain, zone)
        desired = self._desired(domain, exclude_app=exclude_app)
        actual = provider.list_records(zone)
        plan = reconciler.build_plan(desired, actual)
        applied = reconciler.apply_plan(plan, provider)
        return {"domain": name, "zone": zone, "applied": applied, "ok": True}

    def dns_verify(self, name: str) -> dict[str, Any]:
        domain = self._require(name)
        zone = self._zone_for(domain)
        provider = self._provider(domain, zone)
        desired = self._desired(domain)
        verification = reconciler.verify_plan(desired, provider)
        return {"domain": name, "zone": zone, "verify": verification}

    # -- internals --------------------------------------------------------- #

    def _require(self, name: str) -> DomainResource:
        domain = load_domain(self.state_dir, name)
        if domain is None:
            raise DomainError(f"domain {name} is not registered")
        return domain

    def _zone_for(self, domain: DomainResource) -> str:
        if domain.provider.type == "manual":
            from .planner import discover_zone

            return discover_zone(domain.name, provider_zone=domain.provider.zone, registered=native_domain_names(self.state_dir))
        provider = self._provider(domain)
        try:
            return provider.discover_zone(domain.name)
        except Exception as exc:  # noqa: BLE001 - surface provider zone failures
            raise DomainError(f"cannot discover zone for {domain.name}: {exc}") from exc

    def _provider(self, domain: DomainResource, zone: str | None = None):
        provider: Any = self.provider_factory(domain.provider, self.state_dir)
        if getattr(provider, "zone", None) is not None:
            provider.zone = provider.zone or zone or domain.name
        return provider

    def _desired(self, domain: DomainResource, *, exclude_app: str | None = None) -> list[DnsRecord]:
        from .planner import desired_records

        records = desired_records(domain, ipv4=self.public_ipv4(), ipv6=self.public_ipv6())
        records.extend(self._app_records(domain, exclude=exclude_app))
        return records

    def _app_records(self, domain: DomainResource, *, exclude: str | None = None) -> list[DnsRecord]:
        """Fold in ``[dns.*]`` records declared by native apps on this domain.

        Each folded record is owned by ``app:<id>`` so reconciliation is
        bounded: an app's records are created/updated with its install and
        deleted when the app (or its records) go away. Only apps whose
        ``web.domain`` is exactly this domain fold here; apps on subdomains
        reconcile under their own (registered) native domain.
        """
        records: list[DnsRecord] = []
        packages_dir = self.state_dir / "packages"
        if not packages_dir.is_dir():
            return records
        for path in packages_dir.glob("*-manifest.json"):
            app_id = path.name[: -len("-manifest.json")]
            if exclude and app_id == exclude:
                continue
            try:
                from ..native_providers import installed_package_manifest

                manifest = installed_package_manifest(app_id, state_dir=packages_dir)
                if not isinstance(manifest, dict):
                    continue
                web = manifest.get("web") or {}
                if str((web or {}).get("domain", "")).rstrip(".") != domain.name:
                    continue
                for declared in (manifest.get("dns") or {}).values():
                    if not isinstance(declared, dict):
                        continue
                    try:
                        records.append(
                            DnsRecord(
                                zone=domain.name,
                                name=str(declared.get("name") or "@"),
                                type=str(declared["type"]).upper(),
                                value=str(declared["value"]),
                                ttl=int(declared.get("ttl") or 3600),
                                owner=f"app:{app_id}",
                            )
                        )
                    except Exception:  # noqa: BLE001 - skip malformed app records
                        continue
            except (json.JSONDecodeError, OSError):
                continue
        return records

    def _ensure_domain_site(self, name: str) -> str:
        if self.caddy is None:
            return "no-caddy"
        return self.caddy.ensure_domain_site(name)

    def _ensure_nip05_route(self, name: str) -> str:
        if self.caddy is None:
            return "no-caddy"
        return self.caddy.ensure_nip05_route(name)

    def _ensure_portal_routes(self, name: str) -> list[str]:
        if self.caddy is None:
            return ["no-caddy"]
        return self.caddy.ensure_portal_routes(name)

    def _dependents(self, name: str) -> list[str]:
        """Native apps whose ``[web]`` domain is this domain or a subdomain."""
        dependents: list[str] = []
        packages_dir = self.state_dir / "packages"
        if not packages_dir.is_dir():
            return dependents
        for path in packages_dir.glob("*-manifest.json"):
            app_id = path.name[: -len("-manifest.json")]
            try:
                from ..native_providers import installed_package_manifest

                manifest = installed_package_manifest(app_id, state_dir=packages_dir)
                web = manifest.get("web") if isinstance(manifest, dict) else None
                domain = (web or {}).get("domain")
            except (json.JSONDecodeError, OSError):
                continue
            if not isinstance(domain, str) or not domain:
                continue
            if domain.rstrip(".") == name or domain.rstrip(".").endswith("." + name):
                dependents.append(app_id)
        return dependents


def _owned(record: DnsRecord) -> bool:
    owner = record.owner or ""
    return owner.startswith(("nostrhost", "domain:", "app:"))


def _live_caddy() -> Any:
    try:
        from ..caddy_admin import CaddyAdminClient

        return CaddyAdminClient()
    except Exception:  # noqa: BLE001 - a live caddy client is optional in tests
        return None


class DomainError(ValueError):
    pass
