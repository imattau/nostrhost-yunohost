"""CloudflareProvider: reconcile a zone through the Cloudflare REST API.

Credentials come from the broker as a ``secret:dns/cloudflare/<name>`` ref
(see ``nostrhost.credentials``); the provider reads the token itself and the
token never appears in plans, state or logs. Record identity is the
Cloudflare record id, mirrored in the local ownership store so that only
records NostrHost created are ever mutated (the same ownership-bounding
contract as the manual provider).
"""

from __future__ import annotations

import re
import socket
from pathlib import Path
from typing import Any, Callable

from .. import ownership
from ... import credentials
from ..models import DnsProviderCapabilities, DnsRecord

_CF_BASE = "https://api.cloudflare.com/client/v4"
_MAX_PAGES = 50
_DEFAULT_TTL = 300
_CAA_RE = re.compile(r'^(\d+)\s+(\w+)\s+"([^"]+)"$')
_MX_RE = re.compile(r"^(\d{1,5})\s+(.+)$")


def _caa_data(value: str) -> dict[str, Any] | None:
    match = _CAA_RE.match(value.strip())
    if not match:
        return None
    flags, tag, tag_value = match.groups()
    return {"flags": int(flags), "tag": tag, "value": tag_value}


def _caa_value(data: dict[str, Any]) -> str:
    return f'{data.get("flags", 0)} {data.get("tag", "issue")} "{data.get("value", "")}"'


def _mx_parts(value: str) -> tuple[int, str] | None:
    match = _MX_RE.match(value.strip())
    if not match:
        return None
    return int(match.group(1)), match.group(2)


def _mx_value(priority: int, content: str) -> str:
    return f"{priority} {content}"


class CloudflareApi:
    """Minimal Cloudflare REST client (verified HTTPS)."""

    def __init__(self, token: str, *, base: str = _CF_BASE, request: Callable[..., Any] | None = None) -> None:
        self.token = token
        self.base = base.rstrip("/")
        self._zone_ids: dict[str, str] = {}
        self._request = request or self._httpx

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    def _httpx(self, method: str, url: str, **kwargs: Any) -> Any:
        try:
            import httpx
        except ImportError:  # pragma: no cover - packaging provides httpx
            raise RuntimeError("httpx is required for the cloudflare provider") from None
        resp = httpx.request(method, url, headers=self._headers(), timeout=30.0, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def _call(self, method: str, path: str, *, body: dict[str, Any] | None = None, params: dict[str, Any] | None = None) -> Any:
        url = f"{self.base}{path}"
        kwargs: dict[str, Any] = {}
        if body is not None:
            kwargs["json"] = body
        if params:
            kwargs["params"] = params
        payload = self._request(method, url, **kwargs)
        if not isinstance(payload, dict) or not payload.get("success"):
            errors = payload.get("errors") if isinstance(payload, dict) else None
            raise RuntimeError(f"cloudflare api error: {errors or payload}")
        return payload.get("result")

    def find_zone(self, domain: str) -> str:
        result = self._call("GET", "/zones", params={"name": domain, "status": "active"})
        if not result:
            raise RuntimeError(f"cloudflare: no active zone for {domain}")
        zone = result[0]
        self._zone_ids[zone["name"]] = zone["id"]
        return zone["name"]

    def zone_id(self, zone: str) -> str:
        cached = self._zone_ids.get(zone)
        if cached:
            return cached
        return self.find_zone(zone) and self._zone_ids[zone]

    def list_records(self, zone: str) -> list[dict[str, Any]]:
        zone_id = self.zone_id(zone)
        entries: list[dict[str, Any]] = []
        page = 1
        while page <= _MAX_PAGES:
            result = self._call("GET", f"/zones/{zone_id}/dns_records", params={"per_page": 100, "page": page})
            entries.extend(result or [])
            if len(result or []) < 100:
                break
            page += 1
        return entries

    def create_record(self, zone: str, name: str, type_: str, content: str, ttl: int) -> str:
        body = {"type": type_, "name": name, "content": content, "ttl": max(ttl, 60), "proxied": False}
        result = self._call("POST", f"/zones/{self.zone_id(zone)}/dns_records", body=body)
        return result["id"]

    def update_record(self, zone: str, record_id: str, name: str, type_: str, content: str, ttl: int) -> None:
        body = {"type": type_, "name": name, "content": content, "ttl": max(ttl, 60), "proxied": False}
        self._call("PUT", f"/zones/{self.zone_id(zone)}/dns_records/{record_id}", body=body)

    def delete_record(self, zone: str, record_id: str) -> None:
        self._call("DELETE", f"/zones/{self.zone_id(zone)}/dns_records/{record_id}")


def _resolve_zone_id(api: CloudflareApi, zone: str) -> str:  # pragma: no cover - trivial
    return api.zone_id(zone)


class CloudflareProvider:
    """A Cloudflare zone adapter, ownership-bounded like the manual provider."""

    resource_type = "dns.cloudflare"

    capabilities = DnsProviderCapabilities(
        dynamic_ip=True, full_zone=True, wildcard=True, txt=True, caa=True
    )

    def __init__(
        self,
        *,
        credential: str | None = None,
        zone: str | None = None,
        state_dir: Path,
        credential_dir: Path | None = None,
        api: Any = None,
        token: str | None = None,
    ) -> None:
        self.zone = zone or ""
        self.state_dir = state_dir
        # The broker is a sibling of the state dir (…/credentials next to
        # …/state); test state dirs get their own sibling automatically.
        self.credential_dir = credential_dir or credentials.credentials_dir(state_dir)
        self._api = api
        self._token = token
        self._credential = credential

    def _get_api(self) -> CloudflareApi:
        if self._api is not None:
            return self._api
        if self._token is None:
            if self._credential is None:
                raise credentials.CredentialError("cloudflare provider requires a secret:dns/cloudflare/<name> credential")
            self._token = credentials.read_secret(self._credential, dir=self.credential_dir)
        return CloudflareApi(self._token)

    def discover_zone(self, domain: str) -> str:
        api = self._get_api()
        zone = api.find_zone(domain)
        self.zone = zone
        return zone

    # -- record mapping ----------------------------------------------------- #

    @staticmethod
    def _relative(zone: str, fqdn: str) -> str:
        zone = zone.rstrip(".")
        fqdn = fqdn.rstrip(".")
        if fqdn == zone:
            return "@"
        if fqdn.endswith("." + zone):
            return fqdn[: -(len(zone) + 1)]
        return fqdn

    def _entry_to_record(self, zone: str, entry: dict[str, Any]) -> DnsRecord:
        type_ = entry["type"]
        value = str(entry.get("content") or "")
        if type_ == "CAA":
            data = entry.get("data") if isinstance(entry.get("data"), dict) else None
            value = _caa_value(data) if data else value
        elif type_ == "MX":
            priority = entry.get("priority")
            if priority is not None:
                value = _mx_value(int(priority), value)
        ttl = int(entry.get("ttl") or 0)
        ttl = ttl if ttl > 1 else _DEFAULT_TTL
        return DnsRecord(
            zone=zone,
            name=self._relative(zone, entry["name"]),
            type=type_,
            value=value,
            ttl=ttl,
            provider_id=entry["id"],
        )

    def _record_to_entry(self, record: DnsRecord) -> dict[str, Any]:
        type_ = record.type
        content = record.value
        extras: dict[str, Any] = {}
        if type_ == "CAA":
            data = _caa_data(record.value)
            if data:
                extras["data"] = data
        elif type_ == "MX":
            parts = _mx_parts(record.value)
            if parts:
                extras["priority"] = parts[0]
                content = parts[1]
        return {"type": type_, "content": content, **extras}

    # -- provider surface --------------------------------------------------- #

    def list_records(self, zone: str) -> list[DnsRecord]:
        api = self._get_api()
        mirror = ownership.load_zone_state(self.state_dir, zone).get("records", {})
        records: list[DnsRecord] = []
        for entry in api.list_records(zone):
            record = self._entry_to_record(zone, entry)
            mirror_entry = mirror.get(record.fingerprint())
            if isinstance(mirror_entry, dict) and mirror_entry.get("owner"):
                record.owner = mirror_entry["owner"]
            else:
                record.owner = f"cf:{entry['id']}"
            records.append(record)
        return records

    def create_record(self, record: DnsRecord) -> str:
        api = self._get_api()
        zone = record.zone or self.zone
        entry = self._record_to_entry(record)
        cf_id = api.create_record(zone, record.fqdn(), entry["type"], entry["content"], record.ttl)
        ownership.create_record_entry(self.state_dir, record.copy(update={"provider_id": cf_id, "zone": zone}))
        ownership.set_zone_provider(self.state_dir, zone, "cloudflare")
        return record.fingerprint()

    def update_record(self, provider_id: str, record: DnsRecord) -> None:
        api = self._get_api()
        zone = record.zone or self.zone
        entry = self._record_to_entry(record)
        api.update_record(zone, provider_id, record.fqdn(), entry["type"], entry["content"], record.ttl)
        ownership.update_record_entry(self.state_dir, record.fingerprint(), record.copy(update={"provider_id": provider_id, "zone": zone}))

    def delete_record(self, provider_id: str) -> None:
        api = self._get_api()
        zone = self.zone
        if not zone:
            state = ownership.load_zone_state(self.state_dir, self.zone or "")
            zone = state.get("zone") or ""
        api.delete_record(zone, provider_id)
        ownership.delete_record_by_provider_id(self.state_dir, zone, provider_id)

    def verify_record(self, record: DnsRecord) -> dict:
        """Best-effort resolution check via the system resolver (like manual)."""
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
