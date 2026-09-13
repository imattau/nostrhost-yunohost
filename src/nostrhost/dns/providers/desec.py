"""DesecProvider: reconcile a zone through the deSEC REST API.

deSEC (desec.io) is a full-zone, dynamic-IP provider: its RRset API can
list, create, update and delete records, so the provider implements the
full-zone reconciler surface exactly like Cloudflare, with the same
ownership-bounding contract (only records NostrHost created, mirrored
locally, are ever mutated). It also carries ``dynamic_ip=True``, so the DDNS
watcher reconciles it on public-IP change through the normal plan/apply path.

Auth is the deSEC ``Authorization: Token <token>`` header; the token comes
from the credential broker as ``secret:dns/desec/<name>``. An RRset is
identified by ``(subname, type)`` — that tuple is used as the provider
record id in the local ownership mirror.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any, Callable

from ... import credentials
from .. import ownership
from ..models import DnsProviderCapabilities, DnsRecord

_DESEC_BASE = "https://desec.io/api/v1"
_MAX_PAGES = 10


def _request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: float = 30.0,
) -> tuple[int, Any]:
    try:
        import httpx
    except ImportError:  # pragma: no cover - packaging provides httpx
        raise RuntimeError("httpx is required for the desec provider") from None
    kwargs: dict[str, Any] = {"headers": headers or {}, "timeout": timeout}
    if body is not None:
        kwargs["json"] = body
    resp = httpx.request(method, url, **kwargs)
    text = resp.text
    try:
        payload: Any = json.loads(text) if text else None
    except json.JSONDecodeError:
        payload = text
    return resp.status_code, payload


class DesecApi:
    """Minimal deSEC RRset client (verified HTTPS)."""

    def __init__(self, token: str, *, base: str = _DESEC_BASE, request: Callable[..., tuple[int, Any]] | None = None) -> None:
        self.token = token
        self.base = base.rstrip("/")
        self._request = request or _request

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Token {self.token}", "Content-Type": "application/json"}

    def get_domain(self, domain: str) -> dict[str, Any] | None:
        status, payload = self._request("GET", f"{self.base}/domains/{domain}/", headers=self._headers())
        if status == 404:
            return None
        if status != 200 or not isinstance(payload, dict):
            raise RuntimeError(f"desec: cannot read domain {domain} (http {status})")
        return payload

    def list_rrsets(self, domain: str) -> list[dict[str, Any]]:
        rrsets: list[dict[str, Any]] = []
        page = 1
        while page <= _MAX_PAGES:
            status, payload = self._request("GET", f"{self.base}/domains/{domain}/rrsets/?cursor={page - 1}", headers=self._headers())
            if status != 200 or not isinstance(payload, list):
                raise RuntimeError(f"desec: cannot list rrsets for {domain} (http {status})")
            rrsets.extend(payload)
            if len(payload) < 500:
                break
            page += 1
        return rrsets

    @staticmethod
    def _rrset_url(base: str, domain: str, subname: str, type_: str) -> str:
        # The '...' suffix sidesteps the double-slash apex problem for an
        # empty subname (rrsets/.../A/ instead of rrsets//A/).
        return f"{base}/domains/{domain}/rrsets/{subname}.../{type_}/"

    def put_rrset(self, domain: str, subname: str, type_: str, records: list[str], ttl: int) -> None:
        status, payload = self._request(
            "PUT",
            self._rrset_url(self.base, domain, subname, type_),
            headers=self._headers(),
            body={"subname": subname, "type": type_, "ttl": ttl, "records": records},
        )
        if status not in (200, 201):
            raise RuntimeError(f"desec: cannot write {subname or '@'} {type_} for {domain} (http {status}: {_summary(payload)})")

    def delete_rrset(self, domain: str, subname: str, type_: str) -> None:
        status, _ = self._request("DELETE", self._rrset_url(self.base, domain, subname, type_), headers=self._headers())
        if status not in (200, 204):
            raise RuntimeError(f"desec: cannot delete {subname or '@'} {type_} for {domain} (http {status})")


def _summary(payload: Any) -> str:
    if isinstance(payload, list):
        return json.dumps(payload)[:200]
    if isinstance(payload, dict):
        return json.dumps(payload)[:200]
    return str(payload)[:200]


class DesecProvider:
    """A deSEC zone adapter, ownership-bounded like the Cloudflare provider."""

    resource_type = "dns.desec"

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
        self.credential_dir = credential_dir or credentials.credentials_dir(state_dir)
        self._api = api
        self._token = token
        self._credential = credential

    def _get_api(self) -> DesecApi:
        if self._api is not None:
            return self._api
        if self._token is None:
            if self._credential is None:
                raise credentials.CredentialError("desec provider requires a secret:dns/desec/<name> credential")
            self._token = credentials.read_secret(self._credential, dir=self.credential_dir)
        return DesecApi(self._token)

    def discover_zone(self, domain: str) -> str:
        api = self._get_api()
        if api.get_domain(domain) is None:
            raise RuntimeError(f"desec: no domain {domain} on this account")
        self.zone = domain
        return domain

    # -- record mapping ----------------------------------------------------- #

    @staticmethod
    def _subname_for(record: DnsRecord) -> str:
        name = record.name
        if name in ("@", ""):
            return ""
        return name.rstrip(".")

    @staticmethod
    def _name_for(subname: str) -> str:
        return "@" if not subname else subname

    @staticmethod
    def _to_desec_value(record: DnsRecord) -> str:
        # deSEC wants TXT contents enclosed in double quotes (zone-file style).
        if record.type == "TXT":
            escaped = record.value.replace('\\', '\\\\').replace('"', '\\"')
            return f'"{escaped}"'
        return record.value

    @staticmethod
    def _from_desec_value(type_: str, value: str) -> str:
        if type_ == "TXT" and len(value) >= 2 and value.startswith('"') and value.endswith('"'):
            inner = value[1:-1]
            return inner.replace('\\"', '"').replace('\\\\', '\\')
        return value

    def _entry_to_record(self, zone: str, entry: dict[str, Any]) -> DnsRecord:
        subname = str(entry.get("subname") or "")
        records = entry.get("records") or []
        value = self._from_desec_value(str(entry.get("type") or ""), str(records[0]) if records else "")
        return DnsRecord(
            zone=zone,
            name=self._name_for(subname),
            type=str(entry["type"]),
            value=value,
            ttl=int(entry.get("ttl") or 3600),
            provider_id=f"{subname}:{entry['type']}",
        )

    @staticmethod
    def _provider_id_to_subname_type(provider_id: str) -> tuple[str, str]:
        subname, _, type_ = provider_id.partition(":")
        return subname, type_

    # -- provider surface --------------------------------------------------- #

    def list_records(self, zone: str) -> list[DnsRecord]:
        api = self._get_api()
        mirror = ownership.load_zone_state(self.state_dir, zone).get("records", {})
        records: list[DnsRecord] = []
        for entry in api.list_rrsets(zone):
            record = self._entry_to_record(zone, entry)
            mirror_entry = mirror.get(record.fingerprint())
            if isinstance(mirror_entry, dict) and mirror_entry.get("owner"):
                record.owner = mirror_entry["owner"]
            else:
                record.owner = f"desec:{record.provider_id}"
            records.append(record)
        return records

    def create_record(self, record: DnsRecord) -> str:
        api = self._get_api()
        zone = record.zone or self.zone
        subname = self._subname_for(record)
        api.put_rrset(zone, subname, record.type, [self._to_desec_value(record)], record.ttl)
        ownership.create_record_entry(self.state_dir, record.copy(update={"provider_id": f"{subname}:{record.type}", "zone": zone}))
        ownership.set_zone_provider(self.state_dir, zone, "desec")
        return record.fingerprint()

    def update_record(self, provider_id: str, record: DnsRecord) -> None:
        api = self._get_api()
        zone = record.zone or self.zone
        subname, type_ = self._provider_id_to_subname_type(provider_id)
        api.put_rrset(zone, subname, type_, [self._to_desec_value(record)], record.ttl)
        ownership.replace_record_by_provider_id(self.state_dir, zone, provider_id, record.copy(update={"provider_id": provider_id, "zone": zone}))

    def delete_record(self, provider_id: str) -> None:
        api = self._get_api()
        zone = self.zone or ""
        subname, type_ = self._provider_id_to_subname_type(provider_id)
        api.delete_rrset(zone, subname, type_)
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
