"""DuckDnsProvider: point-to-point A/AAAA updates for a duckdns.org host.

DuckDNS is a *dynamic-IP only* provider: it can change the address record of
a ``<subname>.duckdns.org`` host but cannot enumerate, diff or delete zone
records. So this provider does not implement the full-zone reconciler
surface (``list_records``/``create_record``/...) — instead it implements
``push_records``, which the DDNS watcher and ``dns.apply`` use to push the
current public A/AAAA address(es) for the host. ``capabilities.full_zone``
is therefore ``False`` and the domain service routes these domains through
the point-to-point push path.

The token lives in the credential broker as ``secret:dns/duckdns/<name>``
and is read by the provider itself (never by operators/agents).
"""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlencode

from ... import credentials
from ..models import DnsProviderCapabilities, DnsRecord

_DUCK_DUCK_BASE = "https://www.duckdns.org/update"
_SUFFIX = ".duckdns.org"


def _get_request(url: str, timeout: float = 30.0) -> tuple[int, str]:
    """Default GET helper (httpx); returns (status_code, text)."""
    try:
        import httpx
    except ImportError:  # pragma: no cover - packaging provides httpx
        raise RuntimeError("httpx is required for the duckdns provider") from None
    resp = httpx.get(url, timeout=timeout, follow_redirects=True)
    return resp.status_code, resp.text


class DuckDnsProvider:
    """A single duckdns.org host, updated point-to-point on IP change."""

    resource_type = "dns.duckdns"

    capabilities = DnsProviderCapabilities(
        dynamic_ip=True, full_zone=False, wildcard=False, txt=True, caa=False
    )

    def __init__(
        self,
        *,
        credential: str | None = None,
        zone: str | None = None,
        state_dir: Path,
        credential_dir: Path | None = None,
        token: str | None = None,
        request: Callable[[str], tuple[int, str]] | None = None,
        base: str | None = None,
    ) -> None:
        self.zone = zone or ""
        self.state_dir = state_dir
        self.credential_dir = credential_dir or credentials.credentials_dir(state_dir)
        self._token = token
        self._credential = credential
        self._request = request or _get_request
        self.base = (base or _DUCK_DUCK_BASE).rstrip("/")

    def _get_token(self) -> str:
        if self._token is None:
            if self._credential is None:
                raise credentials.CredentialError("duckdns provider requires a secret:dns/duckdns/<name> credential")
            self._token = credentials.read_secret(self._credential, dir=self.credential_dir)
        return self._token

    def discover_zone(self, domain: str) -> str:
        return domain

    @staticmethod
    def subname(host: str) -> str:
        """The DuckDNS ``domains`` parameter: the subname below duckdns.org."""
        host = host.rstrip(".")
        if host.endswith(_SUFFIX):
            return host[: -len(_SUFFIX)]
        return host

    def push_records(self, records: list[DnsRecord]) -> list[dict[str, Any]]:
        """Push the current A/AAAA address for the host's apex.

        Only apex ``A``/``AAAA`` records are sent (DuckDNS cannot represent
        wildcards or other record kinds). ``ip``/``ipv6`` are omitted when a
        family is not exposed so the service auto-detects (or keeps) it.
        """
        token = self._get_token()
        apex = [r for r in records if r.type in ("A", "AAAA") and r.name == "@"]
        if not apex:
            return [{"action": "skip", "note": "no apex A/AAAA records to push"}]
        ipv4 = next((r.value for r in apex if r.type == "A"), None)
        ipv6 = next((r.value for r in apex if r.type == "AAAA"), None)
        domains = ",".join(sorted({self.subname(r.fqdn()) for r in apex}))
        params: dict[str, str] = {"domains": domains, "token": token}
        if ipv4:
            params["ip"] = ipv4
        if ipv6:
            params["ipv6"] = ipv6
        status, body = self._request(f"{self.base}?{urlencode(params)}")
        text = (body or "").strip()
        if text != "OK":
            raise RuntimeError(f"duckdns update failed: {text or f'http {status}'}")
        return [{"action": "update", "record": r.fingerprint(), "domains": domains, "ipv4": ipv4, "ipv6": ipv6} for r in apex]

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
        return {"record": record.fingerprint(), "verified": None, "note": "duckdns is dynamic-IP only; TXT pushed via its txt API"}
