"""DynuProvider: point-to-point A/AAAA updates for a Dynu host.

Like DuckDNS, Dynu's IP-update protocol is *dynamic-IP only*: it updates the
address record of a hostname but does not expose zone enumeration or
record deletion. ``capabilities.full_zone`` is therefore ``False`` and the
provider implements ``push_records`` (used by the DDNS watcher and
``dns.apply``) rather than the full-zone reconciler surface.

Authentication follows Dynu's IP-update protocol: the credential is either
``username:password`` (sent as HTTP Basic auth — the preferred form) or a
bare IP-update password (sent as the ``password`` query parameter, valid
because a ``hostname`` is always supplied).
"""

from __future__ import annotations

import base64
import socket
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlencode

from ... import credentials
from ..models import DnsProviderCapabilities, DnsRecord

_DYNU_BASE = "https://api.dynu.com/nic/update"
_OK_CODES = ("good", "nochg")
_AUTH_CODES = ("badauth", "nohost", "notfqdn")


def _get_request(url: str, headers: dict[str, str] | None = None, timeout: float = 30.0) -> tuple[int, str]:
    try:
        import httpx
    except ImportError:  # pragma: no cover - packaging provides httpx
        raise RuntimeError("httpx is required for the dynu provider") from None
    resp = httpx.get(url, headers=headers or {}, timeout=timeout, follow_redirects=True)
    return resp.status_code, resp.text


def _parse_credential(value: str) -> tuple[str | None, str]:
    """Split ``username:password`` (Basic auth) or a bare password."""
    if ":" in value:
        username, password = value.split(":", 1)
        return username or None, password
    return None, value


class DynuProvider:
    """A single Dynu host, updated point-to-point on IP change."""

    resource_type = "dns.dynu"

    capabilities = DnsProviderCapabilities(
        dynamic_ip=True, full_zone=False, wildcard=False, txt=False, caa=False
    )

    def __init__(
        self,
        *,
        credential: str | None = None,
        zone: str | None = None,
        state_dir: Path,
        credential_dir: Path | None = None,
        token: str | None = None,
        request: Callable[..., tuple[int, str]] | None = None,
        base: str | None = None,
    ) -> None:
        self.zone = zone or ""
        self.state_dir = state_dir
        self.credential_dir = credential_dir or credentials.credentials_dir(state_dir)
        self._token = token
        self._credential = credential
        self._request = request or _get_request
        self.base = (base or _DYNU_BASE).rstrip("/")

    def _get_token(self) -> str:
        if self._token is None:
            if self._credential is None:
                raise credentials.CredentialError("dynu provider requires a secret:dns/dynu/<name> credential")
            self._token = credentials.read_secret(self._credential, dir=self.credential_dir)
        return self._token

    def discover_zone(self, domain: str) -> str:
        return domain

    def push_records(self, records: list[DnsRecord]) -> list[dict[str, Any]]:
        """Push the current A/AAAA address for the host's apex.

        ``myip``/``myipv6`` are set to ``no`` for an unexposed family so Dynu
        does not fall back to the connection address and clobber it.
        """
        token = self._get_token()
        apex = [r for r in records if r.type in ("A", "AAAA") and r.name == "@"]
        if not apex:
            return [{"action": "skip", "note": "no apex A/AAAA records to push"}]
        ipv4 = next((r.value for r in apex if r.type == "A"), None)
        ipv6 = next((r.value for r in apex if r.type == "AAAA"), None)
        hostname = apex[0].fqdn()
        params: dict[str, str] = {"hostname": hostname}
        params["myip"] = ipv4 or "no"
        params["myipv6"] = ipv6 or "no"

        username, password = _parse_credential(token)
        headers: dict[str, str] = {}
        if username is None:
            params["password"] = password
        else:
            raw = f"{username}:{password}".encode("utf-8")
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")

        status, body = self._request(f"{self.base}?{urlencode(params)}", headers)
        code = (body or "").strip().split(" ", 1)[0].lower()
        if code not in _OK_CODES:
            if code in _AUTH_CODES:
                raise credentials.CredentialError(f"dynu rejected the update for {hostname}: {code}")
            raise RuntimeError(f"dynu update failed for {hostname}: {code or f'http {status}'}")
        return [{"action": "update", "record": r.fingerprint(), "hostname": hostname, "ipv4": ipv4, "ipv6": ipv6} for r in apex]

    def verify_record(self, record: DnsRecord) -> dict:
        fqdn = record.fqdn()
        if record.type in ("A", "AAAA"):
            try:
                infos = socket.getaddrinfo(fqdn, None)
            except socket.gaierror as exc:
                return {"record": record.fingerprint(), "verified": False, "error": str(exc)}
            values = {info[4][0] for info in infos}
            return {"record": record.fingerprint(), "verified": record.value in values, "resolved": sorted(values)}
        return {"record": record.fingerprint(), "verified": None, "note": "dynu is dynamic-IP only"}
