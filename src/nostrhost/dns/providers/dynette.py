"""DynetteProvider: point-to-point A/AAAA updates for a YunoHost Dynette host.

Compat layer (W4 Phase D). A host subscribed the legacy way (``yunohost
dyndns subscribe foo.nohost.me``) is a *dynamic-IP only* domain: its address
record is pushed to ``dyndns.yunohost.org`` with an RFC 2136 TSIG
(hmac-sha512) signed update, exactly like the legacy ``yunohost dyndns
update``. ``capabilities.full_zone`` is therefore ``False`` and the provider
implements ``push_records`` (used by ``dns.apply`` and the DDNS watcher)
rather than the full-zone reconciler surface — there is no zone enumeration
API on the Dynette service.

The TSIG key is resolved *conditionally*, in this order:

1. an explicit ``secret:dns/dynette/<name>`` reference — the secret is the
   base64 TSIG key (the part after ``... IN KEY 0 3 165`` in the legacy key
   file);
2. the *default* broker reference ``secret:dns/dynette/<hostname>`` — the
   identity-backed subscription (``nostrhost dns subscribe``, W4 Phase E:
   the node's Nostr identity signs the ownership claim, no TOTP needed);
3. the key file the legacy subscription wrote:
   ``/etc/yunohost/dyndns/K<hostname>.+165+1234.key``;

so a Dynette host subscribed either the nostr-native way or the legacy way
can be registered as a native domain without re-entering its key. If none
exists a CredentialError is raised pointing at ``nostrhost dns subscribe``
(and, for legacy compat, ``yunohost dyndns subscribe``).

The domain service and the watcher resolve the desired A/AAAA from the
server's current public addresses; this provider pushes them through a
delete+add TSIG update on the parent zone (e.g. ``nohost.me``), targeted at
the Dynette authoritative servers (``ns0``/``ns1.yunohost.org``).
"""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any, Callable

from ... import credentials
from ..models import DnsProviderCapabilities, DnsRecord

DEFAULT_KEY_DIR = Path("/etc/yunohost/dyndns")
DYNDNS_AUTH = ("ns0.yunohost.org", "ns1.yunohost.org")
DEFAULT_TTL = 60


def find_tsig_key(hostname: str, key_dir: Path | None = None) -> Path | None:
    """The legacy TSIG key file for ``hostname``, if a subscription exists.

    ``yunohost dyndns subscribe`` writes ``K<hostname>.+165+1234.key``
    (hmac-sha512 / algorithm 165). ``None`` means no legacy key — the compat
    conditional does not engage and an explicit credential is required.
    """
    key_dir = key_dir or DEFAULT_KEY_DIR
    matches = sorted(key_dir.glob(f"K{hostname}.+*.key"))
    return matches[0] if matches else None


def _read_key_secret(key_file: Path) -> str:
    """The TSIG secret out of a legacy ``K<host>.+165+1234.key`` file.

    The file's first line is ``<host>. IN KEY 0 3 165 <secret>`` with the
    base64 secret split over two whitespace-separated chunks; dnspython's
    ``tsigkeyring.from_text`` handles that whitespace.
    """
    line = key_file.read_text(encoding="utf-8").strip().splitlines()[0]
    return line.split(" ", 6)[-1]


def _resolve_servers(names: list[str] | tuple[str, ...]) -> list[str]:
    """Turn hostnames or IP literals into resolvable server IPs."""
    servers: list[str] = []
    for name in names:
        try:
            import ipaddress

            ipaddress.ip_address(name)
            servers.append(name)
            continue
        except ValueError:
            pass
        try:
            import dns.resolver

            for answer in dns.resolver.resolve(name, "A"):
                servers.append(str(answer))
        except Exception:  # noqa: BLE001 - a dead authoritative server is skipped
            continue
    return servers


def _resolve_addresses(hostname: str, servers: list[str]) -> tuple[str | None, str | None]:
    """The host's currently published A/AAAA against the given servers."""
    import dns.resolver

    def _resolve_one(rdtype: str) -> str | None:
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = servers
            answer = resolver.resolve(hostname, rdtype)
            return str(answer[0]) if len(answer) else None
        except Exception:  # noqa: BLE001 - absent/unparseable record => treat as changed
            return None

    return _resolve_one("A"), _resolve_one("AAAA")


def _tsig_push(
    zone: str,
    hostname: str,
    secret: str,
    ipv4: str | None,
    ipv6: str | None,
    ttl: int,
    servers: list[str],
) -> None:
    """Build and send an RFC 2136 TSIG (hmac-sha512) update for the host."""
    import dns.query
    import dns.rcode
    import dns.tsig
    import dns.tsigkeyring
    import dns.update

    servers = _resolve_servers(servers)
    if not servers:
        raise RuntimeError("dynette: could not resolve any authoritative server")
    keyring = dns.tsigkeyring.from_text({f"{hostname}.": secret})
    update = dns.update.Update(zone, keyring=keyring, keyalgorithm=dns.tsig.HMAC_SHA512)
    update.delete(hostname + ".", "A")
    update.delete(hostname + ".", "AAAA")
    if ipv4:
        update.add(hostname + ".", ttl, "A", ipv4)
    if ipv6:
        update.add(hostname + ".", ttl, "AAAA", ipv6)
    response = dns.query.tcp(update, servers[0])
    if response.rcode() != dns.rcode.NOERROR:
        raise RuntimeError(f"dynette update failed: {dns.rcode.to_text(response.rcode())}")


class DynetteProvider:
    """A single Dynette host, updated point-to-point on IP change."""

    resource_type = "dns.dynette"

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
        secret: str | None = None,
        key_dir: Path | None = None,
        auth_servers: list[str] | tuple[str, ...] | None = None,
        resolve: Callable[[str, list[str]], tuple[str | None, str | None]] | None = None,
        push: Callable[..., None] | None = None,
    ) -> None:
        self.zone = zone or ""
        self.state_dir = state_dir
        self.credential_dir = credential_dir or credentials.credentials_dir(state_dir)
        self._credential = credential
        self._secret = secret
        self.key_dir = key_dir or DEFAULT_KEY_DIR
        self.auth_servers = auth_servers or DYNDNS_AUTH
        self._resolve = resolve or _resolve_addresses
        self._push = push or _tsig_push

    def _get_secret(self) -> str:
        if self._secret is not None:
            return self._secret
        if self._credential:
            return credentials.read_secret(self._credential, dir=self.credential_dir)
        default_ref = f"secret:dns/dynette/{self.zone}"
        if credentials.exists(default_ref, dir=self.credential_dir):
            return credentials.read_secret(default_ref, dir=self.credential_dir)
        key_file = find_tsig_key(self.zone, self.key_dir)
        if key_file is None:
            raise credentials.CredentialError(
                "dynette requires a secret:dns/dynette/<name> credential, a "
                f"nostr free-hostname subscription (nostrhost dns subscribe {self.zone}), "
                f"or an existing /etc/yunohost/dyndns/K{self.zone}.+*.key (legacy "
                "'yunohost dyndns subscribe')"
            )
        return _read_key_secret(key_file)

    def discover_zone(self, domain: str) -> str:
        return domain

    def push_records(self, records: list[DnsRecord]) -> list[dict[str, Any]]:
        """Push the current A/AAAA address for the host's apex.

        The desired apex records carry the server's current public addresses;
        the host's published A/AAAA are read back off the Dynette
        authoritative servers and, when unchanged, nothing is pushed.
        """
        apex = [r for r in records if r.type in ("A", "AAAA") and r.name == "@"]
        if not apex:
            return [{"action": "skip", "note": "no apex A/AAAA records to push"}]
        secret = self._get_secret()
        hostname = apex[0].fqdn()
        zone = hostname.split(".", 1)[1]
        ipv4 = next((r.value for r in apex if r.type == "A"), None)
        ipv6 = next((r.value for r in apex if r.type == "AAAA"), None)
        servers = _resolve_servers(list(self.auth_servers))
        if not servers:
            raise RuntimeError("dynette: could not resolve any authoritative server")
        current = self._resolve(hostname, servers)
        if current == (ipv4, ipv6):
            return [{"action": "skip", "note": "address records unchanged", "hostname": hostname, "ipv4": ipv4, "ipv6": ipv6}]
        self._push(zone, hostname, secret, ipv4, ipv6, apex[0].ttl, servers)
        return [{"action": "update", "record": r.fingerprint(), "hostname": hostname, "zone": zone, "ipv4": ipv4, "ipv6": ipv6} for r in apex]

    def verify_record(self, record: DnsRecord) -> dict:
        """Best-effort resolution check via the system resolver (like dynu)."""
        fqdn = record.fqdn()
        if record.type in ("A", "AAAA"):
            try:
                infos = socket.getaddrinfo(fqdn, None)
            except socket.gaierror as exc:
                return {"record": record.fingerprint(), "verified": False, "error": str(exc)}
            values = {info[4][0] for info in infos}
            return {"record": record.fingerprint(), "verified": record.value in values, "resolved": sorted(values)}
        return {"record": record.fingerprint(), "verified": None, "note": "dynette is dynamic-IP only"}
