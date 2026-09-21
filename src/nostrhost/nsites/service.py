"""Nsites gateway lifecycle + publishing service (Phase 1 task 1.4, Phase 3a).

Manages the optional ``nostrhost-nsite`` systemd unit: enable/disable/
configure, rendering ``/etc/nostrhost/nsite.toml``, writing the gateway
domain's Caddy snippet and reconciling the ``nostrhost-nsite:<domain>`` admin
route, and persisting intent in ``state/nsites/gateway.json`` (ngit state,
§3.2). Phase 3a adds site registration and owner-controlled publishing:
``publish_plan`` builds an unsigned manifest and its plan digest (D7),
``publish`` verifies a signed manifest (signature, plan digest, host-key
signer guard, hosted allowlist), broadcasts to relays with per-relay results
(D5) and records the site, ``snapshot`` records a client-signed kind 5128,
``resolve`` reads manifests from relays, ``reachability`` probes relay/server
targets — all bounded.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .manifest import KIND_NAMED, KIND_ROOT, KIND_SNAPSHOT
from .models import CustomDomainRecord, GatewayBlossomLocal, GatewayConfig, SiteRecord

CONFIG_PATH = Path("/etc/nostrhost/nsite.toml")
CADDY_TEMPLATE_DIR = Path("/usr/share/yunohost/conf/caddy")
CADDY_CONF_DIR = Path("/etc/caddy/conf.d")
GATEWAY_UPSTREAM = "127.0.0.1:8195"
SERVICE = "nostrhost-nsite.service"

_LIVE = object()

# Gateway limit caps (implementation plan §4.4), mirrored from the gateway's
# own config checker (libs/nostrhost-nsite/internal/config/config.go) so an
# out-of-range plan is rejected here, before approval, instead of only at
# gateway startup.
MAX_ALLOWED_BLOB_BYTES = 128 * 1024 * 1024  # 128 MiB
MAX_CACHE_QUOTA_FRACTION = 0.5  # cache_quota_bytes ≤ 50% of free space

# Host defaults for publishing when the owner's NIP-65 list is unavailable
# (implementation plan §D5).
DEFAULT_PUBLISH_RELAYS = [
    "wss://purplepag.es",
    "wss://nos.lol",
    "wss://relay.damus.io",
]

_SITE_DIR = "sites"

# Upper bound on how many discovered sites a single nsite.discover call returns
# after validation and per-site dedupe. Independent of the per-relay fetch
# limit; keeps the on-demand scan bounded and the response small.
DISCOVER_MAX_SITES = 200

# Server-side TTL cache for nsite.discover. The relay scan + validation + blob
# probes are expensive (~15s), and the catalogue is re-read every time a user
# returns to the Browse tab; a 5-minute cache makes revisits instant. Keyed by
# the effective relay set + blocklist fingerprint so a config or block change
# invalidates it. ``refresh=True`` bypasses the cache (manual Refresh).
DISCOVER_CACHE_TTL = 300

# Blob-existence probe bounds for nsite.discover: at most ``MAX_PATHS`` paths
# (index.html first) on at most ``MAX_SERVERS`` advertised server hints per
# site, a per-probe timeout, and a hard wall-clock budget for the whole probe
# phase so a scan of a slow/absent Blossom server cannot blow the request
# budget. Sites whose blobs are unreachable everywhere are dropped; sites with
# no server hints (or an exhausted budget) are kept as ``blobs_ok=None``.
DISCOVER_BLOB_MAX_PATHS = 3
DISCOVER_BLOB_MAX_SERVERS = 3
DISCOVER_BLOB_PROBE_TIMEOUT = 2.0
DISCOVER_BLOB_PHASE_TIMEOUT = 6.0

# Module-level discover cache: persists across the transient ``NsiteService``
# instances the operations layer builds per call, so the API (single uvicorn
# worker) and repeated calls share one warm cache.
_discover_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_discover_cache_lock = threading.Lock()

# Module-level collection cache (``nsite.collection.discover``): same shape as
# the nsite discover cache, keyed by the effective relay set so a config or
# block change invalidates it. ``refresh=True`` bypasses it.
_collection_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_collection_cache_lock = threading.Lock()

# Upper bound on how many collections a single discover call returns, and how
# many entries each resolved collection carries back into the Admin.
DISCOVER_MAX_COLLECTIONS = 100
COLLECTION_ENTRY_RESOLVE_LIMIT = 100

# Phase 3b draft area (implementation plan §3.2 / D6): the one fixed
# server-side file path involved in publishing. The Admin agent writes site
# files here; publish_plan can read its inventory ("shown to the user before
# signing") and nsite.mirror re-uploads missing blobs to selected servers
# from it. The path is fixed, never user-supplied.
DRAFT_ROOT = Path(os.environ.get("NOSTRHOST_NSITE_DRAFTS", "/var/lib/nostrhost/nsites/drafts"))


def draft_dir(pubkey: str, d: str = "") -> Path:
    name = pubkey if not d else f"{pubkey}.{d}"
    return DRAFT_ROOT / name


def site_path(state_dir: Path, pubkey: str, d: str = "") -> Path:
    """``state/nsites/sites/<pubkey>[.<d>].json`` (implementation plan §3.2)."""
    name = pubkey if not d else f"{pubkey}.{d}"
    return nsites_state_dir(state_dir) / _SITE_DIR / f"{name}.json"


_DOMAIN_DIR = "domains"


def custom_domain_path(state_dir: Path, fqdn: str) -> Path:
    """``state/nsites/domains/<fqdn>.json`` (implementation plan §3.2, Phase 4).

    The plan names the path ``<fqdn>.json``; a hostile fqdn must therefore be
    validated before this is called (``_valid_fqdn``), since the filename is
    the fqdn itself.
    """
    return nsites_state_dir(state_dir) / _DOMAIN_DIR / f"{fqdn}.json"


_HOSTNAME_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")


def _split_listen(listen: str) -> tuple[str, str]:
    """Split a host:port listen address into (host, port).

    Accepts ``127.0.0.1:8197`` and ``[::1]:8197`` (the Go gateway's
    ``net.SplitHostPort`` format). Raises NsiteError on a malformed value.
    """
    if listen.startswith("["):
        end = listen.find("]")
        if end < 0 or end + 1 >= len(listen) or listen[end + 1] != ":":
            raise NsiteError(f"malformed listen address {listen!r}")
        host, port = listen[1:end], listen[end + 2 :]
    else:
        if ":" not in listen:
            raise NsiteError(f"malformed listen address {listen!r}")
        host, port = listen.rsplit(":", 1)
    if not port or not port.isdigit():
        raise NsiteError(f"malformed listen address {listen!r}")
    return host, port


def _valid_fqdn(fqdn: str) -> bool:
    fqdn = fqdn.rstrip(".").lower()
    return bool(_HOSTNAME_RE.fullmatch(fqdn))


_OPERATOR_CONFIG = "/etc/nostrhost/operator.toml"


def _acme_dns_config() -> tuple[str, str] | None:
    """The operator's ACME DNS-01 credentials for open-mode wildcard certs.

    Open mode (Phase 5) serves any decodable ``*.domain`` label, so Caddy
    needs a wildcard certificate, which is a DNS-01 challenge — a DNS API
    token the operator keeps in ``operator.toml`` (``acme_dns_provider`` +
    ``acme_dns_api_token``), never in the regenconf-tracked Caddy snippet.
    Returns ``None`` when absent so ``enable``/``configure`` reject open mode
    without it (the fork renders the wildcard DNS-01 block only when the
    token is configured).
    """
    import tomllib

    path = os.environ.get("NOSTRHOST_OPERATOR_CONFIG", _OPERATOR_CONFIG)
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        return None
    provider = data.get("acme_dns_provider")
    token = data.get("acme_dns_api_token")
    if isinstance(provider, str) and provider and isinstance(token, str) and token:
        return provider, token
    return None


def _pubkey_hex(pubkey: str) -> str:
    import re as _re

    if _re.fullmatch(r"[0-9a-f]{64}", pubkey or ""):
        return pubkey
    from nostr_sdk import PublicKey

    try:
        return PublicKey.parse(pubkey).to_hex()
    except Exception as exc:  # noqa: BLE001
        raise NsiteError(f"invalid site pubkey: {pubkey!r}") from exc


def plan_digest(
    *, kind: int, d: str, paths: list[tuple[str, str]], servers: list[str], relays: list[str] | None = None
) -> str:
    """The plan digest binding a manifest's signed content (D7, §6 step 5).

    Covers exactly what a manifest carries that the signer commits to: kind,
    ``d``, the (sorted) path tags and the (sorted) server hints. The Admin's
    ``src/lib/nsite/manifest.ts`` computes the identical digest, so a signed
    event submitted to ``nsite.publish`` with a stale/mismatched digest is
    rejected before any broadcast or record (stale-plan rejection).
    """
    values: list[Any] = [kind, d, sorted(paths), sorted(set(servers))]
    if relays is not None:
        values.append(sorted(set(relays)))
    payload = json.dumps(values, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _broadcast(event: dict[str, Any], relays: list[str], timeout: float = 10.0) -> dict[str, Any]:
    """Publish ``event`` to each relay, collecting per-relay results (D5).

    A relay that accepts the event is an OK; any exception (unreachable,
    timeout, explicit rejection) is a failed entry. The caller decides on
    ``succeeded``: at least one OK is a success-with-warnings, none is a
    failure (implementation plan §D5).
    """
    from yunohost.nostr_identity import publish_to_relay

    results: list[dict[str, Any]] = []
    for relay in relays:
        try:
            publish_to_relay(relay, event, timeout=timeout)
            results.append({"relay": relay, "ok": True})
        except Exception as exc:  # noqa: BLE001 - per-relay failures are reported, not raised
            results.append({"relay": relay, "ok": False, "error": str(exc)})
    ok = sum(1 for r in results if r["ok"])
    return {
        "results": results,
        "ok_count": ok,
        "failed_count": len(results) - ok,
        "succeeded": ok > 0,
    }


def _query_relay_events(
    relay_url: str,
    filters: dict[str, Any],
    *,
    limit: int = 20,
    timeout: float = 8.0,
) -> list[dict[str, Any]]:
    """Issue one bounded REQ against a relay and return the matching events.

    Raw NIP-01 WebSocket, mirroring ``events.query_chain_events``. Best-effort:
    an unreachable relay yields ``[]``. The caller bounds relay count and
    timeout so ``nsite.resolve`` cannot be an amplification vector.
    """
    from websockets.sync.client import connect

    deadline = time.time() + timeout
    events: list[dict[str, Any]] = []
    try:
        with connect(relay_url) as ws:
            sub_id = "nostrhost-nsites-" + secrets.token_hex(4)
            ws.send(json.dumps(["REQ", sub_id, filters]))
            while time.time() < deadline and len(events) < limit:
                try:
                    msg = json.loads(ws.recv(timeout=0.5))
                except TimeoutError:
                    continue
                if msg[0] == "EVENT":
                    events.append(msg[2])
                elif msg[0] == "EOSE":
                    break
            ws.send(json.dumps(["CLOSE", sub_id]))
    except Exception:  # noqa: BLE001 - best-effort read
        return []
    return events


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never follow redirects (a redirect could bounce the probe to an
    internal address after the initial target was validated)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that dials a pre-validated IP while keeping the
    hostname in the request (Host header)."""

    def __init__(self, host, port=None, *, pinned_ip, timeout=None, **kwargs):
        super().__init__(host, port, timeout=timeout, **kwargs)
        self._pinned = (pinned_ip, self.port)

    def _create_connection(self, addr, timeout=None, source_address=None):
        return socket.create_connection(self._pinned, timeout, source_address)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that dials a pre-validated IP; SNI and certificate
    verification still use the real hostname."""

    def __init__(self, host, port=None, *, pinned_ip, timeout=None, **kwargs):
        super().__init__(host, port, timeout=timeout, **kwargs)
        self._pinned = (pinned_ip, self.port)

    def _create_connection(self, addr, timeout=None, source_address=None):
        return socket.create_connection(self._pinned, timeout, source_address)


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, *, pinned_ip: str, port: int) -> None:
        super().__init__()
        self._pinned_ip = pinned_ip
        self._port = port

    def http_open(self, req):
        return self.do_open(_PinnedHTTPConnection, req, pinned_ip=self._pinned_ip, port=self._port)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, *, pinned_ip: str, port: int) -> None:
        super().__init__()
        self._pinned_ip = pinned_ip
        self._port = port

    def https_open(self, req):
        return self.do_open(_PinnedHTTPSConnection, req, pinned_ip=self._pinned_ip, port=self._port)


def _validate_probe_url(url: str, *, allow_private: bool) -> set[str]:
    """Validate `url` and resolve its target host, returning the resolved IPs.

    Rejects non-HTTP(S) URLs, embedded credentials, fragments and (unless
    ``allow_private``) targets resolving to private/loopback/link-local/
    reserved/multicast addresses. Callers must pin the connection to one of
    the returned IPs (see ``_pinned_probe_opener``) so a hostname cannot
    rebind to an internal address between this check and the connect (M10).
    """
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise NsiteError(f"invalid probe URL: {exc}") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise NsiteError("url must be an HTTP(S) URL without embedded credentials")
    if len(url) > 4096 or parsed.fragment:
        raise NsiteError("url is too long or contains a fragment")
    effective_port = port if port is not None else (443 if parsed.scheme == "https" else 80)
    if not 1 <= effective_port <= 65535:
        raise NsiteError("URL port is out of range")
    try:
        addresses = {
            ipaddress.ip_address(result[4][0])
            for result in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as exc:
        raise NsiteError(f"could not resolve probe host: {exc}") from exc
    if allow_private:
        return {str(addr) for addr in addresses}
    if any(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_unspecified
        or address.is_multicast
        for address in addresses
    ):
        raise NsiteError("private, loopback, link-local, reserved, unspecified, and multicast probe targets are disabled")
    return {str(addr) for addr in addresses}


def _pinned_probe_opener(url: str, *, allow_private: bool) -> urllib.request.OpenerDirector:
    """A no-redirect opener whose HTTP(S) connections are pinned to one
    validated target IP — closes the DNS-rebinding window (M10)."""
    addresses = _validate_probe_url(url, allow_private=allow_private)
    if not addresses:
        raise NsiteError("could not resolve probe host")
    parsed = urlsplit(url)
    pinned = sorted(addresses)[0]
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    return urllib.request.build_opener(
        _PinnedHTTPHandler(pinned_ip=pinned, port=port),
        _PinnedHTTPSHandler(pinned_ip=pinned, port=port),
        _NoRedirectHandler(),
    )


def _validate_relay_url(relay_url: str, *, allow_private: bool = False) -> None:
    """Validate a relay probe target (M10): ws/wss only, no embedded
    credentials, and (by default) no private/loopback/link-local address."""
    try:
        parsed = urlsplit(relay_url)
        port = parsed.port
    except ValueError as exc:
        raise NsiteError(f"invalid relay URL: {exc}") from exc
    if parsed.scheme not in {"ws", "wss"} or not parsed.hostname or parsed.username or parsed.password:
        raise NsiteError("relay URL must be a ws:// or wss:// URL without embedded credentials")
    if len(relay_url) > 4096 or parsed.fragment:
        raise NsiteError("relay URL is too long or contains a fragment")
    try:
        addresses = {
            ipaddress.ip_address(result[4][0])
            for result in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as exc:
        raise NsiteError(f"could not resolve relay host: {exc}") from exc
    if allow_private:
        return
    if any(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_unspecified
        or address.is_multicast
        for address in addresses
    ):
        raise NsiteError("private, loopback, link-local, reserved, unspecified, and multicast relay targets are disabled")


def _http_probe(url: str, timeout: float = 5.0, *, allow_private: bool = False) -> dict[str, Any]:
    """HEAD a URL through a connection pinned to a validated target IP.

    The probe never follows redirects and (by default) refuses targets that
    resolve to private/loopback addresses, so ``nsite.reachability`` cannot be
    an SSRF into the metadata service or internal hosts (M10).
    """
    try:
        opener = _pinned_probe_opener(url, allow_private=allow_private)
        req = urllib.request.Request(url, method="HEAD")
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310 - pinned to validated IP, bounded
            return {"url": url, "ok": True, "status": resp.status}
    except NsiteError as exc:
        return {"url": url, "ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"url": url, "ok": False, "error": str(exc)}


def _blob_probe(server_url: str, blob_hash: str, timeout: float = 3.0) -> dict[str, Any]:
    """HEAD one Blossom blob (``https://<server>/<sha256>``), IP-pinned (M10).

    Blossom servers address blobs by their sha256. ``HEAD`` first; servers that
    reject HEAD (405/501) get a single-byte ranged GET (``Range: bytes=0-0``),
    accepting 200/206. Server hints are untrusted manifest data, so the probe
    validates the URL and pins the connection exactly like ``_http_probe``.

    Returns ``{"ok", "status", "error", "definite"}`` where ``definite`` is
    False when the outcome is inconclusive (invalid/private URL — can't check;
    timeout — transient). Only definite failures (an HTTP status >= 400, a
    refused connection, or an unresolvable host) count against a site.
    """
    url = server_url.rstrip("/") + "/" + blob_hash
    try:
        opener = _pinned_probe_opener(url, allow_private=False)
        try:
            with opener.open(urllib.request.Request(url, method="HEAD"), timeout=timeout) as resp:  # noqa: S310
                return {"ok": True, "status": resp.status, "definite": True}
        except urllib.error.HTTPError as exc:
            if exc.code in (405, 501):
                req = urllib.request.Request(url, headers={"Range": "bytes=0-0"})  # noqa: S310
                try:
                    with opener.open(req, timeout=timeout) as resp:
                        return {"ok": resp.status in (200, 206), "status": resp.status, "definite": True}
                except urllib.error.HTTPError as exc2:
                    return {"ok": False, "status": exc2.code, "error": str(exc2), "definite": True}
            return {"ok": False, "status": exc.code, "error": str(exc), "definite": True}
    except NsiteError as exc:
        return {"ok": False, "status": None, "error": str(exc), "definite": False}
    except (TimeoutError, urllib.error.URLError) as exc:
        return {"ok": False, "status": None, "error": str(exc), "definite": False}
    except (ConnectionRefusedError, socket.gaierror) as exc:
        return {"ok": False, "status": None, "error": str(exc), "definite": True}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "status": None, "error": str(exc), "definite": False}


def _site_blob_probes(event: dict[str, Any], verdict: Any) -> list[tuple[str, str]]:
    """The bounded (server, blob_hash) probe grid for one validated site.

    Up to ``DISCOVER_BLOB_MAX_SERVERS`` ``server`` hints x up to
    ``DISCOVER_BLOB_MAX_PATHS`` paths (``/index.html`` probed first). Returns
    an empty list when the manifest advertises no server hints.
    """
    servers: list[str] = []
    tags = event.get("tags") or []
    for tag in tags:
        if not isinstance(tag, list) or not tag or not isinstance(tag[0], str):
            continue
        if tag[0] == "server" and len(tag) > 1 and isinstance(tag[1], str) and len(servers) < DISCOVER_BLOB_MAX_SERVERS:
            servers.append(tag[1])
    by_hash = {path: blob for path, blob in verdict.paths}
    ordered = sorted(by_hash, key=lambda p: (p != "/index.html", p))[: DISCOVER_BLOB_MAX_PATHS]
    probes: list[tuple[str, str]] = []
    for server in servers:
        for path in ordered:
            blob = by_hash.get(path)
            if blob:
                probes.append((server, blob))
    return probes


def _site_blob_check(
    event: dict[str, Any],
    verdict: Any,
    deadline: float,
) -> tuple[bool | None, int, bool]:
    """Probe one site's blobs until success, definite failure, or budget end.

    Returns ``(blobs_ok, checked, truncated)``:
      - ``True``  — at least one blob confirmed (2xx) on an advertised server.
      - ``False`` — every probe was a *definite* failure (no blob anywhere).
      - ``None``  — unverifiable: no server hints, an inconclusive probe
        (invalid/private URL, timeout), or the phase deadline was hit.
    ``checked`` is the number of probes actually sent; ``truncated`` marks a
    deadline bail-out so the caller can surface partial verification.
    """
    probes = _site_blob_probes(event, verdict)
    if not probes:
        return None, 0, False
    checked = 0
    for server, blob_hash in probes:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None, checked, True
        result = _blob_probe(server, blob_hash, timeout=min(DISCOVER_BLOB_PROBE_TIMEOUT, max(0.5, remaining)))
        checked += 1
        if result.get("ok"):
            return True, checked, False
        if not result.get("definite", False):
            return None, checked, False
    return False, checked, False


def _operator_blocklist() -> frozenset[str]:
    """The operator's NIP-51 kind-10000 mute list (blocked pubkeys).

    Read from the local control relay, best-effort: any hiccup yields an empty
    set so ``nsite.discover`` never fails over the blocklist.
    """
    from .blocklist import current_blocklist

    try:
        return frozenset(current_blocklist())
    except Exception:  # noqa: BLE001 - best-effort read
        return frozenset()


def _discover_cache_key(scan_relays: list[str]) -> str:
    material = "\n".join(sorted(scan_relays))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _filter_blocked(payload: dict[str, Any], blocked: frozenset[str]) -> dict[str, Any]:
    """Drop the currently-blocked npubs from a (possibly cached) discover payload.

    The cache stores the full valid site list (keyed by relay set only), so a
    block takes effect on the next read without a rescan — and an unblock
    restores the site just as instantly. Returns the input untouched when
    nothing is blocked.
    """
    if not blocked:
        return payload
    sites = payload.get("sites") or []
    kept = [site for site in sites if site.get("pubkey") not in blocked]
    dropped = len(sites) - len(kept)
    if not dropped:
        return payload
    payload = dict(payload)
    payload["sites"] = kept
    payload["count"] = len(kept)
    blob = dict(payload.get("blob_check") or {})
    blob["blocked"] = int(blob.get("blocked", 0)) + dropped
    payload["blob_check"] = blob
    return payload


def _filter_blocked_collections(payload: dict[str, Any], blocked: frozenset[str]) -> dict[str, Any]:
    """Drop blocked curators from a (possibly cached) collection payload.

    Same shape as ``_filter_blocked`` but for the kind-30004 discover payload,
    whose list lives under ``collections`` (each item carries ``pubkey``).
    Returns the input untouched when nothing is blocked.
    """
    if not blocked:
        return payload
    items = payload.get("collections") or []
    kept = [item for item in items if item.get("pubkey") not in blocked]
    dropped = len(items) - len(kept)
    if not dropped:
        return payload
    payload = dict(payload)
    payload["collections"] = kept
    payload["count"] = len(kept)
    return payload


def _draft_path_is_bad(path: str) -> bool:
    """A draft path must satisfy the same rules as a manifest path (D6)."""
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in path):
        return True
    if "\\" in path:
        return True
    for segment in path.split("/"):
        if ".." in segment:
            return True
    return False


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_draft_blob(path: Path) -> bytes | None:
    """Read a draft blob, bounded so an oversized file is skipped not loaded."""
    try:
        size = path.stat().st_size
        if size > 128 * 1024 * 1024:  # mirror cap mirrors the gateway's 128 MiB max
            return None
        return path.read_bytes()
    except OSError:
        return None


def _blossom_has(server: str, sha256: str, timeout: float = 8.0) -> bool:
    """HEAD a blob on a Blossom server (BUD-01); True when present.

    The connection is pinned to a validated target IP (M10) so the server
    cannot rebind between resolution and connect; private targets stay
    allowed because Blossom servers are operator-configured.
    """
    url = f"{server}/{sha256}"
    try:
        opener = _pinned_probe_opener(url, allow_private=True)
        req = urllib.request.Request(url, method="HEAD")
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310 - pinned to validated IP, bounded
            return resp.status == 200
    except Exception:  # noqa: BLE001 - a missing/unreachable blob is reported, not raised
        return False


def _blossom_upload(
    server: str, sha256: str, data: bytes, auth_event: dict[str, Any], timeout: float = 60.0
) -> tuple[bool, str]:
    """PUT a blob to a Blossom server with a kind-24242 auth event (BUD-02/03).

    The connection is pinned to a validated target IP (M10) so the server
    cannot rebind between resolution and connect.
    """
    import base64

    payload = json.dumps(auth_event, separators=(",", ":")).encode("utf-8")
    header = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    url = f"{server}/upload?sha256={sha256}"
    req = urllib.request.Request(
        url,
        data=data,
        method="PUT",
        headers={"Authorization": f"Nostr {header}", "Content-Type": "application/octet-stream"},
    )
    try:
        opener = _pinned_probe_opener(url, allow_private=True)
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310 - pinned to validated IP, bounded
            return resp.status == 200, str(resp.status)
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def _blossom_auth_event(hashes: list[str]) -> dict[str, Any] | None:
    """A kind-24242 auth event covering ``hashes``, signed with the operator key.

    Server-initiated mirror uploads are not user manifests, so the signer
    guard does not apply; the operator key signs the upload auth (BUD-02/03).
    Returns None when the node is not bootstrapped.
    """
    try:
        from yunohost.nostr_identity import _operator_config, _sign_event

        cfg = _operator_config()
        return _sign_event(cfg.sk, cfg.operator_pubkey, 24242, "", [["x", h] for h in hashes])
    except Exception:  # noqa: BLE001 - mirror needs a bootstrapped node
        return None


# --------------------------------------------------------------------------- #
# npk single-artifact distribution (Phase 3c): pack a site root into a
# deterministic .npk and publish its kind-9900 release alongside the manifest.

_NPACK_BIN = os.environ.get("NPACK_BIN", "npack")
_RELEASE_KIND = 9900
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-+][0-9A-Za-z.-]+)?$")


def _npack_available() -> bool:
    try:
        result = subprocess.run([_NPACK_BIN, "--version"], text=True, capture_output=True, check=False, timeout=10)
        return result.returncode == 0
    except Exception:  # noqa: BLE001 - absence just disables the npk option
        return False


def pack_site_npk(pubkey: str, *, d: str = "", version: str = "0.1.0") -> dict[str, Any]:
    """Pack a site's server-side draft into a deterministic .npk artifact.

    The site root (index.html, assets…) sits at the archive root, so the
    gateway's bundle store can serve paths straight from the unpacked tree.
    Requires the ``npack`` binary ($NPACK_BIN). Returns the artifact path,
    its sha256, and the npk package name (``root`` for root sites, the ``d``
    identifier for named sites).
    """
    if not _SEMVER.fullmatch(version):
        raise NsiteError(f"npk version must be SemVer, got {version!r}")
    pubkey = _pubkey_hex(pubkey)
    root = draft_dir(pubkey, d)
    if not root.is_dir():
        raise NsiteError("npk publish requires the server-side draft area (nsite.publish.plan with --site)")
    name = "root" if not d else d

    with tempfile.TemporaryDirectory(prefix="nostrhost-nsite-npk-") as temporary:
        staging = Path(temporary)
        shutil.copytree(root, staging / "site", symlinks=False)
        site_root = staging / "site"
        init = subprocess.run(
            [_NPACK_BIN, "init", str(site_root), "--name", name, "--version", version, "--publisher", pubkey],
            text=True, capture_output=True, check=False, timeout=60,
        )
        if init.returncode != 0:
            raise NsiteError(f"npack init failed: {(init.stderr or init.stdout).strip()}")
        artifact = staging / f"{name}-{version}.npk"
        pack = subprocess.run(
            [_NPACK_BIN, "pack", str(site_root), "--output", str(artifact)],
            text=True, capture_output=True, check=False, timeout=120,
        )
        if pack.returncode != 0:
            raise NsiteError(f"npack pack failed: {(pack.stderr or pack.stdout).strip()}")
        digest = subprocess.run(
            [_NPACK_BIN, "hash", str(artifact)], text=True, capture_output=True, check=False, timeout=30
        )
        if digest.returncode != 0 or not _SHA256_RE.fullmatch(digest.stdout.strip()):
            raise NsiteError("npack hash failed: " + (digest.stderr or digest.stdout).strip())
        artifact_bytes = artifact.read_bytes()
    return {
        "name": name,
        "version": version,
        "sha256": digest.stdout.strip(),
        "bytes": artifact_bytes,
        "publisher": pubkey,
    }


def release_event_template(pubkey: str, *, name: str, version: str, artifact_sha256: str) -> dict[str, Any]:
    """The unsigned kind-9900 release template a site owner signs alongside the
    manifest, so the gateway can resolve publisher/<name> and serve the bundle."""
    return {
        "kind": _RELEASE_KIND,
        "pubkey": pubkey,
        "created_at": 0,
        "tags": [
            ["d", f"{name}/{version}/any"],
            ["v", "1"],
            ["name", name],
            ["version", version],
            ["os", "any"],
            ["arch", "any"],
            ["format", "npk"],
            ["x", artifact_sha256],
        ],
        "content": "",
    }


def release_version(event: dict[str, Any]) -> str:
    """Return the SemVer version a signed release event commits to."""
    for t in event.get("tags", []):
        if isinstance(t, list) and len(t) > 1 and t[0] == "version":
            return str(t[1])
    raise NsiteError("npk release has no version tag")


def verify_release_event(event: dict[str, Any], *, pubkey: str, name: str, artifact_sha256: str) -> None:
    """Reject a signed kind-9900 release that is not a release for this site's
    publisher/name and artifact. The release author must be the manifest author
    (the gateway resolves releases by the site pubkey)."""
    from .manifest import verify_event as _verify

    if not isinstance(event, dict) or event.get("kind") != _RELEASE_KIND:
        raise NsiteError("npk release must be a kind-9900 event")
    if str(event.get("pubkey", "")).lower() != str(pubkey).lower():
        raise NsiteError("npk release publisher does not match the site owner")
    id_ok, sig_ok = _verify(event)
    if not id_ok or not sig_ok:
        raise NsiteError("npk release signature is invalid")
    tags = {str(t[0]): (t[1] if len(t) > 1 else "") for t in event.get("tags", []) if isinstance(t, list) and t}
    if tags.get("name") != name:
        raise NsiteError(f"npk release name does not match the site ({name})")
    if not _SEMVER.fullmatch(str(tags.get("version", ""))):
        raise NsiteError("npk release version is not valid SemVer")
    if str(tags.get("x", "")).lower() != str(artifact_sha256).lower():
        raise NsiteError("npk release artifact sha256 does not match the packed site")


def _default_dns_lookup(qname: str, rtype: str) -> list[str]:
    """Resolve ``qname`` via the host's DNS (best-effort, empty on failure).

    Uses YunoHost's ``dig`` helper so the ownership check is the same one the
    rest of the platform uses for DNS verification (plan §Phase 4). Answers
    are returned lower-cased with a trailing dot stripped.
    """
    try:
        from yunohost.utils.dns import dig

        answers = dig(qname, rtype)
    except Exception:  # noqa: BLE001 - unresolved/unavailable DNS is a failed proof
        return []
    if not isinstance(answers, (list, tuple)):
        return []
    return [str(a).strip().rstrip(".").lower() for a in answers if str(a).strip()]


def _verify_ownership(
    fqdn: str,
    pubkey: str,
    gateway_domain: str,
    method: str,
    verify_dns: Any,
) -> dict[str, Any]:
    """Check one of the two Phase 4 ownership proofs against live DNS.

    ``verify_dns(qname, rtype) -> list[str]`` is the resolution helper
    (injectable for tests; defaults to :func:`_default_dns_lookup`).

    - ``cname``: the fqdn must CNAME to the gateway domain — the operator has
      delegated the name to this host, which both proves ownership and routes
      the site here.
    - ``txt``: ``_nostrhost-site.<fqdn>`` must carry ``nostrhost-site:<pubkey>``
      — the proof is bound to the site owner, so a domain can only ever be
      attached to the pubkey it names.
    """
    if method == "cname":
        targets = verify_dns(fqdn, "CNAME")
        ok = gateway_domain.rstrip(".").lower() in targets
        return {
            "ok": ok,
            "method": method,
            "verification": gateway_domain.rstrip(".").lower(),
            "detail": f"CNAME {fqdn} -> {gateway_domain}" if ok else f"CNAME {fqdn} resolves to {targets or 'nothing'}",
        }
    if method == "txt":
        token = f"nostrhost-site:{pubkey}"
        values = verify_dns(f"_nostrhost-site.{fqdn}", "TXT")
        ok = any(token in v for v in values)
        return {
            "ok": ok,
            "method": method,
            "verification": token,
            "detail": f"TXT _nostrhost-site.{fqdn} contains {token!r}" if ok else f"TXT _nostrhost-site.{fqdn} = {values or 'nothing'}",
        }
    return {"ok": False, "method": method, "verification": "", "detail": f"unknown ownership method {method!r}"}


class NsiteError(ValueError):
    pass


def nsites_state_dir(state_dir: Path) -> Path:
    return state_dir / "nsites"


def gateway_state_path(state_dir: Path) -> Path:
    return nsites_state_dir(state_dir) / "gateway.json"


def load_gateway(state_dir: Path) -> dict[str, Any] | None:
    path = gateway_state_path(state_dir)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def save_gateway(state_dir: Path, state: dict[str, Any]) -> Path:
    d = nsites_state_dir(state_dir)
    d.mkdir(parents=True, exist_ok=True)
    path = gateway_state_path(state_dir)
    path.write_text(
        json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path


def _default_state_dir() -> Path:
    try:
        from yunohost.nostr_state import state_dir_from_env

        return state_dir_from_env()
    except Exception:  # noqa: BLE001
        return Path(os.environ.get("NOSTRHOST_STATE_DIR", "/var/lib/nostrhost/state"))


def _ngit_revision(state_dir: Path | None = None) -> str:
    """The ngit desired-state revision nsite.toml is rendered from (WP7).

    Best-effort: when the state repository is unavailable (tests, fresh
    bootstrap) the provenance falls back to a stable local label so the
    sidecar is still written and drift detection works.
    """
    try:
        from yunohost.nostr_state import StateRepo, state_dir_from_env

        repo = StateRepo(state_dir or state_dir_from_env(), server_pubkey="")
        revision = repo.revision()
        if revision:
            return revision
    except Exception:  # noqa: BLE001 - provenance must never break rendering
        pass
    return "local:state/nsites"


def _live_caddy() -> Any:
    try:
        from ..caddy_admin import CaddyAdminClient

        return CaddyAdminClient()
    except Exception:  # noqa: BLE001 - optional in tests
        return None


def _systemctl(*args: str) -> str:
    return subprocess.run(
        ["systemctl", *args], capture_output=True, text=True, check=False
    ).stdout.strip()


class NsiteService:
    """Gateway lifecycle, with injectable caddy/systemctl for tests."""

    def __init__(
        self,
        *,
        state_dir: Path | None = None,
        caddy: Any = _LIVE,
        systemctl: Any = _LIVE,
        config_path: Path = CONFIG_PATH,
        verify_dns: Any = _LIVE,
    ) -> None:
        self.state_dir = state_dir or _default_state_dir()
        self.caddy = _live_caddy() if caddy is _LIVE else caddy
        self._systemctl = _systemctl if systemctl is _LIVE else systemctl
        self.config_path = Path(config_path)
        self._verify_dns = _default_dns_lookup if verify_dns is _LIVE else verify_dns

    # -- state ------------------------------------------------------------

    def _state(self) -> dict[str, Any]:
        return load_gateway(self.state_dir) or {"enabled": False, "config": {}}

    def _set_state(self, state: dict[str, Any]) -> Path:
        return save_gateway(self.state_dir, state)

    # -- validation -------------------------------------------------------

    def _registered_domain(self, domain: str) -> None:
        from ..domains.service import native_domain_names

        names = native_domain_names(self.state_dir)
        if domain.rstrip(".") not in names:
            raise NsiteError(f"domain {domain} is not a registered native domain")

    def _assert_dedicated_domain(self, domain: str) -> None:
        """D2: the gateway domain must not sit under (or equal) another
        registered domain or a native app's web.domain, so site labels never
        collide with NostrHost's own origins."""
        from ..domains.service import DomainService, native_domain_names

        names = {n.rstrip(".") for n in native_domain_names(self.state_dir)}
        names.discard(domain.rstrip("."))
        for other in names:
            if other.endswith("." + domain.rstrip(".")):
                raise NsiteError(
                    f"domain {domain} cannot be the gateway domain: {other} is a registered subdomain"
                )
        for app in DomainService(state_dir=self.state_dir)._dependents(domain):
            raise NsiteError(
                f"domain {domain} cannot be the gateway domain: native app {app} uses it"
            )

    # -- config rendering -------------------------------------------------

    def render_config(self, config: GatewayConfig) -> Path:
        """Write ``/etc/nostrhost/nsite.toml`` as root:nostrhost-nsite, 0640.

        The gateway runs as the unprivileged ``nostrhost-nsite`` user, so the
        config must be group-readable by that user (root-only 0640 would make
        the unit fail to start with EACCES on every host).

        The ``[[sites]]`` allowlist is rendered from ``state/nsites/sites/*``
        (Phase 3a), so registration and publish both re-render + SIGHUP.

        WP7: the render is provenance-tracked and validated with the
        gateway's own native checker (``nostrhost-nsite -check-config``)
        before the atomic replace; the source revision is the ngit
        desired-state revision the sites/domains were read from.
        """
        text = config.to_toml()
        sites = _sites(self.state_dir)
        if sites:
            parts = [text.rstrip(), ""]
            for site in sites:
                parts.append("[[sites]]")
                parts.append(f'pubkey = "{site.get("pubkey", "")}"')
                parts.append(f"kind = {site.get('kind', KIND_ROOT)}")
                parts.append(f'd = "{site.get("d", "")}"')
            text = "\n".join(parts) + "\n"
        domains = _custom_domains(self.state_dir)
        if domains:
            text = text.rstrip() + "\n"
            for cd in domains:
                text += (
                    "\n[[custom_domains]]\n"
                    f'fqdn = "{cd.get("fqdn", "")}"\n'
                    f'pubkey = "{cd.get("pubkey", "")}"\n'
                    f'd = "{cd.get("d", "")}"\n'
                )
        from dataclasses import replace

        from ..service_projection import render_managed
        from ..service_specs import spec_for_name

        spec = replace(spec_for_name("nsite"), path=str(self.config_path))
        render_managed(
            spec,
            text,
            source_revision=_ngit_revision(self.state_dir),
            renderer="nsites.service.render_config",
            validate=True,
            reload=False,
            chown_group="nostrhost-nsite",
        )
        return self.config_path

    # -- systemd ----------------------------------------------------------

    def _unit_active(self) -> bool:
        return self._systemctl("is-active", SERVICE) == "active"

    def _reload(self) -> None:
        # SIGHUP reload keeps connections and the warm cache.
        self._systemctl("kill", "-s", "HUP", SERVICE)

    def _start(self) -> None:
        self._systemctl("enable", "--now", SERVICE)

    def _stop(self) -> None:
        self._systemctl("disable", "--now", SERVICE)

    # -- Caddy ------------------------------------------------------------

    def _ensure_caddy(self, domain: str) -> dict[str, Any]:
        if self.caddy is None:
            return {"route": None, "note": "caddy client unavailable"}
        route_id = self.caddy.ensure_nsite_routes(domain, GATEWAY_UPSTREAM)
        return {"route": route_id}

    def _remove_caddy(self, domain: str) -> dict[str, Any]:
        if self.caddy is None:
            return {"route": None, "note": "caddy client unavailable"}
        self.caddy.remove_nsite_routes(domain)
        return {"route": f"nostrhost-nsite:{domain}", "removed": True}

    def _ensure_custom_domain(self, fqdn: str) -> dict[str, Any]:
        """Caddy route proxying the attached FQDN to the gateway (Phase 4)."""
        if self.caddy is None:
            return {"route": None, "note": "caddy client unavailable"}
        route_id = self.caddy.ensure_custom_domain_route(fqdn, GATEWAY_UPSTREAM)
        return {"route": route_id}

    def _remove_custom_domain(self, fqdn: str) -> dict[str, Any]:
        if self.caddy is None:
            return {"route": None, "note": "caddy client unavailable"}
        self.caddy.remove_custom_domain_route(fqdn)
        return {"route": f"nostrhost-nsite:{fqdn}", "removed": True}

    def _write_snippet(self, domain: str, *, mode: str = "hosted") -> Path:
        """Write the gateway domain's tracked Caddy snippet so regenconf
        detects manual edits.

        Hosted mode uses ``caddy_nsite.conf`` (On-Demand TLS asking the
        gateway's loopback tls-ask). Open mode (Phase 5) uses
        ``caddy_nsite_open.conf``: a wildcard certificate via DNS-01, so any
        decodable ``*.domain`` label is covered by one cert instead of
        on-demand per-name issuance. The snippet references the operator's
        ACME DNS API token through Caddy env substitution (``{$…}``) — the
        token itself lives only in ``operator.toml``, never in this
        regenconf-tracked file.
        """
        template = CADDY_TEMPLATE_DIR / (
            "caddy_nsite_open.conf" if mode == "open" else "caddy_nsite.conf"
        )
        if not template.is_file():
            return Path("")
        CADDY_CONF_DIR.mkdir(parents=True, exist_ok=True)
        conf = template.read_text(encoding="utf-8").replace("{{ domain }}", domain)
        if mode == "open":
            acme = _acme_dns_config()
            if acme is None:
                # enable/configure gate open mode on the token, so this is
                # unreachable in practice; never render a dns block we can't fill.
                return Path("")
            conf = conf.replace("{{ provider }}", acme[0])
        if (
            domain.endswith(".test")
            or domain.endswith(".local")
            or domain == "localhost"
        ):
            # The template's TLS block is multi-line; match it loosely so
            # local/CI domains fall back to the internal CA instead of ACME.
            conf = re.sub(
                r"tls\s*\{[^}]*\}",
                "tls internal",
                conf,
                count=1,
            )
        path = CADDY_CONF_DIR / f"{domain}.conf"
        path.write_text(conf, encoding="utf-8")
        return path

    def _remove_snippet(self, domain: str) -> None:
        (CADDY_CONF_DIR / f"{domain}.conf").unlink(missing_ok=True)

    def _reload_caddy(self) -> None:
        """Reload Caddy so the per-domain snippet (TLS policy, log, headers)
        takes effect. The route itself is reconciled through the admin API and
        is live immediately; the site-level directives only load on reload."""
        self._systemctl("reload", "caddy")

    # -- gateway operations ----------------------------------------------

    def gateway_status(self) -> dict[str, Any]:
        state = self._state()
        config = state.get("config") or {}
        healthy = False
        health_detail = "unit inactive"
        if state.get("enabled"):
            healthy = self._unit_active()
            health_detail = (
                "unit active"
                if healthy
                else "unit inactive (check systemctl status nostrhost-nsite)"
            )
        gateway_json = {
            "enabled": bool(state.get("enabled")),
            "domain": config.get("domain", ""),
            "mode": config.get("mode", "hosted"),
            "service_active": self._unit_active(),
            "config_path": str(self.config_path),
            "config_exists": self.config_path.is_file(),
            "health": "ok" if healthy else "degraded",
            "health_detail": health_detail,
            "sites": len(_sites(self.state_dir)),
            "config": config,
        }
        if healthy:
            gateway_json["internal"] = self._probe_internal()
        return {"gateway": gateway_json}

    def _probe_internal(self) -> dict[str, Any]:
        try:
            with urllib.request.urlopen(
                "http://127.0.0.1:8196/internal/status", timeout=2
            ) as resp:
                body = resp.read().decode("utf-8", "replace")
            return {"status": "ok", "body": body}
        except Exception as exc:  # noqa: BLE001
            return {"status": "unreachable", "detail": str(exc)}

    def _require_acme_dns(self, mode: str) -> None:
        """Open mode (Phase 5) needs a wildcard certificate, which is a
        DNS-01 challenge: reject it unless the operator configured an ACME
        DNS provider + API token in ``operator.toml`` (D3 lifted for open
        mode). Hosted mode never touches DNS-01."""
        if mode != "open":
            return
        if _acme_dns_config() is None:
            raise NsiteError(
                "open mode requires the operator's ACME DNS-01 credentials: set "
                "acme_dns_provider and acme_dns_api_token in /etc/nostrhost/operator.toml"
            )

    def _validate_limits(self, config: GatewayConfig) -> None:
        """Reject out-of-range gateway limits before the plan is approved
        (implementation plan §4.4). Mirrors the gateway's own config checker:
        ``max_blob_bytes`` may not exceed 128 MiB and ``cache_quota_bytes``
        may not exceed 50% of the filesystem's free space.
        """
        if config.limits.max_blob_bytes > MAX_ALLOWED_BLOB_BYTES:
            raise NsiteError(
                f"max_blob_bytes {config.limits.max_blob_bytes} exceeds "
                f"{MAX_ALLOWED_BLOB_BYTES} (128 MiB)"
            )
        if config.limits.max_blob_bytes <= 0:
            raise NsiteError("max_blob_bytes must be positive")
        if config.limits.cache_quota_bytes <= 0:
            raise NsiteError("cache_quota_bytes must be positive")
        if config.limits.cache_quota_bytes > MAX_CACHE_QUOTA_FRACTION * self._free_space_bytes():
            raise NsiteError(
                f"cache_quota_bytes {config.limits.cache_quota_bytes} exceeds 50% of "
                "the filesystem's free space"
            )

    @staticmethod
    def _free_space_bytes() -> int:
        """Free bytes on the filesystem holding the config/cache directory.

        Best-effort: when the directory or ``shutil.disk_usage`` is
        unavailable the cap check is skipped rather than failing a plan on an
        environment the gateway itself would not run in.
        """
        try:
            return shutil.disk_usage("/var/lib/nostrhost")[2]
        except OSError:  # pragma: no cover - exotic host layout
            return 1 << 63

    # -- local Blossom server (Phase 5, D4) -------------------------------

    @staticmethod
    def _validate_blossom_local(local: Any, *, enabled: bool) -> None:
        """Validate the [blossom.local] config before it is rendered.

        Mirrors the gateway's own checker: a loopback-only listener, a data
        dir, per-blob cap ≤ 128 MiB, and 64-hex admitted pubkeys. The local
        component is a separate quota/retention contract (D4), so its caps are
        validated independently of the gateway fetch limits.
        """
        from yunohost.nostr_identity import _parse_pubkey

        if enabled:
            if not local.listen:
                raise NsiteError("blossom.local.listen is required when enabled")
            host, _ = _split_listen(local.listen)
            if host not in ("127.0.0.1", "localhost", "::1"):
                raise NsiteError(
                    f"blossom.local.listen {local.listen!r} must be a loopback address (D4)"
                )
            if not local.data_dir:
                raise NsiteError("blossom.local.data_dir is required when enabled")
        if local.max_blob_bytes > MAX_ALLOWED_BLOB_BYTES:
            raise NsiteError(
                f"blossom.local.max_blob_bytes {local.max_blob_bytes} exceeds "
                f"{MAX_ALLOWED_BLOB_BYTES} (128 MiB)"
            )
        if local.max_blob_bytes <= 0:
            raise NsiteError("blossom.local.max_blob_bytes must be positive")
        if local.quota_bytes <= 0:
            raise NsiteError("blossom.local.quota_bytes must be positive")
        for key in local.allow_pubkeys:
            try:
                _parse_pubkey(key)
            except Exception as exc:  # noqa: BLE001
                raise NsiteError(f"blossom.local.allow_pubkeys: bad pubkey {key!r}") from exc

    def blossom_status(self) -> dict[str, Any]:
        """Status of the optional local Blossom server (D4)."""
        state = self._state()
        config = state.get("config") or {}
        local = config.get("blossom", {}).get("local", {})
        enabled = bool(local.get("enabled"))
        listen = local.get("listen", "127.0.0.1:8197")
        data_dir = local.get("data_dir", "/var/lib/nostrhost-nsite/blossom")
        detail = "component disabled"
        reachable = False
        used_bytes: int | None = None
        blob_count: int | None = None
        if enabled:
            try:
                with urllib.request.urlopen(
                    f"http://{listen}/status", timeout=2
                ) as resp:
                    reachable = resp.status == 200
                    if reachable:
                        payload = json.loads(resp.read().decode("utf-8", "replace"))
                        used_bytes = payload.get("used_bytes")
                        blob_count = payload.get("blobs")
                detail = "reachable" if reachable else "unreachable"
            except Exception as exc:  # noqa: BLE001
                detail = f"unreachable: {exc}"
        return {
            "blossom": {
                "enabled": enabled,
                "listen": listen,
                "data_dir": data_dir,
                "quota_bytes": local.get("quota_bytes"),
                "max_blob_bytes": local.get("max_blob_bytes"),
                "retention_days": local.get("retention_days"),
                "allow_pubkeys": local.get("allow_pubkeys") or [],
                "used_bytes": used_bytes,
                "blobs": blob_count,
                "health": "ok" if reachable else "degraded",
                "health_detail": detail,
            }
        }

    def blossom_enable(self, local: Any) -> dict[str, Any]:
        """Enable the local Blossom server on the running gateway.

        The gateway must already be enabled (the local server is a listener of
        the same ``nostrhost-nsite`` unit). Rendering the ``[blossom.local]``
        section and SIGHUP starts it; disabling flips the flag and SIGHUPs.
        """
        self._require_gateway()
        model = local if isinstance(local, GatewayBlossomLocal) else GatewayBlossomLocal(**local.dict())
        model = model.copy(update={"enabled": True})
        self._validate_blossom_local(model, enabled=True)
        state = self._state()
        config = state.get("config") or {}
        config.setdefault("blossom", {})["local"] = model.dict()
        self.render_config(GatewayConfig(**config))
        self._set_state({"enabled": True, "config": config})
        self._reload()
        return {
            "action": "nsite.blossom.enable",
            "listen": model.listen,
            "data_dir": model.data_dir,
            "reloaded": SERVICE,
            "ok": True,
        }

    def blossom_configure(self, local: Any) -> dict[str, Any]:
        """Update the local Blossom server's quota/retention/cap contract."""
        self._require_gateway()
        model = local if isinstance(local, GatewayBlossomLocal) else GatewayBlossomLocal(**local.dict())
        model = model.copy(update={"enabled": True})
        self._validate_blossom_local(model, enabled=True)
        state = self._state()
        config = state.get("config") or {}
        config.setdefault("blossom", {})["local"] = model.dict()
        self.render_config(GatewayConfig(**config))
        self._set_state({"enabled": True, "config": config})
        self._reload()
        return {
            "action": "nsite.blossom.configure",
            "listen": model.listen,
            "data_dir": model.data_dir,
            "reloaded": SERVICE,
            "ok": True,
        }

    def blossom_disable(self) -> dict[str, Any]:
        """Disable the local Blossom server (stops the listener via SIGHUP)."""
        self._require_gateway()
        state = self._state()
        config = state.get("config") or {}
        config.setdefault("blossom", {}).setdefault("local", {})
        local = config["blossom"]["local"]
        try:
            model = GatewayBlossomLocal(**local)
        except Exception as exc:  # noqa: BLE001 - a corrupt stored config must not block disable
            raise NsiteError(f"stored blossom.local config is invalid: {exc}") from exc
        self._validate_blossom_local(model, enabled=False)
        config["blossom"]["local"] = {**model.dict(), "enabled": False}
        self.render_config(GatewayConfig(**config))
        self._set_state({"enabled": True, "config": config})
        self._reload()
        return {"action": "nsite.blossom.disable", "reloaded": SERVICE, "ok": True}

    def enable(self, config: GatewayConfig) -> dict[str, Any]:
        self._validate_limits(config)
        if not config.domain:
            raise NsiteError("gateway enable requires a domain")
        self._require_acme_dns(config.mode)
        self._registered_domain(config.domain)
        self._assert_dedicated_domain(config.domain)
        self.render_config(config)
        snippet = self._write_snippet(config.domain, mode=config.mode)
        if snippet != Path(""):
            self._reload_caddy()
        caddy = self._ensure_caddy(config.domain)
        self._set_state({"enabled": True, "config": config.dict()})
        self._start()
        return {
            "action": "nsite.gateway.enable",
            "domain": config.domain,
            "mode": config.mode,
            "config_path": str(self.config_path),
            "snippet": str(snippet) if snippet != Path("") else None,
            "caddy": caddy,
            "service": SERVICE,
            "ok": True,
        }

    def disable(self) -> dict[str, Any]:
        state = self._state()
        domain = (state.get("config") or {}).get("domain", "")
        self._stop()
        caddy: dict[str, Any] = {}
        if domain:
            caddy = self._remove_caddy(domain)
            self._remove_snippet(domain)
        self._set_state({"enabled": False, "config": state.get("config") or {}})
        return {
            "action": "nsite.gateway.disable",
            "domain": domain,
            "caddy": caddy,
            "ok": True,
        }

    def configure(self, config: GatewayConfig) -> dict[str, Any]:
        state = self._state()
        if not state.get("enabled"):
            raise NsiteError("gateway is not enabled; run nsite.gateway.enable first")
        self._validate_limits(config)
        if not config.domain:
            raise NsiteError("gateway configure requires a domain")
        self._require_acme_dns(config.mode)
        if config.domain != (state.get("config") or {}).get("domain"):
            self._registered_domain(config.domain)
            self._assert_dedicated_domain(config.domain)
        self.render_config(config)
        self._write_snippet(config.domain, mode=config.mode)
        self._reload_caddy()
        caddy = self._ensure_caddy(config.domain)
        self._set_state({"enabled": True, "config": config.dict()})
        self._reload()
        return {
            "action": "nsite.gateway.configure",
            "domain": config.domain,
            "mode": config.mode,
            "config_path": str(self.config_path),
            "caddy": caddy,
            "reloaded": SERVICE,
            "ok": True,
        }

    # -- site registry (Phase 3a) ----------------------------------------

    def _require_gateway(self) -> dict[str, Any]:
        state = self._state()
        if not state.get("enabled"):
            raise NsiteError("the gateway is not enabled; enable it before publishing")
        return state

    def _refresh_gateway(self) -> None:
        """Re-render the allowlist into nsite.toml and SIGHUP the gateway."""
        state = self._state()
        config = state.get("config")
        if not state.get("enabled") or not config:
            return
        try:
            self.render_config(GatewayConfig(**config))
        except Exception:  # noqa: BLE001 - config render must not fail the state write
            return
        self._reload()

    def _site_registered(self, pubkey: str, kind: int, d: str) -> bool:
        """Hosted-mode allowlist check: root/named match pubkey+d, snapshots
        match the author's pubkey (implementation plan §4.1 step 2)."""
        for record in _sites(self.state_dir):
            if record.get("pubkey") != pubkey:
                continue
            if kind == KIND_SNAPSHOT or record.get("d", "") == d:
                return True
        return False

    def site_register(
        self,
        pubkey: str,
        *,
        kind: int = KIND_ROOT,
        d: str = "",
        title: str = "",
    ) -> dict[str, Any]:
        from .manifest import is_valid_d

        pubkey = _pubkey_hex(pubkey)
        if kind not in (KIND_ROOT, KIND_NAMED):
            raise NsiteError("site kind must be 15128 (root) or 35128 (named)")
        if kind == KIND_NAMED:
            if not is_valid_d(d):
                raise NsiteError(f"invalid named-site d tag: {d!r}")
        elif d:
            raise NsiteError("root sites take no d tag")
        path = site_path(self.state_dir, pubkey, d)
        record = SiteRecord(
            pubkey=pubkey,
            kind=kind,
            d=d,
            title=title or "",
            provenance={"actor": "nsite.register", "at": time.strftime("%Y-%m-%dT%H:%M:%SZ")},
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record.dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._refresh_gateway()
        return {"action": "nsite.register", "site": record.dict(), "ok": True}

    def site_unregister(self, pubkey: str, *, d: str = "") -> dict[str, Any]:
        pubkey = _pubkey_hex(pubkey)
        path = site_path(self.state_dir, pubkey, d)
        if not path.is_file():
            raise NsiteError("site is not registered")
        path.unlink()
        self._refresh_gateway()
        return {"action": "nsite.unregister", "pubkey": pubkey, "d": d, "removed": True, "ok": True}

    def site_list(self) -> dict[str, Any]:
        return {
            "mode": (self._state().get("config") or {}).get("mode", "hosted"),
            "sites": _sites(self.state_dir),
            "count": len(_sites(self.state_dir)),
        }

    def catalogue_nsite_links(self) -> dict[str, dict[str, str]]:
        """Kind-32267 address -> registered nsite (Phase 5, normal catalogue).

        Every registered site whose manifest carries an ``app`` tag maps its
        ``kind:pubkey:d`` address to the location it is served at. The
        catalogue list annotates the matching kind-32267 entry with an "open
        nsite" link from this index. Reuses the existing catalogue projection
        (custom-catalog logic) — nsites are part of the normal nostrhost
        catalogue, never a separate one.
        """
        from .manifest import _npub_for, canonical_site_url, named_label

        state = self._state()
        gateway_domain = (state.get("config") or {}).get("domain", "")
        if not gateway_domain:
            return {}
        links: dict[str, dict[str, str]] = {}
        for record in _sites(self.state_dir):
            app = record.get("app", "")
            if not app:
                continue
            pubkey = record.get("pubkey", "")
            d = str(record.get("d", ""))
            kind = int(record.get("kind", KIND_ROOT))
            label: str | None = None
            if kind == KIND_NAMED and d:
                label = named_label(pubkey, d)
            elif kind == KIND_ROOT:
                label = _npub_for(pubkey)
            if label:
                links[app] = {
                    "url": f"https://{canonical_site_url(label, gateway_domain)}/",
                    "label": label,
                }
        return links

    def site_inspect(self, pubkey: str, *, d: str = "") -> dict[str, Any]:
        pubkey = _pubkey_hex(pubkey)
        path = site_path(self.state_dir, pubkey, d)
        if not path.is_file():
            raise NsiteError("site is not registered")
        record = json.loads(path.read_text(encoding="utf-8"))
        return {"site": record}

    # -- custom domains (Phase 4) ------------------------------------------

    def domain_list(self) -> dict[str, Any]:
        """Attached custom domains (state/nsites/domains/*). Read-only."""
        domains = _custom_domains(self.state_dir)
        return {
            "domains": domains,
            "count": len(domains),
        }

    def domain_attach(
        self,
        fqdn: str,
        pubkey: str,
        *,
        d: str = "",
        method: str = "cname",
        verify: bool = True,
    ) -> dict[str, Any]:
        """Attach a custom FQDN to a registered site (Phase 4).

        Ownership is proven against live DNS first (``cname`` to the gateway
        domain, or a ``nostrhost-site:<pubkey>`` TXT record under
        ``_nostrhost-site.<fqdn>``), the FQDN must be unique across
        ``state/nsites/domains`` and not overlap the gateway domain, and only
        a registered site can be attached to. On success a Caddy route proxies
        the FQDN to the gateway and the custom-domain mapping is rendered into
        ``nsite.toml`` (so the gateway serves it and on-demand TLS allows it).
        """
        from .manifest import is_valid_d

        fqdn = str(fqdn).rstrip(".").lower()
        if not _valid_fqdn(fqdn):
            raise NsiteError(f"invalid fqdn: {fqdn!r}")
        if method not in ("cname", "txt"):
            raise NsiteError(f"unknown ownership method {method!r} (use 'cname' or 'txt')")
        pubkey = _pubkey_hex(pubkey)
        if d and not is_valid_d(d):
            raise NsiteError(f"invalid named-site d tag: {d!r}")

        state = self._require_gateway()
        gateway_domain = (state.get("config") or {}).get("domain", "")
        if not gateway_domain:
            raise NsiteError("gateway has no configured domain")

        site_path_ = site_path(self.state_dir, pubkey, d)
        if not site_path_.is_file():
            raise NsiteError("site is not registered; run nsite.register first")

        attached = {cd["fqdn"] for cd in _custom_domains(self.state_dir) if cd.get("fqdn")}
        if fqdn in attached:
            raise NsiteError(f"domain {fqdn} is already attached")
        if fqdn == gateway_domain or fqdn.endswith("." + gateway_domain):
            raise NsiteError(f"domain {fqdn} overlaps the gateway domain")
        if gateway_domain.endswith("." + fqdn):
            raise NsiteError(f"domain {fqdn} is a parent of the gateway domain")

        if verify:
            proof = _verify_ownership(fqdn, pubkey, gateway_domain, method, self._verify_dns)
            if not proof["ok"]:
                raise NsiteError(f"ownership proof failed: {proof['detail']}")
        else:
            proof = {
                "ok": True,
                "method": method,
                "verification": (
                    gateway_domain.rstrip(".").lower()
                    if method == "cname"
                    else f"nostrhost-site:{pubkey}"
                ),
                "detail": "verification skipped",
            }

        caddy = self._ensure_custom_domain(fqdn)
        record = CustomDomainRecord(
            fqdn=fqdn,
            pubkey=pubkey,
            d=d,
            method=method,
            verification=proof["verification"],
            verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            provenance={
                "actor": "nsite.domain.attach",
                "at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        )
        path = custom_domain_path(self.state_dir, fqdn)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record.dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._refresh_gateway()
        self._reload_caddy()
        return {
            "action": "nsite.domain.attach",
            "fqdn": fqdn,
            "pubkey": pubkey,
            "d": d,
            "method": method,
            "verification": proof["verification"],
            "caddy": caddy,
            "ok": True,
        }

    def domain_detach(self, fqdn: str) -> dict[str, Any]:
        """Detach a custom FQDN: removes the Caddy route and the state marker
        only (plan §Phase 4) — the site itself is untouched."""
        fqdn = str(fqdn).rstrip(".").lower()
        path = custom_domain_path(self.state_dir, fqdn)
        if not path.is_file():
            raise NsiteError(f"domain {fqdn} is not attached")
        self._require_gateway()
        caddy = self._remove_custom_domain(fqdn)
        path.unlink()
        self._refresh_gateway()
        self._reload_caddy()
        return {
            "action": "nsite.domain.detach",
            "fqdn": fqdn,
            "caddy": caddy,
            "removed": True,
            "ok": True,
        }

    # -- draft area (Phase 3b) --------------------------------------------

    def draft_inventory(self, pubkey: str, *, d: str = "") -> dict[str, Any]:
        """List a site's server-side draft files with their hashes.

        The draft area (D6) is the one fixed server-side file path: the Admin
        agent writes site files here, and publish_plan/mirror read from it.
        Paths are validated with the same rules as manifest paths, so a draft
        can never escape its own directory.
        """
        from .manifest import is_sha256_hex

        pubkey = _pubkey_hex(pubkey)
        root = draft_dir(pubkey, d)
        if not root.is_dir():
            return {"site": pubkey, "d": d, "items": [], "count": 0}
        items: list[dict[str, Any]] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            rel = "/" + path.relative_to(root).as_posix()
            if _draft_path_is_bad(rel):
                continue
            blob_hash = _sha256_file(path)
            if not is_sha256_hex(blob_hash):
                continue
            items.append({"path": rel, "sha256": blob_hash, "size": path.stat().st_size})
        return {"site": pubkey, "d": d, "items": items, "count": len(items)}

    def draft_clear(self, pubkey: str, *, d: str = "") -> dict[str, Any]:
        """Remove a site's draft directory (files only, never symlinks)."""
        pubkey = _pubkey_hex(pubkey)
        root = draft_dir(pubkey, d)
        if root.is_dir():
            for path in sorted(root.rglob("*"), reverse=True):
                if path.is_symlink() or not path.is_file():
                    continue
                path.unlink(missing_ok=True)
            try:
                root.rmdir()
            except OSError:
                pass
        return {"site": pubkey, "d": d, "cleared": True, "ok": True}

    # -- manifest validation / plan / publish (Phase 3a) -----------------

    def validate_manifest(self, event: dict[str, Any]) -> dict[str, Any]:
        from .manifest import validate_manifest as _validate
        from .signer_guard import forbidden_signer_pubkeys

        verdict = _validate(
            event, forbidden_pubkeys=forbidden_signer_pubkeys()
        )
        return {
            "valid": verdict.valid,
            "errors": verdict.errors,
            "site_type": verdict.site_type,
            "pubkey": verdict.pubkey,
            "event_id": verdict.event_id,
            "d": verdict.d,
            "aggregate_hash": verdict.aggregate_hash,
            "label": verdict.label,
            "paths": verdict.paths,
        }

    def publish_plan(
        self,
        pubkey: str,
        *,
        kind: int = KIND_ROOT,
        d: str = "",
        items: list[dict[str, str]] | None = None,
        site: str = "",
        servers: list[str] | None = None,
        relays: list[str] | None = None,
        copy_of: str = "",
        app: str = "",
        npk: bool = False,
        npk_version: str = "0.1.0",
    ) -> dict[str, Any]:
        """Build the unsigned manifest and the plan digest (D7, §6 step 2/5).

        ``items`` is ``[{"path": "/index.html", "sha256": "…64 hex…"}, …]``
        produced by the Admin's client-side inventory+hash. Alternatively
        ``site`` names a server-side draft (Phase 3b, D6): its inventory is
        read from ``/var/lib/nostrhost/nsites/drafts/<site>/`` and shown
        before signing. Nothing is signed or broadcast here.

        ``copy_of`` (Phase 5) is a ``kind:pubkey:d`` address whose manifest
        becomes this plan: the target kind matches the source (a copy of a
        root is a root, of a named site a named site), the target ``d``
        defaults to the source's (override to fork into your own name), and
        the unsigned event carries ``a`` (parent) and ``A`` (origin) tags so
        the published manifest is a genuine copy. The source inventory comes
        from the local site record when the source is registered here, else
        from a relay resolution. ``a``/``A`` are not part of the plan digest
        (they carry no content-integrity meaning), so the signed copy matches
        ``plan_sha256`` exactly like a fresh plan.

        ``app`` (Phase 5) is the optional ``kind:pubkey:d`` address of the
        kind-32267 catalogue declaration this site links to. Like ``a``/``A``
        it is emitted as an ``app`` tag on the unsigned event but excluded from
        the plan digest: the signed event's ``app`` tag is validated
        independently by ``nsite.publish``.
        """
        from .manifest import is_sha256_hex, is_valid_d

        pubkey = _pubkey_hex(pubkey)
        if kind not in (KIND_ROOT, KIND_NAMED):
            raise NsiteError("plan kind must be 15128 (root) or 35128 (named)")

        copy_tags: list[list[str]] = []
        if copy_of:
            parts = copy_of.split(":", 2)
            if (
                len(parts) != 3
                or parts[0] not in ("15128", "35128")
                or not is_sha256_hex(parts[1])
            ):
                raise NsiteError(
                    f"invalid copy source {copy_of!r} (expect kind:pubkey:d with kind 15128/35128)"
                )
            src_kind, src_pubkey, src_d = int(parts[0]), parts[1].lower(), parts[2]
            if kind != src_kind:
                kind = src_kind
            if not d and kind == KIND_NAMED:
                d = src_d
            if not items:
                src_path = site_path(self.state_dir, src_pubkey, src_d)
                if src_path.is_file():
                    try:
                        record = json.loads(src_path.read_text(encoding="utf-8"))
                    except (json.JSONDecodeError, OSError):
                        record = {}
                    items = record.get("paths")
                else:
                    resolved = self.resolve(pubkey=src_pubkey, d=src_d)
                    src_event = resolved.get("manifest")
                    if not resolved.get("found") or not src_event:
                        raise NsiteError(
                            f"copy source {copy_of!r} is not registered locally and could not be resolved from relays"
                        )
                    items = [
                        {"path": str(t[1]), "sha256": str(t[2])}
                        for t in src_event.get("tags", [])
                        if isinstance(t, list) and len(t) >= 3 and t[0] == "path"
                    ]
            if not items:
                raise NsiteError("copy source has no paths to copy")
            copy_tags = [
                ["a", f"{src_kind}:{src_pubkey}:{src_d}"],
                ["A", f"{src_kind}:{src_pubkey}:{src_d}"],
            ]

        if kind == KIND_NAMED and not is_valid_d(d):
            raise NsiteError(f"invalid named-site d tag: {d!r}")
        if kind == KIND_ROOT and d:
            raise NsiteError("root sites take no d tag")

        if not items and site:
            items = self.draft_inventory(pubkey, d=d)["items"]
        if not items:
            raise NsiteError("a manifest needs at least one path/blob (pass items or a draft site)")

        paths: list[tuple[str, str]] = []
        for item in items:
            path = str(item.get("path", ""))
            blob_hash = str(item.get("sha256", ""))
            if not path.startswith("/"):
                raise NsiteError(f"path must start with '/': {path!r}")
            if not is_sha256_hex(blob_hash):
                raise NsiteError(f"invalid blob hash for {path!r}")
            paths.append((path, blob_hash))
        from ..connectivity import effective as effective_connectivity

        network = effective_connectivity()
        servers = [s for s in (servers or []) if s] or list(network["blossom_servers"])
        relays = [r for r in (relays or []) if r] or list(network["relays"]["nsite"])
        for url in servers + relays:
            if not url.startswith(("https://", "wss://")):
                raise NsiteError(f"refusing non-TLS server/relay URL: {url!r}")

        from .manifest import aggregate_hash, is_valid_ref

        tags: list[list[str]] = []
        if kind == KIND_NAMED:
            tags.append(["d", d])
        tags.extend(copy_tags)
        if app:
            if not is_valid_ref(app):
                raise NsiteError(
                    f"invalid app address {app!r} (expect 'kind:pubkey:d' linking to a kind-32267 declaration)"
                )
            tags.append(["app", app])
        for path, blob_hash in sorted(paths):
            tags.append(["path", path, blob_hash])
        if servers:
            for server in sorted(set(servers)):
                tags.append(["server", server])
        tags.append(["x", aggregate_hash(paths), "aggregate"])

        plan = {
            "pubkey": pubkey,
            "kind": kind,
            "d": d,
            "items": [{"path": p, "sha256": h} for p, h in paths],
            "servers": servers,
            "relays": relays,
            "copy_of": copy_of,
            "unsigned_event": {
                "kind": kind,
                "pubkey": pubkey,
                "created_at": 0,
                "tags": tags,
                "content": "",
            },
            "plan_sha256": plan_digest(kind=kind, d=d, paths=paths, servers=servers, relays=relays),
        }
        result = {"plan": plan}
        if npk:
            result["npk"] = self._npk_plan(pubkey, d=d, kind=kind, version=npk_version, servers=servers)
        return result

    def _npk_plan(self, pubkey: str, *, d: str, kind: int, version: str, servers: list[str]) -> dict[str, Any]:
        """Pack the site draft into a deterministic .npk and build the release
        template the owner signs alongside the manifest (Phase 3c)."""
        if not _npack_available():
            raise NsiteError("npk publish requires the npack binary ($NPACK_BIN); build forks/npack first")
        packed = pack_site_npk(pubkey, d=d, version=version)
        name = packed["name"]
        return {
            "name": name,
            "version": packed["version"],
            "artifact_sha256": packed["sha256"],
            "release_event": release_event_template(pubkey, name=name, version=packed["version"], artifact_sha256=packed["sha256"]),
            "kind": kind,
            "d": d,
            "servers": servers,
        }

    def publish(
        self,
        event: dict[str, Any],
        *,
        plan_sha256: str = "",
        relays: list[str] | None = None,
        npk_release_event: dict[str, Any] | None = None,
        npk_sha256: str = "",
    ) -> dict[str, Any]:
        """Verify a signed manifest, broadcast it and record the site.

        Rejects (before any broadcast or record) when the event is not a valid
        manifest, is signed by a host key, the plan digest does not match the
        event's signed content, or (hosted mode) the pubkey is unregistered.
        A publish that reaches at least one relay succeeds with a warning list;
        one that reaches none fails (implementation plan §D5).

        ``npk_release_event`` + ``npk_sha256`` (Phase 3c): when both are given,
        the release is verified (kind-9900, site-owner signed, matching
        publisher/name/artifact), the site's draft is re-packed deterministically
        and uploaded to the manifest's Blossom servers, and the release is
        broadcast alongside the manifest.
        """
        from .manifest import validate_manifest as _validate
        from .signer_guard import forbidden_signer_pubkeys

        self._require_gateway()
        verdict = _validate(event, forbidden_pubkeys=forbidden_signer_pubkeys())
        if not verdict.valid:
            raise NsiteError(
                "manifest is not valid: " + ", ".join(verdict.errors)
            )
        if verdict.pubkey is None:
            raise NsiteError("manifest has no signable pubkey")

        path_tags = [t for t in event.get("tags", []) if t and t[0] == "path"]
        server_tags = [t[1] for t in event.get("tags", []) if t and t[0] == "server"]
        paths = [(str(t[1]), str(t[2])) for t in path_tags if len(t) >= 3]
        d = verdict.d or ""
        servers = [str(s) for s in server_tags]
        from ..connectivity import effective as effective_connectivity

        planned_relays = [r for r in (relays or []) if r] or list(effective_connectivity()["relays"]["nsite"])
        digest = plan_digest(kind=event["kind"], d=d, paths=paths, servers=servers, relays=planned_relays)
        if plan_sha256 and digest != plan_sha256:
            raise NsiteError("plan digest mismatch: the signed manifest does not match the planned content")
        if plan_sha256 == "":
            # digest binding is mandatory when a plan was expected; a caller
            # that omits it gets a plan-less publish only if the operation
            # opts in. We require it (D7: every submitted manifest is checked).
            raise NsiteError("publish requires the plan_sha256 from nsite.publish.plan")

        mode = (self._state().get("config") or {}).get("mode", "hosted")
        if mode == "hosted" and not self._site_registered(
            verdict.pubkey, event["kind"], d
        ):
            raise NsiteError(
                f"pubkey {verdict.pubkey[:16]}… is not registered in hosted mode; run nsite.register first"
            )

        from ..connectivity import effective as effective_connectivity

        broadcast_relays = [r for r in (relays or []) if r] or list(effective_connectivity()["relays"]["nsite"])

        npk_result: dict[str, Any] = {}
        if npk_release_event is not None or npk_sha256:
            npk_result = self._publish_npk_release(
                verdict.pubkey,
                d=d,
                release_event=npk_release_event,
                artifact_sha256=npk_sha256,
                servers=servers,
                relays=broadcast_relays,
            )

        broadcast = _broadcast(event, broadcast_relays)
        if not broadcast["succeeded"]:
            raise NsiteError(
                "publish reached no relay: " + ", ".join(
                    f"{r['relay']}: {r.get('error', 'rejected')}" for r in broadcast["results"]
                )
            )

        self._record_site(verdict.pubkey, event["kind"], d, event, servers, broadcast_relays)

        site_url = None
        state = self._state()
        gateway_domain = (state.get("config") or {}).get("domain", "")
        if gateway_domain and verdict.label:
            from .manifest import canonical_site_url

            site_url = canonical_site_url(verdict.label, gateway_domain)

        return {
            "action": "nsite.publish",
            "event_id": verdict.event_id,
            "pubkey": verdict.pubkey,
            "kind": event["kind"],
            "d": d,
            "label": verdict.label,
            "aggregate_hash": verdict.aggregate_hash,
            "site_url": site_url,
            "plan_matched": True,
            "relays": broadcast,
            "npk": npk_result or None,
            "ok": True,
        }

    def _publish_npk_release(
        self,
        pubkey: str,
        *,
        d: str,
        release_event: dict[str, Any] | None,
        artifact_sha256: str,
        servers: list[str],
        relays: list[str],
    ) -> dict[str, Any]:
        """Verify a signed kind-9900 release, upload the site bundle and
        broadcast the release (Phase 3c). The bundle is re-packed from the
        draft deterministically, so its sha256 must match the signed release.
        """
        if not release_event or not artifact_sha256:
            raise NsiteError("npk publish requires both the signed release event and its artifact sha256")
        if not _SHA256_RE.fullmatch(artifact_sha256):
            raise NsiteError("npk artifact sha256 must be 64 lowercase hex characters")
        if not servers:
            raise NsiteError("npk publish requires Blossom server hints in the manifest")
        if not _npack_available():
            raise NsiteError("npk publish requires the npack binary ($NPACK_BIN); build forks/npack first")

        name = "root" if not d else d
        verify_release_event(release_event, pubkey=pubkey, name=name, artifact_sha256=artifact_sha256)

        # Deterministic re-pack: the same draft yields the same archive sha256.
        packed = pack_site_npk(pubkey, d=d, version=release_version(release_event))
        if packed["sha256"] != artifact_sha256:
            raise NsiteError("npk bundle no longer matches the signed release; rebuild the plan and re-sign")
        if packed["name"] != name:
            raise NsiteError("npk bundle name does not match the site")

        auth = _blossom_auth_event([artifact_sha256])
        uploads: list[dict[str, Any]] = []
        failed: list[str] = []
        for server in servers:
            if _blossom_has(server, artifact_sha256):
                uploads.append({"server": server, "skipped": True})
                continue
            ok, detail = _blossom_upload(server, artifact_sha256, packed["bytes"], auth or {})
            if ok:
                uploads.append({"server": server, "uploaded": True})
            else:
                failed.append(f"{server}: {detail}")
        if failed:
            raise NsiteError("npk bundle upload failed for: " + "; ".join(failed))

        release_broadcast = _broadcast(release_event, relays)
        if not release_broadcast["succeeded"]:
            raise NsiteError(
                "npk release reached no relay: " + ", ".join(
                    f"{r['relay']}: {r.get('error', 'rejected')}" for r in release_broadcast["results"]
                )
            )
        return {
            "name": name,
            "artifact_sha256": artifact_sha256,
            "uploaded": uploads,
            "release_event_id": release_event.get("id", ""),
            "release_broadcast": release_broadcast,
        }

    def _record_site(
        self,
        pubkey: str,
        kind: int,
        d: str,
        event: dict[str, Any],
        servers: list[str],
        relays: list[str],
    ) -> None:
        path = site_path(self.state_dir, pubkey, d)
        record: dict[str, Any] = {}
        if path.is_file():
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                record = {}
        record.update(
            {
                "pubkey": pubkey,
                "kind": kind,
                "d": d,
                "title": record.get("title", ""),
                "last_event_id": event.get("id", ""),
                "aggregate_hash": _aggregate_from_event(event),
                "paths": _paths_from_event(event),
                "app": _app_from_event(event),
                "servers": servers,
                "relays": relays,
                "provenance": {
                    "actor": "nsite.publish",
                    "at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                },
            }
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._refresh_gateway()

    def snapshot(
        self,
        event: dict[str, Any],
        *,
        plan_sha256: str = "",
        relays: list[str] | None = None,
    ) -> dict[str, Any]:
        """Record a client-signed kind 5128 snapshot (implementation plan §5).

        The snapshot is built and signed client-side (it references the root
        manifest's ``a`` tag and recomputes the aggregate); the server
        validates it exactly like a publish and records the event id on the
        site record's ``snapshots`` list. A snapshot does not change the
        allowlist.
        """
        from .manifest import validate_manifest as _validate
        from .signer_guard import forbidden_signer_pubkeys

        self._require_gateway()
        verdict = _validate(event, forbidden_pubkeys=forbidden_signer_pubkeys())
        if not verdict.valid or verdict.site_type != "snapshot":
            raise NsiteError(
                "snapshot is not a valid kind-5128 manifest: "
                + ", ".join(verdict.errors or ["bad_kind"])
            )
        if verdict.pubkey is None:
            raise NsiteError("snapshot has no signable pubkey")
        if plan_sha256 and verdict.aggregate_hash and verdict.aggregate_hash != plan_sha256:
            # For snapshots the client binds the aggregate it signed; keep the
            # same reject-a-stale-plan shape as publish.
            raise NsiteError("snapshot aggregate does not match the planned digest")

        from ..connectivity import effective as effective_connectivity

        broadcast_relays = [r for r in (relays or []) if r] or list(effective_connectivity()["relays"]["nsite"])
        broadcast = _broadcast(event, broadcast_relays)
        if not broadcast["succeeded"]:
            raise NsiteError("snapshot reached no relay")

        # Record on the site the snapshot references (its ``a`` tag), not the
        # snapshot's own (d-less) identity.
        ref_pubkey, ref_d = verdict.pubkey, ""
        for t in event.get("tags", []):
            if isinstance(t, list) and t and t[0] == "a" and len(t) > 1:
                parts = str(t[1]).split(":", 2)
                if len(parts) == 3 and parts[1]:
                    ref_pubkey, ref_d = parts[1], parts[2]
        path = site_path(self.state_dir, ref_pubkey, ref_d)
        if path.is_file():
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                record = {}
            snapshots = record.get("snapshots", [])
            if verdict.event_id not in snapshots:
                snapshots.append(verdict.event_id)
            record["snapshots"] = snapshots
            path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        return {
            "action": "nsite.snapshot",
            "event_id": verdict.event_id,
            "pubkey": verdict.pubkey,
            "label": verdict.label,
            "relays": broadcast,
            "ok": True,
        }

    # -- read-only network tools (Phase 3a) -------------------------------

    def mirror(
        self,
        pubkey: str,
        *,
        d: str = "",
        servers: list[str] | None = None,
    ) -> dict[str, Any]:
        """Re-upload a site's missing blobs to the selected Blossom servers.

        Reads the site's last published manifest (its recorded path->hash
        list), finds each blob in the server-side draft area, and PUTs the
        ones the target server does not already have (BUD-01 HEAD skip) with
        a kind-24242 auth event per batch (BUD-02/03). A blob missing from the
        draft (or whose draft bytes do not hash to the recorded value) is
        reported, not uploaded.
        """
        pubkey = _pubkey_hex(pubkey)
        servers = [s for s in (servers or []) if s]
        if not servers:
            raise NsiteError("mirror requires at least one Blossom server")
        for server in servers:
            if not server.startswith("https://"):
                raise NsiteError(f"refusing non-HTTPS Blossom server: {server!r}")
        record_path = site_path(self.state_dir, pubkey, d)
        if not record_path.is_file():
            raise NsiteError("site is not registered")
        record = json.loads(record_path.read_text(encoding="utf-8"))
        paths = record.get("paths") or []
        if not paths:
            raise NsiteError("site has no recorded manifest paths to mirror")

        root = draft_dir(pubkey, d)
        by_path: dict[str, tuple[Path, bytes | None]] = {}
        if root.is_dir():
            for path in sorted(root.rglob("*")):
                if not path.is_file() or path.is_symlink():
                    continue
                rel = "/" + path.relative_to(root).as_posix()
                by_path[rel] = (path, None)

        server_results: list[dict[str, Any]] = []
        total_uploaded = 0
        for server in servers:
            to_upload: list[tuple[str, str, bytes]] = []
            skipped = 0
            missing = 0
            for item in paths:
                rel = str(item.get("path", ""))
                expected = str(item.get("sha256", ""))
                if _blossom_has(server, expected):
                    skipped += 1
                    continue
                entry = by_path.get(rel)
                if entry is None:
                    missing += 1
                    continue
                data = _read_draft_blob(entry[0])
                if data is None or _sha256_file(entry[0]) != expected:
                    missing += 1
                    continue
                to_upload.append((rel, expected, data))
            failed: list[str] = []
            uploaded: list[str] = []
            # one 24242 auth event per batch of up to 20 hashes
            for start in range(0, len(to_upload), 20):
                batch = to_upload[start : start + 20]
                auth = _blossom_auth_event([h for _, h, _ in batch])
                for rel, blob_hash, data in batch:
                    ok, detail = _blossom_upload(server, blob_hash, data, auth or {})
                    if ok:
                        uploaded.append(rel)
                        total_uploaded += 1
                    else:
                        failed.append(rel)
            server_results.append(
                {
                    "server": server,
                    "uploaded": uploaded,
                    "skipped": skipped,
                    "missing_from_draft": missing,
                    "failed": failed,
                    "ok": not failed,
                }
            )
        return {
            "action": "nsite.mirror",
            "pubkey": pubkey,
            "d": d,
            "servers": server_results,
            "total_uploaded": total_uploaded,
            "ok": True,
        }

    # -- read-only network tools (Phase 3a) -------------------------------

    def resolve(
        self,
        *,
        label: str = "",
        pubkey: str = "",
        d: str = "",
        relays: list[str] | None = None,
        limit: int = 5,
        timeout: float = 8.0,
    ) -> dict[str, Any]:
        """Fetch the current manifest for a label or pubkey from public relays.

        Bounded: at most ``limit`` relays, each with ``timeout`` seconds and
        at most 20 events, then the newest valid manifest wins. Reads only.
        """
        from .manifest import decode_label

        kind: int | None = None
        author = ""
        event_id = ""
        if label:
            site_type, hex_value, label_d = decode_label(label)
            if site_type is None:
                raise NsiteError(f"cannot decode site label {label!r}")
            kind = {"root": KIND_ROOT, "named": KIND_NAMED, "snapshot": KIND_SNAPSHOT}.get(
                site_type, KIND_ROOT
            )
            if site_type == "snapshot":
                event_id, author = hex_value, ""
            else:
                author, d = hex_value, label_d or d
        elif pubkey:
            author = _pubkey_hex(pubkey)
            kind = KIND_NAMED if d else KIND_ROOT
        else:
            raise NsiteError("resolve needs a label or a pubkey")

        lookup_relays = [r for r in (relays or []) if r]
        # M10: caller-supplied relays are validated (ws/wss only, no private/
        # loopback targets) so resolve cannot be an SSRF vector. Config-default
        # relays are operator-trusted and left untouched.
        if relays:
            for relay in lookup_relays:
                _validate_relay_url(relay)
        if not lookup_relays:
            state = self._state()
            config = state.get("config") or {}
            configured = config.get("relays", {}).get("lookup")
            if configured and configured != ["wss://purplepag.es", "wss://user.kindpag.es"]:
                lookup_relays = configured
            else:
                from ..connectivity import effective as effective_connectivity

                lookup_relays = effective_connectivity()["relays"]["nsite_lookup"]

        filters: dict[str, Any] = {"kinds": [kind]}
        if author:
            filters["authors"] = [author]
        if event_id:
            filters["ids"] = [event_id]

        candidates: list[dict[str, Any]] = []
        for relay in lookup_relays[:limit]:
            candidates.extend(_query_relay_events(relay, filters, limit=20, timeout=timeout))
        if not candidates:
            return {"found": False, "relays_queried": lookup_relays[:limit], "manifest": None}

        from .manifest import validate_manifest as _validate

        newest: tuple[int, dict[str, Any], Any] | None = None
        for event in candidates:
            verdict = _validate(event)
            if not verdict.valid:
                continue
            if d and (verdict.d or "") != d:
                continue
            if kind == KIND_NAMED and not d:
                continue
            created_at = int(event.get("created_at", 0))
            if newest is None or created_at > newest[0]:
                newest = (created_at, event, verdict)
        if newest is None:
            return {"found": False, "relays_queried": lookup_relays[:limit], "manifest": None}

        _created, event, verdict = newest
        return {
            "found": True,
            "relays_queried": lookup_relays[:limit],
            "manifest": {
                "event_id": verdict.event_id,
                "pubkey": verdict.pubkey,
                "kind": event["kind"],
                "d": verdict.d,
                "label": verdict.label,
                "aggregate_hash": verdict.aggregate_hash,
                "paths": verdict.paths,
            },
        }

    def discover(
        self,
        *,
        limit: int = 200,
        max_relays: int = 6,
        timeout: float = 8.0,
        refresh: bool = False,
    ) -> dict[str, Any]:
        """Discover nsite manifests (kinds 15128/35128) from the relays.

        On-demand, bounded read — no state is written. Scans the
        operator-trusted catalogue + nsite-lookup relay sets, validates every
        candidate with the full NIP-5A checks, keeps the newest valid manifest
        per site (pubkey + d), drops sites whose blobs are unreachable on every
        advertised Blossom server (bounded, SSRF-safe probes) and the operator's
        blocked npubs (NIP-51 kind-10000 mute list), and returns bounded
        metadata only. Untrusted free text (manifest ``content``, oversized
        ``title``) never leaves this method, so the result is safe to render
        and to ship through MCP.

        Results are cached for ``DISCOVER_CACHE_TTL`` seconds, keyed by the
        effective relay set, so returning to the catalogue is instant;
        ``refresh=True`` bypasses the cache (the admin Refresh button /
        ``--refresh``). The cached payload is re-filtered against the current
        blocklist on every read, so a newly blocked npub disappears from the
        catalogue immediately without a rescan.
        """
        from ..connectivity import effective as effective_connectivity
        from .manifest import validate_manifest as _validate

        effective = effective_connectivity()
        relays: list[str] = []
        for purpose in ("catalogue", "nsite_lookup"):
            for url in effective["relays"].get(purpose) or []:
                if url in relays:
                    continue
                try:
                    _validate_relay_url(url)
                except NsiteError:
                    continue
                relays.append(url)

        scan_relays = relays[:max_relays]
        blocked = _operator_blocklist()
        cache_key = _discover_cache_key(scan_relays)
        now = time.time()
        with _discover_cache_lock:
            cached = _discover_cache.get(cache_key)
            if cached is not None and not refresh and (now - cached[0]) < DISCOVER_CACHE_TTL:
                # The cache stores the full valid site list keyed by relay set
                # only, so a block added since caching takes effect on the next
                # read (and an unblock restores) without a full rescan.
                payload = dict(cached[1])
                payload = _filter_blocked(payload, blocked)
                payload["cached"] = True
                payload["cached_at"] = int(cached[0])
                return payload

        # Concurrent relay fetch: a serial scan would take ~relays × timeout
        # (up to ~48s with max_relays=6 and an 8s per-relay deadline), routinely
        # overrunning the admin client's request timeout. Querying the relays
        # in parallel drops wall time to ≈ the slowest relay, so the on-demand
        # scan stays comfortably inside the request budget. Results are merged
        # after the parallel fetch, so validation/dedupe stay order-independent.
        candidates: list[dict[str, Any]] = []
        if scan_relays:
            with ThreadPoolExecutor(max_workers=len(scan_relays)) as pool:
                futures = [
                    pool.submit(
                        _query_relay_events,
                        relay,
                        {"kinds": [KIND_ROOT, KIND_NAMED]},
                        limit=limit,
                        timeout=timeout,
                    )
                    for relay in scan_relays
                ]
                for future in futures:
                    try:
                        candidates.extend(future.result())
                    except Exception:  # noqa: BLE001 - a failed relay scan is skipped
                        continue

        registered_keys = {
            f"{record.get('pubkey', '')}:{str(record.get('d', ''))}"
            for record in _sites(self.state_dir)
        }

        # Newest valid manifest per site, deterministic tie-break on event id.
        newest: dict[tuple[str, str], tuple[int, str, dict[str, Any], Any]] = {}
        for event in candidates:
            verdict = _validate(event)
            if not verdict.valid or not verdict.pubkey:
                continue
            if verdict.site_type not in ("root", "named"):
                continue
            key = (verdict.pubkey, verdict.d or "")
            created_at = int(event.get("created_at", 0))
            event_id = str(event.get("id", ""))
            existing = newest.get(key)
            if existing is None or created_at > existing[0] or (
                created_at == existing[0] and event_id > existing[1]
            ):
                newest[key] = (created_at, event_id, event, verdict)

        # Verify blob existence (bounded, parallel, under one phase deadline)
        # for every valid site. The cached payload deliberately keeps the full
        # list unfiltered so the blocklist can be applied on each read (block
        # and unblock both take effect without a rescan); sites are probed
        # regardless of the blocklist so an unblocked site is immediately
        # verifiable.
        blob_stats: dict[str, int | bool] = {
            "checked": 0,
            "ok": 0,
            "unknown": 0,
            "excluded": 0,
            "blocked": 0,
            "truncated": False,
        }
        sites: list[dict[str, Any]] = []
        if newest:
            blob_deadline = time.time() + DISCOVER_BLOB_PHASE_TIMEOUT
            with ThreadPoolExecutor(max_workers=min(32, len(newest))) as pool:
                futures = {
                    pool.submit(_site_blob_check, event, verdict, blob_deadline): (event, verdict)
                    for _created_at, _event_id, event, verdict in newest.values()
                }
                for future, (event, verdict) in futures.items():
                    ok, checked, truncated = future.result()
                    blob_stats["checked"] = int(blob_stats["checked"]) + checked
                    blob_stats["truncated"] = bool(blob_stats["truncated"]) or truncated
                    if ok is False:
                        blob_stats["excluded"] = int(blob_stats["excluded"]) + 1
                        continue
                    blob_stats["ok" if ok else "unknown"] = int(blob_stats["ok" if ok else "unknown"]) + 1
                    meta = _site_metadata(event, verdict, registered_keys)
                    if meta:
                        meta["blobs_ok"] = ok
                        meta["blobs_checked"] = checked
                        sites.append(meta)

        sites.sort(key=lambda site: (-site["created_at"], site["label"] or ""))
        truncated = len(sites) > DISCOVER_MAX_SITES
        payload: dict[str, Any] = {
            "sites": sites[:DISCOVER_MAX_SITES],
            "relays_queried": scan_relays,
            "count": len(sites[:DISCOVER_MAX_SITES]),
            "truncated": truncated,
            "blob_check": blob_stats,
            "cached": False,
            "cached_at": None,
        }
        with _discover_cache_lock:
            _discover_cache[cache_key] = (now, payload)
        return _filter_blocked(payload, blocked)

    # -- curated nsite collections (kind 30004, NSITES-CURATED-LISTS.md) ---

    def collection_validate(self, event: dict[str, Any]) -> dict[str, Any]:
        """Validate a candidate collection event (no network)."""
        from .collections import validate_collection as _validate
        from .signer_guard import forbidden_signer_pubkeys

        v = _validate(event, forbidden_pubkeys=forbidden_signer_pubkeys())
        return {
            "valid": v.valid,
            "errors": v.errors,
            "coordinate": v.coordinate,
            "pubkey": v.pubkey,
            "event_id": v.event_id,
            "d": v.d,
            "title": v.title,
            "entries": [entry.__dict__ for entry in v.entries],
        }

    def collection_publish_plan(
        self,
        pubkey: str,
        *,
        d: str,
        title: str = "",
        description: str = "",
        image: str = "",
        entries: list[dict[str, str]] | None = None,
        relays: list[str] | None = None,
        copy_of: str = "",
    ) -> dict[str, Any]:
        """Build the unsigned kind-30004 event and its plan digest.

        ``entries`` is the ordered ``[{"kind": "live-root"|"live-named"|"pinned",
        "ref": "…", "relay": "…"}]`` list from the Admin, in display order.
        ``copy_of`` (a ``30004:<pubkey>:<d>`` coordinate) resolves the source
        collection from relays and re-signs its entries under this curator's
        pubkey with a fresh ``d`` — "save a copy". Nothing is signed or
        broadcast here.
        """
        from .collections import (
            COLLECTION_KIND,
            collection_plan_digest,
            is_valid_coordinate,
            is_valid_d,
        )

        pubkey = _pubkey_hex(pubkey)
        if not is_valid_d(d):
            raise NsiteError(f"invalid collection d tag: {d!r}")

        src_entries: list[dict[str, str]] = []
        if copy_of:
            if not is_valid_coordinate(copy_of) or not copy_of.startswith(f"{COLLECTION_KIND}:"):
                raise NsiteError(
                    f"invalid copy source {copy_of!r} (expect 30004:<pubkey>:<d>)"
                )
            resolved = self.collection_resolve(copy_of)
            if not resolved.get("found"):
                raise NsiteError(f"copy source {copy_of!r} could not be resolved from relays")
            src_entries = [
                {"kind": e["kind"], "ref": e["ref"], "relay": e.get("relay", "")}
                for e in resolved.get("entries", [])
            ]
            if not src_entries:
                raise NsiteError("copy source has no entries to copy")

        entry_tags: list[list[str]] = []
        seen: set[str] = set()
        ordered: list[dict[str, str]] = []
        raw = entries if entries is not None else src_entries
        for item in raw:
            kind = str(item.get("kind", ""))
            ref = str(item.get("ref", ""))
            relay = str(item.get("relay", ""))
            if kind not in ("live-root", "live-named", "pinned"):
                raise NsiteError(f"invalid entry kind {kind!r}")
            if ref in seen:
                raise NsiteError(f"duplicate entry {ref!r}")
            seen.add(ref)
            tag = ["a" if kind in ("live-root", "live-named") else "e", ref]
            if relay:
                tag.append(relay)
            entry_tags.append(tag)
            ordered.append({"kind": kind, "ref": ref, "relay": relay})

        from ..connectivity import effective as _effective

        relays = [r for r in (relays or []) if r] or list(_effective()["relays"]["nsite"])
        for url in relays:
            if not url.startswith("wss://"):
                raise NsiteError(f"refusing non-WSS relay URL: {url!r}")

        tags: list[list[str]] = [
            ["d", d],
            ["t", "nsite"],
        ]
        if title:
            tags.append(["title", title[:120]])
        if description:
            tags.append(["description", description[:500]])
        if image:
            tags.append(["image", image])
        tags.extend(entry_tags)

        digest = collection_plan_digest(
            pubkey=pubkey,
            d=d,
            title=title[:120],
            description=description[:500],
            image=image,
            entries=entry_tags,
            relays=relays,
        )
        plan = {
            "pubkey": pubkey,
            "d": d,
            "title": title[:120],
            "description": description[:500],
            "image": image,
            "entries": ordered,
            "relays": relays,
            "copy_of": copy_of,
            "unsigned_event": {
                "kind": COLLECTION_KIND,
                "pubkey": pubkey,
                "created_at": 0,
                "tags": tags,
                "content": "",
            },
            "plan_sha256": digest,
        }
        return {"plan": plan}

    def collection_publish(
        self,
        event: dict[str, Any],
        *,
        plan_sha256: str = "",
        relays: list[str] | None = None,
    ) -> dict[str, Any]:
        """Verify a signed collection, broadcast it and report per-relay results.

        Rejects (before any broadcast) when the event is not a valid kind-30004
        ``t = nsite`` collection, is signed by a host key, or the plan digest
        does not match the event's signed content. A publish that reaches at
        least one relay succeeds with a warning list; one that reaches none
        fails (D5 semantics). No local state is written — the signed event on
        external relays is authoritative.
        """
        from .collections import (
            COLLECTION_KIND,
            collection_plan_digest,
            validate_collection as _validate,
        )
        from .signer_guard import forbidden_signer_pubkeys

        verdict = _validate(event, forbidden_pubkeys=forbidden_signer_pubkeys())
        if not verdict.valid or verdict.pubkey is None:
            raise NsiteError(
                "collection is not valid: " + ", ".join(verdict.errors or ["bad_event"])
            )

        entry_tags: list[list[str]] = []
        for t in event.get("tags", []):
            if isinstance(t, list) and t and t[0] in ("a", "e"):
                entry_tags.append(t)
        from ..connectivity import effective as _effective

        planned = [r for r in (relays or []) if r] or list(_effective()["relays"]["nsite"])
        digest = collection_plan_digest(
            pubkey=verdict.pubkey,
            d=verdict.d or "",
            title=verdict.title,
            description=verdict.description,
            image=verdict.image,
            entries=entry_tags,
            relays=planned,
        )
        if plan_sha256 and digest != plan_sha256:
            raise NsiteError("plan digest mismatch: the signed collection does not match the planned content")
        if not plan_sha256:
            raise NsiteError("collection publish requires the plan_sha256 from nsite.collection.publish.plan")

        broadcast = _broadcast(event, planned)
        if not broadcast["succeeded"]:
            raise NsiteError(
                "collection publish reached no relay: " + ", ".join(
                    f"{r['relay']}: {r.get('error', 'rejected')}" for r in broadcast["results"]
                )
            )
        return {
            "action": "nsite.collection.publish",
            "event_id": verdict.event_id,
            "coordinate": verdict.coordinate,
            "d": verdict.d,
            "title": verdict.title,
            "entries": len(verdict.entries),
            "relays": broadcast,
            "ok": True,
        }

    def collection_resolve(
        self,
        coordinate: str,
        *,
        relays: list[str] | None = None,
        limit: int = 5,
        timeout: float = 8.0,
    ) -> dict[str, Any]:
        """Resolve one collection coordinate and its entries from public relays.

        Bounded: at most ``limit`` relays for the collection event, each with
        ``timeout`` seconds; newest valid event for the exact coordinate wins.
        Each live/pinned entry is then resolved with the same bounded nsite
        ``resolve`` (the entry's relay hint first, then lookup relays) so the
        result renders ordered entries with per-entry availability. Reads only.
        """
        from .collections import COLLECTION_KIND, is_valid_coordinate

        if not is_valid_coordinate(coordinate) or not coordinate.startswith(f"{COLLECTION_KIND}:"):
            raise NsiteError(f"invalid collection coordinate {coordinate!r}")
        parts = coordinate.split(":", 2)
        author, d = parts[1], parts[2]

        lookup_relays = [r for r in (relays or []) if r]
        if relays:
            for relay in lookup_relays:
                _validate_relay_url(relay)
        if not lookup_relays:
            from ..connectivity import effective as _effective

            lookup_relays = _effective()["relays"]["nsite_lookup"]

        filters: dict[str, Any] = {"kinds": [COLLECTION_KIND], "#d": [d], "authors": [author]}
        candidates: list[dict[str, Any]] = []
        for relay in lookup_relays[:limit]:
            candidates.extend(_query_relay_events(relay, filters, limit=20, timeout=timeout))
        if not candidates:
            return {"found": False, "relays_queried": lookup_relays[:limit], "collection": None}

        from .collections import validate_collection as _validate

        newest: tuple[int, str, dict[str, Any], Any] | None = None
        for event in candidates:
            v = _validate(event)
            if not v.valid or v.pubkey != author or (v.d or "") != d:
                continue
            created_at = int(event.get("created_at", 0))
            event_id = str(event.get("id", ""))
            if newest is None or created_at > newest[0] or (
                created_at == newest[0] and event_id > newest[1]
            ):
                newest = (created_at, event_id, event, v)
        if newest is None:
            return {"found": False, "relays_queried": lookup_relays[:limit], "collection": None}

        _created, _event_id, event, verdict = newest
        entries_out: list[dict[str, Any]] = []
        for entry in verdict.entries[:COLLECTION_ENTRY_RESOLVE_LIMIT]:
            resolved = None
            if entry.kind in ("live-root", "live-named"):
                try:
                    resolved = self.resolve(
                        pubkey=entry.ref.split(":", 2)[1],
                        d=entry.ref.split(":", 2)[2],
                        relays=[entry.relay] if entry.relay else None,
                        limit=2,
                        timeout=min(timeout, 6.0),
                    )
                except NsiteError:
                    resolved = None
            elif entry.kind == "pinned":
                # A pinned entry references a kind-5128 snapshot event id: an
                # immutable version. Resolve it by its snapshot label.
                from .manifest import snapshot_label

                try:
                    resolved = self.resolve(
                        label=snapshot_label(entry.ref),
                        relays=[entry.relay] if entry.relay else None,
                        limit=2,
                        timeout=min(timeout, 6.0),
                    )
                except NsiteError:
                    resolved = None
            entries_out.append(
                {
                    "kind": entry.kind,
                    "ref": entry.ref,
                    "relay": entry.relay,
                    "site": (resolved.get("manifest") if resolved and resolved.get("found") else None),
                    "available": bool(resolved and resolved.get("found")),
                }
            )

        blocked = _operator_blocklist()
        return {
            "found": True,
            "relays_queried": lookup_relays[:limit],
            "coordinate": verdict.coordinate,
            "d": verdict.d,
            "pubkey": verdict.pubkey,
            "event_id": verdict.event_id,
            "title": verdict.title,
            "description": verdict.description,
            "image": verdict.image,
            "created_at": int(event.get("created_at", 0)),
            "entries": entries_out,
            "entries_total": len(verdict.entries),
            "blocked": author in blocked,
        }

    def collection_discover(
        self,
        *,
        limit: int = 100,
        max_relays: int = 6,
        timeout: float = 8.0,
        refresh: bool = False,
    ) -> dict[str, Any]:
        """Discover kind-30004 ``t = nsite`` collections from the relays.

        On-demand, bounded read — no state is written. Scans the operator-
        trusted catalogue + nsite-lookup relay sets for ``{"kinds":[30004],
        "#t":["nsite"]}``, validates every candidate, keeps the newest valid
        event per coordinate (event-id tie-break), drops the operator's blocked
        npubs and returns bounded metadata only. Results are cached for
        ``DISCOVER_CACHE_TTL`` seconds keyed by the effective relay set;
        ``refresh=True`` bypasses the cache.
        """
        from ..connectivity import effective as _effective
        from .collections import COLLECTION_KIND, validate_collection as _validate

        effective = _effective()
        relays: list[str] = []
        for purpose in ("catalogue", "nsite_lookup"):
            for url in effective["relays"].get(purpose) or []:
                if url in relays:
                    continue
                try:
                    _validate_relay_url(url)
                except NsiteError:
                    continue
                relays.append(url)

        scan_relays = relays[:max_relays]
        blocked = _operator_blocklist()
        cache_key = _discover_cache_key(scan_relays)
        now = time.time()
        with _collection_cache_lock:
            cached = _collection_cache.get(cache_key)
            if cached is not None and not refresh and (now - cached[0]) < DISCOVER_CACHE_TTL:
                payload = _filter_blocked_collections(dict(cached[1]), blocked)
                payload["cached"] = True
                payload["cached_at"] = int(cached[0])
                return payload

        candidates: list[dict[str, Any]] = []
        if scan_relays:
            with ThreadPoolExecutor(max_workers=len(scan_relays)) as pool:
                futures = [
                    pool.submit(
                        _query_relay_events,
                        relay,
                        {"kinds": [COLLECTION_KIND], "#t": ["nsite"]},
                        limit=limit,
                        timeout=timeout,
                    )
                    for relay in scan_relays
                ]
                for future in futures:
                    try:
                        candidates.extend(future.result())
                    except Exception:  # noqa: BLE001 - a failed relay scan is skipped
                        continue

        newest: dict[str, tuple[int, str, dict[str, Any], Any]] = {}
        for event in candidates:
            verdict = _validate(event)
            if not verdict.valid or not verdict.coordinate:
                continue
            key = verdict.coordinate
            created_at = int(event.get("created_at", 0))
            event_id = str(event.get("id", ""))
            existing = newest.get(key)
            if existing is None or created_at > existing[0] or (
                created_at == existing[0] and event_id > existing[1]
            ):
                newest[key] = (created_at, event_id, event, verdict)

        collections: list[dict[str, Any]] = []
        for _created_at, _event_id, event, verdict in newest.values():
            if verdict.pubkey in blocked:
                continue
            collections.append(
                {
                    "coordinate": verdict.coordinate,
                    "pubkey": verdict.pubkey,
                    "d": verdict.d,
                    "title": verdict.title[:120],
                    "description": verdict.description[:500],
                    "image": verdict.image,
                    "event_id": verdict.event_id,
                    "created_at": int(event.get("created_at", 0)),
                    "entries": len(verdict.entries),
                }
            )
        collections.sort(key=lambda c: (-c["created_at"], c["coordinate"] or ""))
        truncated = len(collections) > DISCOVER_MAX_COLLECTIONS
        payload: dict[str, Any] = {
            "collections": collections[:DISCOVER_MAX_COLLECTIONS],
            "relays_queried": scan_relays,
            "count": len(collections[:DISCOVER_MAX_COLLECTIONS]),
            "truncated": truncated,
            "cached": False,
            "cached_at": None,
        }
        with _collection_cache_lock:
            _collection_cache[cache_key] = (now, payload)
        return _filter_blocked_collections(payload, blocked)

    def reachability(
        self,
        *,
        relays: list[str] | None = None,
        servers: list[str] | None = None,
        timeout: float = 5.0,
    ) -> dict[str, Any]:
        """Probe relay (WebSocket) and server (HTTP HEAD) reachability.

        Bounded per target; results are advisory only. Targets are validated
        first (M10): only ws/wss relays and HTTP(S) servers are accepted,
        embedded credentials are refused, and targets resolving to private/
        loopback/link-local addresses are rejected so the probe cannot be an
        SSRF into internal hosts.
        """
        relay_results: list[dict[str, Any]] = []
        for relay in (relays or []):
            try:
                _validate_relay_url(relay)
            except NsiteError as exc:
                relay_results.append({"relay": relay, "ok": False, "error": str(exc)})
                continue
            started = time.time()
            try:
                _query_relay_events(relay, {"kinds": []}, limit=1, timeout=timeout)
                relay_results.append(
                    {"relay": relay, "ok": True, "roundtrip_ms": int((time.time() - started) * 1000)}
                )
            except Exception as exc:  # noqa: BLE001
                relay_results.append({"relay": relay, "ok": False, "error": str(exc)})
        server_results = [_http_probe(url, timeout=timeout) for url in (servers or [])]
        return {"relays": relay_results, "servers": server_results}


def _aggregate_from_event(event: dict[str, Any]) -> str:
    from .manifest import aggregate_hash

    paths = [
        (str(t[1]), str(t[2]))
        for t in event.get("tags", [])
        if isinstance(t, list) and len(t) >= 3 and t[0] == "path"
    ]
    return aggregate_hash(paths)


def _paths_from_event(event: dict[str, Any]) -> list[dict[str, str]]:
    """The manifest's path->hash list, stored on the site record so
    ``nsite.mirror`` knows which blobs a site needs on each server."""
    return [
        {"path": str(t[1]), "sha256": str(t[2])}
        for t in event.get("tags", [])
        if isinstance(t, list) and len(t) >= 3 and t[0] == "path"
    ]


def _app_from_event(event: dict[str, Any]) -> str:
    """The ``app`` tag's "kind:pubkey:d" address (Phase 5), if the manifest
    links itself to a kind-32267 catalogue declaration."""
    for t in event.get("tags", []):
        if isinstance(t, list) and len(t) >= 2 and t[0] == "app":
            return str(t[1])
    return ""


def _site_metadata(
    event: dict[str, Any],
    verdict: Any,
    registered_keys: set[str],
) -> dict[str, Any]:
    """Bounded, safe metadata for one validated manifest (nsite.discover).

    Only whitelisted fields leave this function: identity, kind, the NIP-5A
    ``title`` (length-capped), bounded ``server``/``r`` hints, aggregate
    summary counts and whether the site is already registered on this host.
    Manifest ``content`` and raw tags are never copied out.
    """
    title = ""
    servers: list[str] = []
    relays: list[str] = []
    raw_tags = event.get("tags")
    tags = raw_tags if isinstance(raw_tags, list) else []
    for tag in tags:
        if not isinstance(tag, list) or not tag or not isinstance(tag[0], str):
            continue
        key = tag[0]
        value = tag[1] if len(tag) > 1 and isinstance(tag[1], str) else ""
        if key == "title" and value and not title:
            title = value
        elif key == "server" and value and len(servers) < 10:
            servers.append(value)
        elif key in ("r", "relay") and value and len(relays) < 10:
            relays.append(value)
    return {
        "label": verdict.label,
        "pubkey": verdict.pubkey,
        "kind": int(event.get("kind", 0)),
        "d": verdict.d or "",
        "title": title[:120],
        "servers": servers,
        "relays": relays,
        "event_id": verdict.event_id,
        "created_at": int(event.get("created_at", 0)),
        "paths_count": len(verdict.paths),
        "app": verdict.app or "",
        "registered": f"{verdict.pubkey}:{verdict.d or ''}" in registered_keys,
    }


def _sites(state_dir: Path) -> list[dict[str, Any]]:
    d = nsites_state_dir(state_dir) / "sites"
    if not d.is_dir():
        return []
    out = []
    for path in sorted(d.glob("*.json")):
        try:
            out.append(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            continue
    return out


def _custom_domains(state_dir: Path) -> list[dict[str, Any]]:
    d = nsites_state_dir(state_dir) / _DOMAIN_DIR
    if not d.is_dir():
        return []
    out = []
    for path in sorted(d.glob("*.json")):
        try:
            out.append(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            continue
    return out
