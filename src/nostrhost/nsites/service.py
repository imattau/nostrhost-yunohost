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
import json
import os
import re
import secrets
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any

from .manifest import KIND_NAMED, KIND_ROOT, KIND_SNAPSHOT
from .models import CustomDomainRecord, GatewayConfig, SiteRecord

CONFIG_PATH = Path("/etc/nostrhost/nsite.toml")
CADDY_TEMPLATE_DIR = Path("/usr/share/yunohost/conf/caddy")
CADDY_CONF_DIR = Path("/etc/caddy/conf.d")
GATEWAY_UPSTREAM = "127.0.0.1:8195"
SERVICE = "nostrhost-nsite.service"

_LIVE = object()

# Host defaults for publishing when the owner's NIP-65 list is unavailable
# (implementation plan §D5).
DEFAULT_PUBLISH_RELAYS = [
    "wss://purplepag.es",
    "wss://nos.lol",
    "wss://relay.damus.io",
]

_SITE_DIR = "sites"

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


def _valid_fqdn(fqdn: str) -> bool:
    fqdn = fqdn.rstrip(".").lower()
    return bool(_HOSTNAME_RE.fullmatch(fqdn))


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
    *, kind: int, d: str, paths: list[tuple[str, str]], servers: list[str]
) -> str:
    """The plan digest binding a manifest's signed content (D7, §6 step 5).

    Covers exactly what a manifest carries that the signer commits to: kind,
    ``d``, the (sorted) path tags and the (sorted) server hints. The Admin's
    ``src/lib/nsite/manifest.ts`` computes the identical digest, so a signed
    event submitted to ``nsite.publish`` with a stale/mismatched digest is
    rejected before any broadcast or record (stale-plan rejection).
    """
    payload = json.dumps(
        [kind, d, sorted(paths), sorted(set(servers))], separators=(",", ":")
    )
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


def _http_probe(url: str, timeout: float = 5.0) -> dict[str, Any]:
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator-provided target, bounded
            return {"url": url, "ok": True, "status": resp.status}
    except Exception as exc:  # noqa: BLE001
        return {"url": url, "ok": False, "error": str(exc)}


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
    """HEAD a blob on a Blossom server (BUD-01); True when present."""
    try:
        req = urllib.request.Request(f"{server}/{sha256}", method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator-configured server
            return resp.status == 200
    except Exception:  # noqa: BLE001 - a missing/unreachable blob is reported, not raised
        return False


def _blossom_upload(
    server: str, sha256: str, data: bytes, auth_event: dict[str, Any], timeout: float = 60.0
) -> tuple[bool, str]:
    """PUT a blob to a Blossom server with a kind-24242 auth event (BUD-02/03)."""
    import base64

    payload = json.dumps(auth_event, separators=(",", ":")).encode("utf-8")
    header = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    req = urllib.request.Request(
        f"{server}/upload?sha256={sha256}",
        data=data,
        method="PUT",
        headers={"Authorization": f"Nostr {header}", "Content-Type": "application/octet-stream"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator-configured server
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
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(text, encoding="utf-8")
        try:
            import grp

            gid = grp.getgrnam("nostrhost-nsite").gr_gid
            os.chown(self.config_path, 0, gid)
        except (KeyError, OSError):
            pass
        try:
            os.chmod(self.config_path, 0o640)
        except OSError:
            pass
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

    def _write_snippet(self, domain: str) -> Path:
        """Write the gateway domain's tracked Caddy snippet (caddy_nsite.conf
        template) so regenconf detects manual edits."""
        template = CADDY_TEMPLATE_DIR / "caddy_nsite.conf"
        if not template.is_file():
            return Path("")
        CADDY_CONF_DIR.mkdir(parents=True, exist_ok=True)
        conf = template.read_text(encoding="utf-8").replace("{{ domain }}", domain)
        if (
            domain.endswith(".test")
            or domain.endswith(".local")
            or domain == "localhost"
        ):
            # The template's on-demand block is multi-line; match it loosely so
            # local/CI domains fall back to the internal CA instead of ACME.
            conf = re.sub(r"tls\s*\{\s*on_demand\s*\}", "tls internal", conf)
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

    def enable(self, config: GatewayConfig) -> dict[str, Any]:
        if not config.domain:
            raise NsiteError("gateway enable requires a domain")
        self._registered_domain(config.domain)
        self._assert_dedicated_domain(config.domain)
        self.render_config(config)
        snippet = self._write_snippet(config.domain)
        if snippet != Path(""):
            self._reload_caddy()
        caddy = self._ensure_caddy(config.domain)
        self._set_state({"enabled": True, "config": config.dict()})
        self._start()
        return {
            "action": "nsite.gateway.enable",
            "domain": config.domain,
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
        if not config.domain:
            raise NsiteError("gateway configure requires a domain")
        if config.domain != (state.get("config") or {}).get("domain"):
            self._registered_domain(config.domain)
            self._assert_dedicated_domain(config.domain)
        self.render_config(config)
        self._write_snippet(config.domain)
        self._reload_caddy()
        caddy = self._ensure_caddy(config.domain)
        self._set_state({"enabled": True, "config": config.dict()})
        self._reload()
        return {
            "action": "nsite.gateway.configure",
            "domain": config.domain,
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
    ) -> dict[str, Any]:
        """Build the unsigned manifest and the plan digest (D7, §6 step 2/5).

        ``items`` is ``[{"path": "/index.html", "sha256": "…64 hex…"}, …]``
        produced by the Admin's client-side inventory+hash. Alternatively
        ``site`` names a server-side draft (Phase 3b, D6): its inventory is
        read from ``/var/lib/nostrhost/nsites/drafts/<site>/`` and shown
        before signing. Nothing is signed or broadcast here.
        """
        from .manifest import is_sha256_hex, is_valid_d

        pubkey = _pubkey_hex(pubkey)
        if kind not in (KIND_ROOT, KIND_NAMED):
            raise NsiteError("plan kind must be 15128 (root) or 35128 (named)")
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
        servers = [s for s in (servers or []) if s]
        relays = [r for r in (relays or []) if r] or list(DEFAULT_PUBLISH_RELAYS)
        for url in servers + relays:
            if not url.startswith(("https://", "wss://")):
                raise NsiteError(f"refusing non-TLS server/relay URL: {url!r}")

        from .manifest import aggregate_hash

        tags: list[list[str]] = []
        if kind == KIND_NAMED:
            tags.append(["d", d])
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
            "unsigned_event": {
                "kind": kind,
                "pubkey": pubkey,
                "created_at": 0,
                "tags": tags,
                "content": "",
            },
            "plan_sha256": plan_digest(kind=kind, d=d, paths=paths, servers=servers),
        }
        return {"plan": plan}

    def publish(
        self,
        event: dict[str, Any],
        *,
        plan_sha256: str = "",
        relays: list[str] | None = None,
    ) -> dict[str, Any]:
        """Verify a signed manifest, broadcast it and record the site.

        Rejects (before any broadcast or record) when the event is not a valid
        manifest, is signed by a host key, the plan digest does not match the
        event's signed content, or (hosted mode) the pubkey is unregistered.
        A publish that reaches at least one relay succeeds with a warning list;
        one that reaches none fails (implementation plan §D5).
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
        digest = plan_digest(kind=event["kind"], d=d, paths=paths, servers=servers)
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

        broadcast_relays = [r for r in (relays or []) if r] or list(DEFAULT_PUBLISH_RELAYS)
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
            "ok": True,
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

        broadcast_relays = [r for r in (relays or []) if r] or list(DEFAULT_PUBLISH_RELAYS)
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
        if not lookup_relays:
            state = self._state()
            config = state.get("config") or {}
            lookup_relays = config.get("relays", {}).get("lookup") or ["wss://purplepag.es", "wss://user.kindpag.es"]

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

    def reachability(
        self,
        *,
        relays: list[str] | None = None,
        servers: list[str] | None = None,
        timeout: float = 5.0,
    ) -> dict[str, Any]:
        """Probe relay (WebSocket) and server (HTTP HEAD) reachability.

        Bounded per target; results are advisory only.
        """
        relay_results: list[dict[str, Any]] = []
        for relay in (relays or []):
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
