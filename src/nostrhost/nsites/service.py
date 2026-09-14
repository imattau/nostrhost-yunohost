"""Nsites gateway lifecycle service (Phase 1, task 1.4).

Manages the optional ``nostrhost-nsite`` systemd unit: enable/disable/
configure, rendering ``/etc/nostrhost/nsite.toml``, writing the gateway
domain's Caddy snippet and reconciling the ``nostrhost-nsite:<domain>`` admin
route, and persisting intent in ``state/nsites/gateway.json`` (ngit state,
§3.2). Site registration/publishing is Phase 3.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.request
from pathlib import Path
from typing import Any

from .models import GatewayConfig

CONFIG_PATH = Path("/etc/nostrhost/nsite.toml")
CADDY_TEMPLATE_DIR = Path("/usr/share/yunohost/conf/caddy")
CADDY_CONF_DIR = Path("/etc/caddy/conf.d")
GATEWAY_UPSTREAM = "127.0.0.1:8195"
SERVICE = "nostrhost-nsite.service"

_LIVE = object()


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
    ) -> None:
        self.state_dir = state_dir or _default_state_dir()
        self.caddy = _live_caddy() if caddy is _LIVE else caddy
        self._systemctl = _systemctl if systemctl is _LIVE else systemctl
        self.config_path = Path(config_path)

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
        """
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(config.to_toml(), encoding="utf-8")
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
