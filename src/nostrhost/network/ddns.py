"""DDNS IP watcher (W4 Phase C).

``DdnsWatchRunner`` implements the DDNS-as-capability path: it polls the
public IPv4/IPv6 address on an interval and, when either changes, reconciles
every registered domain whose provider advertises ``dynamic_ip`` — full-zone
providers (manual/cloudflare/deSEC) through the normal plan/apply reconcile,
dynamic-IP-only providers (DuckDNS/Dynu) through their point-to-point push.
State (last-seen addresses, last update) is persisted so a daemon restart
does not fire a spurious update.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from .public_ip import IpWatcher

logger = logging.getLogger("nostrhost.ddns")


class WatchState:
    """Persisted watcher state (last-seen addresses + last update time)."""

    def __init__(self, *, state_dir: Path, path: Path | None = None) -> None:
        self.state_dir = Path(state_dir)
        self.path = path or self.state_dir / "ddns-watch.json"
        self.data: dict[str, Any] = self._load()

    @property
    def last_ipv4(self) -> str | None:
        return self.data.get("ipv4")

    @property
    def last_ipv6(self) -> str | None:
        return self.data.get("ipv6")

    @property
    def last_update(self) -> str | None:
        return self.data.get("last_update")

    def _load(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def save(self, *, ipv4: str | None, ipv6: str | None, last_update: str | None = None) -> None:
        self.data["ipv4"] = ipv4
        self.data["ipv6"] = ipv6
        if last_update is not None:
            self.data["last_update"] = last_update
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(self.path)


class DdnsWatchRunner:
    """Poll the public IP and reconcile dynamic domains on change."""

    def __init__(
        self,
        *,
        service: Any = None,
        watcher: IpWatcher | None = None,
        interval: float = 300.0,
        state_dir: Path | None = None,
    ) -> None:
        if service is None:
            from ..domains.service import DomainService

            service = DomainService()
        self.service = service
        self.state_dir = Path(state_dir or service.state_dir)
        self.interval = max(interval, 15.0)
        self._state = WatchState(state_dir=self.state_dir)
        self.watcher = watcher or IpWatcher()
        # Seed last-seen so a daemon restart does not fire a spurious update.
        self.watcher._last[4] = self._state.last_ipv4  # noqa: SLF001 - same package
        self.watcher._last[6] = self._state.last_ipv6  # noqa: SLF001 - same package

    def poll_once(self) -> dict[str, Any]:
        """One poll cycle: report an address change and reconcile if any."""
        change = self.watcher.poll()
        changed = change.get("changed", {})
        result: dict[str, Any] = {
            "changed": changed,
            "ipv4": change.get("ipv4"),
            "ipv6": change.get("ipv6"),
        }
        if changed:
            result["updated"] = self.service.dns_update_dynamic().get("updated", [])
            self._state.save(ipv4=change.get("ipv4"), ipv6=change.get("ipv6"), last_update=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        else:
            self._state.save(ipv4=change.get("ipv4"), ipv6=change.get("ipv6"))
        return result

    def run_forever(self) -> None:
        """Run the poll loop until killed."""
        while True:
            try:
                result = self.poll_once()
                if result["changed"]:
                    logger.info("public IP change detected: %s", result["changed"])
                    for item in result.get("updated", []):
                        if not item.get("ok"):
                            logger.error("dns update failed for %s: %s", item.get("domain"), item.get("error"))
            except Exception as exc:  # noqa: BLE001 - the daemon must keep running
                logger.error("ddns watch poll failed: %s", exc)
            time.sleep(self.interval)
