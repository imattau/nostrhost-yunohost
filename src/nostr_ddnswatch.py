"""nostr-ddnswatchd — DDNS IP watcher daemon (W4 Phase C).

Polls the public IPv4/IPv6 address on an interval and, when either changes,
reconciles every registered domain whose DNS provider advertises the
``dynamic_ip`` capability (manual/cloudflare/deSEC via plan/apply, DuckDNS/
Dynu via point-to-point push). Run as root. Config via
``/etc/nostrhost/ddns.toml`` (``[watch] interval``) or
``NOSTRHOST_DDNS_INTERVAL`` / ``NOSTRHOST_DDNS_CONFIG`` env vars.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

DEFAULT_INTERVAL = 300.0
DEFAULT_CONFIG = Path("/etc/nostrhost/ddns.toml")

logger = logging.getLogger("nostr-ddnswatchd")


def _load_config() -> float:
    interval = DEFAULT_INTERVAL
    config = Path(os.environ.get("NOSTRHOST_DDNS_CONFIG", str(DEFAULT_CONFIG)))
    if config.is_file():
        try:
            import tomllib

            with config.open("rb") as fh:
                data = tomllib.load(fh)
            interval = float(data.get("watch", {}).get("interval", DEFAULT_INTERVAL))
        except Exception as exc:  # noqa: BLE001 - a broken config falls back to defaults
            logger.warning("cannot read %s: %s (using defaults)", config, exc)
    return float(os.environ.get("NOSTRHOST_DDNS_INTERVAL", interval))


def run() -> int:
    from yunohost.nostrhost.network.ddns import DdnsWatchRunner

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    interval = _load_config()
    logger.info("nostr-ddnswatchd starting (interval %ss)", interval)
    DdnsWatchRunner(interval=interval).run_forever()
    return 0  # pragma: no cover - unreachable


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run())
