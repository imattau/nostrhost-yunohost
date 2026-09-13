"""Public IP discovery (W4).

Thin, injectable wrapper over the fork's ``get_public_ip`` probe so DNS
reconciliation, diagnostics and fleet tooling all read the same fact
without each doing its own WAN detection.
"""

from __future__ import annotations

from typing import Any


def probe(protocol: int = 4) -> str | None:
    """Current public address for ``protocol`` (4 or 6), or None."""
    try:
        from yunohost.utils.network import get_public_ip

        return get_public_ip(protocol)  # type: ignore[arg-type]
    except Exception:  # noqa: BLE001 - probing is best-effort
        return None


def snapshot() -> dict[str, Any]:
    return {"ipv4": probe(4), "ipv6": probe(6)}


class IpWatcher:
    """Remembers the last seen public addresses and reports changes.

    Used by the DDNS-as-capability path: on change, the caller reconciles
    the affected domains' A/AAAA records through their provider.
    """

    def __init__(self, *, probe_factory=probe) -> None:
        self._probe = probe_factory
        self._last: dict[int, str | None] = {}

    def poll(self) -> dict[str, Any]:
        changed: dict[str, Any] = {}
        for protocol in (4, 6):
            current = self._probe(protocol)
            previous = self._last.get(protocol)
            if current != previous:
                changed[str(protocol)] = {"from": previous, "to": current}
                self._last[protocol] = current
        return {"changed": changed, "ipv4": self._last.get(4), "ipv6": self._last.get(6)}
