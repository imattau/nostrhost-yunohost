"""Security-event projector (roadmap §18.5 / CROWDSEC-MIGRATION P5).

Consumes CrowdSec alerts/decisions from LAPI (``cscli alerts list -o json``,
polling — no LAPI websocket yet) and emits one kind-2213 ``security`` notice
per *coalesced* source via the existing ``publish_notice`` path. This is the
first real producer for the 2210-2213 notice pipeline and the concrete
replacement of the mail-based security notifications: there is **no dual
mail+nostr path** for security events.

Coalescing: CrowdSec can emit overlapping decisions for one source IP (e.g.
``ssh-bf`` *and* ``ssh-slow-bf``), so the projector groups a poll's new
alerts by source value and merges the scenario reasons — one ban yields
exactly one kind-2213 notice.

Severity mapping (configurable via /etc/nostrhost/security.toml):
  severity_default   - a first ban for a source (default ``warning``, which
                       matches policy.toml's default severity_min)
  severity_recurring - a source that was already seen re-banning after its
                       previous ban expired (default ``critical``)

The projector keeps lightweight bookkeeping in ``/var/lib/nostrhost/
security.json`` (last seen alert id + sources already seen + last emitted
event). ``Backend.security()`` reads this for the semantic-state
``security/intrusion-protection.toml`` record.

Publishing failures are swallowed (matching the notice publisher's posture) —
a CrowdSec blip must never crash the daemon.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from logging import getLogger
from pathlib import Path
from typing import Any, Callable

from .nostr_notify import (
    SEVERITY_CRITICAL,
    SEVERITY_INFO,
    SEVERITY_WARNING,
    publish_notice,
)

KIND_SECURITY_EVENT = 2213

DEFAULT_SECURITY_CONFIG = "/etc/nostrhost/security.toml"
DEFAULT_STATE_FILE = "/var/lib/nostrhost/security.json"

logger = getLogger("yunohost.nostr_security")


class SecurityError(RuntimeError):
    """The security projector could not read CrowdSec state."""


@dataclass
class SecurityConfig:
    severity_default: str = SEVERITY_WARNING
    severity_recurring: str = SEVERITY_CRITICAL
    interval: float = 30.0
    max_alerts: int = 1000

    @classmethod
    def load(cls, path: str | Path | None = None) -> "SecurityConfig":
        import tomllib

        cfg = cls()
        candidate = Path(path or os.environ.get("NOSTRHOST_SECURITY_CONFIG", DEFAULT_SECURITY_CONFIG))
        try:
            data = tomllib.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            logger.debug("security config unavailable (%s); using defaults", exc)
            return cfg
        cfg.severity_default = str(data.get("severity_default", cfg.severity_default))
        cfg.severity_recurring = str(data.get("severity_recurring", cfg.severity_recurring))
        cfg.interval = float(data.get("interval", cfg.interval))
        cfg.max_alerts = int(data.get("max_alerts", cfg.max_alerts))
        return cfg


@dataclass
class SecurityState:
    """Last-alert + known-source bookkeeping (survives daemon restarts)."""

    path: Path
    last_alert_id: int = 0
    sources: set[str] = field(default_factory=set)
    last_event: dict[str, Any] | None = None

    @classmethod
    def load(cls, path: str | Path) -> "SecurityState":
        state = cls(path=Path(path))
        try:
            data = json.loads(state.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return state
        state.last_alert_id = int(data.get("last_alert_id", 0))
        state.sources = set(data.get("sources", []))
        state.last_event = data.get("last_event")
        return state

    def save(self) -> None:
        data = {
            "last_alert_id": self.last_alert_id,
            "sources": sorted(self.sources),
            "last_event": self.last_event,
        }
        temporary = self.path.with_suffix(".tmp")
        temporary.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(self.path)


def _source_value(alert: dict[str, Any]) -> str | None:
    source = alert.get("source") or {}
    return source.get("value") or source.get("ip")


def cscli_alerts(max_alerts: int = 1000) -> list[dict[str, Any]]:
    """Fetch alerts from the local LAPI via cscli (injectable for tests)."""
    import subprocess

    res = subprocess.run(
        ["cscli", "alerts", "list", "-o", "json"],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        raise SecurityError(f"cscli alerts failed: {res.stderr.strip()}")
    try:
        alerts = json.loads(res.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise SecurityError(f"cscli alerts returned invalid json: {exc}") from exc
    return sorted(alerts, key=lambda a: int(a.get("id", 0)))[-max_alerts:]


def coalesce(alerts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Fold a batch of alerts into one entry per source value.

    Each alert is one scenario firing; an IP can appear in several (ssh-bf +
    ssh-slow-bf, or the Caddy 401 scenarios) — fold them into a single entry
    with the merged scenario list + decisions so one ban yields one notice.
    """
    grouped: dict[str, dict[str, Any]] = {}
    for alert in sorted(alerts, key=lambda a: int(a.get("id", 0))):
        source = _source_value(alert)
        if not source:
            continue
        entry = grouped.setdefault(
            source,
            {
                "id": int(alert.get("id", 0)),
                "scenarios": [],
                "decisions": [],
                "created_at": alert.get("created_at"),
            },
        )
        entry["id"] = max(entry["id"], int(alert.get("id", 0)))
        scenario = alert.get("scenario")
        if scenario and scenario not in entry["scenarios"]:
            entry["scenarios"].append(scenario)
        for decision in alert.get("decisions", []):
            if decision not in entry["decisions"]:
                entry["decisions"].append(decision)
    return grouped


def _severity(source: str, seen: set[str], cfg: SecurityConfig) -> str:
    if source in seen:
        return cfg.severity_recurring
    return cfg.severity_default


class SecurityProjector:
    """Poll CrowdSec alerts, coalesce, and publish one 2213 per source."""

    def __init__(
        self,
        *,
        alerts_provider: Callable[[int], list[dict[str, Any]]] | None = None,
        publish: Callable[..., dict[str, Any] | None] | None = None,
        state: SecurityState | None = None,
        cfg: SecurityConfig | None = None,
        server_sk: str | None = None,
        control_relay: str | None = None,
    ) -> None:
        self.alerts_provider = alerts_provider or cscli_alerts
        self.state = state or SecurityState.load(DEFAULT_STATE_FILE)
        self.cfg = cfg or SecurityConfig.load()
        self.server_sk = server_sk
        self.control_relay = control_relay

        if publish is None:
            def _default_publish(*, severity, summary, **kwargs):
                return publish_notice(
                    class_="security",
                    severity=severity,
                    summary=summary,
                    kind=KIND_SECURITY_EVENT,
                    server_sk=self.server_sk,
                    control_relay=self.control_relay,
                    **kwargs,
                )

            self.publish = _default_publish
        else:
            self.publish = publish

    def poll_once(self) -> list[dict[str, Any]]:
        """Fetch new alerts since the last poll, coalesce, publish, persist.

        Returns one dict per published (coalesced) source.
        """
        alerts = self.alerts_provider(self.cfg.max_alerts)
        new = [alert for alert in alerts if int(alert.get("id", 0)) > self.state.last_alert_id]
        if not new:
            return []

        published: list[dict[str, Any]] = []
        for source, group in coalesce(new).items():
            summary = f"intrusion detected from {source}: " + ", ".join(group["scenarios"])
            severity = _severity(source, self.state.sources, self.cfg)
            extra = {
                "source": source,
                "scenario": group["scenarios"],
                "decisions": group["decisions"],
                "alert_id": group["id"],
            }
            event = self.publish(
                severity=severity,
                summary=summary,
                extra=extra,
            )
            published.append({"source": source, "severity": severity, "event": event})
            self.state.sources.add(source)
            self.state.last_event = {
                "alert_id": group["id"],
                "source": source,
                "severity": severity,
                "summary": summary,
                "published": event is not None,
            }

        self.state.last_alert_id = max(
            (int(a.get("id", 0)) for a in new), default=self.state.last_alert_id
        )
        self.state.save()
        return published

    def run(self) -> None:
        """Poll forever (daemon entry point)."""
        while True:
            try:
                self.poll_once()
            except Exception as exc:  # noqa: BLE001 - a poll failure must not kill the daemon
                logger.warning("security projector poll failed: %s", exc)
            time.sleep(self.cfg.interval)


def run() -> int:
    """Daemon entry point (bin/nostr-securityd)."""
    SecurityProjector().run()
    return 0