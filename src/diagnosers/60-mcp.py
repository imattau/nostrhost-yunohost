"""MCP endpoint diagnosis (docs/MCP-SETUP-RUNBOOK.md §9 checkpoints).

Checks the host-local half of the chain an MCP client depends on: the
operation executor, the catalogue sync path, and the control relay that
nostr_notify.py's notice publishing depends on. Deliberately does not check
the MCP HTTP endpoint itself, its reverse-proxy route, DNS or TLS (runbook
§§2-4) — those depend on a hostname nostrhost-mcp has no standard, discoverable
config for yet (it isn't packaged; see docs/MCP-TRANSITION.md Phase 6). Every
check here is best-effort: a check this diagnoser can't evaluate (systemctl
unavailable, config unreadable) is reported as informational or skipped
outright rather than raising, consistent with the rest of the diagnosis
subsystem's degrade-gracefully contract.
"""

import os
import shutil
import subprocess

from ..diagnosis import Diagnoser

try:
    from ..nostr_operations import _control_relay
except ImportError:  # pragma: no cover - nostr_operations always ships alongside this
    _control_relay = None

RELAY_CONFIG = os.environ.get("NOSTRHOST_RELAY_CONFIG", "/etc/nostrhost/relay.toml")
CATALOG_DECLARATION_KIND = 32267


def _systemd_active(unit: str) -> str | None:
    """systemctl's own state word ('active', 'inactive', 'failed', ...), or
    None when systemctl itself can't be consulted."""
    if not shutil.which("systemctl"):
        return None
    try:
        result = subprocess.run(
            ["systemctl", "is-active", unit], capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() or None


def _unit_installed(unit: str) -> bool | None:
    """Whether a systemd unit file exists for ``unit``, or None when that
    can't be determined (systemctl unavailable)."""
    if not shutil.which("systemctl"):
        return None
    try:
        result = subprocess.run(
            ["systemctl", "list-unit-files", unit], capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return unit in result.stdout


def _relay_allowed_kinds(path: str) -> list | None:
    """The control relay's ``allowed_kinds``, or None when the config can't
    be read/parsed (relay not on this host, or a non-default layout)."""
    try:
        import tomllib

        with open(path, "rb") as fh:
            config = tomllib.load(fh)
    except (OSError, ValueError):
        return None
    allowed = config.get("allowed_kinds")
    return allowed if isinstance(allowed, list) else None


def _relay_reachable(relay_url: str, timeout: float = 5.0) -> str | None:
    """Open (and immediately close) a plain WebSocket connection to the
    control relay. Returns None on success, or a short error string.

    Deliberately doesn't publish anything: nostr_notify.publish_notice()
    itself swallows connection failures so the underlying certificate/
    diagnosis operation is never blocked by a bad relay (see its own
    docstring) — which means every one of its callers is currently blind to
    "the relay has been unreachable for a week" until they read logs. This
    is the read-only half of that check, surfaced where an admin already
    looks for host-health problems.
    """
    try:
        from websockets.sync.client import connect
    except ImportError as exc:
        return f"websockets library unavailable: {exc}"
    try:
        with connect(relay_url, open_timeout=timeout):
            return None
    except Exception as exc:  # noqa: BLE001 - report every failure mode the same way
        return str(exc)


class MyDiagnoser(Diagnoser):
    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 300
    dependencies: list[str] = []

    def run(self):
        yield from self._check_operationsd()
        yield from self._check_catalog()
        yield from self._check_notify()

    def _check_operationsd(self):
        """nostr-operationsd is a core component (always installed): its
        absence or non-running state blocks every MCP write operation from
        ever progressing past 'approval_required' (runbook Issue 9)."""
        unit = "nostr-operationsd"
        state = _systemd_active(unit)
        if state == "active":
            yield dict(meta={"service": unit}, status="SUCCESS", summary="diagnosis_mcp_operationsd_up")
        elif state is None:
            yield dict(meta={"service": unit}, status="WARNING", summary="diagnosis_mcp_service_unknown")
        else:
            yield dict(
                meta={"service": unit},
                status="ERROR",
                summary="diagnosis_mcp_operationsd_down",
                details=["diagnosis_mcp_operationsd_down_details"],
            )

    def _check_catalog(self):
        """nostrhost-catalog is optional (not every node publishes packages),
        so a missing unit is informational, not an error (runbook Issue 8)."""
        unit = "nostrhost-catalog"
        installed = _unit_installed(unit)
        if installed is False:
            yield dict(meta={"service": unit}, status="INFO", summary="diagnosis_mcp_catalog_not_installed")
        else:
            state = _systemd_active(unit)
            if state == "active":
                yield dict(meta={"service": unit}, status="SUCCESS", summary="diagnosis_mcp_catalog_up")
            elif state is None:
                yield dict(meta={"service": unit}, status="WARNING", summary="diagnosis_mcp_service_unknown")
            else:
                yield dict(
                    meta={"service": unit},
                    status="ERROR",
                    summary="diagnosis_mcp_catalog_down",
                    details=["diagnosis_mcp_catalog_down_details"],
                )

        allowed_kinds = _relay_allowed_kinds(RELAY_CONFIG)
        if allowed_kinds is None:
            return  # relay config unreadable from here — nothing to report
        if CATALOG_DECLARATION_KIND in allowed_kinds:
            yield dict(status="SUCCESS", summary="diagnosis_mcp_catalog_kind_allowed")
        else:
            yield dict(
                status="WARNING",
                summary="diagnosis_mcp_catalog_kind_not_allowed",
                details=["diagnosis_mcp_catalog_kind_not_allowed_details"],
            )

    def _check_notify(self):
        """Whether nostr_notify.publish_notice()'s target relay is reachable
        at all - a relay that's been down for a week silently means no
        automatic-diagnosis notice, certificate-renewal warning, etc. has
        actually reached anyone, since publish_notice() only logs and moves
        on (see its own docstring). WARNING, not ERROR: an unreachable relay
        degrades notification delivery, it doesn't break diagnosis itself."""
        if _control_relay is None:
            return  # nostr_operations not importable here - nothing to check

        relay_url = _control_relay(None)
        error = _relay_reachable(relay_url)
        if error is None:
            yield dict(meta={"relay": relay_url}, status="SUCCESS", summary="diagnosis_mcp_notify_relay_reachable")
        else:
            yield dict(
                meta={"relay": relay_url},
                status="WARNING",
                summary="diagnosis_mcp_notify_relay_unreachable",
                details=["diagnosis_mcp_notify_relay_unreachable_details"],
                data={"error": error},
            )
