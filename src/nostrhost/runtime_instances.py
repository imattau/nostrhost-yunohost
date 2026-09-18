"""Control-plane helpers for ``multi-tenant-runtime`` packages.

``package_engine.plan_package()`` only ever emits *template-level* operations
(``runtime_instance.template.ensure`` / ``.socket.enable`` / ``.reaper.ensure``)
for a `[runtime_instance]` resource - install time never enumerates the app's
current members, since membership changes after install (a member can be
granted the app's permission long after the app was installed).

Most packaged apps (opencode included) can only bind a TCP port, not a Unix
socket, so ``<app>@.socket`` doesn't activate the backend service directly -
its ``Service=`` override (see ``RuntimeInstanceTemplateProvider.render_socket``)
points at a paired ``<app>-bridge@.service`` running ``systemd-socket-proxyd``,
which forwards into the backend's own ``PrivateNetwork=yes`` namespace. The
bridge unit declares ``BindsTo=``/``After=`` on the backend, so systemd's own
dependency resolution starts the backend whenever the socket lazily activates
the bridge, and stopping the bridge cascade-stops the backend - no hand-rolled
"is the instance running yet" bookkeeping needed for the start path (this
resolves what the design plan called Open Question 1).

This module holds the control-plane logic that instead runs outside the
install/removal plan, against one already-installed multi-tenant-runtime app,
keyed by a concrete username:

- ``ensure_instance_running`` - a defensive belt-and-braces hook a caller can
  use to explicitly start the backend instance ahead of a connection;
  ``systemctl start`` on an already-running unit is a harmless no-op, so this
  is safe but not required given the ``BindsTo=`` wiring above.
- ``count_socket_connections`` - an app-agnostic "is anyone connected right
  now" signal for one instance's Unix socket, read from ``/proc/net/unix``
  (no cooperation needed from the packaged app). The reaper uses this to
  decide whether an idle instance is safe to stop - stopping the *bridge*
  unit (not the backend directly), since ``BindsTo=`` cascades the stop.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any, Callable

_SAFE_APP = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.@:-]*")
_SAFE_USER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*")


class RuntimeInstanceError(RuntimeError):
    """A runtime-instance control-plane operation could not be performed."""


def _safe(value: str, pattern: re.Pattern[str], *, what: str) -> str:
    if not pattern.fullmatch(value):
        raise RuntimeInstanceError(f"unsafe {what}: {value!r}")
    return value


def instance_unit_name(app: str, username: str) -> str:
    """Return the concrete ``<app>@<user>.service`` unit name for one member."""
    app = _safe(app, _SAFE_APP, what="app id")
    username = _safe(username, _SAFE_USER, what="username")
    return f"{app}@{username}.service"


def bridge_unit_name(app: str, username: str) -> str:
    """Return the concrete ``<app>-bridge@<user>.service`` unit name.

    This is the unit the reaper should stop: it ``BindsTo=`` the backend
    instance, so stopping it cascade-stops the backend atomically.
    """
    app = _safe(app, _SAFE_APP, what="app id")
    username = _safe(username, _SAFE_USER, what="username")
    return f"{app}-bridge@{username}.service"


def ensure_instance_running(
    app: str,
    username: str,
    *,
    command: Callable[..., Any] | None = None,
) -> str:
    """Explicitly start one member's concrete runtime instance.

    Belt-and-braces companion to socket activation (see Open Question 1):
    ``systemctl start`` on an already-running instance is a harmless no-op, so
    this is safe to call unconditionally before proxying to a socket that may
    not have been activated yet.
    """
    unit = instance_unit_name(app, username)
    runner = command or subprocess.run
    runner(["systemctl", "start", unit], check=True)
    return unit


def count_socket_connections(socket_path: str | Path, *, proc_net_unix: Path = Path("/proc/net/unix")) -> int:
    """Count open connections to ``socket_path`` via ``/proc/net/unix``.

    App-agnostic: works for any Unix-domain socket without cooperation from
    the packaged app. Returns 0 (not an error) when the socket has no
    connections or the proc file cannot be read yet (e.g. instance not
    started), so the reaper's "idle" decision degrades safely rather than
    raising during normal reap cycles.
    """
    target = str(Path(socket_path))
    try:
        lines = proc_net_unix.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return 0
    count = 0
    for line in lines[1:]:  # first line is the column header
        fields = line.split()
        if not fields:
            continue
        path = fields[-1] if len(fields) > 7 else None
        if path == target:
            count += 1
    return count


def instance_idle(
    socket_path: str | Path,
    *,
    proc_net_unix: Path = Path("/proc/net/unix"),
) -> bool:
    """True when a runtime instance's socket currently has no connections."""
    return count_socket_connections(socket_path, proc_net_unix=proc_net_unix) == 0


_UNIT_SUFFIX = re.compile(r"@([^@]+)\.service$")


def running_instance_usernames(
    app: str,
    *,
    command: Callable[..., Any] | None = None,
) -> list[str]:
    """List usernames with a currently-running ``<app>@<user>.service``."""
    app = _safe(app, _SAFE_APP, what="app id")
    runner = command or subprocess.run
    result = runner(
        ["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain", f"{app}@*.service"],
        check=True, capture_output=True, text=True,
    )
    usernames: list[str] = []
    for line in (getattr(result, "stdout", "") or "").splitlines():
        unit = line.split()[0] if line.split() else ""
        match = _UNIT_SUFFIX.search(unit)
        if match:
            usernames.append(match.group(1))
    return usernames


def reap_idle_instances(
    app: str,
    socket_path_template: str,
    *,
    command: Callable[..., Any] | None = None,
    proc_net_unix: Path = Path("/proc/net/unix"),
) -> list[str]:
    """Stop every running instance of ``app`` whose socket is idle right now.

    Called once per reaper timer tick (the tick interval is the effective
    idle-timeout window - see ``RuntimeInstanceReaperProvider``). The socket
    unit stays enabled throughout, so the very next connection re-activates
    the bridge (and, via ``BindsTo=``, the backend) - this is the "spawn on
    demand, reap when idle" loop. Returns the usernames whose instance was
    stopped.
    """
    app = _safe(app, _SAFE_APP, what="app id")
    runner = command or subprocess.run
    stopped: list[str] = []
    for username in running_instance_usernames(app, command=runner):
        socket_path = socket_path_template.replace("%i", username)
        if instance_idle(socket_path, proc_net_unix=proc_net_unix):
            # Stop the bridge, not the backend directly: BindsTo= on the
            # bridge cascades the stop to the backend atomically.
            unit = bridge_unit_name(app, username)
            runner(["systemctl", "stop", unit], check=True)
            stopped.append(username)
    return stopped
