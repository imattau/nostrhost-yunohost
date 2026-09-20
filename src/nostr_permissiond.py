"""Permission-list projector (nostr-permissiond) — roadmap §25 Phase 2.

Subscribes to NIP-51 permission-list events (kind 30000, see
``nostrhost.nip51_permissions``) on the local control relay, materialises
membership into the projector's own store, and regenerates the
world-readable permission projection the Caddy authd reads
(``nostrhost.permissions.write_permissions_projection``).

Since WP2 the subscription runs through the shared
:class:`~nostr_projector.ProjectionRuntime` (NIP-42 AUTH, deterministic
replay, reconnect backoff, quarantine, durable checkpointing); the pure
``handle_permission_event`` remains the unit-testable core and the
:class:`PermissionProjector` adds rebuild/verify/health.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from pathlib import Path
from typing import Any, Callable

from nostrhost.events import _d_tag
from nostrhost.nip51_permissions import PERMISSION_LIST_KIND, PermissionStore
from nostrhost.permissions import write_permissions_projection
from nostrhost_projection import (
    DEFAULT_CURSOR_DIR,
    Projector,
    ProjectionResult,
    ProjectionRuntime,
    REGISTRY,
)
from .nostr_identity import (
    _configure_daemon_logging,
    _init_headless_yunohost,
    _operator_config,
    _require_bootstrapped,
    default_auth,
)

logger = logging.getLogger("nostr-permissiond")

PROJECTION_NAME = "permissions"


class PermissionProjector(Projector):
    """Projector contract around the NIP-51 permission store."""

    name = PROJECTION_NAME
    schema = 1

    def __init__(
        self,
        *,
        store: PermissionStore | None = None,
        admin_pubkeys: tuple[str, ...] | list[str] = (),
        on_change: Callable[[], None] | None = None,
        cursor_dir: str = DEFAULT_CURSOR_DIR,
    ) -> None:
        super().__init__(cursor_dir=cursor_dir)
        self.store = store or PermissionStore()
        self.admin_pubkeys = tuple(admin_pubkeys)
        self._on_change = on_change or write_permissions_projection

    def validate(self, event: dict[str, Any]) -> Any:
        """Return the accepted permission name, or None to reject."""
        if event.get("kind") != PERMISSION_LIST_KIND:
            return None
        if event.get("pubkey") not in self.admin_pubkeys:
            self.quarantine(event, "permission-list authored by non-admin")
            return None
        permission = _d_tag(event)
        if not permission:
            self.quarantine(event, "permission-list without a 'd' tag")
            return None
        return permission

    def apply(self, event: dict[str, Any]) -> ProjectionResult:
        permission = self.validate(event)
        if permission is None:
            return ProjectionResult(accepted=False, reason="invalid")
        applied = self.store.apply_event(event, admin_pubkeys=self.admin_pubkeys)
        if applied:
            self._regenerate()
        # A stale event is accepted-but-ignored: still advance the checkpoint
        # so a replay does not re-process it, but do not rewrite the projection.
        self._advance(event)
        return ProjectionResult(accepted=True, changed=applied)

    def _regenerate(self) -> None:
        try:
            self._on_change()
        except Exception as exc:  # noqa: BLE001 - keep the projector alive
            self.health_state.last_error = f"projection regenerate failed: {exc}"
            logger.error("failed to regenerate permission projection: %s", exc)

    def _serialized(self) -> str:
        import json

        return json.dumps(
            {
                name: {
                    "pubkeys": list(grant.pubkeys),
                    "public": grant.public,
                    "created_at": grant.created_at,
                }
                for name, grant in sorted(self.store.all_grants().items())
            },
            sort_keys=True,
        )

    def clone(self) -> "PermissionProjector":
        """A fresh projector over an empty temp store, for :func:`verify`."""
        import tempfile

        tmp = tempfile.NamedTemporaryFile(prefix="permissions-verify-", suffix=".json", delete=False)
        tmp.close()
        return PermissionProjector(
            store=PermissionStore(Path(tmp.name)),
            admin_pubkeys=self.admin_pubkeys,
            on_change=lambda: None,
            cursor_dir=str(self.cursor_dir),
        )

    def current(self) -> str:
        """Current rendered projection (for :func:`verify`)."""
        return self._serialized()

    def render(self, state: Any) -> str | None:
        return self._serialized()

    def commit(self, candidate: str) -> None:  # pragma: no cover - store owns the write
        self._regenerate()


def handle_permission_event(
    event: dict[str, Any],
    *,
    store: PermissionStore,
    admin_pubkeys: tuple[str, ...] | list[str],
) -> bool:
    """Apply one permission-list event and regenerate the projection file
    when it changed something. Returns True when the event was an accepted
    permission-list definition (matching ``handle_identity_event``'s
    return contract)."""
    applied = store.apply_event(event, admin_pubkeys=admin_pubkeys)
    if applied:
        try:
            write_permissions_projection()
        except Exception as exc:  # noqa: BLE001 - keep the projector alive
            logger.error("failed to regenerate permission projection: %s", exc)
    return applied


async def subscribe_loop(
    relay_url: str,
    *,
    store: PermissionStore,
    admin_pubkeys: tuple[str, ...] | list[str],
    on_event: Callable[[dict[str, Any]], None] | None = None,
    stop: asyncio.Event | None = None,
    cursor_dir: str = DEFAULT_CURSOR_DIR,
) -> None:
    """Subscribe to permission-list events and project until stopped.

    Delegates to the shared :class:`ProjectionRuntime` (WP2). ``on_event`` is
    invoked for each accepted event, preserving the previous daemon contract.
    """
    projector = PermissionProjector(
        store=store, admin_pubkeys=admin_pubkeys, cursor_dir=cursor_dir
    )
    REGISTRY.register(projector)
    def _notify(events: list[dict[str, Any]]) -> None:
        if on_event is not None:
            for event in events:
                on_event(event)

    runtime = ProjectionRuntime(
        relay_url,
        projector=projector,
        kinds=[PERMISSION_LIST_KIND],
        on_replay=_notify if on_event else None,
        stop=stop,
        auth_factory=default_auth,
    )
    await runtime.run()


def rebuild(relay_url: str, *, admin_pubkeys: tuple[str, ...] | list[str], store: PermissionStore | None = None) -> dict[str, Any]:
    """Rebuild the permission projection from the relay (WP2 ``--rebuild``)."""
    from nostrhost.events import query_chain_events

    store = store or PermissionStore()
    projector = PermissionProjector(store=store, admin_pubkeys=admin_pubkeys)
    events = query_chain_events(relay_url, kinds=(PERMISSION_LIST_KIND,), limit=500)
    report = rebuild_events_into(projector, events)
    return report


def rebuild_events_into(projector: Projector, events: list[dict[str, Any]]) -> dict[str, Any]:
    from nostrhost_projection import rebuild as _rebuild

    return _rebuild(events, projector=projector)


def run() -> None:
    """Entry point for bin/nostr-permissiond."""
    _configure_daemon_logging()
    _init_headless_yunohost()
    _require_bootstrapped()
    cfg = _operator_config()
    store = PermissionStore()
    stop = threading.Event()
    try:
        asyncio.run(
            subscribe_loop(
                cfg.control_relay,
                store=store,
                admin_pubkeys=cfg.admins,
            )
        )
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
