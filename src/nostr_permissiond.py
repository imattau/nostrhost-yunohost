"""Permission-list projector (nostr-permissiond) — roadmap §25 Phase 2.

Subscribes to NIP-51 permission-list events (kind 30000, see
``nostrhost.nip51_permissions``) on the local control relay, materialises
membership into the projector's own store, and regenerates the
world-readable permission projection the Caddy authd reads
(``nostrhost.permissions.write_permissions_projection``).

Structured the same way as ``nostr_identityd``: a pure, unit-testable
``handle_permission_event`` plus a thin async relay-subscription loop that
calls it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import threading
from typing import Any, Callable

from nostrhost.nip51_permissions import PERMISSION_LIST_KIND, PermissionStore
from nostrhost.permissions import write_permissions_projection
from .nostr_identity import (
    _init_headless_yunohost,
    _operator_config,
    _require_bootstrapped,
    _sign_auth_event,
    _wait_auth_ok_async,
    default_auth,
)

logger = logging.getLogger("nostr-permissiond")


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
) -> None:
    """Subscribe to permission-list events and project until stopped.

    Same replay/AUTH/backoff handling as ``nostr_identityd.subscribe_loop``.
    """
    import websockets

    filter: dict[str, Any] = {"kinds": [PERMISSION_LIST_KIND]}
    while not (stop is not None and stop.is_set()):
        try:
            async with websockets.connect(relay_url) as ws:
                sub_id = "nostrhost-permission-" + secrets.token_hex(4)
                await ws.send(json.dumps(["REQ", sub_id, filter]))
                logger.info("permission projector subscribed to %s", relay_url)
                replay: list[dict[str, Any]] = []
                replaying = True
                async for raw in ws:
                    msg = json.loads(raw)
                    if msg[0] == "AUTH":
                        challenge = msg[1] if len(msg) > 1 else ""
                        auth = default_auth()
                        if auth is not None:
                            auth_ev = _sign_auth_event(auth[0], auth[1], relay_url, challenge, sub_id)
                            await ws.send(json.dumps(["AUTH", auth_ev]))
                            await _wait_auth_ok_async(ws, auth_ev["id"])
                            replay = []
                            replaying = True
                            await ws.send(json.dumps(["REQ", sub_id, filter]))
                        continue
                    if msg[0] == "EVENT":
                        if replaying:
                            replay.append(msg[2])
                        else:
                            handled = handle_permission_event(
                                msg[2], store=store, admin_pubkeys=admin_pubkeys
                            )
                            if on_event is not None and handled:
                                on_event(msg[2])
                    elif msg[0] == "EOSE":
                        for ev in sorted(
                            replay,
                            key=lambda e: (int(e.get("created_at") or 0), str(e.get("id") or "")),
                        ):
                            handled = handle_permission_event(
                                ev, store=store, admin_pubkeys=admin_pubkeys
                            )
                            if on_event is not None and handled:
                                on_event(ev)
                        replay.clear()
                        replaying = False
                    elif msg[0] == "CLOSED":
                        logger.warning("relay closed subscription: %s", msg[2] if len(msg) > 2 else "")
                        break
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - keep the projector alive
            logger.error("subscription error: %s; retrying in 5s", exc)
            await asyncio.sleep(5)


def run() -> None:
    """Entry point for bin/nostr-permissiond."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
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
