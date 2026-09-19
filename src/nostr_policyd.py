"""Policy declaration projector daemon (nostr-policyd) — WP6.

Subscribes to kind-31101 declarations (notification rules, desired Restic
policy, host operation safeguards) and folds them into the
``PolicyStore`` + the compatibility files the existing services read
(notify recipients/policy TOML, restic.toml desired fields, policy.toml).
Runs on the shared :class:`~nostr_projector.ProjectionRuntime`; rebuild/
verify/shadow are wired through ``bin/nostr-projector``.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from pathlib import Path
from typing import Any, Callable

from .nostrhost.policy_projection import POLICY_KINDS, PolicyProjector, PolicyStore, render_entry
from .nostr_projector import (
    DEFAULT_CURSOR_DIR,
    ProjectionRuntime,
    REGISTRY,
)
from .nostr_identity import (
    _configure_daemon_logging,
    _init_headless_yunohost,
    _operator_config,
    _require_bootstrapped,
)

logger = logging.getLogger("nostr-policyd")


def _default_render(entry: Any) -> None:
    """Render a changed coordinate into its compatibility file(s)."""
    render_entry(entry)


async def subscribe_loop(
    relay_url: str,
    *,
    store: PolicyStore,
    admin_pubkeys: tuple[str, ...] | list[str],
    on_change: Callable[[Any], None] | None = None,
    stop: asyncio.Event | None = None,
    cursor_dir: str | Path = DEFAULT_CURSOR_DIR,
) -> None:
    projector = PolicyProjector(
        store=store,
        admin_pubkeys=admin_pubkeys,
        on_change=on_change or _default_render,
        cursor_dir=cursor_dir,
    )
    REGISTRY.register(projector)
    runtime = ProjectionRuntime(
        relay_url,
        projector=projector,
        kinds=list(POLICY_KINDS),
        limit=2000,
        stop=stop,
    )
    await runtime.run()


def rebuild(relay_url: str, *, admin_pubkeys: tuple[str, ...] | list[str]) -> dict[str, Any]:
    """Rebuild the policy projection from the relay (WP6)."""
    from .nostr_projector import rebuild as _rebuild
    from .nostrhost.events import query_chain_events

    events: list[dict[str, Any]] = []
    for kind in POLICY_KINDS:
        events.extend(query_chain_events(relay_url, kinds=(kind,), limit=500, page_all=True))
    projector = PolicyProjector(admin_pubkeys=admin_pubkeys)
    report = _rebuild(events, projector=projector)
    report["projection"] = projector._digest()
    return report


def run() -> None:
    """Entry point for bin/nostr-policyd."""
    _configure_daemon_logging()
    _init_headless_yunohost()
    _require_bootstrapped()
    cfg = _operator_config()
    store = PolicyStore()
    stop = threading.Event()
    logger.info("policy projector subscribing to %s", cfg.control_relay)
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
