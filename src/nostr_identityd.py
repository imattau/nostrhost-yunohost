"""Identity projector (nostr-identityd) — roadmap §4 / Phase 3.

Consumes identity-definition events (kind 31102) from the local control
relay, materialises the pubkey ↔ account mapping in the projection store
(nostrhost-auth MappingStore), and ensures the LDAP compatibility account
exists (auto-creating it via the fork's user machinery when an identity
event names a username that doesn't exist yet).

Author semantics (Phase 3, admin-only): only events signed by a configured
admin are accepted. The relay enforces transport (kind allowlist); this
projector enforces identity semantics.

The subscription is a live NIP-01 REQ over a raw async WebSocket; on connect
the relay replays all stored matching events, so the projection is eventually
consistent across restarts. Relay I/O needs no nostr-sdk signer.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .nostr_identity import (
    DEFAULT_IDENTITY_DB,
    IDENTITY_KIND,
    _init_headless_yunohost,
    _operator_config,
    _require_bootstrapped,
    _store,
)

logger = logging.getLogger("nostr-identityd")


class AccountBackend:
    """Duck-typed account materialisation backend.

    Production is :class:`YnhAccountBackend` (real YunoHost user creation);
    tests inject a fake with the same surface.
    """

    def user_exists(self, username: str) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    def ensure_user(self, username: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class YnhAccountBackend(AccountBackend):
    """Real YunoHost account backend: create via user_create (main domain),
    with a generated strong password that is never used for login (password
    recovery stays via admin reset)."""

    def user_exists(self, username: str) -> bool:
        from yunohost.user import user_list

        return username in user_list()["users"]

    def ensure_user(self, username: str) -> None:
        import secrets as _secrets

        from yunohost.domain import _get_maindomain
        from yunohost.user import user_create

        password = _secrets.token_urlsafe(24) + "Aa1!"
        user_create(
            username=username,
            domain=_get_maindomain(),
            password=password,
            fullname=username,
            admin=False,
        )


def handle_identity_event(
    event: dict[str, Any],
    *,
    store: Any,
    admin_pubkeys: tuple[str, ...] | list[str],
    accounts: AccountBackend | None = None,
) -> bool:
    """Materialise one identity event into the projection store (+ LDAP).

    Returns True when the event was an accepted identity definition.
    """
    if event.get("kind") != IDENTITY_KIND:
        return False

    author = event.get("pubkey")
    if author not in admin_pubkeys:
        logger.warning("identity event authored by non-admin %s ignored", author)
        return False

    d_tag = _d_tag(event)
    if not d_tag:
        logger.warning("identity event without a subject 'd' tag ignored")
        return False

    try:
        body = json.loads(event.get("content") or "{}")
    except json.JSONDecodeError:
        logger.warning("identity event with invalid content ignored")
        return False

    username = str(body.get("username") or "").strip()
    enabled = bool(body.get("enabled", True))
    signer_type = str(body.get("signer_type") or "unknown")
    label = body.get("label")
    if enabled and not username:
        logger.warning("identity event with empty username ignored")
        return False

    existing = store.get_identity_by_pubkey(d_tag)
    if enabled:
        if accounts is not None and existing is None:
            if not accounts.user_exists(username):
                accounts.ensure_user(username)
                logger.info("created compatibility account %s", username)
        if existing is not None:
            store.set_identity_enabled(existing.identity_id, existing.ynh_username, True)
            logger.info("re-enabled identity %s for %s", d_tag[:16], existing.ynh_username)
        else:
            store.add_identity(username, d_tag, signer_type=signer_type, label=label, linked_by="admin")
            logger.info("linked identity %s -> %s", d_tag[:16], username)
    else:
        if existing is not None:
            store.revoke_identity(existing.identity_id, existing.ynh_username)
            logger.info("revoked identity %s -> %s", d_tag[:16], existing.ynh_username)
    return True


def _d_tag(event: dict[str, Any]) -> str | None:
    for tag in event.get("tags") or []:
        if tag and tag[0] == "d" and len(tag) > 1:
            return tag[1]
    return None


async def subscribe_loop(
    relay_url: str,
    *,
    store: Any,
    admin_pubkeys: tuple[str, ...] | list[str],
    accounts: AccountBackend | None = None,
    on_event: Callable[[dict[str, Any]], None] | None = None,
    stop: asyncio.Event | None = None,
) -> None:
    """Subscribe to identity kinds and materialise until stopped. Reconnects
    on error after a short backoff."""
    import websockets

    filter: dict[str, Any] = {"kinds": [IDENTITY_KIND, 0]}
    while not (stop is not None and stop.is_set()):
        try:
            async with websockets.connect(relay_url) as ws:
                sub_id = "nostrhost-identity-" + secrets.token_hex(4)
                await ws.send(json.dumps(["REQ", sub_id, filter]))
                logger.info("identity projector subscribed to %s", relay_url)
                replay: list[dict[str, Any]] = []
                replaying = True
                async for raw in ws:
                    msg = json.loads(raw)
                    if msg[0] == "EVENT":
                        if replaying:
                            replay.append(msg[2])
                        else:
                            handled = handle_identity_event(
                                msg[2], store=store, admin_pubkeys=admin_pubkeys, accounts=accounts
                            )
                            if on_event is not None and handled:
                                on_event(msg[2])
                    elif msg[0] == "EOSE":
                        for ev in sorted(
                            replay,
                            key=lambda e: (int(e.get("created_at") or 0), str(e.get("id") or "")),
                        ):
                            handled = handle_identity_event(
                                ev, store=store, admin_pubkeys=admin_pubkeys, accounts=accounts
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
    """Entry point for bin/nostr-identityd."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    _init_headless_yunohost()
    _require_bootstrapped()
    cfg = _operator_config()
    store = _store()
    accounts: AccountBackend = YnhAccountBackend()
    try:
        asyncio.run(
            subscribe_loop(
                cfg.control_relay,
                store=store,
                admin_pubkeys=cfg.admins,
                accounts=accounts,
            )
        )
    except KeyboardInterrupt:
        pass