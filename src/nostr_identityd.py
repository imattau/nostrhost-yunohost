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
import os
import secrets
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .nostr_identity import (
    DEFAULT_IDENTITY_DB,
    IDENTITY_KIND,
    _init_headless_yunohost,
    _operator_config,
    _require_bootstrapped,
    _sign_auth_event,
    _store,
    _wait_auth_ok_async,
    default_auth,
)
from nostrhost_auth.identity.mappings import PubkeyAlreadyLinked

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
            store.update_identity_profile(
                existing.identity_id,
                existing.ynh_username,
                signer_type=signer_type,
                label=label,
            )
            logger.info(
                "re-enabled identity %s for %s (signer=%s label=%r)",
                d_tag[:16],
                existing.ynh_username,
                signer_type,
                label,
            )
        else:
            try:
                store.add_identity(username, d_tag, signer_type=signer_type, label=label, linked_by="admin")
            except PubkeyAlreadyLinked:
                logger.warning("identity %s already linked to a different account; ignored", d_tag[:16])
                return True
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


# --------------------------------------------------------------------------- #
# local control socket (privilege-separated self-service identity management)
#
# The portal-api service runs as the low-privilege ``ynh-portal`` user and must
# not hold the root-only operator keys, but a user linking/revoking their own
# Nostr identity needs the operator to author the kind-31102 definition event.
# This UNIX socket (root:ynh-portal, 0660) is the boundary: the portal-api
# does the user-visible verification (session + challenge signature) and this
# daemon does the operator-signed publication, after re-validating that the
# request is well-formed and that a revoke/rename targets the caller's own
# identity. SO_PEERCRED restricts who may connect.

CONTROL_SOCKET_DEFAULT = "/run/nostrhost/identity.sock"


def _portal_uid() -> int | None:
    """The ynh-portal uid, or None when the user does not exist yet."""
    try:
        import pwd

        return pwd.getpwnam("ynh-portal").pw_uid
    except (KeyError, ImportError):  # pragma: no cover - user is package-owned
        return None


def _portal_gid() -> int | None:
    """The ynh-portal gid, or None when the user does not exist yet."""
    try:
        import pwd

        return pwd.getpwnam("ynh-portal").pw_gid
    except (KeyError, ImportError):  # pragma: no cover - user is package-owned
        return None


def _peer_uid(conn: Any) -> int | None:
    """Best-effort SO_PEERCRED uid of the connecting peer (Linux)."""
    import socket as _socket
    import struct

    try:
        # SO_PEERCRED is a 12-byte struct {pid, uid, gid}; passing the length
        # is required, otherwise getsockopt returns only the first field.
        creds = conn.getsockopt(_socket.SOL_SOCKET, _socket.SO_PEERCRED, 12)
        if isinstance(creds, bytes):
            return struct.unpack("3i", creds)[1]
        return creds.uid  # type: ignore[attr-defined]
    except Exception:  # pragma: no cover - non-Linux or sandboxed socket
        return None


def handle_control_request(
    request: dict[str, Any],
    *,
    store: Any,
    operator_sk: str,
    control_relay: str,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Validate + author one identity-management request.

    Returns a JSON-serialisable ``{"ok": bool, ...}`` dict. The operator
    signing is delegated to ``link_identity``/``revoke_identity``; the
    projector materialises the resulting kind-31102 events as usual.
    """
    from .nostr_identity import (
        VALID_SIGNER_TYPES,
        _parse_pubkey,
        link_identity,
        revoke_identity,
    )

    try:
        action = request.get("action")
        username = str(request.get("username") or "").strip()
        if not username:
            return {"ok": False, "error": "username is required"}

        if action == "link":
            try:
                pubkey = _parse_pubkey(request.get("pubkey"))
            except Exception:
                return {"ok": False, "error": "pubkey is not a valid npub or hex pubkey"}
            signer_type = str(request.get("signer_type") or "unknown")
            if signer_type not in VALID_SIGNER_TYPES:
                return {"ok": False, "error": f"signer_type must be one of {', '.join(VALID_SIGNER_TYPES)}"}
            label = request.get("label")
            existing = store.get_identity_by_pubkey(pubkey)
            if existing is not None and existing.ynh_username != username:
                return {"ok": False, "error": "that pubkey is already linked to a different account"}
            event = link_identity(
                username,
                pubkey,
                operator_sk=operator_sk,
                control_relay=control_relay,
                signer_type=signer_type,
                label=label,
                transport=transport,
            )
            return {"ok": True, "event_id": event["id"], "pubkey": pubkey}

        if action in ("revoke", "rename"):
            try:
                pubkey = _parse_pubkey(request.get("pubkey"))
            except Exception:
                return {"ok": False, "error": "pubkey is not a valid npub or hex pubkey"}
            identity = store.get_identity_by_pubkey(pubkey)
            if identity is None or identity.ynh_username != username:
                return {"ok": False, "error": "pubkey is not linked to this account"}
            if action == "revoke":
                event = revoke_identity(pubkey, operator_sk=operator_sk, control_relay=control_relay, transport=transport)
                return {"ok": True, "event_id": event["id"], "pubkey": pubkey}
            label = request.get("label")
            if not isinstance(label, str) or not label.strip():
                return {"ok": False, "error": "label is required"}
            event = link_identity(
                username,
                pubkey,
                operator_sk=operator_sk,
                control_relay=control_relay,
                signer_type=identity.signer_type,
                label=label.strip(),
                transport=transport,
            )
            return {"ok": True, "event_id": event["id"], "pubkey": pubkey}

        if action == "unlink":
            identities = store.list_by_username(username, include_disabled=False)
            event_ids = []
            for identity in identities:
                event = revoke_identity(identity.pubkey, operator_sk=operator_sk, control_relay=control_relay, transport=transport)
                event_ids.append(event["id"])
            return {"ok": True, "event_ids": event_ids}

        return {"ok": False, "error": f"unknown action {action!r}"}
    except Exception as exc:  # noqa: BLE001 - the socket protocol is JSON-only
        logger.error("identity control request failed: %s", exc)
        return {"ok": False, "error": str(exc)}


def serve_control(
    store: Any,
    *,
    operator_sk: str,
    control_relay: str,
    sock_path: str | Path | None = None,
    stop: "threading.Event | None" = None,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> "threading.Thread":
    """Serve the local identity-management control socket in a thread."""
    import socket
    import threading

    sock_path = Path(sock_path or os.environ.get("NOSTRHOST_IDENTITY_SOCKET", CONTROL_SOCKET_DEFAULT))
    sock_path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(sock_path.parent, 0o770)
    try:
        sock_path.unlink()
    except FileNotFoundError:
        pass

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(sock_path))
    server.listen(8)
    os.chmod(sock_path, 0o660)
    portal_uid = _portal_uid()
    portal_gid = _portal_gid()
    if portal_uid is not None and portal_gid is not None:
        # The portal-api service connects as ynh-portal: root owns the socket,
        # the group grants connect access. Mirror nostrhost-bootstrap's
        # portal.toml ownership (best-effort, the user is package-owned).
        os.chown(sock_path.parent, 0, portal_gid)
        os.chown(sock_path, 0, portal_gid)

    def accept_loop() -> None:
        allowed = [0]
        if portal_uid is not None:
            allowed.append(portal_uid)
        while stop is None or not stop.is_set():
            try:
                conn, _ = server.accept()
            except OSError:  # pragma: no cover - socket closed at shutdown
                break
            try:
                peer = _peer_uid(conn)
                if peer is not None and peer not in allowed:
                    conn.sendall(b'{"ok": false, "error": "forbidden"}\n')
                    conn.close()
                    continue
                conn.settimeout(10)
                data = conn.recv(65536).decode("utf-8", "replace")
                request = json.loads(data) if data.strip() else {}
                if not isinstance(request, dict):
                    request = {}
                result = handle_control_request(
                    request,
                    store=store,
                    operator_sk=operator_sk,
                    control_relay=control_relay,
                    transport=transport,
                )
                conn.sendall((json.dumps(result) + "\n").encode())
            except Exception as exc:  # noqa: BLE001 - keep the socket alive
                try:
                    conn.sendall((json.dumps({"ok": False, "error": str(exc)}) + "\n").encode())
                except Exception:  # pragma: no cover - peer already gone
                    pass
            finally:
                conn.close()

    thread = threading.Thread(target=accept_loop, daemon=True, name="identity-control")
    thread.start()
    return thread


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
    stop = threading.Event()
    serve_control(
        store,
        operator_sk=cfg.operator_sk,
        control_relay=cfg.control_relay,
        stop=stop,
    )
    logger.info("identity control socket ready at %s", CONTROL_SOCKET_DEFAULT)
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
    finally:
        stop.set()