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
import threading
from pathlib import Path
from typing import Any, Callable

from .nostr_identity import (
    IDENTITY_KIND,
    _configure_daemon_logging,
    _init_headless_yunohost,
    _operator_config,
    _require_bootstrapped,
    _store,
)
from .nostr_projector import (
    DEFAULT_CURSOR_DIR,
    Projector,
    ProjectionResult,
    ProjectionRuntime,
    REGISTRY,
)
from nostrhost_auth.identity.mappings import PubkeyAlreadyLinked
from .nostrhost.events import _d_tag, query_chain_events

logger = logging.getLogger("nostr-identityd")


class AccountBackend:
    """Duck-typed account materialisation backend.

    Production is :class:`YnhAccountBackend` (real YunoHost user creation);
    tests inject a fake with the same surface.
    """

    def user_exists(self, username: str) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    def ensure_user(self, username: str, *, admin: bool = False) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class YnhAccountBackend(AccountBackend):
    """Real YunoHost account backend: create via user_create (main domain),
    with a generated strong password that is never used for login (password
    recovery stays via admin reset)."""

    def user_exists(self, username: str) -> bool:
        from yunohost.user import user_list

        return username in user_list()["users"]

    def ensure_user(self, username: str, *, admin: bool = False) -> None:
        import secrets as _secrets

        from yunohost.domain import _get_maindomain
        from yunohost.user import user_create

        password = _secrets.token_urlsafe(24) + "Aa1!"
        user_create(
            username=username,
            domain=_get_maindomain(),
            password=password,
            fullname=username,
            admin=bool(admin),
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
    admin_flag = bool(body.get("admin", False))
    if enabled and not username:
        logger.warning("identity event with empty username ignored")
        return False

    existing = store.get_identity_by_pubkey(d_tag)
    if enabled:
        if accounts is not None and existing is None:
            if not accounts.user_exists(username):
                accounts.ensure_user(username, admin=admin_flag)
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

        if action == "set-preferences":
            # WP4 self-service: the portal has already authenticated the
            # session; here we only accept a preference document for a pubkey
            # that is *linked to the caller's own account*. The projector keys
            # the coordinate by that pubkey, so a user can never write another
            # user's preferences, and the document is server-attested (the
            # operator authors it about the subject, exactly like identity
            # linking) because the server holds no user signer key.
            from yunohost.nostrhost.list_specs import user_preferences_coordinate

            try:
                pubkey = _parse_pubkey(request.get("pubkey"))
            except Exception:
                return {"ok": False, "error": "pubkey is not a valid npub or hex pubkey"}
            identity = store.get_identity_by_pubkey(pubkey)
            if identity is None or identity.ynh_username != username:
                return {"ok": False, "error": "pubkey is not linked to this account"}
            settings = request.get("settings")
            if not isinstance(settings, dict):
                return {"ok": False, "error": "settings must be an object"}
            coordinate = user_preferences_coordinate(pubkey)
            import json as _json

            from yunohost.nostr_identity import _pubkey, _sign_event, publish_to_relay
            from yunohost.nostrhost.list_specs import KIND_APP_DATA

            event = _sign_event(
                operator_sk,
                _pubkey(operator_sk),
                KIND_APP_DATA,
                _json.dumps(settings),
                [["d", coordinate]],
            )
            (transport or publish_to_relay)(control_relay, event)
            return {"ok": True, "event_id": event["id"], "coordinate": coordinate}

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


class IdentityProjector(Projector):
    """Projector contract around the kind-31102 identity mapping (+ LDAP).

    The heavy lifting stays in :func:`handle_identity_event`; this class adds
    the shared lifecycle (quarantine, checkpoint, health, registry).
    """

    name = "identity"
    schema = 1

    def __init__(
        self,
        *,
        store: Any,
        admin_pubkeys: tuple[str, ...] | list[str],
        accounts: AccountBackend | None = None,
        cursor_dir: str = DEFAULT_CURSOR_DIR,
    ) -> None:
        super().__init__(cursor_dir=cursor_dir)
        self.store = store
        self.admin_pubkeys = tuple(admin_pubkeys)
        self.accounts = accounts

    def validate(self, event: dict[str, Any]) -> Any:
        if event.get("kind") not in (IDENTITY_KIND, 0):
            return None
        if event.get("kind") == IDENTITY_KIND and event.get("pubkey") not in self.admin_pubkeys:
            self.quarantine(event, "identity event authored by non-admin")
            return None
        return event

    def apply(self, event: dict[str, Any]) -> ProjectionResult:
        if self.validate(event) is None:
            return ProjectionResult(accepted=False, reason="invalid")
        handled = handle_identity_event(
            event,
            store=self.store,
            admin_pubkeys=self.admin_pubkeys,
            accounts=self.accounts,
        )
        self._advance(event)
        return ProjectionResult(accepted=True, changed=handled)

    def current(self) -> str:
        """Deterministic digest of the live mapping (for :func:`verify`)."""
        return self._digest()

    def render(self, state: Any) -> str | None:
        return self._digest()

    def commit(self, candidate: str) -> None:  # pragma: no cover - store owns the write
        raise NotImplementedError("identity mapping is written by handle_identity_event")

    def _digest(self) -> str:
        rows = [
            {
                "pubkey": identity.pubkey,
                "username": identity.ynh_username,
                "enabled": bool(identity.enabled),
                "signer_type": identity.signer_type,
                "label": identity.label,
            }
            for identity in self.store.list_all()
        ]
        rows.sort(key=lambda r: (r["username"], r["pubkey"]))
        return json.dumps(rows, sort_keys=True)

    def clone(self) -> "IdentityProjector":
        """A fresh projector over an empty temp DB, for :func:`verify`.

        Never provisions Unix accounts: a verification refold is data-only.
        """
        import tempfile

        tmp = tempfile.NamedTemporaryFile(prefix="identity-verify-", suffix=".db", delete=False)
        tmp.close()
        return IdentityProjector(
            store=_store(Path(tmp.name)),
            admin_pubkeys=self.admin_pubkeys,
            accounts=None,
            cursor_dir=str(self.cursor_dir),
        )


async def subscribe_loop(
    relay_url: str,
    *,
    store: Any,
    admin_pubkeys: tuple[str, ...] | list[str],
    accounts: AccountBackend | None = None,
    on_event: Callable[[dict[str, Any]], None] | None = None,
    stop: asyncio.Event | None = None,
    cursor_dir: str = DEFAULT_CURSOR_DIR,
) -> None:
    """Subscribe to identity kinds and materialise until stopped.

    Delegates the WebSocket replay/AUTH/backoff loop to the shared
    :class:`~nostr_projector.ProjectionRuntime` (WP2).
    """
    projector = IdentityProjector(
        store=store,
        admin_pubkeys=admin_pubkeys,
        accounts=accounts,
        cursor_dir=cursor_dir,
    )
    REGISTRY.register(projector)

    def _notify(events: list[dict[str, Any]]) -> None:
        if on_event is not None:
            for event in events:
                if event.get("kind") == IDENTITY_KIND:
                    on_event(event)

    runtime = ProjectionRuntime(
        relay_url,
        projector=projector,
        kinds=[IDENTITY_KIND, 0],
        on_replay=_notify if on_event else None,
        stop=stop,
    )
    await runtime.run()


def rebuild(
    relay_url: str,
    *,
    admin_pubkeys: tuple[str, ...] | list[str],
    store: Any = None,
    accounts: AccountBackend | None = None,
) -> dict[str, Any]:
    """Rebuild the identity projection (``identity.db``) from kind 31102 (WP3).

    Replays the relay's identity definitions through the projector into the
    mapping store. ``accounts`` should be ``None`` for a pure data rebuild —
    account provisioning is an execution side-effect, not part of the
    projection, and must not run during a state rebuild.
    """
    from .nostr_projector import rebuild as _rebuild

    projector = IdentityProjector(
        store=store if store is not None else _store(),
        admin_pubkeys=admin_pubkeys,
        accounts=accounts,
    )
    events = query_chain_events(relay_url, kinds=(IDENTITY_KIND,), limit=500)
    report = _rebuild(events, projector=projector)
    report["projection"] = projector._digest()
    return report


def verify(
    relay_url: str,
    *,
    admin_pubkeys: tuple[str, ...] | list[str],
    store: Any = None,
) -> list[str]:
    """Report drift between ``identity.db`` and a relay replay (WP3 verify)."""
    from .nostr_projector import verify as _verify

    projector = IdentityProjector(
        store=store if store is not None else _store(),
        admin_pubkeys=admin_pubkeys,
    )
    events = query_chain_events(relay_url, kinds=(IDENTITY_KIND,), limit=500)
    return _verify(projector, events)


def run() -> None:
    """Entry point for bin/nostr-identityd."""
    _configure_daemon_logging()
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
