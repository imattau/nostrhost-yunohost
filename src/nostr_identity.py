"""Nostr-native identity for the derivative fork (roadmap §4 / Phase 3).

Identity is *projected*, not stored here: signed identity-definition events
(kind 31102) on the local control relay are authoritative; this module
materialises/reads them via the nostrhost-auth mapping store and exposes the
native resolution surface (`resolve_pubkey`, `resolve_username`,
`link_identity`, `revoke_identity`).

Authorship is admin-only in Phase 3 (self-service linking arrives with the
portal in Phase 4). Relay I/O uses the raw NIP-01 WebSocket protocol against
the local control relay — no nostr-sdk signer required.

Heavy dependencies (nostrhost_auth, coincurve, websockets) are imported
lazily so the module is importable and unit-testable without them; the
transport and store are injectable for tests.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

IDENTITY_KIND = 31102

DEFAULT_IDENTITY_DB = "/etc/nostrhost/identity.db"
DEFAULT_CONTROL_RELAY = "ws://127.0.0.1:4848"
OPERATOR_CONFIG = "/etc/nostrhost/operator.toml"

VALID_SIGNER_TYPES = ("nip07", "nip46", "passkey", "unknown")


class IdentityError(ValueError):
    """The identity operation failed (unknown user, bad pubkey, config, …)."""


@dataclass(frozen=True)
class Identity:
    """One pubkey ↔ YunoHost-account mapping (roadmap's core identity)."""

    pubkey: str
    username: str
    signer_type: str
    label: str | None
    enabled: bool
    identity_id: int | None
    created_at: int
    last_used: int | None


@dataclass(frozen=True)
class OperatorConfig:
    """The node's identity configuration (server / operator / admins).

    Three distinct roles (roadmap Phase 3, hardened bootstrap):

      server_sk     — the server's own machine identity; signs execution
                      events (2203/2204). Distinct from the operator once
                      bootstrapped; falls back to the operator key for
                      legacy single-key configs.
      operator_sk   — the primary human admin; signs approvals (2201/2202),
                      capability grants (31100) and identity definitions
                      (31102).
      admins        — the admin pubkeys the projector/executor accept events
                      from (always includes the operator).
    """

    operator_sk: str
    operator_pubkey: str
    control_relay: str
    server_sk: str
    server_pubkey: str
    admins: tuple[str, ...] = field(default_factory=tuple)


# --------------------------------------------------------------------------- #
# projection store

def _store(db_path: str | Path | None = None):
    from nostrhost_auth.identity.mappings import MappingStore

    return MappingStore(Path(db_path or os.environ.get("NOSTRHOST_IDENTITY_DB", DEFAULT_IDENTITY_DB)))


def _init_headless_yunohost() -> None:
    """Initialise moulinette + logging so YunoHost machinery (user creation,
    tool execution) can be invoked from a daemon/headless context where no
    CLI or API interface is running.

    YunoHost's operation logger reads ``Moulinette.interface.type`` and
    translation needs the locales dir loaded; without this, calling e.g.
    ``user_create`` from ``nostr-identityd`` fails with
    ``AttributeError: 'NoneType' object has no attribute 'type'``.
    """
    from moulinette import Moulinette, m18n

    if Moulinette.interface is None:
        m18n.set_locales_dir("/usr/share/yunohost/locales/")
        m18n.set_locale("en")

        class _HeadlessCli:
            type = "cli"

            def display(self, *args: Any, **kwargs: Any) -> None:  # pragma: no cover - cosmetic
                return None

            def prompt(self, *args: Any, **kwargs: Any) -> Any:
                raise RuntimeError("interactive prompt not available in headless mode")

        Moulinette._interface = _HeadlessCli()

    from yunohost.utils.logging import init_logging

    init_logging(interface="cli", debug=False, quiet=True)


def _to_identity(rec: Any) -> Identity:
    return Identity(
        pubkey=rec.pubkey,
        username=rec.ynh_username,
        signer_type=rec.signer_type,
        label=rec.label,
        enabled=rec.enabled,
        identity_id=rec.identity_id,
        created_at=rec.created_at,
        last_used=rec.last_used,
    )


def _parse_pubkey(pubkey_or_npub: str) -> str:
    if pubkey_or_npub.startswith("npub1"):
        from nostrhost_auth.identity.npub import npub_to_hex

        return npub_to_hex(pubkey_or_npub)
    if not _is_hex64(pubkey_or_npub):
        raise IdentityError("pubkey must be a 64-hex string or an npub")
    return pubkey_or_npub


def _is_hex64(s: str) -> bool:
    return len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s)


# --------------------------------------------------------------------------- #
# resolution

def resolve_pubkey(pubkey_hex: str, *, db_path: str | Path | None = None) -> Identity | None:
    """Resolve a canonical hex pubkey to its YunoHost account identity.

    Returns None for unknown or revoked identities (the mapping store only
    returns enabled rows for pubkey lookups).
    """
    rec = _store(db_path).get_by_pubkey(pubkey_hex)
    return _to_identity(rec) if rec else None


def resolve_username(username: str, *, db_path: str | Path | None = None) -> list[Identity]:
    """List the enabled identities linked to a YunoHost account."""
    return [_to_identity(r) for r in _store(db_path).list_by_username(username) if r.enabled]


def list_identities_for_username(username: str, *, db_path: str | Path | None = None) -> list[Identity]:
    """List every identity linked to a YunoHost account, including revoked.

    The account page uses this so a user can see (and re-link via replace) an
    identity that was revoked, rather than it silently disappearing.
    """
    return [_to_identity(r) for r in _store(db_path).list_by_username(username)]


def list_identities(*, db_path: str | Path | None = None) -> list[Identity]:
    """List all identities (including revoked)."""
    return [_to_identity(r) for r in _store(db_path).list_all()]


# --------------------------------------------------------------------------- #
# authoring

def _sign_event(operator_sk: str, operator_pubkey: str, kind: int, content: str, tags: list[list[str]]) -> dict[str, Any]:
    """Build and sign a NIP-01 event with coincurve (pure python, no
    nostr-sdk signer needed)."""
    from coincurve import PrivateKey

    created_at = int(time.time())
    serialized = json.dumps(
        [0, operator_pubkey, created_at, kind, tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    event_id = hashlib.sha256(serialized).hexdigest()
    sig = PrivateKey(bytes.fromhex(operator_sk)).sign_schnorr(bytes.fromhex(event_id)).hex()
    return {
        "id": event_id,
        "pubkey": operator_pubkey,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": sig,
    }


def _operator_config(
    operator_sk: str | None = None,
    control_relay: str | None = None,
    admins: list[str] | None = None,
    server_sk: str | None = None,
) -> OperatorConfig:
    conf = _read_operator_config()
    sk = operator_sk or os.environ.get("NOSTRHOST_OPERATOR_SK") or conf.get("operator_sk")
    relay = control_relay or os.environ.get("NOSTRHOST_CONTROL_RELAY") or DEFAULT_CONTROL_RELAY
    if not sk or not _is_hex64(sk):
        raise IdentityError("operator_sk is not configured (set NOSTRHOST_OPERATOR_SK or " + OPERATOR_CONFIG + ")")
    from coincurve import PublicKeyXOnly

    operator_pubkey = PublicKeyXOnly.from_secret(bytes.fromhex(sk)).format().hex()
    srv = server_sk or os.environ.get("NOSTRHOST_SERVER_SK") or conf.get("server_sk") or sk
    server_pubkey = PublicKeyXOnly.from_secret(bytes.fromhex(srv)).format().hex()
    if admins is None:
        file_admins = conf.get("admins")
        admins = file_admins if isinstance(file_admins, list) else []
    if not admins:
        admins = [operator_pubkey]
    return OperatorConfig(sk, operator_pubkey, relay, srv, server_pubkey, tuple(admins))


def is_bootstrapped() -> bool:
    """Whether the node has an operator configured (bootstrap done).

    Bootstrap (nostrhost-bootstrap, root-only) is the high-trust, local
    action that generates the server identity + operator keys and designates
    the admins. Pre-bootstrap the server has no operator to act on its
    behalf; post-bootstrap, authority flows through the configured admins
    (approvals, grants, identity events)."""
    if os.environ.get("NOSTRHOST_OPERATOR_SK"):
        return True
    return bool(_read_operator_config().get("operator_sk"))


def _require_bootstrapped() -> None:
    """Raise unless the node has an operator configured. Daemons and the
    mutating CLI tools call this so a fresh server fails with a clear
    pointer to the bootstrap action instead of a raw config error."""
    if not is_bootstrapped():
        raise IdentityError(
            "nostrhost is not bootstrapped: no operator key configured in "
            + OPERATOR_CONFIG + ". Run `nostrhost-bootstrap` (root) to generate the "
            "server identity and operator key before starting the daemons."
        )


def _read_operator_config() -> dict[str, Any]:
    path = Path(os.environ.get("NOSTRHOST_OPERATOR_CONFIG", OPERATOR_CONFIG))
    if not path.exists():
        return {}
    with path.open("rb") as fh:
        return tomllib.load(fh)


# --------------------------------------------------------------------------- #
# NIP-42 client auth (kind 22242) for the control relay

AUTH_KIND = 22242


def default_auth() -> tuple[str, str] | None:
    """The key a headless client authenticates relay connections with: the
    operator (a relay admin, always allowlisted). None when the node is not
    bootstrapped yet, or when the caller cannot read the root-only operator
    config (e.g. the portal service) - NIP-42 auth is only needed for
    protected kinds, so a non-protected publish still works without it."""
    try:
        cfg = _operator_config()
    except (IdentityError, OSError):
        return None
    return cfg.operator_sk, cfg.operator_pubkey


def _sign_auth_event(sk: str, pubkey: str, relay_url: str, challenge: str, sub_id: str = "") -> dict[str, Any]:
    """Build and sign a NIP-42 kind-22242 AUTH event for a relay challenge."""
    return _sign_event(sk, pubkey, AUTH_KIND, sub_id, [["relay", relay_url], ["challenge", challenge]])


def link_identity(
    username: str,
    pubkey_or_npub: str,
    *,
    operator_sk: str | None = None,
    control_relay: str | None = None,
    signer_type: str = "unknown",
    label: str | None = None,
    enabled: bool = True,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Author an identity-definition event linking `pubkey_or_npub` to a
    YunoHost account. Publishes kind 31102 to the control relay as the
    operator; the projector materialises it. Returns the signed event."""
    if signer_type not in VALID_SIGNER_TYPES:
        raise IdentityError(f"signer_type must be one of {', '.join(VALID_SIGNER_TYPES)}")
    pubkey = _parse_pubkey(pubkey_or_npub)
    cfg = _operator_config(operator_sk, control_relay)
    content = json.dumps({"username": username, "signer_type": signer_type, "label": label, "enabled": bool(enabled)})
    event = _sign_event(cfg.operator_sk, cfg.operator_pubkey, IDENTITY_KIND, content, [["d", pubkey]])
    (transport or publish_to_relay)(cfg.control_relay, event)
    return event


def revoke_identity(
    pubkey_or_npub: str,
    *,
    operator_sk: str | None = None,
    control_relay: str | None = None,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Author a revocation (enabled:false) for a linked pubkey."""
    pubkey = _parse_pubkey(pubkey_or_npub)
    cfg = _operator_config(operator_sk, control_relay)
    content = json.dumps({"username": "", "enabled": False})
    event = _sign_event(cfg.operator_sk, cfg.operator_pubkey, IDENTITY_KIND, content, [["d", pubkey]])
    (transport or publish_to_relay)(cfg.control_relay, event)
    return event


def _wait_auth_ok(ws: Any, auth_id: str, deadline: float) -> None:
    """Drain messages until the relay acknowledges the AUTH event. The relay
    applies the authenticated pubkey in a per-message goroutine, so a client
    must not re-send its EVENT/REQ until the AUTH OK arrives (otherwise the
    re-send races the auth state and is still rejected as unauthenticated)."""
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            raise IdentityError("relay did not acknowledge the AUTH event")
        ack = json.loads(ws.recv(timeout=remaining))
        if ack[0] == "OK" and ack[1] == auth_id:
            return


async def _wait_auth_ok_async(ws: Any, auth_id: str, timeout: float = 10.0) -> None:
    """Async counterpart of :func:`_wait_auth_ok` for the daemon subscribe
    loops (websockets async client)."""
    import asyncio

    deadline = time.time() + timeout
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            raise IdentityError("relay did not acknowledge the AUTH event")
        ack = json.loads(await asyncio.wait_for(ws.recv(), timeout=remaining))
        if ack[0] == "OK" and ack[1] == auth_id:
            return


def publish_to_relay(relay_url: str, event: dict[str, Any], timeout: float = 10.0) -> None:
    """Publish an event to the control relay over raw NIP-01 WebSocket.

    If the relay requires NIP-42 auth for the event's kind, it answers the
    first attempt with ``["AUTH", <challenge>]`` (and a rejection): this
    client signs a kind-22242 AUTH event with the operator key (via
    :func:`default_auth`), waits for its acknowledgement, then re-sends the
    event (ignoring the pre-auth rejection). Without a configured operator it
    cannot authenticate and any rejection raises immediately."""
    import time

    from websockets.sync.client import connect

    auth = default_auth()
    with connect(relay_url) as ws:
        ws.send(json.dumps(["EVENT", event]))
        authed = False
        pending_rejection = False
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise IdentityError(f"relay did not acknowledge event {event['id'][:16]} within {timeout}s")
            msg = json.loads(ws.recv(timeout=remaining))
            if msg[0] == "AUTH":
                if auth is not None and not authed:
                    challenge = msg[1] if len(msg) > 1 else ""
                    auth_event = _sign_auth_event(auth[0], auth[1], relay_url, challenge)
                    ws.send(json.dumps(["AUTH", auth_event]))
                    _wait_auth_ok(ws, auth_event["id"], deadline)
                    authed = True
                    ws.send(json.dumps(["EVENT", event]))  # re-send after auth
                continue
            if msg[0] == "OK" and msg[1] == event["id"]:
                if msg[2] is True:
                    return
                if auth is None or (authed and pending_rejection):
                    raise IdentityError(f"relay rejected event: {msg[3]}")
                pending_rejection = True  # pre-auth rejection; the AUTH follows
                continue


def _build_identity_event(
    operator_sk: str,
    operator_pubkey: str,
    subject_pubkey: str,
    username: str,
    signer_type: str,
    label: str | None,
    enabled: bool,
) -> dict[str, Any]:
    """Build (without publishing) an identity-definition event — used by the
    projector's tests to fabricate events authored by an admin for a subject."""
    content = json.dumps({"username": username, "signer_type": signer_type, "label": label, "enabled": enabled})
    return _sign_event(operator_sk, operator_pubkey, IDENTITY_KIND, content, [["d", subject_pubkey]])