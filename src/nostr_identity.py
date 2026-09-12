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
import secrets
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

IDENTITY_KIND = 31102

DEFAULT_IDENTITY_DB = "/etc/nostrhost/identity.db"
DEFAULT_CONTROL_RELAY = "ws://127.0.0.1:4848"
OPERATOR_CONFIG = "/etc/nostrhost/operator.toml"
DEFAULT_RELAY_CONFIG = "/etc/nostrhost/relay.toml"
NOTICE_CONFIG = "/etc/nostrhost/portal.toml"

# Kinds the local control relay accepts: the control plane (2200-2213, 31100,
# 31102) plus the state-repository announcement (30617) so `postinstall
# --restore` can discover the node's state repo through the relay.
CONTROL_KINDS = [2200, 2201, 2202, 2203, 2204, 2206, 2210, 2211, 2212, 2213, 31100, 31102, 30617]

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

    Five distinct roles (roadmap §19/§27, hardened bootstrap):

      server_sk     — the server's own machine identity; signs execution
                      events (2203/2204). Distinct from the operator once
                      bootstrapped; falls back to the operator key for
                      legacy single-key configs.
      operator_sk   — the primary human admin; signs approvals (2201/2202),
                      capability grants (31100) and identity definitions
                      (31102).
      publisher_sk  — the catalogue publisher key; signs catalogue
                      declarations (catalog.publish). Writer-only on the
                      control relay, never a NIP-86 admin.
      notifier_sk   — the notification service key; reads notices and sends
                      NIP-17 DMs only, distinct from the control-plane keys.
      admins        — the admin pubkeys the projector/executor accept events
                      from (always includes the operator).
    """

    operator_sk: str
    operator_pubkey: str
    control_relay: str
    server_sk: str
    server_pubkey: str
    publisher_sk: str
    publisher_pubkey: str
    notifier_sk: str
    notifier_pubkey: str
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
    from nostrhost.core import Moulinette
    from nostrhost.i18n import set_locale, set_locales_dir

    if Moulinette.interface is None:
        set_locales_dir("/usr/share/yunohost/locales/")
        set_locale("en")

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


def _gen_sk() -> str:
    """Generate a fresh 32-byte nostr secret key as 64-hex."""
    return secrets.token_bytes(32).hex()


def _pubkey(sk: str) -> str:
    from coincurve import PublicKeyXOnly

    return PublicKeyXOnly.from_secret(bytes.fromhex(sk)).format().hex()


def _npub(pk: str) -> str:
    from nostrhost_auth.identity.npub import hex_to_npub

    return hex_to_npub(pk)


# --------------------------------------------------------------------------- #
# bootstrap (native postinstall) — key generation + identity config

def bootstrap_node(
    *,
    operator_sk: str | None = None,
    server_sk: str | None = None,
    notice_sk: str | None = None,
    publisher_sk: str | None = None,
    notifier_sk: str | None = None,
    admins: list[str] | None = None,
    relay: str = DEFAULT_CONTROL_RELAY,
    force: bool = False,
    write_relay: str | None = None,
    write_notice: bool = True,
) -> dict[str, Any]:
    """Generate (or import) the node's five identity keys and write the
    root-only operator config — the local, high-trust bootstrap action.

    On a fresh server there is no operator yet: nothing can act on the node's
    behalf and the daemons refuse to start. This provisions the hardened
    identity model:

      server_sk   — the server's own machine key (signs execution events)
      operator_sk — the primary admin key (signs approvals, grants, identity
                    definitions)
      notice_sk   — the portal's dedicated low-privilege notice key
      publisher_sk — the catalogue publisher key (signs catalogue
                    declarations; writer-only on the control relay)
      notifier_sk — the notification service key (reads notices, sends
                    NIP-17 DMs; distinct from the control-plane keys)

    Writes:
      - operator.toml (0600): server_sk / operator_sk / publisher_sk /
        notifier_sk / control_relay / admins
      - portal.toml (0640 root:ynh-portal): the low-privilege notice key
      - optionally a relay config (``write_relay``) that allowlists the four
        control keys (operator, server, notice, publisher) as writers on the
        local control plane.

    Returns a dict with the generated/imported keys and derived pubkeys.
    """
    path = Path(os.environ.get("NOSTRHOST_OPERATOR_CONFIG", OPERATOR_CONFIG))
    existing = _read_operator_config()
    if existing.get("operator_sk") and not force:
        raise IdentityError(f"{path} already has an operator key; pass force=True to regenerate")

    server_sk = server_sk or _gen_sk()
    operator_sk = operator_sk or _gen_sk()
    notice_sk = notice_sk or _gen_sk()
    publisher_sk = publisher_sk or _gen_sk()
    notifier_sk = notifier_sk or _gen_sk()
    for name, sk in (
        ("--server-sk", server_sk),
        ("--operator-sk", operator_sk),
        ("--notice-sk", notice_sk),
        ("--publisher-sk", publisher_sk),
        ("--notifier-sk", notifier_sk),
    ):
        if not _is_hex64(sk):
            raise IdentityError(f"{name} must be a 64-char hex secret key")

    operator_pk = _pubkey(operator_sk)
    admin_pubkeys = [a.strip() for a in (admins or [])]
    if not admin_pubkeys:
        admin_pubkeys = [operator_pk]

    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# nostrhost node identity (root-only). Generated by the native postinstall.",
        "# server_sk = server machine key (signs execution events 2203/2204)",
        "# operator_sk = primary admin (signs approvals, grants, identity defs)",
        "# publisher_sk = catalogue publisher (catalog.publish; writer-only)",
        "# notifier_sk = notification service (reads notices, sends NIP-17 DMs)",
        f'server_sk = "{server_sk}"',
        f'operator_sk = "{operator_sk}"',
        f'publisher_sk = "{publisher_sk}"',
        f'notifier_sk = "{notifier_sk}"',
        f'control_relay = "{relay}"',
        'admins = ["' + '", "'.join(admin_pubkeys) + '"]',
    ]
    tmp = path.with_suffix(".toml.tmp")
    tmp.write_text("\n".join(lines) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    os.chmod(path, 0o600)

    if write_notice:
        notice_path = Path(os.environ.get("NOSTRHOST_NOTICE_CONFIG", NOTICE_CONFIG))
        notice_path.parent.mkdir(parents=True, exist_ok=True)
        ntmp = notice_path.with_suffix(".toml.tmp")
        ntmp.write_text(
            "# nostrhost portal notice key (ynh-portal). "
            "Generated by the native postinstall.\n"
            f'notice_sk = "{notice_sk}"\n'
            f'control_relay = "{relay}"\n'
        )
        os.chmod(ntmp, 0o640)
        os.replace(ntmp, notice_path)
        os.chmod(notice_path, 0o640)
        try:
            import pwd

            os.chown(notice_path, 0, pwd.getpwnam("ynh-portal").pw_uid)
        except (KeyError, ImportError):
            pass  # no ynh-portal user yet (pre-install): the notice stays a no-op

    server_pk = _pubkey(server_sk)
    notice_pk = _pubkey(notice_sk)
    publisher_pk = _pubkey(publisher_sk)
    notifier_pk = _pubkey(notifier_sk)

    if write_relay:
        relay_path = Path(write_relay)
        relay_path.parent.mkdir(parents=True, exist_ok=True)
        relay_body = "\n".join(
            [
                'listen_host = "127.0.0.1"',
                "listen_port = 4848",
                'name = "nostrhost"',
                'description = "NostrHost local control plane"',
                f'operator_pubkey = "{operator_pk}"',
                f'server_pubkey = "{server_pk}"',
                f'notice_pubkey = "{notice_pk}"',
                f'publisher_pubkey = "{publisher_pk}"',
                "allowlist_mode = true",
                "require_auth_kinds = []",
                "allowed_kinds = [" + ", ".join(str(k) for k in CONTROL_KINDS) + "]",
                "max_content_length = 100000",
                'events_db_path = "/var/lib/nostrhost/events.db"',
                'policy_db_path = "/var/lib/nostrhost/policy.db"',
            ]
        )
        relay_path.write_text(relay_body + "\n")

    return {
        "server_sk": server_sk,
        "server_pubkey": server_pk,
        "operator_sk": operator_sk,
        "operator_pubkey": operator_pk,
        "notice_sk": notice_sk,
        "notice_pubkey": notice_pk,
        "publisher_sk": publisher_sk,
        "publisher_pubkey": publisher_pk,
        "notifier_sk": notifier_sk,
        "notifier_pubkey": notifier_pk,
        "admins": admin_pubkeys,
        "control_relay": relay,
    }


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
    pub = os.environ.get("NOSTRHOST_PUBLISHER_SK") or conf.get("publisher_sk") or sk
    publisher_pubkey = PublicKeyXOnly.from_secret(bytes.fromhex(pub)).format().hex()
    ntf = os.environ.get("NOSTRHOST_NOTIFIER_SK") or conf.get("notifier_sk") or sk
    notifier_pubkey = PublicKeyXOnly.from_secret(bytes.fromhex(ntf)).format().hex()
    if admins is None:
        file_admins = conf.get("admins")
        admins = file_admins if isinstance(file_admins, list) else []
    if not admins:
        admins = [operator_pubkey]
    return OperatorConfig(
        sk, operator_pubkey, relay, srv, server_pubkey, pub, publisher_pubkey, ntf, notifier_pubkey, tuple(admins)
    )


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
