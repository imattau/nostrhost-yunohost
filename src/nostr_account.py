"""Passwordless identity self-service (roadmap §8 ``/nostr-account``).

The portal's account page lists the session user's linked Nostr identities
(kind 31102 projection) and lets them link / revoke / rename / unlink their
own identities, plus manage saved signers client-side.

Privilege boundary: these portalapi routes run as the low-privilege
``ynh-portal`` user. Reading the identity projection is fine (``identity.db``
is world-readable), but authoring a kind-31102 identity definition requires
the root-only operator key. So every mutation here is verified in-process
(session + challenge signature, exactly like ``nostr_login.handle_login``) and
then forwarded over a local UNIX socket to ``nostr-identityd``, which re-checks
the request and performs the operator-signed publication (see
``nostr_identityd.serve_control``).
"""

from __future__ import annotations

import json
import logging
import os
import socket
from pathlib import Path

from .nostr_login import CLOCK_SKEW, LoginError, _challenges

logger = logging.getLogger("nostrhost-account")

LINK_ACTION = "nostrhost-link"
IDENTITY_SOCKET = "/run/nostrhost/identity.sock"
PORTAL_CONFIG = "/etc/nostrhost/portal.toml"
CLIENT_TIMEOUT = 10.0  # seconds the socket client waits for identityd

# Bunker/NIP-46 session bookkeeping (visibility only - see
# nostrhost_auth.identity.signer_sessions for why this doesn't go through
# identityd's operator-signed event pipeline like the identities table does).
DEFAULT_SIGNER_SESSIONS_DB = "/var/lib/nostrhost/signer_sessions.db"
MAX_SIGNER_RELAYS = 10


class AccountError(ValueError):
    """The identity self-service operation failed."""


def allow_identity_linking(conf_path: str | Path | None = None) -> bool:
    """Whether the administrator has enabled self-service identity linking.

    Read from the portal config (``allow_identity_linking``), defaulting to
    enabled. A missing/unreadable config degrades to the permissive default -
    the portal-api user must not fail the account page over an optional flag.
    """
    import tomllib

    path = Path(conf_path or os.environ.get("NOSTRHOST_NOTICE_CONFIG", PORTAL_CONFIG))
    try:
        with path.open("rb") as fh:
            conf = tomllib.load(fh)
        return bool(conf.get("allow_identity_linking", True))
    except Exception:
        return True


def _session_username() -> str | None:
    """The session user, or None when there is no portal session."""
    from .authenticators.ldap_ynhuser import Authenticator

    try:
        infos = Authenticator().get_session_cookie()
    except Exception:
        infos = None
    username = (infos or {}).get("user") if isinstance(infos, dict) else None
    return username if isinstance(username, str) and username else None


def identityd_request(request: dict, *, sock_path: str | Path | None = None) -> dict:
    """Send one identity-management request to ``nostr-identityd`` and return
    its response. Raises :class:`AccountError` on transport failures so the
    caller can degrade with a clear message (the daemon may be starting)."""
    path = Path(sock_path or os.environ.get("NOSTRHOST_IDENTITY_SOCKET", IDENTITY_SOCKET))
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(CLIENT_TIMEOUT)
            conn.connect(str(path))
            conn.sendall(json.dumps(request).encode())
            data = conn.recv(65536).decode("utf-8", "replace")
    except FileNotFoundError:
        raise AccountError("identity service is not running yet - try again in a moment")
    except (ConnectionRefusedError, OSError) as exc:
        raise AccountError(f"identity service is unavailable: {exc}")

    if not data.strip():
        raise AccountError("identity service returned an empty response")
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        raise AccountError("identity service returned an unreadable response")


def _require_session() -> str:
    username = _session_username()
    if not username:
        from bottle import HTTPResponse

        raise HTTPResponse("not signed in", 401)
    return username


def _require_linking_enabled() -> None:
    if not allow_identity_linking():
        raise LoginError("identity linking is disabled by the administrator")


def _signer_session_store():
    from nostrhost_auth.identity.signer_sessions import SignerSessionStore

    return SignerSessionStore(
        Path(os.environ.get("NOSTRHOST_SIGNER_SESSIONS_DB", DEFAULT_SIGNER_SESSIONS_DB))
    )


def _serialize_signer_session(session) -> dict:
    from nostrhost_auth.identity.npub import hex_to_npub

    return {
        "session_id": session.session_id,
        "remote_pubkey": session.bunker_pubkey,
        "remote_npub": hex_to_npub(session.bunker_pubkey),
        "relays": json.loads(session.relays),
        "label": session.label,
        "connected_at": session.connected_at,
        "last_used": session.last_used,
    }


def _serialize_identity(identity) -> dict:
    from nostrhost_auth.identity.npub import hex_to_npub

    return {
        "id": identity.identity_id,
        "pubkey": identity.pubkey,
        "npub": hex_to_npub(identity.pubkey),
        "label": identity.label,
        "signer_type": identity.signer_type,
        "enabled": identity.enabled,
        "created_at": identity.created_at,
        "last_used": identity.last_used,
    }


# --------------------------------------------------------------------------- #
# portalapi routes (registered by src/__init__.py::portalapi)

def nip05_route():
    """NIP-05 ``/.well-known/nostr.json`` (W4).

    Served on every native domain with ``[nostr] nip05 = true`` via Caddy's
    reverse-proxy to the authd. Only ever reveals a pubkey for a username
    that has actually linked an identity (opt-in), matching NIP-05
    behaviour across providers.
    """
    from bottle import request

    from nostrhost_auth.nip05 import build_nostr_json

    from .nostr_identity import resolve_username

    class _Mapping:
        def get_by_username(self, username):
            for identity in resolve_username(username) or []:
                if identity.enabled:
                    return identity
            return None

    name = request.query.get("name")
    return build_nostr_json(_Mapping(), name)


def identities_route():
    """List the session user's linked Nostr identities (+ policy flag)."""

    from .nostr_identity import list_identities_for_username

    username = _require_session()
    identities = list_identities_for_username(username)
    return {
        "username": username,
        "allow_identity_linking": allow_identity_linking(),
        "identities": [_serialize_identity(i) for i in identities],
    }


def link_challenge_route():
    """Issue a challenge the user signs (kind 22242) to prove key control."""
    from bottle import HTTPResponse, request

    _require_session()
    _require_linking_enabled()
    host = request.get_header("host")
    if not host:
        raise HTTPResponse("Missing Host header", 400)
    challenge = _challenges.issue(domain=host, action=LINK_ACTION)
    return {"challenge": challenge.nonce}


def _verify_link_event(event: dict, *, domain: str) -> str:
    """Consume + verify a kind-22242 link challenge; return the pubkey."""
    from nostrhost_auth.auth.nostr_verify import (
        InvalidEvent,
        extract_tag_from_raw_event,
        verify_challenge_response,
    )

    nonce = extract_tag_from_raw_event(event, "challenge")
    if not nonce:
        raise LoginError("missing challenge tag")
    challenge = _challenges.consume(nonce)
    if challenge is None:
        raise LoginError("invalid or expired challenge")
    if challenge.domain != domain:
        raise LoginError("challenge was issued for a different domain")
    if challenge.action != LINK_ACTION:
        raise LoginError("challenge was issued for a different action")
    try:
        return verify_challenge_response(
            json.dumps(event),
            expected_nonce=challenge.nonce,
            expected_domain=challenge.domain,
            expected_action=challenge.action,
            issued_at=challenge.issued_at,
            expires_at=challenge.expires_at,
            clock_skew=CLOCK_SKEW,
        )
    except InvalidEvent as exc:
        raise LoginError(str(exc)) from exc


def link_route():
    """Link (or replace) the session user's identity with a verified pubkey."""
    from bottle import HTTPResponse, request

    username = _require_session()
    _require_linking_enabled()
    body = request.json or {}
    event = body.get("event")
    if not isinstance(event, dict):
        raise HTTPResponse("Missing signed event", 400)
    host = request.get_header("host")
    if not host:
        raise HTTPResponse("Missing Host header", 400)
    try:
        pubkey = _verify_link_event(event, domain=host)
        mode = body.get("mode", "replace")
        signer_type = body.get("signer_type") or "unknown"
        label = body.get("label")

        if mode == "replace":
            result = identityd_request(
                {"action": "unlink", "username": username},
            )
            if not result.get("ok"):
                raise AccountError(result.get("error") or "could not replace identities")
        elif mode != "add":
            raise HTTPResponse(f"unknown mode {mode!r}", 400)

        result = identityd_request(
            {
                "action": "link",
                "username": username,
                "pubkey": pubkey,
                "signer_type": signer_type,
                "label": label,
            },
        )
        if not result.get("ok"):
            raise AccountError(result.get("error") or "linking failed")
        return {"ok": True, "pubkey": pubkey}
    except LoginError as exc:
        raise HTTPResponse(str(exc), 401)
    except AccountError as exc:
        raise HTTPResponse(str(exc), 502)


def _owned_identity(identity_id: int) -> str:
    """Return the pubkey of a session user's identity, or raise 404."""
    from bottle import HTTPResponse

    from .nostr_identity import _store

    store = _store()
    identity = store.get_by_id(identity_id)
    if identity is None or identity.ynh_username != _session_username():
        raise HTTPResponse("identity not found", 404)
    return identity.pubkey


def revoke_route():
    """Revoke one of the session user's identities."""
    from bottle import HTTPResponse, request

    username = _require_session()
    body = request.json or {}
    try:
        identity_id = int(body.get("identity_id"))
    except (TypeError, ValueError):
        raise HTTPResponse("identity_id is required", 400)
    pubkey = _owned_identity(identity_id)
    result = identityd_request({"action": "revoke", "username": username, "pubkey": pubkey})
    if not result.get("ok"):
        raise HTTPResponse(result.get("error") or "could not revoke that identity", 502)
    return {"ok": True, "pubkey": pubkey}


def rename_route():
    """Rename one of the session user's identities."""
    from bottle import HTTPResponse, request

    username = _require_session()
    body = request.json or {}
    try:
        identity_id = int(body.get("identity_id"))
    except (TypeError, ValueError):
        raise HTTPResponse("identity_id is required", 400)
    label = body.get("label")
    if not isinstance(label, str) or not label.strip():
        raise HTTPResponse("label is required", 400)
    pubkey = _owned_identity(identity_id)
    result = identityd_request(
        {"action": "rename", "username": username, "pubkey": pubkey, "label": label.strip()}
    )
    if not result.get("ok"):
        raise HTTPResponse(result.get("error") or "could not rename that identity", 502)
    return {"ok": True, "pubkey": pubkey}


def unlink_route():
    """Unlink every identity linked to the session user."""
    from bottle import HTTPResponse

    username = _require_session()
    result = identityd_request({"action": "unlink", "username": username})
    if not result.get("ok"):
        raise HTTPResponse(result.get("error") or "could not unlink identities", 502)
    _signer_session_store().delete_all_for_username(username)
    return {"ok": True, "event_ids": result.get("event_ids", [])}


# --------------------------------------------------------------------------- #
# remote-signer (NIP-46 bunker) session bookkeeping
#
# These routes never see the browser's NIP-46 client secret key - the client
# (public/nostr/nostr-connect-ui.js) keeps that in localStorage and only ever
# reports the remote signer's pubkey, its relays and a label, purely so the
# account page can show every bunker a user's browser remembers instead of
# just one. Revoking here hides a session from that list; it does not
# terminate the underlying bunker connection (see signer_sessions.py).

def signers_route():
    """List the session user's remembered remote-signer sessions."""
    username = _require_session()
    sessions = _signer_session_store().list_by_username(username)
    return {"sessions": [_serialize_signer_session(s) for s in sessions]}


def register_signer_route():
    """Record (or refresh) a bunker session the client just connected to."""
    from bottle import HTTPResponse, request

    from nostrhost_auth.identity.npub import npub_to_hex

    username = _require_session()
    body = request.json or {}

    session_id = body.get("session_id")
    if not isinstance(session_id, str) or not session_id.strip():
        raise HTTPResponse("session_id is required", 400)

    raw_pubkey = body.get("remote_pubkey")
    if not isinstance(raw_pubkey, str) or not raw_pubkey.strip():
        raise HTTPResponse("remote_pubkey is required", 400)
    try:
        pubkey = npub_to_hex(raw_pubkey) if raw_pubkey.startswith("npub1") else raw_pubkey
    except Exception:
        raise HTTPResponse("remote_pubkey is not a valid pubkey or npub", 400)
    if len(pubkey) != 64 or not all(c in "0123456789abcdefABCDEF" for c in pubkey):
        raise HTTPResponse("remote_pubkey is not a valid pubkey or npub", 400)

    relays = body.get("relays") or []
    if not isinstance(relays, list) or not all(isinstance(r, str) for r in relays):
        raise HTTPResponse("relays must be a list of relay URLs", 400)
    relays = relays[:MAX_SIGNER_RELAYS]

    label = body.get("label")
    if label is not None and not isinstance(label, str):
        raise HTTPResponse("label must be a string", 400)

    try:
        session = _signer_session_store().register(
            session_id.strip(), username, pubkey.lower(), json.dumps(relays), label=label
        )
    except ValueError as exc:
        raise HTTPResponse(str(exc), 409)
    return {"ok": True, "session": _serialize_signer_session(session)}


def revoke_signer_route():
    """Forget one of the session user's remembered bunker sessions."""
    from bottle import HTTPResponse, request

    username = _require_session()
    body = request.json or {}
    session_id = body.get("session_id")
    if not isinstance(session_id, str) or not session_id.strip():
        raise HTTPResponse("session_id is required", 400)

    if not _signer_session_store().revoke(session_id.strip(), username):
        raise HTTPResponse("signer session not found", 404)
    return {"ok": True}
