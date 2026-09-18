"""NIP-46 (Nostr Connect) client — server-side remote-signer requests.

The admin console connects a NIP-46 bunker in the browser, but approvals
should also reach an administrator's remote signer when no console is open.
That requires the *node* to act as a NIP-46 client: publish a kind-24133
request (NIP-44 encrypted) to the relays the signer listens on, where the
signer prompts its owner and returns the signed event on the same relays.

This module implements that client from first principles on top of
``nostr_sdk``'s NIP-44 primitives and the fork's own event signer. It does not
use ``nostr_sdk.NostrConnect`` because that binding only parses ``bunker://``
URIs (no ``nostrconnect://`` flow) and hides the transport, whereas the
signer bridge needs both the request/response correlation and an injectable
transport for hermetic tests.

Nothing here holds authority: a request is only a *request*. The signer's
owner still approves every signature, and the returned event is validated by
``nostr_operations.validate_signed_approval`` before it is published.
"""

from __future__ import annotations

import json
import secrets
import time
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urlsplit

from .nostr_identity import _is_hex64, _sign_event
from .nostr_operations import _derive_pubkey

# NIP-46 transport event kind.
NIP46_KIND = 24133

# A transport publishes a signed request event to the signer's relays and
# returns the first response event authored by ``responder_pubkey`` that is
# addressed to the request's author (the client's ``p`` tag). It returns None
# on timeout. Injectable so the client can be tested without a relay.
Transport = Callable[[list[str], dict[str, Any], str, float], dict[str, Any] | None]


class Nip46Error(Exception):
    """A NIP-46 request failed (transport, protocol or signer error)."""


class Nip46Timeout(Nip46Error):
    """No response arrived from the signer within the timeout."""


# --------------------------------------------------------------------------- #
# bunker:// parsing

def _normalise_npub(value: str) -> str:
    if value.startswith("npub1"):
        from nostr_sdk import PublicKey

        return PublicKey.parse(value).to_hex()
    return value.lower()


def parse_bunker_uri(uri: str) -> dict[str, Any]:
    """Parse a ``bunker://<signer-pubkey>?relay=...&secret=...`` URI.

    Returns ``{"signer_pubkey", "relays", "secret"}``. The secret (when
    present) is the pairing credential the signer expects on ``connect``.
    """
    if not isinstance(uri, str) or not uri.startswith("bunker://"):
        raise Nip46Error("bunker URI must start with bunker://")
    split = urlsplit(uri)
    signer = unquote(split.netloc) or unquote(split.path.lstrip("/"))
    signer = _normalise_npub(signer.strip())
    if not _is_hex64(signer):
        raise Nip46Error("bunker URI is missing a valid signer pubkey")
    query = parse_qs(split.query)
    relays = [unquote(r) for r in query.get("relay", []) if r]
    if not relays:
        raise Nip46Error("bunker URI names no relay")
    secret = (query.get("secret") or [None])[0]
    return {"signer_pubkey": signer, "relays": relays, "secret": secret}


# --------------------------------------------------------------------------- #
# message construction

def _encrypt(client_sk: str, signer_pubkey: str, plaintext: str) -> str:
    from nostr_sdk import Nip44Version, PublicKey, SecretKey, nip44_encrypt

    return nip44_encrypt(
        SecretKey.parse(client_sk),
        PublicKey.parse(signer_pubkey),
        plaintext,
        Nip44Version.V2,
    )


def _decrypt(client_sk: str, signer_pubkey: str, payload: str) -> str:
    from nostr_sdk import PublicKey, SecretKey, nip44_decrypt

    return nip44_decrypt(SecretKey.parse(client_sk), PublicKey.parse(signer_pubkey), payload)


def build_request_event(
    *,
    client_sk: str,
    signer_pubkey: str,
    method: str,
    params: list[Any],
    request_id: str | None = None,
    created_at: int | None = None,
) -> dict[str, Any]:
    """Build and sign a kind-24133 NIP-46 request event.

    The JSON-RPC body ``{"id", "method", "params"}`` is NIP-44 encrypted to
    the signer; the event carries the standard ``p`` (signer) tag.
    """
    request_id = request_id or secrets.token_hex(8)
    payload = json.dumps({"id": request_id, "method": method, "params": params})
    content = _encrypt(client_sk, signer_pubkey, payload)
    client_pubkey = _derive_pubkey(client_sk)
    event = _sign_event(
        client_sk,
        client_pubkey,
        NIP46_KIND,
        content,
        [["p", signer_pubkey]],
        created_at=created_at,
    )
    event["_request_id"] = request_id  # internal correlation hint (never published)
    return event


def parse_response(client_sk: str, signer_pubkey: str, event: dict[str, Any]) -> dict[str, Any]:
    """Decrypt a signer's kind-24133 response into its JSON-RPC body."""
    if int(event.get("kind") or 0) != NIP46_KIND:
        raise Nip46Error("response is not a NIP-46 event")
    if str(event.get("pubkey", "")).lower() != signer_pubkey.lower():
        raise Nip46Error("response is not from the requested signer")
    try:
        plaintext = _decrypt(client_sk, signer_pubkey, str(event.get("content") or ""))
    except Exception as exc:  # noqa: BLE001 - undecryptable is a protocol error
        raise Nip46Error(f"could not decrypt the signer response: {exc}") from exc
    try:
        body = json.loads(plaintext)
    except ValueError as exc:
        raise Nip46Error("signer response was not valid JSON") from exc
    if not isinstance(body, dict):
        raise Nip46Error("signer response was not a JSON object")
    return body


# --------------------------------------------------------------------------- #
# client

def _transport_or_default(transport: Transport | None) -> Transport:
    return transport or relay_transport


def sign_event_via_bunker(
    *,
    client_sk: str,
    signer_pubkey: str,
    relays: list[str],
    unsigned_event: dict[str, Any],
    secret: str | None = None,
    transport: Transport | None = None,
    timeout: float = 60.0,
    connect: bool = True,
) -> dict[str, Any]:
    """Ask a remote signer to sign ``unsigned_event`` via NIP-46.

    Sends ``connect`` first when a secret is supplied (the signer authorises
    the client), then ``sign_event``. Returns the signed event dict; raises
    :class:`Nip46Error` on a signer error and :class:`Nip46Timeout` when no
    response arrives. The caller MUST still validate the returned event.
    """
    exchange = _transport_or_default(transport)
    deadline = time.time() + timeout

    if connect and secret is not None:
        connect_event = build_request_event(
            client_sk=client_sk,
            signer_pubkey=signer_pubkey,
            method="connect",
            params=[signer_pubkey, secret],
        )
        remaining = max(0.1, deadline - time.time())
        response = exchange(relays, connect_event, signer_pubkey, remaining)
        if response is None:
            raise Nip46Timeout("signer did not answer the connect request")
        body = parse_response(client_sk, signer_pubkey, response)
        if body.get("error"):
            raise Nip46Error(f"signer refused the connection: {body['error']}")

    request_event = build_request_event(
        client_sk=client_sk,
        signer_pubkey=signer_pubkey,
        method="sign_event",
        params=[json.dumps(unsigned_event)],
    )
    remaining = max(0.1, deadline - time.time())
    response = exchange(relays, request_event, signer_pubkey, remaining)
    if response is None:
        raise Nip46Timeout(f"signer {signer_pubkey[:12]}… did not answer within {timeout:.0f}s")
    body = parse_response(client_sk, signer_pubkey, response)
    if body.get("error"):
        raise Nip46Error(f"signer rejected the request: {body['error']}")
    result = body.get("result")
    if not isinstance(result, str):
        raise Nip46Error("signer response contained no signed event")
    try:
        signed = json.loads(result)
    except ValueError as exc:
        raise Nip46Error("signer returned an unparseable event") from exc
    if not isinstance(signed, dict):
        raise Nip46Error("signer returned a non-object event")
    return signed


# --------------------------------------------------------------------------- #
# default relay transport

def relay_transport(
    relays: list[str],
    event: dict[str, Any],
    responder_pubkey: str,
    timeout: float,
) -> dict[str, Any] | None:
    """Publish ``event`` to ``relays`` and wait for the signer's response.

    One short-lived WebSocket per relay: REQ for kind-24133 events addressed
    to the client (``#p``) plus our EVENT, then wait until the shared deadline
    for the first event authored by ``responder_pubkey``. Best-effort per
    relay; returns None if none answers.
    """
    from websockets.sync.client import connect as ws_connect

    client_pubkey = event.get("pubkey", "")
    since = int(event.get("created_at", time.time())) - 5
    sub_id = "nostrhost-nip46-" + secrets.token_hex(4)
    subscription = json.dumps(["REQ", sub_id, {"kinds": [NIP46_KIND], "#p": [client_pubkey], "since": since}])
    deadline = time.time() + timeout

    for relay in relays:
        if time.time() >= deadline:
            break
        try:
            with ws_connect(relay, open_timeout=min(10.0, max(1.0, timeout))) as ws:
                ws.send(subscription)
                ws.send(json.dumps(["EVENT", event]))
                while time.time() < deadline:
                    try:
                        message = json.loads(ws.recv(timeout=0.5))
                    except TimeoutError:
                        continue
                    if not isinstance(message, list) or message[0] != "EVENT":
                        continue
                    candidate = message[2]
                    if not isinstance(candidate, dict):
                        continue
                    if str(candidate.get("pubkey", "")).lower() != responder_pubkey.lower():
                        continue
                    return candidate
        except Exception:  # noqa: BLE001 - try the next relay
            continue
    return None
