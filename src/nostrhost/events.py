"""Operation event streaming (SSE source).

The executor publishes signed chain events (2203 execution.started, 2205
execution.progress, 2204 execution.result) to the control relay.  This module
subscribes to those kinds and yields the events for one operation, so
interfaces (the admin UI via SSE, CLI ``--follow``, MCP) render live progress
-- the replacement for moulinette's SSE/log-broker plumbing.

The relay's control kinds are NIP-42 protected, so the stream authenticates
as the operator (or an injected auth tuple) before REQ.
"""

from __future__ import annotations

import json
import secrets
import time
from collections.abc import Iterator
from typing import Any

from yunohost.nostr_identity import _sign_auth_event, _wait_auth_ok, default_auth

from yunohost.nostr_operations import (
    KIND_EXECUTION_RESULT,
    KIND_EXECUTION_STARTED,
    KIND_EXECUTION_PROGRESS,
    KIND_OPERATION_REJECTION,
)

# Execution kinds plus 2202 (rejection): a rejected operation is also a
# terminal outcome, so the stream must surface it or interfaces polling
# op_status could never tell "rejected" apart from "still awaiting approval".
STREAM_KINDS = (KIND_EXECUTION_STARTED, KIND_EXECUTION_PROGRESS, KIND_EXECUTION_RESULT, KIND_OPERATION_REJECTION)


def _e_tag(event: dict[str, Any]) -> str | None:
    for tag in event.get("tags") or []:
        if tag and tag[0] == "e" and len(tag) > 1:
            return tag[1]
    return None


def _tag_value(event: dict[str, Any], name: str) -> str | None:
    for tag in event.get("tags") or []:
        if tag and tag[0] == name and len(tag) > 1:
            return str(tag[1])
    return None


def _d_tag(event: dict[str, Any]) -> str | None:
    """The event's ``d`` tag value (NIP-01 replaceable-event identifier).

    Shared with :mod:`nostrhost.nip51_permissions`, which imports this
    directly rather than re-deriving it from its own ``_tag_values`` — one
    implementation for both, so a change to "which d tag wins" on a
    duplicate-tagged event only has to be made once.
    """
    return _tag_value(event, "d")


def stream_operation_events(
    request_id: str,
    *,
    relay_url: str,
    auth: tuple[str, str] | None = None,
    timeout: float = 30.0,
) -> Iterator[dict[str, Any]]:
    """Yield the signed chain events for ``request_id`` until its result.

    Subscribes to the control relay for the execution kinds, filters by the
    ``e`` tag, yields each event (started/progress/result), and stops once a
    kind-2204 result for this request is seen.  Yields nothing if the relay
    cannot be reached within ``timeout``.
    """
    from websockets.sync.client import connect

    auth = auth or default_auth()
    deadline = time.time() + timeout
    try:
        with connect(relay_url) as ws:
            sub_id = "nostrhost-events-" + secrets.token_hex(4)
            request = json.dumps(["REQ", sub_id, {"kinds": list(STREAM_KINDS), "#e": [request_id]}])
            ws.send(request)
            while time.time() < deadline:
                try:
                    msg = json.loads(ws.recv(timeout=0.5))
                except TimeoutError:
                    continue
                if msg[0] == "AUTH":
                    if auth is not None:
                        challenge = msg[1] if len(msg) > 1 else ""
                        auth_event = _sign_auth_event(auth[0], auth[1], relay_url, challenge, sub_id)
                        ws.send(json.dumps(["AUTH", auth_event]))
                        _wait_auth_ok(ws, auth_event["id"], deadline)
                        ws.send(request)  # re-send after auth
                    continue
                if msg[0] != "EVENT":
                    if msg[0] == "EOSE":
                        continue
                    continue
                event = msg[2]
                if _e_tag(event) != request_id:
                    continue
                yield event
                if int(event.get("kind", 0)) in (KIND_EXECUTION_RESULT, KIND_OPERATION_REJECTION):
                    return
    except Exception:  # noqa: BLE001 - stream is best-effort
        return


def sse_format(event: dict[str, Any]) -> str:
    """Render an event dict as a Server-Sent Events frame."""
    return f"data: {json.dumps(event)}\n\n"


def sse_ping() -> str:
    """Heartbeat comment frame to keep the connection alive."""
    return ": ping\n\n"


#: A single REQ is silently truncated by the relay's backend to this many
#: events (badger's default `MaxLimit/4`; see nostrhost-control server.go).
#: Any "read the whole history" path must page with `until` or it will drop
#: the older events.
RELAY_DEFAULT_PAGE = 5000


def _collect_page(ws: Any, sub_id: str, request: str, deadline: float, events: list[dict[str, Any]]) -> int:
    """Drain one REQ until EOSE; return the number of events received."""
    received = 0
    while time.time() < deadline:
        try:
            msg = json.loads(ws.recv(timeout=0.5))
        except TimeoutError:
            continue
        if msg[0] == "AUTH":
            continue  # handled by the caller's auth handshake before paging
        if msg[0] == "EVENT":
            events.append(msg[2])
            received += 1
        elif msg[0] == "EOSE":
            return received
        elif msg[0] == "CLOSED":
            return received
    return received


def query_chain_events(
    relay_url: str,
    *,
    kinds: tuple[int, ...] | None = None,
    authors: tuple[str, ...] | None = None,
    limit: int = 100,
    since: int | None = None,
    auth: tuple[str, str] | None = None,
    timeout: float = 30.0,
    page_all: bool = False,
    page_limit: int = RELAY_DEFAULT_PAGE,
) -> list[dict[str, Any]]:
    """Query the control relay for signed chain events (the durable audit).

    The signed operation chain (kinds 2200 request / 2201 approval / 2202
    rejection / 2203 executing / 2204 result / 2205 progress, plus the
    capability/delegation kinds 31100 / 27236 / 27237) is the audit log
    (nostr_operations.py module docstring). This helper issues a REQ for the
    requested kinds against the control relay, authenticating as the operator
    (the control kinds are NIP-42 protected) exactly like
    :func:`stream_operation_events`, and returns the stored events in relay
    order (oldest first). Best-effort: an unreachable relay yields an empty
    list rather than raising, so a read-only audit call degrades gracefully.

    ``page_all`` pages backwards with ``until`` so a history larger than the
    relay's single-REQ cap cannot silently omit older events (the relay
    truncates an oversized/unlimited REQ to ``RELAY_DEFAULT_PAGE``); it stops
    at ``limit`` events, when a page comes back short, or when ``since`` is
    reached — whichever comes first. When False this is a single REQ (the
    legacy behaviour), for callers that only want a bounded recent window.
    """
    from yunohost.nostr_operations import CHAIN_KINDS

    from websockets.sync.client import connect

    auth = auth or default_auth()
    event_kinds = list(kinds) if kinds else list(CHAIN_KINDS)
    if not page_all:
        filters: dict[str, Any] = {"kinds": event_kinds, "limit": limit}
        if authors:
            filters["authors"] = list(authors)
        if since is not None:
            filters["since"] = int(since)
        deadline = time.time() + timeout
        events: list[dict[str, Any]] = []
        try:
            with connect(relay_url) as ws:
                sub_id = "nostrhost-audit-" + secrets.token_hex(4)
                request = json.dumps(["REQ", sub_id, filters])
                ws.send(request)
                while time.time() < deadline and len(events) < limit:
                    try:
                        msg = json.loads(ws.recv(timeout=0.5))
                    except TimeoutError:
                        continue
                    if msg[0] == "AUTH":
                        if auth is not None:
                            challenge = msg[1] if len(msg) > 1 else ""
                            auth_event = _sign_auth_event(auth[0], auth[1], relay_url, challenge, sub_id)
                            ws.send(json.dumps(["AUTH", auth_event]))
                            _wait_auth_ok(ws, auth_event["id"], deadline)
                            ws.send(request)  # re-send after auth
                        continue
                    if msg[0] == "EVENT":
                        events.append(msg[2])
                    elif msg[0] == "EOSE":
                        break
        except Exception:  # noqa: BLE001 - audit query is best-effort
            return []
        return events

    # Paged mode: walk backwards with `until`, deduping by event id.
    collected: dict[str, dict[str, Any]] = {}
    until: int | None = None
    try:
        with connect(relay_url) as ws:
            sub_id = "nostrhost-audit-" + secrets.token_hex(4)

            def _req() -> str:
                obj: dict[str, Any] = {"kinds": event_kinds, "limit": page_limit}
                if authors:
                    obj["authors"] = list(authors)
                if since is not None:
                    obj["since"] = int(since)
                if until is not None:
                    obj["until"] = until
                return json.dumps(["REQ", sub_id, obj])

            request = _req()
            # Authenticate first (if configured) on a throwaway REQ, then page
            # on the authenticated connection. When no auth is configured the
            # connection is unauth'd and the first page is read directly, so
            # the page is not consumed twice.
            if auth is not None:
                ws.send(request)
                auth_deadline = time.time() + timeout
                waste: list[dict[str, Any]] = []
                while time.time() < auth_deadline:
                    try:
                        msg = json.loads(ws.recv(timeout=0.5))
                    except TimeoutError:
                        continue
                    if msg[0] == "AUTH":
                        challenge = msg[1] if len(msg) > 1 else ""
                        auth_event = _sign_auth_event(auth[0], auth[1], relay_url, challenge, sub_id)
                        ws.send(json.dumps(["AUTH", auth_event]))
                        _wait_auth_ok(ws, auth_event["id"], auth_deadline)
                        break
                    if msg[0] in ("EOSE", "CLOSED"):
                        break
                    if msg[0] == "EVENT":
                        waste.append(msg[2])
                for event in waste or []:
                    collected[event["id"]] = event
                request = _req()
            ws.send(request)  # first page for the paging loop

            deadline = time.time() + timeout
            while time.time() < deadline and len(collected) < limit:
                page: list[dict[str, Any]] = []
                page_deadline = time.time() + timeout
                received = _collect_page(ws, sub_id, request, page_deadline, page)
                fresh = [event for event in page if event.get("id") not in collected]
                for event in page:
                    collected[event["id"]] = event
                # A short page means the store is exhausted; a full page with
                # no fresh ids would loop forever on a same-second boundary.
                if received < page_limit or not fresh:
                    break
                oldest = min(int(event.get("created_at") or 0) for event in page)
                next_until = oldest - 1 if (until is not None and oldest >= until) else oldest
                if next_until <= 0:
                    break
                if since is not None and next_until < int(since):
                    break
                until = next_until
                request = _req()
                ws.send(request)
    except Exception:  # noqa: BLE001 - audit query is best-effort
        events = list(collected.values())
        events = [
            event
            for event in events
            if since is None or int(event.get("created_at") or 0) >= int(since)
        ]
        return sorted(events, key=lambda e: int(e.get("created_at") or 0))[:limit]
    events = list(collected.values())
    if since is not None:
        events = [event for event in events if int(event.get("created_at") or 0) >= int(since)]
    events = sorted(events, key=lambda e: int(e.get("created_at") or 0))
    return events[:limit]
