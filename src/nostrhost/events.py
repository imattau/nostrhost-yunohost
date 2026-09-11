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
)

STREAM_KINDS = (KIND_EXECUTION_STARTED, KIND_EXECUTION_PROGRESS, KIND_EXECUTION_RESULT)


def _e_tag(event: dict[str, Any]) -> str | None:
    for tag in event.get("tags") or []:
        if tag and tag[0] == "e" and len(tag) > 1:
            return tag[1]
    return None


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
                if int(event.get("kind", 0)) == KIND_EXECUTION_RESULT:
                    return
    except Exception:  # noqa: BLE001 - stream is best-effort
        return


def sse_format(event: dict[str, Any]) -> str:
    """Render an event dict as a Server-Sent Events frame."""
    return f"data: {json.dumps(event)}\n\n"


def sse_ping() -> str:
    """Heartbeat comment frame to keep the connection alive."""
    return ": ping\n\n"
