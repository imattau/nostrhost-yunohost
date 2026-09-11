"""Small MCP-facing adapter for the Nostr control-plane operation chain.

This module intentionally does not depend on an MCP SDK.  MCP servers can
map ``list_tools`` and ``call_tool`` to their SDK's types, while all
authorization, approval, execution, and audit behavior remains in the
signed operation chain.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any, Callable

from .nostr_operations import (
    approve_operation_nip46,
    build_operation_request,
    known_tools,
    tool_spec,
)

KIND_EXECUTION_RESULT = 2204
KIND_EXECUTION_PROGRESS = 2205


class MCPAdapterError(ValueError):
    """The MCP call or relay event could not be mapped safely."""


class NostrMCPAdapter:
    """Protocol-neutral MCP bridge backed by signed Nostr operations.

    ``transport`` receives ``(relay, event)`` and is the only publishing
    dependency.  Results are populated by feeding relay events to
    :meth:`ingest_event`; this keeps the adapter usable with both async MCP
    servers and the existing synchronous YunoHost daemon.
    """

    def __init__(
        self,
        *,
        requester_sk: str,
        requester_pubkey: str,
        control_relay: str,
        transport: Callable[[str, dict[str, Any]], None],
    ) -> None:
        self.requester_sk = requester_sk
        self.requester_pubkey = requester_pubkey
        self.control_relay = control_relay
        self.transport = transport
        self.results: dict[str, dict[str, Any]] = {}
        self.progress: dict[str, dict[str, Any]] = {}

    def list_tools(self) -> list[dict[str, Any]]:
        """Return MCP-compatible tool metadata from the native registry."""
        return [
            {
                "name": name,
                "description": tool_spec(name).description,
                "inputSchema": {"type": "object"},
            }
            for name in known_tools()
        ]

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        actor_pubkey: str | None = None,
    ) -> dict[str, Any]:
        """Publish one signed operation request and return its correlation id."""
        spec = tool_spec(name)
        if spec is None:
            raise MCPAdapterError(f"unknown tool {name!r}")
        if arguments is not None and not isinstance(arguments, dict):
            raise MCPAdapterError("MCP tool arguments must be an object")
        event = build_operation_request(
            self.requester_sk, self.requester_pubkey, name, arguments or {}, actor_pubkey=actor_pubkey
        )
        self.transport(self.control_relay, event)
        return {
            "content": [{"type": "text", "text": "operation submitted"}],
            "isError": False,
            "_nostr": {"request_id": event["id"], "kind": event["kind"]},
        }

    def approve_with_nip46(
        self,
        request_id: str,
        *,
        signer: Callable[[dict[str, Any]], dict[str, Any]],
        admin_pubkey: str,
        note: str | None = None,
    ) -> dict[str, Any]:
        """Publish a privileged approval signed by a NIP-46 remote signer."""
        return approve_operation_nip46(
            request_id,
            signer=signer,
            admin_pubkey=admin_pubkey,
            control_relay=self.control_relay,
            note=note,
            transport=self.transport,
        )

    def ingest_event(self, event: dict[str, Any]) -> bool:
        """Project a kind-2204 result (or 2205 progress) from the relay."""
        request_id = next(
            (tag[1] for tag in event.get("tags") or [] if len(tag) >= 2 and tag[0] == "e"),
            None,
        )
        if not request_id:
            return False
        kind = int(event.get("kind") or 0)
        if kind == KIND_EXECUTION_PROGRESS:
            try:
                body = json.loads(event.get("content") or "{}")
            except (TypeError, json.JSONDecodeError):
                return False
            if isinstance(body, dict) and "stage" in body:
                self.progress[request_id] = body
                return True
            return False
        if kind != KIND_EXECUTION_RESULT:
            return False
        try:
            body = json.loads(event.get("content") or "{}")
        except (TypeError, json.JSONDecodeError):
            return False
        if not isinstance(body, dict) or "ok" not in body:
            return False
        actor = next(
            (tag[1] for tag in event.get("tags") or [] if len(tag) >= 2 and tag[0] == "actor"),
            None,
        )
        if actor:
            body = {**body, "_nostr_actor": actor}
        self.results[request_id] = body
        return True

    def result(self, request_id: str) -> dict[str, Any] | None:
        """Return the latest projected result, or ``None`` while pending."""
        return self.results.get(request_id)

    def latest_progress(self, request_id: str) -> dict[str, Any] | None:
        """Return the latest projected 2205 progress for a request."""
        return self.progress.get(request_id)

    def events(self, request_id: str, *, timeout: float = 60.0) -> Iterator[dict[str, Any]]:
        """Stream a request's chain events (started/progress/result) live.

        Backed by ``nostrhost.events.stream_operation_events``; an MCP host
        can surface these as progress notifications.
        """
        from nostrhost.events import stream_operation_events

        return stream_operation_events(
            request_id,
            relay_url=self.control_relay,
            timeout=timeout,
        )
