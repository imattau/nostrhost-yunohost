"""Small MCP-facing adapter for the Nostr control-plane operation chain.

This module intentionally does not depend on an MCP SDK.  MCP servers can
map ``list_tools`` and ``call_tool`` to their SDK's types, while all
authorization, approval, execution, and audit behavior remains in the
signed operation chain.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from .nostr_operations import (
    approve_operation_nip46,
    build_operation_request,
    known_tools,
    tool_spec,
)

KIND_EXECUTION_RESULT = 2204


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

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Publish one signed operation request and return its correlation id."""
        spec = tool_spec(name)
        if spec is None:
            raise MCPAdapterError(f"unknown tool {name!r}")
        if arguments is not None and not isinstance(arguments, dict):
            raise MCPAdapterError("MCP tool arguments must be an object")
        event = build_operation_request(
            self.requester_sk, self.requester_pubkey, name, arguments or {}
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
        """Project a kind-2204 result received from the control relay."""
        if event.get("kind") != KIND_EXECUTION_RESULT:
            return False
        request_id = next(
            (tag[1] for tag in event.get("tags") or [] if len(tag) >= 2 and tag[0] == "e"),
            None,
        )
        if not request_id:
            return False
        try:
            body = json.loads(event.get("content") or "{}")
        except (TypeError, json.JSONDecodeError):
            return False
        if not isinstance(body, dict) or "ok" not in body:
            return False
        self.results[request_id] = body
        return True

    def result(self, request_id: str) -> dict[str, Any] | None:
        """Return the latest projected result, or ``None`` while pending."""
        return self.results.get(request_id)
