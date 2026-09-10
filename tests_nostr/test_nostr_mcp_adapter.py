from __future__ import annotations

import hashlib
import json
import os

import pytest
from coincurve import PublicKeyXOnly

from yunohost.nostr_identity import _sign_event
from yunohost.nostr_mcp_adapter import MCPAdapterError, NostrMCPAdapter
from yunohost.nostr_operations import build_execution_result


def new_key():
    sk = os.urandom(32).hex()
    return sk, PublicKeyXOnly.from_secret(bytes.fromhex(sk)).format().hex()


def test_mcp_adapter_lists_native_tools_and_submits_signed_request():
    sk, pk = new_key()
    sent = []
    adapter = NostrMCPAdapter(
        requester_sk=sk,
        requester_pubkey=pk,
        control_relay="ws://relay",
        transport=lambda relay, event: sent.append((relay, event)),
    )

    tools = adapter.list_tools()
    assert any(tool["name"] == "system.version" for tool in tools)
    response = adapter.call_tool("system.version", {})

    assert response["isError"] is False
    assert response["_nostr"]["request_id"] == sent[0][1]["id"]
    assert json.loads(sent[0][1]["content"]) == {"tool": "system.version", "args": {}}


def test_mcp_adapter_preserves_authenticated_actor_identity():
    sk, pk = new_key()
    _, actor_pk = new_key()
    sent = []
    adapter = NostrMCPAdapter(
        requester_sk=sk,
        requester_pubkey=pk,
        control_relay="ws://relay",
        transport=lambda relay, event: sent.append(event),
    )
    adapter.call_tool("system.version", actor_pubkey=actor_pk)
    assert ["actor", actor_pk] in sent[0]["tags"]
    assert sent[0]["pubkey"] == pk


def test_mcp_adapter_correlates_result_events():
    sk, pk = new_key()
    adapter = NostrMCPAdapter(
        requester_sk=sk,
        requester_pubkey=pk,
        control_relay="ws://relay",
        transport=lambda relay, event: None,
    )
    request = adapter.call_tool("system.version")
    request_id = request["_nostr"]["request_id"]
    server_sk, server_pk = new_key()
    result = build_execution_result(
        server_sk, server_pk, request_id, ok=True, actor_pubkey=pk, result={"ready": True}
    )

    assert adapter.ingest_event(result)
    assert adapter.result(request_id) == {
        "ok": True, "result": {"ready": True}, "_nostr_actor": pk
    }


def test_mcp_adapter_rejects_unknown_tool():
    sk, pk = new_key()
    adapter = NostrMCPAdapter(
        requester_sk=sk,
        requester_pubkey=pk,
        control_relay="ws://relay",
        transport=lambda relay, event: None,
    )
    with pytest.raises(MCPAdapterError):
        adapter.call_tool("system.upgrade")


def test_mcp_adapter_uses_nip46_for_privileged_approval():
    requester_sk, requester_pk = new_key()
    owner_sk, owner_pk = new_key()
    sent = []
    adapter = NostrMCPAdapter(
        requester_sk=requester_sk,
        requester_pubkey=requester_pk,
        control_relay="ws://relay",
        transport=lambda relay, event: sent.append(event),
    )
    request_id = adapter.call_tool("system.version")["_nostr"]["request_id"]

    def bunker_sign(unsigned):
        return _sign_event(
            owner_sk,
            owner_pk,
            unsigned["kind"],
            unsigned["content"],
            unsigned["tags"],
        )

    approval = adapter.approve_with_nip46(request_id, signer=bunker_sign, admin_pubkey=owner_pk)
    assert approval["kind"] == 2201
    assert ["t", "nip46"] in approval["tags"]
    assert sent[-1] == approval


def test_nip46_approval_cannot_be_retargeted_after_signing():
    requester_sk, requester_pk = new_key()
    owner_sk, owner_pk = new_key()
    adapter = NostrMCPAdapter(
        requester_sk=requester_sk,
        requester_pubkey=requester_pk,
        control_relay="ws://relay",
        transport=lambda relay, event: None,
    )
    request_id = adapter.call_tool("system.version")["_nostr"]["request_id"]

    def bad_sign(unsigned):
        event = _sign_event(owner_sk, owner_pk, unsigned["kind"], unsigned["content"], unsigned["tags"])
        event["tags"] = [["e", "f" * 64], ["t", "nip46"]]
        return event

    with pytest.raises(Exception, match="does not target"):
        adapter.approve_with_nip46(request_id, signer=bad_sign, admin_pubkey=owner_pk)
