"""Tests for operation-chain authoring + the safe tool registry."""

from __future__ import annotations

import json
import os

import pytest
from coincurve import PublicKeyXOnly

from yunohost.nostr_operations import (
    KIND_CAPABILITY,
    KIND_EXECUTION_RESULT,
    KIND_EXECUTION_STARTED,
    KIND_OPERATION_APPROVAL,
    KIND_OPERATION_REJECTION,
    KIND_OPERATION_REQUEST,
    OperationError,
    TOOLS,
    approve_operation,
    build_approval,
    build_capability,
    build_delegation,
    build_delegation_revocation,
    build_execution_result,
    build_execution_started,
    build_operation_request,
    build_rejection,
    grant_capability,
    known_tools,
    reject_operation,
    request_operation,
    tool_spec,
)


def new_key():
    sk = os.urandom(32).hex()
    pk = PublicKeyXOnly.from_secret(bytes.fromhex(sk)).format().hex()
    return sk, pk


class FakeTransport:
    """Captures published events instead of hitting a relay."""

    def __init__(self):
        self.events = []

    def __call__(self, relay_url, event):
        self.events.append(event)


def test_registry_has_the_safe_tools():
    assert known_tools() == [
        "app.list",
        "app.remove",
        "rollback.apply",
        "service.control",
        "service.restart",
        "service.status",
        "state.reconcile",
        "system.version",
    ]
    assert tool_spec("system.version").scope == "server.read"
    assert tool_spec("app.list").scope == "apps.read"
    assert tool_spec("service.status").scope == "services.read"
    assert tool_spec("service.restart").scope == "services.write"
    assert tool_spec("rollback.apply").scope == "state.write"
    for name, spec in TOOLS.items():
        assert spec.handler is not None
        assert spec.require_approval is True  # nothing auto-runs in Phase 3
    assert tool_spec("app.upgrade") is None


def test_request_event_shape():
    sk, pk = new_key()
    ev = build_operation_request(sk, pk, "system.version", {"full": True}, target="agent")
    assert ev["kind"] == KIND_OPERATION_REQUEST
    assert ev["pubkey"] == pk
    assert ["p", "agent"] in ev["tags"]
    body = json.loads(ev["content"])
    assert body["tool"] == "system.version"
    assert body["args"] == {"full": True}


def test_chain_step_events_reference_request():
    sk, pk = new_key()
    req_id = "a" * 64
    assert ["e", req_id] in build_approval(sk, pk, req_id)["tags"]
    assert ["e", req_id] in build_rejection(sk, pk, req_id, "no")["tags"]
    assert ["e", req_id] in build_execution_started(sk, pk, req_id)["tags"]
    res = build_execution_result(sk, pk, req_id, ok=False, error="boom")
    assert ["e", req_id] in res["tags"]
    body = json.loads(res["content"])
    assert body["ok"] is False and body["error"] == "boom"


def test_capability_event_shape():
    sk, pk = new_key()
    agent = "b" * 64
    ev = build_capability(sk, pk, agent, "agent", ["server.read", "apps.read"])
    assert ev["kind"] == KIND_CAPABILITY
    assert ["d", agent] in ev["tags"]
    assert json.loads(ev["content"]) == {"type": "agent", "scopes": ["server.read", "apps.read"]}


def test_delegation_event_shape_and_revocation():
    import time

    sk, pk = new_key()
    delegate = "b" * 64
    ev = build_delegation(sk, pk, delegate, "c" * 64, ["apps.read"], int(time.time()) + 3600)
    assert ev["kind"] == 27236
    assert ["p", delegate] in ev["tags"]
    assert ["server", "c" * 64] in ev["tags"]
    assert ["scope", "apps.read"] in ev["tags"]
    rev = build_delegation_revocation(sk, pk, ev["id"])
    assert rev["kind"] == 27237 and ["e", ev["id"]] in rev["tags"]


def test_request_operation_publishes_via_transport():
    agent_sk, agent_pk = new_key()
    transport = FakeTransport()
    ev = request_operation("system.version", {}, requester_sk=agent_sk, transport=transport)
    assert len(transport.events) == 1
    assert transport.events[0]["kind"] == KIND_OPERATION_REQUEST
    assert transport.events[0]["pubkey"] == agent_pk


def test_request_operation_rejects_unknown_tool():
    with pytest.raises(OperationError):
        request_operation("app.upgrade", {}, transport=FakeTransport())


def test_approve_and_reject_publish_as_admin():
    admin_sk, _ = new_key()
    transport = FakeTransport()
    approve_operation("c" * 64, admin_sk=admin_sk, transport=transport)
    reject_operation("c" * 64, admin_sk=admin_sk, reason="denied", transport=transport)
    assert [e["kind"] for e in transport.events] == [KIND_OPERATION_APPROVAL, KIND_OPERATION_REJECTION]


def test_grant_capability_publishes():
    admin_sk, _ = new_key()
    transport = FakeTransport()
    ev = grant_capability("d" * 64, ["services.read"], admin_sk=admin_sk, transport=transport)
    assert ev["kind"] == KIND_CAPABILITY
    assert ["d", "d" * 64] in ev["tags"]


def _sample_plan() -> dict:
    return {
        "schema": 1,
        "from": "a" * 64,
        "to": "b" * 64,
        "restic_snapshot": "",
        "steps": [
            {
                "section": "services",
                "file": "services/dnsmasq.toml",
                "action": "modify",
                "change_class": "runtime-setting",
                "reversibility": "automatic",
                "automatic": True,
                "restore_required": False,
                "tool": "service.control",
                "args": {"name": "dnsmasq", "action": "restart"},
                "reverse": "control",
            }
        ],
        "approved": False,
    }


def test_rollback_apply_handler_validates_args():
    from yunohost.nostr_operations import OperationError, _safe_rollback_apply

    with pytest.raises(OperationError):
        _safe_rollback_apply()  # no plan
    with pytest.raises(OperationError):
        _safe_rollback_apply(plan="not-a-plan")  # non-dict plan
    with pytest.raises(OperationError):
        _safe_rollback_apply(plan={"steps": []}, extra="boom")  # extra args


def test_rollback_apply_shared_executor_rejects_bad_plan():
    from yunohost.nostr_operations import OperationError, _run_rollback_apply

    with pytest.raises(OperationError):
        _run_rollback_apply({}, backend=object(), restic=None)  # missing plan key
    with pytest.raises(OperationError):
        _run_rollback_apply({"plan": {"steps": []}}, backend=object(), restic=None)  # empty steps
    plan = _sample_plan()
    plan["approved"] = True
    with pytest.raises(OperationError, match="already executed"):
        _run_rollback_apply({"plan": plan}, backend=object(), restic=None)


def test_operation_events_carry_first_class_actor():
    sk, pk = new_key()
    _, actor = new_key()
    request = build_operation_request(sk, pk, "system.version", {}, actor_pubkey=actor)
    assert ["actor", actor] in request["tags"]
    started = build_execution_started(sk, pk, request["id"], actor_pubkey=actor)
    result = build_execution_result(sk, pk, request["id"], ok=True, actor_pubkey=actor)
    assert ["actor", actor] in started["tags"]
    assert ["actor", actor] in result["tags"]
