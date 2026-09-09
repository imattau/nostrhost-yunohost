"""End-to-end engine tests for the operation vertical slice.

Proves the whole architectural claim without a relay or LDAP: signed chain
events fed to the engine produce the correct signed 2203/2204 outcome events,
authorisation gating (grant / admin / deny) works, and invalid transitions
are refused even when correctly signed.

The engine's publish callback is a capture list; the executor backend is a
fake recording tool calls.
"""

from __future__ import annotations

import json
import os

import pytest
from coincurve import PublicKeyXOnly

from yunohost.nostr_operations import (
    build_approval,
    build_capability,
    build_execution_result,
    build_execution_started,
    build_operation_request,
    build_rejection,
)
from yunohost.nostr_operations_state import OpState
from yunohost.nostr_operationsd import OperationEngine, _sorted_replay


def new_key():
    sk = os.urandom(32).hex()
    pk = PublicKeyXOnly.from_secret(bytes.fromhex(sk)).format().hex()
    return sk, pk


class FakeBackend:
    """Records tool executions; `fail` tools raise to exercise the error path."""

    def __init__(self):
        self.calls = []
        self.results = {"system.version": {"versions": {"yunohost": "12.1.41.2"}}}

    def execute(self, tool, args):
        self.calls.append((tool, args))
        if tool == "boom" or args.get("__force__") == "boom":
            raise RuntimeError("boom failed")
        return self.results.get(tool, {"ok": tool})


class Harness:
    """A wired engine: real signing, captured publishes, fake backend."""

    def __init__(self):
        self.server_sk, self.server_pk = new_key()
        self.admin_sk, self.admin_pk = new_key()
        self.agent_sk, self.agent_pk = new_key()
        self.published = []
        self.backend = FakeBackend()
        self.engine = OperationEngine(
            publish=self.published.append,
            server_sk=self.server_sk,
            admins=[self.admin_pk],
            backend=self.backend,
        )

    def grant(self, scopes, subject_pk=None):
        subject = subject_pk or self.agent_pk
        ev = build_capability(self.admin_sk, self.admin_pk, subject, "agent", scopes)
        assert self.engine.handle_event(ev)

    def request(self, tool, args=None, requester_sk=None, requester_pk=None):
        sk = requester_sk or self.agent_sk
        pk = requester_pk or self.agent_pk
        ev = build_operation_request(sk, pk, tool, args or {})
        return ev, self.engine.handle_event(ev)

    def approve(self, request_id):
        return self.engine.handle_event(build_approval(self.admin_sk, self.admin_pk, request_id))

    def events_by_kind(self, kind):
        return [e for e in self.published if e["kind"] == kind]


def _content(ev):
    return json.loads(ev["content"])


def test_e2e_request_approval_execute_result():
    h = Harness()
    h.grant(["server.read"])

    ev, handled = h.request("system.version")
    request_id = ev["id"]
    assert handled
    assert h.engine.state(request_id) == OpState.REQUESTED
    assert h.events_by_kind(2202) == []  # not yet auto-resolved

    assert h.approve(request_id)
    assert h.engine.state(request_id) == OpState.SUCCEEDED
    assert h.backend.calls == [("system.version", {})]

    started = h.events_by_kind(2203)
    results = h.events_by_kind(2204)
    assert len(started) == len(results) == 1
    assert started[0]["pubkey"] == h.server_pk
    assert ["e", request_id] in started[0]["tags"]
    assert results[0]["pubkey"] == h.server_pk
    body = _content(results[0])
    assert body["ok"] is True
    assert body["result"]["versions"]["yunohost"] == "12.1.41.2"


def test_e2e_denied_requester_is_auto_rejected():
    h = Harness()  # no grant for the agent

    ev, handled = h.request("system.version")
    assert handled
    request_id = ev["id"]
    assert h.engine.state(request_id) == OpState.REJECTED
    assert h.backend.calls == []
    assert _content(h.events_by_kind(2204)[0]) == {"ok": False, "reason": "unauthorized"}


def test_unknown_tool_is_auto_rejected():
    h = Harness()
    h.grant(["server.read"])
    ev, handled = h.request("no.such.tool")
    assert handled
    assert h.engine.state(ev["id"]) == OpState.REJECTED
    assert _content(h.events_by_kind(2204)[0])["reason"].startswith("unknown_tool")


def test_admin_can_operate_without_grant():
    h = Harness()
    ev, handled = h.request("system.version", requester_sk=h.admin_sk, requester_pk=h.admin_pk)
    assert h.engine.state(ev["id"]) == OpState.REQUESTED
    assert h.approve(ev["id"])
    assert h.engine.state(ev["id"]) == OpState.SUCCEEDED
    assert h.backend.calls == [("system.version", {})]


def test_rejection_by_admin_denies():
    h = Harness()
    h.grant(["server.read"])
    ev, handled = h.request("system.version")
    request_id = ev["id"]
    ev_rej = build_rejection(h.admin_sk, h.admin_pk, request_id, reason="not now")
    assert h.engine.handle_event(ev_rej)
    assert h.engine.state(request_id) == OpState.REJECTED
    assert h.backend.calls == []
    # a later approval must NOT resurrect the request
    assert not h.approve(request_id)
    assert h.engine.state(request_id) == OpState.REJECTED
    assert h.backend.calls == []


def test_approval_by_non_admin_is_ignored():
    h = Harness()
    h.grant(["server.read"])
    ev, handled = h.request("system.version")
    request_id = ev["id"]
    other_sk, other_pk = new_key()
    ev_na = build_approval(other_sk, other_pk, request_id)
    assert not h.engine.handle_event(ev_na)  # correctly signed but not by an admin
    assert h.engine.state(request_id) == OpState.REQUESTED
    assert h.backend.calls == []


def test_execute_requires_approval_for_default_tools():
    h = Harness()
    h.grant(["server.read"])
    ev, handled = h.request("system.version")
    request_id = ev["id"]
    # no approval given -> nothing executed
    assert h.backend.calls == []
    assert h.events_by_kind(2203) == []
    assert h.events_by_kind(2204) == []


def test_error_path_reports_failed_result():
    h = Harness()
    h.grant(["server.read"])
    # unknown tool reaches the registry anyway as a request; use boom via raw
    # request to a known-name-but-failing tool through the backend
    ev, handled = h.request("system.version", args={"__force__": "boom"})
    request_id = ev["id"]
    h.approve(request_id)
    assert h.engine.state(request_id) == OpState.FAILED
    body = _content(h.events_by_kind(2204)[0])
    assert body["ok"] is False


def test_replay_is_idempotent():
    h = Harness()
    h.grant(["server.read"])
    ev, handled = h.request("system.version")
    request_id = ev["id"]
    h.approve(request_id)
    calls_after = list(h.backend.calls)
    # replay the request event (relay re-send) — must not re-execute
    assert not h.engine.handle_event(ev)
    assert h.backend.calls == calls_after
    assert h.engine.state(request_id) == OpState.SUCCEEDED
    # replay approval — must not re-execute either
    assert not h.approve(request_id)
    assert h.backend.calls == calls_after


def test_result_events_observed_into_state():
    h = Harness()
    h.grant(["server.read"])
    ev, handled = h.request("system.version")
    request_id = ev["id"]
    # simulate another executor's lifecycle replaying 2203/2204
    h.engine.handle_event(build_execution_started(h.server_sk, h.server_pk, request_id))
    assert h.engine.state(request_id) == OpState.EXECUTING
    h.engine.handle_event(build_execution_result(h.server_sk, h.server_pk, request_id, ok=True, result={"x": 1}))
    assert h.engine.state(request_id) == OpState.SUCCEEDED


def test_capability_events_scope_grants():
    h = Harness()
    assert not h.engine._authorized(h.agent_pk, "services.read")
    h.grant(["services.read"])
    assert h.engine._authorized(h.agent_pk, "services.read")
    assert not h.engine._authorized(h.agent_pk, "apps.read")


def test_scope_gating_denies_other_scope():
    h = Harness()
    h.grant(["services.read"])  # wrong scope for system.version
    ev, handled = h.request("system.version")
    assert h.engine.state(ev["id"]) == OpState.REJECTED
    assert h.backend.calls == []


def test_tool_args_are_forwarded():
    h = Harness()
    h.grant(["apps.read"])
    ev, handled = h.request("app.list", args={"full": True})
    request_id = ev["id"]
    h.approve(request_id)
    assert h.backend.calls == [("app.list", {"full": True})]


def test_replay_sort_places_grants_before_requests():
    """A same-second replay must feed capability grants to the engine before
    the requests they authorise — otherwise a restart rejects an in-flight
    request as unauthorized (seen live on the VM)."""
    from yunohost.nostr_operations import KIND_CAPABILITY, KIND_OPERATION_REQUEST

    now = 1788966000
    req = {"kind": KIND_OPERATION_REQUEST, "created_at": now, "id": "a" * 64}
    grant = {"kind": KIND_CAPABILITY, "created_at": now, "id": "b" * 64}
    approval = {"kind": 2201, "created_at": now, "id": "c" * 64}
    ordered = _sorted_replay([approval, req, grant])
    kinds = [e["kind"] for e in ordered]
    assert kinds == [KIND_CAPABILITY, KIND_OPERATION_REQUEST, 2201]
