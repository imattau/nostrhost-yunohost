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
    build_delegation,
    build_delegation_revocation,
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

    def __init__(self, policy=None, policy_owner=None):
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
            policy=policy,
            policy_owner=policy_owner,
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
    h.grant(["services.restart"])

    ev, handled = h.request("service.restart", {"name": "caddy"})
    request_id = ev["id"]
    assert handled
    assert h.engine.state(request_id) == OpState.REQUESTED
    assert h.events_by_kind(2202) == []  # not yet auto-resolved

    assert h.approve(request_id)
    assert h.engine.state(request_id) == OpState.SUCCEEDED
    assert h.backend.calls == [("service.restart", {"name": "caddy"})]

    started = h.events_by_kind(2203)
    results = h.events_by_kind(2204)
    assert len(started) == len(results) == 1
    assert started[0]["pubkey"] == h.server_pk
    assert ["e", request_id] in started[0]["tags"]
    assert results[0]["pubkey"] == h.server_pk
    body = _content(results[0])
    assert body["ok"] is True
    assert body["result"] == {"ok": "service.restart"}


def test_policy_adapter_receives_actor_and_is_published_in_result():
    decisions = []

    def policy(tool, args, actor):
        decisions.append((tool, args, actor))
        return {"allow": True, "version": "policy-v1", "plan_sha256": "abc"}

    h = Harness(policy=policy)
    h.grant(["services.restart"])
    ev, _ = h.request("service.restart", {"name": "caddy"})
    assert h.approve(ev["id"])
    assert len(decisions) == 2  # request-time and approval-time evaluation
    assert decisions[0][0] == "service.restart" and decisions[0][2] == h.agent_pk
    body = _content(h.events_by_kind(2204)[0])
    assert body["policy"] == {"allow": True, "version": "policy-v1", "plan_sha256": "abc"}


def test_policy_adapter_can_deny_before_provider_execution():
    h = Harness(policy=lambda _tool, _args, _actor: {"allow": False, "reason": "plan is untrusted"})
    h.grant(["server.read"])
    ev, handled = h.request("system.version")
    assert handled and h.engine.state(ev["id"]) == OpState.REJECTED
    assert h.backend.calls == []
    assert _content(h.events_by_kind(2204)[0])["reason"] == "policy_denied:plan is untrusted"


def test_owner_policy_requires_operator_approval():
    h = Harness(policy=lambda _tool, _args, _actor: {"allow": True, "owner_signature_required": True})
    h.grant(["services.restart"])
    ev, _ = h.request("service.restart", {"name": "caddy"})
    assert not h.approve(ev["id"])
    assert h.engine.state(ev["id"]) == OpState.REQUESTED

    h.engine._policy_owner = h.admin_pk
    assert h.approve(ev["id"])
    assert h.engine.state(ev["id"]) == OpState.SUCCEEDED


def test_e2e_preserves_actor_separately_from_request_signer():
    h = Harness()
    _, actor_pk = new_key()
    h.grant(["services.restart"], subject_pk=actor_pk)
    ev = build_operation_request(h.agent_sk, h.agent_pk, "service.restart", {"name": "caddy"}, actor_pubkey=actor_pk)
    assert h.engine.handle_event(ev)
    assert h.engine.records[ev["id"]].requester == h.agent_pk
    assert h.engine.records[ev["id"]].actor == actor_pk
    assert h.approve(ev["id"])
    assert ["actor", actor_pk] in h.events_by_kind(2203)[0]["tags"]
    assert ["actor", actor_pk] in h.events_by_kind(2204)[0]["tags"]


def test_actor_scope_gates_request_not_requester():
    """The MCP adapter signs as a trusted node key; the client npub rides as
    the actor and its capability grant is what authorizes the request."""
    h = Harness()
    _, actor_pk = new_key()
    # actor without a grant is rejected even though the requester is an admin
    ev = build_operation_request(h.admin_sk, h.admin_pk, "service.restart", {"name": "caddy"}, actor_pubkey=actor_pk)
    assert h.engine.handle_event(ev)
    assert h.engine.state(ev["id"]) == OpState.REJECTED
    assert _content(h.events_by_kind(2204)[0]) == {"ok": False, "reason": "unauthorized"}

    h.grant(["server.read"], subject_pk=actor_pk)
    ev2 = build_operation_request(h.admin_sk, h.admin_pk, "system.status", {}, actor_pubkey=actor_pk)
    assert h.engine.handle_event(ev2)
    assert h.engine.state(ev2["id"]) == OpState.SUCCEEDED
    assert ["actor", actor_pk] in h.events_by_kind(2204)[0]["tags"]


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
    ev, handled = h.request("service.restart", {"name": "caddy"}, requester_sk=h.admin_sk, requester_pk=h.admin_pk)
    assert h.engine.state(ev["id"]) == OpState.REQUESTED
    assert h.approve(ev["id"])
    assert h.engine.state(ev["id"]) == OpState.SUCCEEDED
    assert h.backend.calls == [("service.restart", {"name": "caddy"})]


def test_rejection_by_admin_denies():
    h = Harness()
    h.grant(["services.restart"])
    ev, handled = h.request("service.restart", {"name": "caddy"})
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
    h.grant(["services.restart"])
    ev, handled = h.request("service.restart", {"name": "caddy"})
    request_id = ev["id"]
    other_sk, other_pk = new_key()
    ev_na = build_approval(other_sk, other_pk, request_id)
    assert not h.engine.handle_event(ev_na)  # correctly signed but not by an admin
    assert h.engine.state(request_id) == OpState.REQUESTED
    assert h.backend.calls == []


def test_execute_requires_approval_for_default_tools():
    h = Harness()
    h.grant(["services.restart"])
    ev, handled = h.request("service.restart", {"name": "caddy"})
    # no approval given -> nothing executed
    assert handled
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
    h.grant(["services.restart"])
    ev, handled = h.request("service.restart", {"name": "caddy"})
    request_id = ev["id"]
    assert h.engine.state(request_id) == OpState.REQUESTED  # approval-gated, not auto-executed
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


def test_subscribe_processes_live_events_after_eose(monkeypatch):
    """After the replay EOSE, live events must be processed immediately — not
    buffered into the replay list forever (a restart-side regression that
    left post-restart approvals unexecuted on the VM)."""
    import asyncio
    import websockets

    from yunohost.nostr_operationsd import subscribe_loop

    h = Harness()
    h.grant(["server.read"])
    request_ev, _ = h.request("system.version")
    approval_ev = build_approval(h.admin_sk, h.admin_pk, request_ev["id"])

    class FakeWS:
        def __init__(self):
            self._msgs = [
                ["EVENT", "s", request_ev],
                ["EOSE", "s"],
                ["EVENT", "s", approval_ev],
            ]
            self._i = 0

        async def send(self, data):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def __aiter__(self):
            return self

        async def __anext__(self):
            if self._i < len(self._msgs):
                m = self._msgs[self._i]
                self._i += 1
                return json.dumps(m)
            raise StopAsyncIteration

    calls = {"n": 0}

    def fake_connect(url):
        calls["n"] += 1
        if calls["n"] == 1:
            return FakeWS()
        raise RuntimeError("end the first connection")  # -> daemon reconnect sleep

    monkeypatch.setattr(websockets, "connect", fake_connect)

    async def drive():
        task = asyncio.create_task(subscribe_loop("ws://x", engine=h.engine))
        try:
            await asyncio.wait_for(task, timeout=1.0)
        except asyncio.TimeoutError:
            pass  # the daemon loop never returns by design

    asyncio.run(drive())
    assert h.engine.state(request_ev["id"]) == OpState.SUCCEEDED
    assert h.backend.calls == [("system.version", {})]


def test_write_tool_requires_write_scope():
    """service.restart (a write op) must be rejected without services.write."""
    h = Harness()
    h.grant(["services.read"])  # read scope is not enough
    ev, handled = h.request("service.restart", args={"name": "nginx"})
    assert handled
    assert h.engine.state(ev["id"]) == OpState.REJECTED
    assert h.backend.calls == []


def test_write_tool_requires_approval_then_executes():
    h = Harness()
    h.grant(["services.restart"])
    ev, handled = h.request("service.restart", args={"name": "dnsmasq"})
    request_id = ev["id"]
    assert handled
    assert h.engine.state(request_id) == OpState.REQUESTED  # approval-gated
    assert h.backend.calls == []
    assert h.approve(request_id)
    assert h.engine.state(request_id) == OpState.SUCCEEDED
    assert h.backend.calls == [("service.restart", {"name": "dnsmasq"})]
    results = h.events_by_kind(2204)
    assert results[0]["pubkey"] == h.server_pk  # executed by the server key


def test_service_restart_handler_argument_validation():
    """The write handler rejects malformed args before touching services."""
    from yunohost.nostr_operations import OperationError, _safe_service_restart

    with pytest.raises(OperationError):
        _safe_service_restart()  # no name
    with pytest.raises(OperationError):
        _safe_service_restart(name="nginx", extra="boom")


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


def test_rollback_apply_full_chain_granted_and_approved():
    """rollback.apply is a first-class chain operation: scope-granted agent
    requests, admin approval gates execution, and the plan steps run through
    the same backend the engine uses (audited 2203/2204 signed by the server
    key)."""
    h = Harness()
    h.grant(["state.write"])

    ev, handled = h.request("rollback.apply", args={"plan": _sample_plan()})
    request_id = ev["id"]
    assert handled
    assert h.engine.state(request_id) == OpState.REQUESTED  # approval-gated
    assert h.backend.calls == []

    assert h.approve(request_id)
    assert h.engine.state(request_id) == OpState.SUCCEEDED
    assert ("service.control", {"name": "dnsmasq", "action": "restart"}) in h.backend.calls

    started = h.events_by_kind(2203)
    results = h.events_by_kind(2204)
    assert len(started) == len(results) == 1
    assert started[0]["pubkey"] == h.server_pk
    assert results[0]["pubkey"] == h.server_pk
    body = _content(results[0])
    assert body["ok"] is True
    steps = body["result"]["steps"]
    assert steps[0]["status"] == "executed"


def test_delegation_authorizes_subset_and_revocation_removes_access():
    import time

    h = Harness()
    h.grant(["services.restart"])
    delegate_sk, delegate_pk = new_key()
    delegation = build_delegation(
        h.agent_sk, h.agent_pk, delegate_pk, h.server_pk, ["services.restart"], int(time.time()) + 3600
    )
    assert h.engine.handle_event(delegation)

    request = build_operation_request(delegate_sk, delegate_pk, "service.restart", {"name": "caddy"})
    assert h.engine.handle_event(request)
    assert h.engine.state(request["id"]) == OpState.REQUESTED
    assert h.approve(request["id"])
    assert h.engine.state(request["id"]) == OpState.SUCCEEDED

    assert h.engine.handle_event(build_delegation_revocation(h.agent_sk, h.agent_pk, delegation["id"]))
    denied = build_operation_request(delegate_sk, delegate_pk, "service.restart", {"name": "other"})
    assert h.engine.handle_event(denied)
    assert h.engine.state(denied["id"]) == OpState.REJECTED


def test_rollback_apply_denied_without_state_scope():
    h = Harness()
    h.grant(["services.write"])  # wrong scope for rollback.apply
    ev, handled = h.request("rollback.apply", args={"plan": _sample_plan()})
    assert handled
    assert h.engine.state(ev["id"]) == OpState.REJECTED
    assert h.backend.calls == []
    assert _content(h.events_by_kind(2204)[0]) == {"ok": False, "reason": "unauthorized"}


def test_rollback_apply_admin_can_request_and_approve():
    h = Harness()
    ev, handled = h.request(
        "rollback.apply", args={"plan": _sample_plan()}, requester_sk=h.admin_sk, requester_pk=h.admin_pk
    )
    assert handled
    assert h.engine.state(ev["id"]) == OpState.REQUESTED
    assert h.approve(ev["id"])
    assert h.engine.state(ev["id"]) == OpState.SUCCEEDED
    assert ("service.control", {"name": "dnsmasq", "action": "restart"}) in h.backend.calls


def test_rollback_apply_unapproved_never_executes():
    h = Harness()
    h.grant(["state.write"])
    ev, handled = h.request("rollback.apply", args={"plan": _sample_plan()})
    request_id = ev["id"]
    assert handled
    assert h.backend.calls == []
    assert h.events_by_kind(2203) == []
    assert h.events_by_kind(2204) == []
    assert h.engine.state(request_id) == OpState.REQUESTED


def test_rollback_apply_bad_plan_reports_failed_result():
    h = Harness()
    h.grant(["state.write"])
    ev, handled = h.request("rollback.apply", args={"plan": {"steps": []}})
    request_id = ev["id"]
    assert handled
    assert h.approve(request_id)
    assert h.engine.state(request_id) == OpState.FAILED
    body = _content(h.events_by_kind(2204)[0])
    assert body["ok"] is False
    assert "steps" in body["error"]


def test_rollback_apply_partial_plan_reports_failed_result():
    h = Harness()
    h.grant(["state.write"])
    plan = _sample_plan()
    plan["steps"][0].update(
        reversibility="impossible", automatic=False, tool=None, reverse="manual"
    )
    ev, handled = h.request("rollback.apply", args={"plan": plan})
    assert handled
    assert h.approve(ev["id"])
    assert h.engine.state(ev["id"]) == OpState.FAILED
    body = _content(h.events_by_kind(2204)[0])
    assert body["ok"] is False
    assert body["result"]["steps"][0]["status"] == "blocked"


def test_app_remove_handler_argument_validation():
    """The rollback app-removal handler is bounded: single app id, explicit
    purge flag, no extra args."""
    from yunohost.nostr_operations import OperationError, _safe_app_remove

    with pytest.raises(OperationError):
        _safe_app_remove()  # no app
    with pytest.raises(OperationError):
        _safe_app_remove(app="hello_nostr_ynh", extra="boom")


def test_subscribe_authenticates_via_nip42_then_reads(monkeypatch):
    """On an AUTH challenge the daemon signs kind 22242, waits for the auth
    OK, re-sends the REQ, and only then processes the replay — so protected
    kinds (NIP-42 restored) don't get missed (the live-after-EOSE + auth race
    seen on the VM where the projector missed an identity event)."""
    import asyncio
    import websockets

    from yunohost.nostr_operationsd import subscribe_loop

    h = Harness()
    h.grant(["server.read"])
    request_ev, _ = h.request("system.version")
    approval_ev = build_approval(h.admin_sk, h.admin_pk, request_ev["id"])

    sk, pk = new_key()
    monkeypatch.setattr(
        "yunohost.nostr_operationsd.default_auth", lambda: (sk, pk)
    )
    sent = []

    class FakeWS:
        def __init__(self):
            self._msgs = [
                ["AUTH", "challenge-read"],
                "__AUTH_OK__",
                ["EVENT", "s", request_ev],
                ["EOSE", "s"],
                ["EVENT", "s", approval_ev],
            ]
            self._i = 0
            self.auth_event = None

        async def send(self, data):
            sent.append(json.loads(data))
            if sent[-1][0] == "AUTH":
                self.auth_event = sent[-1][1]

        async def _next(self):
            if self._i >= len(self._msgs):
                await asyncio.sleep(3600)
            m = self._msgs[self._i]
            self._i += 1
            if m == "__AUTH_OK__":
                return json.dumps(["OK", self.auth_event["id"], True, "auth ok"])
            return json.dumps(m)

        async def recv(self):
            return await self._next()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def __aiter__(self):
            return self

        async def __anext__(self):
            return await self._next()

    fake = FakeWS()

    def fake_connect(url, **kwargs):
        return fake

    monkeypatch.setattr(websockets, "connect", fake_connect)

    async def drive():
        task = asyncio.create_task(subscribe_loop("ws://x", engine=h.engine))
        try:
            await asyncio.wait_for(task, timeout=1.0)
        except asyncio.TimeoutError:
            pass  # daemon loop never returns by design

    asyncio.run(drive())

    assert fake.auth_event is not None
    assert fake.auth_event["kind"] == 22242
    assert any(t[0] == "challenge" and t[1] == "challenge-read" for t in fake.auth_event["tags"])
    # REQ was re-sent after auth
    assert any(m[0] == "REQ" for m in sent)
    assert h.engine.state(request_ev["id"]) == OpState.SUCCEEDED
    assert h.backend.calls == [("system.version", {})]
