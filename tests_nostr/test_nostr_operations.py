"""Tests for operation-chain authoring + the safe tool registry."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import new_key
from yunohost.nostr_operations import (
    KIND_CAPABILITY,
    KIND_OPERATION_APPROVAL,
    KIND_OPERATION_REJECTION,
    KIND_OPERATION_REQUEST,
    OperationError,
    TOOLS,
    approve_operation,
    build_approval,
    build_approval_template,
    build_capability,
    build_delegation,
    build_delegation_revocation,
    build_execution_result,
    build_execution_started,
    build_operation_request,
    build_rejection,
    build_rejection_template,
    get_operation,
    grant_capability,
    known_tools,
    list_capabilities,
    list_operations,
    reject_operation,
    request_operation,
    tool_spec,
    validate_signed_approval,
    validate_signed_rejection,
)


class FakeTransport:
    """Captures published events instead of hitting a relay."""

    def __init__(self):
        self.events = []

    def __call__(self, relay_url, event):
        self.events.append(event)


def test_registry_has_the_safe_tools():
    assert known_tools() == [
        "agent.contribution.settings.set",
        "agent.contribution.share",
        "agent.contribution.submit",
        "agent.disable",
        "agent.enable",
        "agent.export.run",
        "agent.init",
        "agent.mode.set",
        "agent.model.download",
        "agent.model.select",
        "app.change_url",
        "app.config.read",
        "app.config.set",
        "app.install",
        "app.list",
        "app.remove",
        "app.upgrade",
        "audit.get",
        "audit.list",
        "backup.create",
        "backup.delete",
        "backup.info",
        "backup.list",
        "backup.restore",
        "capability.delegate",
        "capability.grant",
        "capability.revoke",
        "catalog.announce",
        "catalog.announcements",
        "catalog.attest",
        "catalog.candidates",
        "catalog.declare",
        "catalog.get",
        "catalog.history",
        "catalog.list",
        "catalog.profile.get",
        "catalog.profile.set",
        "catalog.publish",
        "catalog.reverify",
        "catalog.trust",
        "catalog.verify",
        "credential.list",
        "credential.remove",
        "credential.set",
        "diagnosis.ignore",
        "diagnosis.ignored",
        "diagnosis.run",
        "diagnosis.unignore",
        "dns.apply",
        "dns.plan",
        "dns.subscribe",
        "dns.subscriptions",
        "dns.unsubscribe",
        "dns.verify",
        "dns.watch",
        "domain.add",
        "domain.cert.info",
        "domain.cert.install",
        "domain.inspect",
        "domain.list",
        "domain.primary.set",
        "domain.remove",
        "firewall.close",
        "firewall.list",
        "firewall.open",
        "firewall.reload",
        "identity.link",
        "identity.revoke",
        "logs.problems",
        "logs.read",
        "logs.web",
        "network.public_ip",
        "nostr.connectivity.set",
        "nsite.block.add",
        "nsite.block.list",
        "nsite.block.remove",
        "nsite.block.set",
        "nsite.discover",
        "nsite.domain.attach",
        "nsite.domain.detach",
        "nsite.domain.list",
        "nsite.gateway.configure",
        "nsite.gateway.disable",
        "nsite.gateway.enable",
        "nsite.gateway.status",
        "nsite.inspect",
        "nsite.list",
        "nsite.mirror",
        "nsite.publish",
        "nsite.publish.plan",
        "nsite.reachability",
        "nsite.register",
        "nsite.resolve",
        "nsite.snapshot",
        "nsite.unregister",
        "nsite.validate_manifest",
        "package.fetch_manifest",
        "package.plan",
        "package.reconcile",
        "rollback.apply",
        "service.control",
        "service.history",
        "service.restart",
        "service.status",
        "settings.get",
        "settings.list",
        "settings.reset",
        "settings.reset_all",
        "settings.set",
        "state.reconcile",
        "system.migrate",
        "system.migrations",
        "system.reboot",
        "system.shutdown",
        "system.status",
        "system.upgrade",
        "system.version",
        "updates.check",
        "updates.refresh",
        "user.create",
        "user.delete",
        "user.group.create",
        "user.group.delete",
        "user.group.list",
        "user.group.update",
        "user.list",
        "user.permission.add",
        "user.permission.info",
        "user.permission.list",
        "user.permission.remove",
        "user.permission.update",
        "user.update",
    ]
    assert tool_spec("system.version").scope == "server.read"
    assert tool_spec("system.version").require_approval is False
    assert tool_spec("app.list").scope == "apps.read"
    assert tool_spec("app.list").require_approval is False
    assert tool_spec("service.status").scope == "services.read"
    assert tool_spec("service.status").require_approval is False
    assert tool_spec("service.restart").scope == "services.restart"
    assert tool_spec("rollback.apply").scope == "state.write"
    assert tool_spec("package.plan").require_approval is False
    assert tool_spec("domain.list").scope == "domains.read"
    assert tool_spec("domain.add").scope == "domains.write"
    assert tool_spec("dns.apply").scope == "dns.write"
    assert tool_spec("dns.plan").require_approval is False
    # Broadened native surface (MCP transition Phase 0): granular scopes and
    # the reference policy tiers.
    assert tool_spec("app.remove").scope == "apps.remove"
    assert tool_spec("app.install").scope == "apps.install"
    assert tool_spec("app.upgrade").scope == "apps.upgrade"
    assert tool_spec("backup.create").scope == "backups.create"
    assert tool_spec("backup.restore").scope == "backups.restore"
    assert tool_spec("user.create").scope == "users.write"
    assert tool_spec("user.delete").scope == "users.delete"
    assert tool_spec("system.upgrade").scope == "system.upgrade"
    assert tool_spec("firewall.open").scope == "firewall.write"
    assert tool_spec("diagnosis.run").scope == "diagnosis.read"
    assert tool_spec("diagnosis.run").require_approval is False
    assert tool_spec("diagnosis.ignored").scope == "diagnosis.read"
    assert tool_spec("diagnosis.ignored").require_approval is False
    assert tool_spec("diagnosis.ignore").scope == "diagnosis.write"
    assert tool_spec("diagnosis.unignore").scope == "diagnosis.write"
    # Phase 5 backlog surface: scopes, approval posture, and the gated reads.
    assert tool_spec("updates.check").require_approval is False
    assert tool_spec("updates.refresh").scope == "system.update"
    assert tool_spec("system.migrations").scope == "system.update"
    assert tool_spec("system.migrations").require_approval is False
    assert tool_spec("system.migrate").scope == "system.migrate"
    assert tool_spec("service.history").require_approval is False
    assert tool_spec("logs.read").scope == "logs.read"
    assert tool_spec("logs.read").require_approval is False
    assert tool_spec("logs.web").scope == "logs.read"
    assert tool_spec("backup.delete").scope == "backups.delete"
    assert tool_spec("domain.cert.info").scope == "domains.read"
    assert tool_spec("domain.cert.info").require_approval is False
    assert tool_spec("domain.cert.install").scope == "domains.write"
    assert tool_spec("user.update").scope == "users.write"
    assert tool_spec("user.group.list").require_approval is False
    assert tool_spec("user.group.delete").scope == "users.delete"
    assert tool_spec("user.permission.list").require_approval is False
    assert tool_spec("user.permission.info").scope == "users.read"
    assert tool_spec("catalog.verify").scope == "catalog.verify"
    assert tool_spec("catalog.verify").require_approval is False
    assert tool_spec("audit.list").scope == "audit.read"
    assert tool_spec("audit.get").scope == "audit.read"
    assert tool_spec("system.reboot").scope == "system.power"
    assert tool_spec("system.shutdown").scope == "system.power"
    assert tool_spec("settings.list").scope == "settings.read"
    assert tool_spec("settings.list").require_approval is False
    assert tool_spec("settings.get").scope == "settings.read"
    assert tool_spec("settings.get").require_approval is False
    assert tool_spec("settings.set").scope == "settings.write"
    assert tool_spec("settings.reset").scope == "settings.write"
    assert tool_spec("settings.reset_all").scope == "settings.write"
    for name, spec in TOOLS.items():
        assert spec.handler is not None
        if name not in (
            "package.plan",
            "package.fetch_manifest",
            "domain.list",
            "domain.inspect",
            "nsite.gateway.status",
            "nsite.list",
            "nsite.discover",
            "nsite.block.list",
            "nsite.inspect",
            "nsite.resolve",
            "nsite.validate_manifest",
            "nsite.reachability",
            "nsite.publish.plan",
            "nsite.domain.list",
            "dns.plan",
            "dns.verify",
            "dns.watch",
            "dns.subscriptions",
            "network.public_ip",
            "credential.list",
            "system.version",
            "app.list",
            "service.status",
            "system.status",
            "app.config.read",
            "backup.list",
            "backup.info",
            "user.list",
            "firewall.list",
            "diagnosis.run",
            "diagnosis.ignored",
            "catalog.list",
            "catalog.get",
            "catalog.announcements",
            "catalog.candidates",
            "catalog.history",
            "catalog.profile.get",
            "catalog.reverify",
            "catalog.trust",
            "updates.check",
            "updates.refresh",
            "system.migrations",
            "service.history",
            "logs.read",
            "logs.web",
            "logs.problems",
            "domain.cert.info",
            "user.group.list",
            "user.permission.list",
            "user.permission.info",
            "catalog.verify",
            "settings.list",
            "settings.get",
        ):
            assert spec.require_approval is True
    assert tool_spec("app.upgrade") is not None


def test_registry_schemas_and_catalog():
    """Every new op exposes a JSON-Schema input model through the catalogue."""
    from yunohost.nostr_operations import operation_catalog

    catalog = operation_catalog()
    assert catalog["schema_version"] == 2
    assert catalog["digest"].startswith("sha256:")
    by_name = {entry["name"]: entry for entry in catalog["operations"]}
    assert len(catalog["operations"]) == len(known_tools())
    for name, spec in TOOLS.items():
        entry = by_name[name]
        assert entry["scopes"] == list(spec.scopes)
        assert entry["approval"]["minimum"] == ("admin" if spec.require_approval else "none")
        assert entry["risk"] in ("low", "medium", "high")
        assert entry["reversibility"] in ("reversible", "partial", "irreversible")
        assert entry["description"]
        assert entry["result_schema"] == spec.result_schema()
    app_install = by_name["app.install"]
    assert app_install["risk"] == "high"
    assert app_install["input_schema"]["required"] == ["app"]
    # extra="forbid" models surface as additionalProperties: false
    assert app_install["input_schema"].get("additionalProperties") is False
    # unknown tools carry no schema
    assert operation_catalog()
    import json

    assert json.dumps(catalog)  # fully JSON-serialisable


def test_every_write_tool_carries_an_input_model():
    """Every approval-gated (mutation) op must expose a JSON-Schema input model
    so generated MCP tools advertise their real arguments (Phase 3)."""
    from yunohost.nostr_operations import TOOLS, operation_catalog

    for name, spec in TOOLS.items():
        if spec.require_approval:
            assert spec.input_model is not None, f"write tool {name} is missing an input_model"
    catalog = {entry["name"]: entry for entry in operation_catalog()["operations"]}
    for name in TOOLS:
        if TOOLS[name].require_approval:
            schema = catalog[name]["input_schema"]
            assert schema and isinstance(schema.get("properties"), dict), f"write tool {name} has no schema properties"
            assert schema.get("additionalProperties") is False, f"write tool {name} schema must forbid extra args"


def test_service_status_accepts_the_planner_name_argument(monkeypatch):
    import sys
    from types import ModuleType
    from yunohost.nostr_operations import _safe_service_status

    calls = []

    def fake_status(names=None):
        calls.append(names)
        if names is None:
            return {"caddy": {"status": "running"}, "opendkim": {"status": "running"}}
        return {names: {"status": "running"}}

    service = ModuleType("yunohost.service")
    service._get_services = lambda: {"caddy": {}, "opendkim": {}}
    service.service_status = fake_status
    monkeypatch.setitem(sys.modules, "yunohost.service", service)

    assert _safe_service_status(name="opendkim") == {"opendkim": {"status": "running"}}
    assert _safe_service_status() == {
        "caddy": {"status": "running"},
        "opendkim": {"status": "running"},
    }
    assert calls == ["opendkim", None]


@pytest.mark.parametrize(
    "legacy_apps",
    [
        [{"id": "legacy-app", "version": "1.2"}],
        {"legacy-app": {"id": "legacy-app", "version": "1.2"}},
    ],
)
def test_app_list_normalizes_legacy_registry_shapes(monkeypatch, legacy_apps):
    import sys
    from types import ModuleType

    from yunohost.nostr_operations import _safe_app_list

    legacy_app = ModuleType("yunohost.app")
    legacy_app.app_list = lambda **_kwargs: {"apps": legacy_apps}
    native_providers = ModuleType("nostrhost.native_providers")
    native_providers.installed_package_manifest = lambda _app_id: None
    monkeypatch.setitem(sys.modules, "yunohost.app", legacy_app)
    monkeypatch.setitem(sys.modules, "nostrhost.native_providers", native_providers)
    monkeypatch.setattr(Path, "glob", lambda _path, _pattern: [])

    assert _safe_app_list() == {
        "apps": {"legacy-app": {"id": "legacy-app", "version": "1.2"}}
    }


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
    request_operation("system.version", {}, requester_sk=agent_sk, transport=transport)
    assert len(transport.events) == 1
    assert transport.events[0]["kind"] == KIND_OPERATION_REQUEST
    assert transport.events[0]["pubkey"] == agent_pk


def test_request_operation_rejects_unknown_tool():
    with pytest.raises(OperationError):
        request_operation("app.bogus", {}, transport=FakeTransport())


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


def _capability_event(subject, scopes, *, created_at, type_="agent", event_id=None):
    return {
        "id": event_id or f"e-{subject}-{created_at}",
        "kind": KIND_CAPABILITY,
        "created_at": created_at,
        "tags": [["d", subject]],
        "content": json.dumps({"type": type_, "scopes": scopes}),
    }


def test_list_capabilities_returns_active_grants():
    admin_sk, _ = new_key()
    events = [_capability_event("agent-1", ["apps.read", "server.read"], created_at=1000)]
    grants = list_capabilities(admin_sk=admin_sk, query=lambda *a, **kw: events)
    assert grants == [
        {"pubkey": "agent-1", "type": "agent", "scopes": ["apps.read", "server.read"], "granted_at": 1000, "event_id": events[0]["id"]}
    ]


def test_list_capabilities_keeps_only_the_newest_event_per_subject():
    admin_sk, _ = new_key()
    events = [
        _capability_event("agent-1", ["apps.read"], created_at=1000),
        _capability_event("agent-1", ["services.read"], created_at=2000),
    ]
    grants = list_capabilities(admin_sk=admin_sk, query=lambda *a, **kw: events)
    assert len(grants) == 1
    assert grants[0]["scopes"] == ["services.read"]


def test_list_capabilities_omits_revoked_subjects():
    """An empty-scope grant is grant_capability's own revoke convention."""
    admin_sk, _ = new_key()
    events = [
        _capability_event("agent-1", ["apps.read"], created_at=1000),
        _capability_event("agent-1", [], created_at=2000),
    ]
    grants = list_capabilities(admin_sk=admin_sk, query=lambda *a, **kw: events)
    assert grants == []


def test_list_capabilities_sorts_newest_first():
    admin_sk, _ = new_key()
    events = [
        _capability_event("agent-1", ["apps.read"], created_at=1000),
        _capability_event("agent-2", ["services.read"], created_at=2000),
    ]
    grants = list_capabilities(admin_sk=admin_sk, query=lambda *a, **kw: events)
    assert [g["pubkey"] for g in grants] == ["agent-2", "agent-1"]


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


# --------------------------------------------------------------------------- #
# NIP-46 (bunker/remote-signer) approval + rejection templates


def _sign_with_key(sk: str, event: dict) -> dict:
    """Fill in id/pubkey/sig exactly the way a NIP-46 bunker signer would."""
    from nostr_sdk import EventBuilder, Keys, Kind, Tag, Timestamp

    keys = Keys.parse(sk)
    built = (
        EventBuilder(Kind(event["kind"]), event["content"])
        .tags([Tag.parse(tag) for tag in event["tags"]])
        .custom_created_at(Timestamp.from_secs(event["created_at"]))
        .finalize(keys)
    )
    return {
        "id": built.id().to_hex(),
        "pubkey": keys.public_key().to_hex(),
        "created_at": event["created_at"],
        "kind": event["kind"],
        "tags": event["tags"],
        "content": event["content"],
        "sig": built.signature(),
    }


def test_nip46_approval_round_trip():
    admin_sk, admin_pk = new_key()
    request_id = "d" * 64
    template = build_approval_template(admin_pk, request_id, "looks fine")
    signed = _sign_with_key(admin_sk, template)
    validated = validate_signed_approval(signed, request_id)
    assert validated["pubkey"] == admin_pk
    assert ["t", "nip46"] in validated["tags"]


def test_nip46_rejection_round_trip():
    admin_sk, admin_pk = new_key()
    request_id = "e" * 64
    template = build_rejection_template(admin_pk, request_id, "not authorized")
    signed = _sign_with_key(admin_sk, template)
    validated = validate_signed_rejection(signed, request_id)
    assert validated["pubkey"] == admin_pk
    assert json.loads(validated["content"])["reason"] == "not authorized"


def test_nip46_approval_rejects_wrong_request_id():
    admin_sk, admin_pk = new_key()
    template = build_approval_template(admin_pk, "d" * 64, None)
    signed = _sign_with_key(admin_sk, template)
    with pytest.raises(OperationError, match="does not target"):
        validate_signed_approval(signed, "f" * 64)


def test_nip46_approval_rejects_tampered_content():
    admin_sk, admin_pk = new_key()
    request_id = "d" * 64
    template = build_approval_template(admin_pk, request_id, None)
    signed = _sign_with_key(admin_sk, template)
    signed["content"] = json.dumps({"note": "tampered"})
    with pytest.raises(OperationError, match="does not match its contents"):
        validate_signed_approval(signed, request_id)


def test_nip46_rejection_rejects_wrong_kind():
    admin_sk, admin_pk = new_key()
    request_id = "d" * 64
    template = build_rejection_template(admin_pk, request_id, None)
    template["kind"] = KIND_OPERATION_APPROVAL  # signer/caller mixed up approve vs reject
    signed = _sign_with_key(admin_sk, template)
    with pytest.raises(OperationError, match="non-rejection"):
        validate_signed_rejection(signed, request_id)


# --------------------------------------------------------------------------- #
# listing operations from the control relay's chain events


def test_list_operations_reduces_chain_to_state(monkeypatch):
    sk, pk = new_key()
    admin_sk, admin_pk = new_key()
    request = build_operation_request(sk, pk, "system.version", {})
    approval = build_approval(admin_sk, admin_pk, request["id"])

    monkeypatch.setattr(
        "yunohost.nostr_operations.fetch_chain_events",
        lambda relay, **kw: [request, approval],
    )

    entries = list_operations()
    assert len(entries) == 1
    assert entries[0]["request_id"] == request["id"]
    assert entries[0]["tool"] == "system.version"
    assert entries[0]["state"] == "APPROVED"


def test_list_operations_marks_failed_result(monkeypatch):
    sk, pk = new_key()
    request = build_operation_request(sk, pk, "system.version", {})
    started = build_execution_started(sk, pk, request["id"])
    result = build_execution_result(sk, pk, request["id"], ok=False, error="boom")

    monkeypatch.setattr(
        "yunohost.nostr_operations.fetch_chain_events",
        lambda relay, **kw: [request, started, result],
    )

    entry = get_operation(request["id"])
    assert entry is not None
    assert entry["state"] == "FAILED"


def test_list_operations_marks_immediate_rejection_without_execution(monkeypatch):
    """The executor's immediate policy rejection is a 2204 with no 2203: the
    chain must read FAILED, not stay APPROVED once the admin later approves."""
    sk, pk = new_key()
    admin_sk, admin_pk = new_key()
    request = build_operation_request(sk, pk, "system.version", {})
    rejection = build_execution_result(
        sk, pk, request["id"], ok=False, reason="catalog_digest_mismatch"
    )
    approval = build_approval(admin_sk, admin_pk, request["id"])

    monkeypatch.setattr(
        "yunohost.nostr_operations.fetch_chain_events",
        lambda relay, **kw: [request, rejection, approval],
    )

    entry = get_operation(request["id"])
    assert entry is not None
    assert entry["state"] == "FAILED"


def test_list_operations_orders_same_second_events_by_chain_position(monkeypatch):
    """A 2203 and its 2204 usually share a created_at second; the reduction must
    still apply execution-started before the result."""
    sk, pk = new_key()
    request = build_operation_request(sk, pk, "system.version", {})
    started = build_execution_started(sk, pk, request["id"])
    result = build_execution_result(sk, pk, request["id"], ok=True, result={})

    # Deliberately hand the snapshot back in the wrong order (result first).
    monkeypatch.setattr(
        "yunohost.nostr_operations.fetch_chain_events",
        lambda relay, **kw: [result, started, request],
    )

    entry = get_operation(request["id"])
    assert entry is not None
    assert entry["state"] == "SUCCEEDED"


def test_list_operations_ignores_orphaned_followon(monkeypatch):
    """A 2201 whose 2200 isn't in this relay snapshot is skipped, not crashed on."""
    admin_sk, admin_pk = new_key()
    orphan_approval = build_approval(admin_sk, admin_pk, "a" * 64)

    monkeypatch.setattr(
        "yunohost.nostr_operations.fetch_chain_events",
        lambda relay, **kw: [orphan_approval],
    )

    assert list_operations() == []


def test_get_operation_returns_none_when_missing(monkeypatch):
    monkeypatch.setattr("yunohost.nostr_operations.fetch_chain_events", lambda relay, **kw: [])
    assert get_operation("a" * 64) is None


def test_list_operations_respects_limit(monkeypatch):
    sk, pk = new_key()
    # Distinct actor tags so each request hashes to a different event id -
    # otherwise three identical (tool, args, created_at) requests would
    # collide onto the same id and this test wouldn't exercise the limit.
    requests = [
        build_operation_request(sk, pk, "system.version", {}, actor_pubkey=new_key()[1])
        for _ in range(3)
    ]

    monkeypatch.setattr("yunohost.nostr_operations.fetch_chain_events", lambda relay, **kw: requests)

    assert len(list_operations(limit=2)) == 2
    assert len(list_operations()) == 3
