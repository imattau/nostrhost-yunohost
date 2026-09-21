"""Tests for the Phase 5 audit operations (audit.list / audit.get).

The audit surface reads the signed operation chain on the control relay and
projects it per-operation: one entry per kind-2200 request with its terminal
state, plus standalone capability/delegation events. These tests exercise the
handler contract and the chain -> operation projection.
"""

from __future__ import annotations

import json

import pytest

from yunohost.nostr_operations import OperationError
from yunohost.nostrhost import native_ops


def _norm(event_id, kind, created_at, *, request_id=None, tool=None, content="", pubkey="p" * 64):
    """A raw chain event (as the relay stores it): chain steps carry an ``e``
    tag back to the request; the 2200 request is addressed by its own id."""
    tags = [["e", request_id]] if request_id and kind != 2200 else []
    return {
        "id": event_id,
        "kind": kind,
        "pubkey": pubkey,
        "created_at": created_at,
        "tags": tags,
        "content": content,
    }


def _chain(request_id="r" * 64, *, tool="app.install", ok=True):
    """A normalized 2200 -> 2201 -> 2203 -> 2204 chain for one operation.

    A 2200 request's own id IS the request id; the approval/execution/result
    events reference it via ``#e``, so they all share ``request_id``."""
    return [
        _norm(request_id, kind=2200, created_at=1000, request_id=request_id, tool=tool, content=json.dumps({"tool": tool, "args": {}})),
        _norm("b" * 64, kind=2201, created_at=1001, request_id=request_id),
        _norm("c" * 64, kind=2203, created_at=1002, request_id=request_id),
        _norm("d" * 64, kind=2204, created_at=1003, request_id=request_id, content=json.dumps({"ok": ok, "result": {}})),
    ]


def test_audit_list_projects_operations(monkeypatch):
    chain = _chain("rid-1", tool="backup.create")
    monkeypatch.setattr(native_ops, "_audit_raw_events", lambda kinds=None, limit=100, since=None, **kw: chain)
    result = native_ops._safe_audit_list(limit=10)
    assert len(result["entries"]) == 1
    entry = result["entries"][0]
    assert entry["request_id"] == "rid-1"
    assert entry["tool"] == "backup.create"
    assert entry["state"] == "SUCCEEDED"


def test_audit_list_shows_failed_and_rejected(monkeypatch):
    ok_chain = _chain("rid-ok", tool="backup.create")
    fail_chain = _chain("rid-fail", tool="app.upgrade", ok=False)
    reject_chain = _chain("rid-rej", tool="domain.remove")
    reject_chain = [reject_chain[0], _norm("e1", kind=2202, created_at=1001, request_id="rid-rej")]
    monkeypatch.setattr(native_ops, "_audit_raw_events", lambda kinds=None, limit=100, since=None, **kw: ok_chain + fail_chain + reject_chain)
    entries = native_ops._safe_audit_list(limit=10)["entries"]
    states = {e["tool"]: e["state"] for e in entries}
    assert states["backup.create"] == "SUCCEEDED"
    assert states["app.upgrade"] == "FAILED"
    assert states["domain.remove"] == "REJECTED"


def test_audit_list_includes_capability_events(monkeypatch):
    chain = _chain("rid-1", tool="user.group.create")
    chain.append(_norm("cap1", kind=31100, created_at=2000, tool="capability.grant", content=json.dumps({"scopes": ["server.read"]})))
    monkeypatch.setattr(native_ops, "_audit_raw_events", lambda kinds=None, limit=100, since=None, **kw: chain)
    entries = native_ops._safe_audit_list(limit=10)["entries"]
    assert entries[0]["kind"] == 31100  # newest first
    assert entries[0]["request_id"] is None
    assert [e["kind"] for e in entries] == [31100, 2200]


def test_audit_list_rejects_extra(monkeypatch):
    monkeypatch.setattr(native_ops, "_audit_raw_events", lambda kinds=None, limit=100, since=None, **kw: [])
    with pytest.raises(OperationError):
        native_ops._safe_audit_list(bogus=True)


def test_audit_get_by_request_id(monkeypatch):
    entry = {"id": "rid-target", "request_id": "rid-target", "tool": "x", "state": "REQUESTED"}
    monkeypatch.setattr(native_ops, "_audit_operations", lambda limit=100: [entry])
    result = native_ops._safe_audit_get("rid-target")
    assert result["request_id"] == "rid-target"


def test_audit_get_requires_id():
    with pytest.raises(OperationError, match="audit_id"):
        native_ops._safe_audit_get("")


def test_audit_get_missing_raises(monkeypatch):
    entry = {"id": "rid-1", "request_id": "rid-1", "tool": "x", "state": "REQUESTED"}
    monkeypatch.setattr(native_ops, "_audit_operations", lambda limit=100: [entry])
    with pytest.raises(OperationError, match="not found"):
        native_ops._safe_audit_get("rid-missing")


def test_audit_list_uses_wide_window(monkeypatch):
    fetched = {}

    def fake(kinds=None, limit=100, since=None, **kw):
        fetched["limit"] = limit
        return [_chain(f"rid-{i}", tool="x")[0] for i in range(5)]

    monkeypatch.setattr(native_ops, "_audit_raw_events", fake)
    result = native_ops._safe_audit_list(limit=3)
    assert len(result["entries"]) == 3
    assert fetched["limit"] >= native_ops.AUDIT_LIST_WINDOW


def test_audit_events_normalizes_chain(monkeypatch):
    """The chain query seam normalizes a 2200 request and a capability grant."""
    import yunohost.nostrhost.events as ev

    request = {
        "id": "a" * 64,
        "kind": 2200,
        "pubkey": "b" * 64,
        "created_at": 1000,
        "content": json.dumps({"tool": "app.install", "args": {"app": "x"}}),
        "tags": [["e", "r" * 64]],
    }
    capability = {
        "id": "c" * 64,
        "kind": 31100,
        "pubkey": "d" * 64,
        "created_at": 2000,
        "content": json.dumps({"type": "capability", "scopes": ["server.read"]}),
        "tags": [["d", "e" * 64]],
    }
    monkeypatch.setattr(ev, "query_chain_events", lambda *a, **kw: [request, capability])
    monkeypatch.setattr(
        "yunohost.nostr_identity._operator_config",
        lambda: type("Cfg", (), {"control_relay": "ws://127.0.0.1:4848"})(),
    )
    entries = native_ops._audit_events()
    assert [e["kind"] for e in entries] == [31100, 2200]  # newest first
    request_entry = next(e for e in entries if e["kind"] == 2200)
    # A kind-2200 request carries no ``e`` tag: its own id IS the request id.
    assert request_entry["request_id"] == "a" * 64
    assert request_entry["tool"] == "app.install"
    cap_entry = next(e for e in entries if e["kind"] == 31100)
    assert cap_entry["tool"] == "capability.grant"


# --------------------------------------------------------------------------- #
# WP5: unified fold + read-side signer/link validation


def _real_chain(sk, pk, admin_sk, admin_pk, *, ok=True, server_sk=None, server_pk=None):
    from yunohost.nostr_operations import (
        build_approval,
        build_execution_result,
        build_execution_started,
        build_operation_request,
    )

    server_sk = server_sk or sk
    server_pk = server_pk or pk
    request = build_operation_request(sk, pk, "system.version", {})
    approval = build_approval(admin_sk, admin_pk, request["id"])
    started = build_execution_started(server_sk, server_pk, request["id"])
    result = build_execution_result(server_sk, server_pk, request["id"], ok=ok)
    return request, approval, started, result


def test_audit_and_operations_folds_agree_on_same_second_chain(monkeypatch):
    """WP5: audit.list and /package/operations must reduce a same-second
    2203+2204 chain identically (they used to use divergent folds)."""
    from conftest import new_key
    from yunohost import nostr_operations

    sk, pk = new_key()
    admin_sk, admin_pk = new_key()
    chain = _real_chain(sk, pk, admin_sk, admin_pk, ok=True)
    # Force the started/result to share a second and hand them over reversed.
    monkeypatch.setattr(nostr_operations, "_operations_cache", {})
    monkeypatch.setattr("yunohost.nostrhost.events.query_chain_events", lambda relay, **kw: [chain[3], chain[2], chain[1], chain[0]])
    ops_entry = nostr_operations.get_operation(chain[0]["id"])

    monkeypatch.setattr(native_ops, "_audit_raw_events", lambda **kw: [chain[3], chain[2], chain[1], chain[0]])
    audit_entry = next(e for e in native_ops._safe_audit_list(limit=10)["entries"] if e.get("request_id") == chain[0]["id"])

    assert ops_entry["state"] == "SUCCEEDED"
    assert audit_entry["state"] == ops_entry["state"]


def test_audit_fold_annotates_forged_server_result(monkeypatch):
    """WP5: a 2203/2204 not authored by the server key is annotated, not
    dropped, so an operator can see a foreign chain."""
    from conftest import new_key
    from yunohost import nostr_operations

    sk, pk = new_key()
    admin_sk, admin_pk = new_key()
    server_sk, server_pk = new_key()
    attacker_sk, attacker_pk = new_key()
    request, approval, _, _ = _real_chain(sk, pk, admin_sk, admin_pk)
    forged_started = nostr_operations.build_execution_started(attacker_sk, attacker_pk, request["id"])
    chain = [request, approval, forged_started]

    monkeypatch.setattr(native_ops, "_audit_raw_events", lambda **kw: chain)
    monkeypatch.setattr(
        native_ops, "_audit_authority",
        lambda: ((admin_pk,), server_pk),
    )
    entry = next(e for e in native_ops._safe_audit_list(limit=10)["entries"] if e.get("request_id") == request["id"])
    assert entry["validated"] is False
    assert any("2203" in anomaly and "non-server" in anomaly for anomaly in entry["anomalies"])


def test_audit_fold_flags_non_admin_approval(monkeypatch):
    from conftest import new_key
    from yunohost import nostr_operations

    sk, pk = new_key()
    rogue_sk, rogue_pk = new_key()
    _, admin_pk = new_key()
    server_sk, server_pk = new_key()
    request = nostr_operations.build_operation_request(sk, pk, "system.version", {})
    rogue_approval = nostr_operations.build_approval(rogue_sk, rogue_pk, request["id"])

    monkeypatch.setattr(native_ops, "_audit_raw_events", lambda **kw: [request, rogue_approval])
    monkeypatch.setattr(native_ops, "_audit_authority", lambda: ((admin_pk,), server_pk))
    entry = next(e for e in native_ops._safe_audit_list(limit=10)["entries"] if e.get("request_id") == request["id"])
    assert entry["validated"] is False
    assert any("2201" in anomaly and "non-admin" in anomaly for anomaly in entry["anomalies"])


def test_audit_fold_validates_clean_chain(monkeypatch):
    from conftest import new_key
    from yunohost import nostr_operations

    sk, pk = new_key()
    admin_sk, admin_pk = new_key()
    server_sk, server_pk = new_key()
    request, approval, started, result = _real_chain(sk, pk, admin_sk, admin_pk)
    # Rebuild execution events with the real server key.
    started = nostr_operations.build_execution_started(server_sk, server_pk, request["id"])
    result = nostr_operations.build_execution_result(server_sk, server_pk, request["id"], ok=True)

    monkeypatch.setattr(native_ops, "_audit_raw_events", lambda **kw: [request, approval, started, result])
    monkeypatch.setattr(native_ops, "_audit_authority", lambda: ((admin_pk,), server_pk))
    entry = next(e for e in native_ops._safe_audit_list(limit=10)["entries"] if e.get("request_id") == request["id"])
    assert entry["validated"] is True
    assert entry["anomalies"] == []
    assert entry["state"] == "SUCCEEDED"
