"""Tests for the Phase 5 audit operations (audit.list / audit.get).

The audit surface reads the signed operation chain on the control relay via
``_audit_events``; these tests exercise the handler contract through that
seam plus the chain-event normalization itself.
"""

from __future__ import annotations

import json

import pytest

from yunohost.nostr_operations import OperationError
from yunohost.nostrhost import native_ops


def _entry(eid="e" * 64, *, kind=2200, rid="r" * 64, tool="system.status"):
    return {
        "id": eid,
        "kind": kind,
        "pubkey": "p" * 64,
        "created_at": 1750000000,
        "request_id": rid,
        "tool": tool,
    }


def test_audit_list_returns_entries(monkeypatch):
    monkeypatch.setattr(
        native_ops,
        "_audit_events",
        lambda kinds=None, limit=100, since=None: [_entry("e1", rid="r1", tool="app.install"), _entry("e2", rid="r2", tool="backup.create")],
    )
    result = native_ops._safe_audit_list(limit=10)
    assert [e["id"] for e in result["entries"]] == ["e1", "e2"]


def test_audit_list_rejects_extra(monkeypatch):
    monkeypatch.setattr(native_ops, "_audit_events", lambda kinds=None, limit=100, since=None: [])
    with pytest.raises(OperationError):
        native_ops._safe_audit_list(bogus=True)


def test_audit_get_by_event_id(monkeypatch):
    monkeypatch.setattr(
        native_ops,
        "_audit_events",
        lambda kinds=None, limit=100, since=None: [_entry("e-target"), _entry("e-other")],
    )
    result = native_ops._safe_audit_get("e-target")
    assert result["id"] == "e-target"


def test_audit_get_by_request_id(monkeypatch):
    monkeypatch.setattr(
        native_ops,
        "_audit_events",
        lambda kinds=None, limit=100, since=None: [_entry("e1", rid="req-9"), _entry("e2", rid="req-8")],
    )
    result = native_ops._safe_audit_get("req-8")
    assert result["id"] == "e2"


def test_audit_get_requires_id():
    with pytest.raises(OperationError, match="audit_id"):
        native_ops._safe_audit_get("")


def test_audit_get_missing_raises(monkeypatch):
    monkeypatch.setattr(native_ops, "_audit_events", lambda kinds=None, limit=100, since=None: [_entry("e1")])
    with pytest.raises(OperationError, match="not found"):
        native_ops._safe_audit_get("e-missing")


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
    assert request_entry["request_id"] == "r" * 64
    assert request_entry["tool"] == "app.install"
    cap_entry = next(e for e in entries if e["kind"] == 31100)
    assert cap_entry["tool"] == "capability.grant"
