"""Tests for the system/service notice publisher (roadmap §18.1/§18.2 Phase 2)."""

from __future__ import annotations

import json
import os

import pytest
from nostr_sdk import Keys

from yunohost.nostr_notify import (
    KIND_SERVICE_EVENT,
    KIND_SYSTEM_EVENT,
    SEVERITY_CRITICAL,
    SEVERITY_WARNING,
    publish_notice,
)


def new_key():
    sk = os.urandom(32).hex()
    pk = Keys.parse(sk).public_key().to_hex()
    return sk, pk


class FakeTransport:
    """Captures published events instead of hitting a relay."""

    def __init__(self):
        self.events = []

    def __call__(self, relay_url, event):
        self.events.append((relay_url, event))


class RaisingTransport:
    def __call__(self, relay_url, event):
        raise ConnectionRefusedError("relay unreachable")


def test_publish_notice_signs_and_publishes():
    sk, pk = new_key()
    transport = FakeTransport()

    event = publish_notice(
        "certificate",
        SEVERITY_WARNING,
        "cert for example.org expires soon",
        server_sk=sk,
        transport=transport,
    )

    assert event is not None
    assert len(transport.events) == 1
    _, published = transport.events[0]
    assert published == event
    assert event["kind"] == KIND_SYSTEM_EVENT
    assert event["pubkey"] == pk

    content = json.loads(event["content"])
    assert content == {
        "class": "certificate",
        "severity": "warning",
        "summary": "cert for example.org expires soon",
    }


def test_publish_notice_extra_fields_are_merged():
    sk, _ = new_key()
    transport = FakeTransport()

    event = publish_notice(
        "diagnosis",
        SEVERITY_CRITICAL,
        "3 issues found",
        extra={"issue_count": 3},
        server_sk=sk,
        transport=transport,
    )

    content = json.loads(event["content"])
    assert content["issue_count"] == 3
    assert content["class"] == "diagnosis"


def test_publish_notice_custom_kind():
    sk, _ = new_key()
    transport = FakeTransport()

    event = publish_notice(
        "health",
        SEVERITY_WARNING,
        "disk almost full",
        kind=KIND_SERVICE_EVENT,
        server_sk=sk,
        transport=transport,
    )

    assert event["kind"] == KIND_SERVICE_EVENT


def test_publish_notice_rejects_unknown_severity():
    sk, _ = new_key()
    with pytest.raises(ValueError):
        publish_notice(
            "backup", "urgent", "oops", server_sk=sk, transport=FakeTransport()
        )


def test_publish_notice_swallows_transport_failures():
    sk, _ = new_key()
    # Must not raise: a notification failure must never break the caller
    # (certificate renewal / diagnosis) — see the module docstring.
    result = publish_notice(
        "certificate",
        SEVERITY_WARNING,
        "cert renewal failed",
        server_sk=sk,
        transport=RaisingTransport(),
    )
    assert result is None


def test_publish_notice_swallows_missing_config_when_no_server_sk(monkeypatch):
    # No server_sk passed and no operator config available (unbootstrapped
    # node) — must degrade to None, not raise.
    monkeypatch.delenv("NOSTRHOST_OPERATOR_SK", raising=False)
    monkeypatch.delenv("NOSTRHOST_OPERATOR_CONFIG", raising=False)
    monkeypatch.setenv("NOSTRHOST_OPERATOR_CONFIG", "/nonexistent/operator.toml")

    result = publish_notice(
        "certificate",
        SEVERITY_WARNING,
        "cert renewal failed",
        transport=FakeTransport(),
    )
    assert result is None
