"""NIP-51 kind-10000 mute-list blocklist for nsite.discover.

The blocklist is the operator's kind-10000 mute list on the control relay: a
full replacement (``publish_blocklist``) whose ``p`` tags are the blocked
npub pubkeys. ``nsite.discover`` reads it at scan time and excludes those
pubkeys from results.
"""

from __future__ import annotations

import json
import os
import time

import pytest

from nostrhost.nsites.blocklist import (
    BLOCK_KIND,
    _newest_block_event,
    current_blocklist,
    parse_blocked,
    publish_blocklist,
)


def _new_key():
    nostr_sdk = pytest.importorskip("nostr_sdk", reason="requires nostr-sdk (real signing round-trip)")
    sk = os.urandom(32).hex()
    pk = nostr_sdk.Keys.parse(sk).public_key().to_hex()
    return sk, pk


class FakeTransport:
    def __init__(self):
        self.sent = []

    def __call__(self, relay, event):
        self.sent.append((relay, event))


def test_publish_blocklist_ships_p_tags_and_kind():
    sk, pk = _new_key()
    _, blocked_a = _new_key()
    _, blocked_b = _new_key()
    transport = FakeTransport()

    result = publish_blocklist(
        [blocked_b, blocked_a],
        operator_sk=sk,
        control_relay="ws://127.0.0.1:4848",
        transport=transport,
    )

    relay, event = transport.sent[0]
    assert relay == "ws://127.0.0.1:4848"
    assert event["kind"] == BLOCK_KIND
    assert event["pubkey"] == pk
    assert event["tags"] == [["p", pk] for pk in sorted([blocked_a, blocked_b])]  # sorted, deduped
    assert result["pubkeys"] == sorted([blocked_a, blocked_b])

    from nostr_sdk import Event as NsEvent

    assert NsEvent.from_json(json.dumps(event)).verify()


def test_publish_blocklist_empty_clears():
    sk, _ = _new_key()
    transport = FakeTransport()

    publish_blocklist([], operator_sk=sk, control_relay="ws://127.0.0.1:4848", transport=transport)

    event = transport.sent[0][1]
    assert [t for t in event["tags"] if t[0] == "p"] == []


def test_publish_blocklist_created_at_strictly_newer_than_latest():
    sk, pk = _new_key()
    transport = FakeTransport()

    result = publish_blocklist(
        [pk],
        operator_sk=sk,
        control_relay="ws://127.0.0.1:4848",
        transport=transport,
        latest_created_at=int(time.time()),
    )

    event = transport.sent[0][1]
    assert event["created_at"] > int(time.time())
    assert result["published_at"] == event["created_at"]


def _block_event(*, author, members=(), created_at=100, event_id="e1"):
    return {
        "id": event_id,
        "kind": BLOCK_KIND,
        "pubkey": author,
        "created_at": created_at,
        "tags": [["p", m] for m in members],
        "content": "",
    }


def test_newest_block_event_keeps_newest_operator_event():
    op = "1" * 64
    other = "2" * 64
    events = [
        _block_event(author=op, members=["a" * 64], created_at=100),
        _block_event(author=op, members=["b" * 64], created_at=200, event_id="e2"),
        _block_event(author=other, members=["c" * 64], created_at=300),
    ]
    newest = _newest_block_event(events, op)
    assert newest["id"] == "e2"
    assert parse_blocked(newest) == ["b" * 64]


def test_parse_blocked_dedupes_in_order():
    event = _block_event(author="1" * 64, members=["a" * 64, "b" * 64, "a" * 64])
    assert parse_blocked(event) == ["a" * 64, "b" * 64]


def test_current_blocklist_reads_newest_event():
    sk, op = _new_key()
    events = [
        _block_event(author=op, members=["a" * 64], created_at=100),
        _block_event(author=op, members=["b" * 64], created_at=200, event_id="e2"),
    ]

    def fake_fetch(relay, *, kinds, timeout):
        assert kinds == (BLOCK_KIND,)
        assert relay == "ws://127.0.0.1:4848"
        return events

    blocked = current_blocklist(
        operator_sk=sk,
        control_relay="ws://127.0.0.1:4848",
        fetch=fake_fetch,
    )
    assert blocked == ["b" * 64]


def test_current_blocklist_survives_fetch_errors():
    def broken_fetch(relay, *, kinds, timeout):
        raise RuntimeError("control relay unavailable")

    assert current_blocklist(operator_sk=os.urandom(32).hex(), control_relay="ws://127.0.0.1:4848", fetch=broken_fetch) == []
