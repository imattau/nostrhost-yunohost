"""WP5 tests: bounded `until` pagination for the chain read paths.

The relay's badger backend truncates an oversized/single REQ to its default
page (5000), so a large history must be walked backwards with `until` or the
older terminal events are silently omitted. These tests drive the paging loop
with a fake websocket that returns one page per REQ.
"""

from __future__ import annotations

import json

import pytest


class _FakeWS:
    """Serves scripted pages: each REQ pops the next page."""

    def __init__(self, pages: list[list[dict]]):
        self._pages = list(pages)
        self._current: list[dict] = []
        self._queue: list[str] = []
        self.requests: list[dict] = []

    def send(self, data: str):
        msg = json.loads(data)
        if msg[0] == "REQ":
            self.requests.append(msg[2])
            self._current = self._pages.pop(0) if self._pages else []
            self._queue = [json.dumps(["EVENT", "s", e]) for e in self._current] + [json.dumps(["EOSE", "s"])]
        # EVENT/AUTH sends are ignored

    def recv(self, timeout=None):
        if not self._queue:
            raise TimeoutError
        return self._queue.pop(0)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _evt(i: int, *, kind=2204, created_at=None) -> dict:
    return {
        "id": f"{i:064d}",
        "kind": kind,
        "pubkey": "p" * 64,
        "created_at": created_at if created_at is not None else 1000 + i,
        "tags": [],
        "content": "{}",
    }


def _patch_connect(monkeypatch, ws):
    import websockets.sync.client as wsc

    monkeypatch.setattr(wsc, "connect", lambda url, **kw: ws)
    # query_chain_events imports `connect` lazily from this module.
    return ws


def test_single_page_mode_stops_at_limit(monkeypatch):
    from yunohost.nostrhost.events import query_chain_events

    ws = _FakeWS([[_evt(i) for i in range(3)]])
    _patch_connect(monkeypatch, ws)
    # No auth configured ⇒ the handshake is skipped.
    monkeypatch.setattr("yunohost.nostrhost.events.default_auth", lambda: None)
    events = query_chain_events("ws://x", kinds=(2204,), limit=3)
    assert len(events) == 3
    assert "until" not in ws.requests[0]


def test_page_all_walks_backwards_with_until(monkeypatch):
    from yunohost.nostrhost.events import query_chain_events

    # page_limit=2: page 1 returns newest two, page 2 the next two, page 3 short.
    pages = [
        [_evt(10, created_at=1010), _evt(9, created_at=1009)],
        [_evt(8, created_at=1008), _evt(7, created_at=1007)],
        [_evt(6, created_at=1006)],
    ]
    ws = _FakeWS(pages)
    _patch_connect(monkeypatch, ws)
    monkeypatch.setattr("yunohost.nostrhost.events.default_auth", lambda: None)

    events = query_chain_events("ws://x", kinds=(2204,), limit=100, page_all=True, page_limit=2)
    # All five events across the three pages, oldest first.
    assert [e["created_at"] for e in events] == [1006, 1007, 1008, 1009, 1010]
    # The next REQ pages backwards from the oldest event of the previous page
    # (inclusive; duplicates are deduped).
    assert ws.requests[1].get("until") == 1009
    assert ws.requests[2].get("until") == 1007


def test_page_all_stops_on_since(monkeypatch):
    from yunohost.nostrhost.events import query_chain_events

    pages = [
        [_evt(5, created_at=1005), _evt(4, created_at=1004)],
        [_evt(3, created_at=1003), _evt(2, created_at=1002)],
    ]
    ws = _FakeWS(pages)
    _patch_connect(monkeypatch, ws)
    monkeypatch.setattr("yunohost.nostrhost.events.default_auth", lambda: None)

    events = query_chain_events("ws://x", kinds=(2204,), limit=100, since=1004, page_all=True, page_limit=2)
    # Only events at/after `since` are returned.
    assert [e["created_at"] for e in events] == [1004, 1005]


def test_page_all_respects_limit(monkeypatch):
    from yunohost.nostrhost.events import query_chain_events

    pages = [
        [_evt(i, created_at=2000 + i) for i in range(5)],
        [_evt(100 + i, created_at=1990 + i) for i in range(5)],
    ]
    ws = _FakeWS(pages)
    _patch_connect(monkeypatch, ws)
    monkeypatch.setattr("yunohost.nostrhost.events.default_auth", lambda: None)

    events = query_chain_events("ws://x", kinds=(2204,), limit=6, page_all=True, page_limit=5)
    assert len(events) == 6
