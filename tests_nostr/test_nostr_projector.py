"""Unit tests for the shared projector framework (WP2).

Run with: pytest tests_nostr/  (needs nostrhost-auth)
"""

from __future__ import annotations

import json
from pathlib import Path

from yunohost.nostr_projector import (
    DEFAULT_CURSOR_DIR,
    Checkpoint,
    Projector,
    ProjectionRegistry,
    ProjectionResult,
    ProjectionRuntime,
    load_checkpoint,
    read_status_dir,
    rebuild,
    save_checkpoint,
    shadow,
    sort_events,
    verify,
)

ADMIN = "1111111111111111111111111111111111111111111111111111111111111111"
SUBJECT = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def _event(kind=31100, d=SUBJECT, content=None, created_at=1000, event_id="e1", author=ADMIN):
    return {
        "id": event_id,
        "kind": kind,
        "created_at": created_at,
        "tags": [["d", d]],
        "content": json.dumps(content if content is not None else {"type": "agent", "scopes": ["app.read"]}),
        "pubkey": author,
    }


class FileProjector(Projector):
    """Projector writing a JSON file, for exercising the lifecycle."""

    name = "test-file"

    def __init__(self, target: Path, **kwargs):
        super().__init__(**kwargs)
        self.target = target
        self.state: dict = {}

    def validate(self, event):
        if event.get("kind") != 31100:
            return None
        if event.get("pubkey") != ADMIN:
            return None
        try:
            return json.loads(event.get("content") or "{}")
        except ValueError:
            return None

    def fold(self, current, fact):
        return fact

    def apply(self, event):
        fact = self.validate(event)
        if fact is None:
            self.quarantine(event, "not an admin capability")
            return ProjectionResult(accepted=False, reason="invalid")
        self.state = fact
        self.commit(json.dumps({"scopes": fact.get("scopes", [])}))
        self._advance(event)
        return ProjectionResult(accepted=True, changed=True)

    def render(self, state):
        return json.dumps({"scopes": (state or {}).get("scopes", [])})

    def commit(self, candidate):
        self.target.write_text(candidate, encoding="utf-8")

    def current(self):
        return self.target.read_text(encoding="utf-8") if self.target.exists() else None


def test_atomic_checkpoint_roundtrip(tmp_path):
    cp = Checkpoint(name="x", event_id="abc", created_at=5, revision="rev:1")
    save_checkpoint(cp, cursor_dir=tmp_path)
    loaded = load_checkpoint("x", cursor_dir=tmp_path)
    assert loaded.event_id == "abc"
    assert loaded.created_at == 5
    assert loaded.revision == "rev:1"
    assert loaded.updated_at > 0
    # No stray temp files.
    assert sorted(p.name for p in tmp_path.iterdir()) == ["x.json"]


def test_missing_checkpoint_is_empty(tmp_path):
    cp = load_checkpoint("nope", cursor_dir=tmp_path)
    assert cp.event_id == "" and cp.created_at == 0


def test_apply_commits_then_checkpoints(tmp_path):
    target = tmp_path / "proj.json"
    p = FileProjector(target, cursor_dir=tmp_path / "cursors")
    result = p.apply(_event(content={"type": "agent", "scopes": ["a", "b"]}, event_id="ev9"))
    assert result.accepted
    assert json.loads(target.read_text())["scopes"] == ["a", "b"]
    health = p.health()
    assert health.applied_revision
    assert p.checkpoint.event_id == "ev9"
    # Checkpoint persisted.
    assert load_checkpoint("test-file", cursor_dir=tmp_path / "cursors").event_id == "ev9"


def test_checkpoint_only_after_commit_on_failure(tmp_path):
    class Failing(FileProjector):
        name = "failing"

        def commit(self, candidate):
            raise OSError("disk full")

    p = Failing(tmp_path / "out.json", cursor_dir=tmp_path / "c")
    # apply() propagates the commit error; the runtime quarantines it.
    try:
        p.apply(_event(event_id="ev1"))
        raised = False
    except OSError:
        raised = True
    assert raised
    assert p.checkpoint.event_id == ""  # never advanced past a failed commit


def test_invalid_event_is_quarantined_not_fatal(tmp_path):
    p = FileProjector(tmp_path / "out.json", cursor_dir=tmp_path / "c")
    bad = _event(author="2222222222222222222222222222222222222222222222222222222222222222", event_id="bad")
    result = p.apply(bad)
    assert not result.accepted
    assert p.health().quarantined == 1
    assert p.quarantined()[0]["reason"]
    assert p.checkpoint.event_id == ""  # invalid event did not advance the cursor


def test_duplicate_delivery_is_idempotent(tmp_path):
    target = tmp_path / "out.json"
    p = FileProjector(target, cursor_dir=tmp_path / "c")
    event = _event(event_id="dup")
    p.apply(event)
    first = target.read_text()
    p.apply(dict(event))  # duplicate
    assert target.read_text() == first
    assert p.checkpoint.event_id == "dup"


def test_sort_events_deterministic(tmp_path):
    events = [
        _event(event_id="b", created_at=5),
        _event(event_id="a", created_at=5),
        {"id": "c", "kind": 2200, "created_at": 5, "tags": [], "content": "{}"},
    ]
    ordered = sort_events(events, priority={2200: 0, 31100: 5})
    assert [e["id"] for e in ordered] == ["c", "a", "b"]


def test_rebuild_refolds_all(tmp_path):
    p = FileProjector(tmp_path / "out.json", cursor_dir=tmp_path / "c")
    events = [
        _event(content={"type": "agent", "scopes": ["x"]}, created_at=1, event_id="1"),
        _event(content={"type": "agent", "scopes": ["x", "y"]}, created_at=2, event_id="2"),
    ]
    report = rebuild(events, projector=p)
    assert report["accepted"] == 2
    assert json.loads((tmp_path / "out.json").read_text())["scopes"] == ["x", "y"]


def test_verify_detects_drift(tmp_path):
    target = tmp_path / "out.json"
    p = FileProjector(target, cursor_dir=tmp_path / "c")
    target.write_text(json.dumps({"scopes": ["stale"]}))
    problems = verify(p, [_event(content={"type": "agent", "scopes": ["fresh"]})])
    assert problems  # committed projection differs from the rendered candidate


def test_verify_clean_when_matched(tmp_path):
    target = tmp_path / "out.json"
    p = FileProjector(target, cursor_dir=tmp_path / "c")
    event = _event(content={"type": "agent", "scopes": ["fresh"]})
    p.apply(event)
    assert verify(p, [event]) == []


def test_shadow_writes_staging_path(tmp_path):
    p = FileProjector(tmp_path / "live.json", cursor_dir=tmp_path / "c")
    staging = tmp_path / "staging.json"
    report = shadow([_event(content={"type": "agent", "scopes": ["z"]})], projector=p, staging_path=staging)
    assert staging.exists()
    assert report["staging_path"] == str(staging)
    assert not (tmp_path / "live.json").exists()  # shadow did not touch the live store


def test_runtime_quarantines_future_events(tmp_path):
    p = FileProjector(tmp_path / "out.json", cursor_dir=tmp_path / "c")
    runtime = ProjectionRuntime(
        "ws://127.0.0.1:4848",
        projector=p,
        kinds=[31100],
        clock=lambda: 1000.0,
    )
    runtime._apply(_event(created_at=100000, event_id="future"))
    assert p.health().quarantined == 1
    assert "skew" in p.quarantined()[0]["reason"]


def test_registry_snapshot(tmp_path):
    p = FileProjector(tmp_path / "out.json", cursor_dir=tmp_path / "c")
    registry = ProjectionRegistry()
    registry.register(p)
    p.apply(_event(event_id="e"))
    snapshot = registry.snapshot()
    assert snapshot[0]["name"] == "test-file"
    assert snapshot[0]["fresh"] is True


def test_read_status_dir_is_cross_process(tmp_path):
    save_checkpoint(Checkpoint(name="identity", event_id="abc", revision="rev:3"), cursor_dir=tmp_path)
    rows = read_status_dir(tmp_path)
    assert rows == [
        {"name": "identity", "applied_revision": "rev:3", "last_event_id": "abc", "updated_at": rows[0]["updated_at"]}
    ]


def test_default_cursor_dir_outside_config_tree():
    assert not DEFAULT_CURSOR_DIR.startswith("/etc/")


def test_runtime_apply_override_replaces_projector_apply(tmp_path):
    """The runtime dispatches through ``apply`` when given, so a daemon that
    executes as well as folds (operationsd) reuses the shared loop."""
    p = FileProjector(tmp_path / "out.json", cursor_dir=tmp_path / "c")
    seen = []
    runtime = ProjectionRuntime(
        "ws://127.0.0.1:4848",
        projector=p,
        kinds=[31100],
        clock=lambda: 1000.0,
        apply=lambda ev: seen.append(ev["id"]),
    )
    runtime._apply(_event(event_id="override"))
    assert seen == ["override"]
    # The projector's own apply never ran.
    assert not (tmp_path / "out.json").exists()


def test_runtime_prepare_replay_runs_before_sorted_application(tmp_path):
    """operationsd scans the raw replay for terminal results before the sorted
    chain is fed; prepare_replay must see the unsorted buffer first."""
    import asyncio

    import websockets

    p = FileProjector(tmp_path / "out.json", cursor_dir=tmp_path / "c")
    order = []
    events = [
        _event(kind=2204, event_id="late", created_at=1000),
        _event(kind=31100, event_id="early", created_at=900),
    ]

    class FakeWS:
        def __init__(self):
            self._msgs = [["EVENT", "s", events[0]], ["EVENT", "s", events[1]], ["EOSE", "s"]]

        async def send(self, data):
            return None

        async def recv(self):
            return json.dumps(self._msgs.pop(0))

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def __aiter__(self):
            return self

        async def __anext__(self):
            if not self._msgs:
                await asyncio.sleep(3600)
            return json.dumps(self._msgs.pop(0))

    fake = FakeWS()

    async def drive():
        runtime = ProjectionRuntime(
            "ws://x",
            projector=p,
            kinds=[31100, 2204],
            clock=lambda: 10_000.0,
            prepare_replay=lambda replay: order.append(("prepare", [e["id"] for e in replay])),
            apply=lambda ev: order.append(("apply", ev["id"])),
        )
        original_connect = websockets.connect
        websockets.connect = lambda url, **kw: fake
        task = asyncio.create_task(runtime.run())
        try:
            await asyncio.wait_for(task, timeout=0.5)
        except asyncio.TimeoutError:
            pass
        finally:
            websockets.connect = original_connect
            task.cancel()

    asyncio.run(drive())
    assert order[0] == ("prepare", ["late", "early"])  # raw replay, unsorted
    assert order[1:] == [("apply", "early"), ("apply", "late")]  # sorted by created_at


def test_runtime_apply_in_thread_runs_off_loop(tmp_path):
    import asyncio
    import threading

    p = FileProjector(tmp_path / "out.json", cursor_dir=tmp_path / "c")
    seen = {}
    runtime = ProjectionRuntime(
        "ws://x",
        projector=p,
        kinds=[31100],
        apply_in_thread=True,
        apply=lambda ev: seen.update(ev_id=ev["id"], thread=threading.get_ident()),
    )

    async def drive():
        await runtime._dispatch(_event(event_id="threaded"))
        return threading.get_ident()

    loop_thread = asyncio.run(drive())
    assert seen["ev_id"] == "threaded"
    assert seen["thread"] != loop_thread
    assert DEFAULT_CURSOR_DIR.startswith("/var/lib/nostrhost/")
