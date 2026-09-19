"""Shared projector framework (WP2) — roadmap / docs/RELAY-STATE-MIGRATION-PLAN.md.

Identity, permission and operations daemons each subscribe to the local control
relay and materialise a read model from signed events. Before this module they
duplicated the same WebSocket replay/AUTH/backoff loop and had no durable
checkpoint, no rebuild/verify/shadow commands and no health surface.

This module provides:

* :class:`Projector` — the lifecycle contract every projector implements
  (``validate`` → ``fold`` → ``render`` → ``commit`` → ``checkpoint`` →
  ``health``), matching §7 of the migration plan;
* :class:`ProjectionRuntime` — the shared NIP-01 REQ loop with NIP-42 AUTH,
  replay buffering, deterministic ordering, reconnect backoff, quarantine of
  invalid events and durable checkpointing;
* :func:`rebuild` / :func:`verify` / :func:`shadow` — operational modes;
* :class:`ProjectionRegistry` — the in-process status registry the API and
  diagnosis read (``/package/projections``).

Design rules enforced here (migration plan §7):

* a projection is written through a temporary file then atomically renamed;
* an event is never checkpointed before its projection commits;
* duplicate delivery is idempotent and out-of-order delivery refolds;
* an invalid event is quarantined with a bounded reason and does not advance
  the checkpoint past it silently;
* the last-known-good projection is preserved when rendering or validation
  fails;
* service cursors live outside the authoritative configuration tree.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from .nostr_identity import (
    _sign_auth_event,
    _wait_auth_ok_async,
    default_auth,
)

logger = logging.getLogger("nostr-projector")

# Cursors live outside the authoritative configuration tree (§7): projections
# are rebuildable and a lost cursor only costs a replay, so they do not belong
# under /etc/nostrhost.
DEFAULT_CURSOR_DIR = "/var/lib/nostrhost/projections"

# An event whose created_at is further ahead than this is not trusted on
# arrival; §6.2 bounds timestamp skew at ingress. Replay is always trusted.
MAX_FUTURE_SKEW = 900.0

BACKOFF_SECONDS = 5.0


@dataclass
class ProjectionHealth:
    """Health snapshot for one projection (§7 ``Health()``)."""

    name: str
    source_revision: str = ""
    applied_revision: str = ""
    applied_at: float = 0.0
    schema: int = 1
    last_error: str = ""
    quarantined: int = 0
    lag_seconds: float = 0.0
    connected: bool = False
    mode: str = "event-authoritative"

    @property
    def fresh(self) -> bool:
        return self.applied_revision != "" and not self.last_error

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source_revision": self.source_revision,
            "applied_revision": self.applied_revision,
            "applied_at": self.applied_at,
            "schema": self.schema,
            "last_error": self.last_error,
            "quarantined": self.quarantined,
            "lag_seconds": self.lag_seconds,
            "connected": self.connected,
            "mode": self.mode,
            "fresh": self.fresh,
        }


@dataclass
class Checkpoint:
    """Durable cursor for a projection address family."""

    name: str
    event_id: str = ""
    created_at: int = 0
    revision: str = ""
    updated_at: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "event_id": self.event_id,
            "created_at": self.created_at,
            "revision": self.revision,
            "updated_at": self.updated_at,
        }


def _atomic_write(path: Path, payload: str, mode: int = 0o600) -> None:
    """Write via a temporary file in the same directory then rename (§7)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.{os.getpid()}.tmp"
    with tmp.open("w", encoding="utf-8") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def load_checkpoint(name: str, *, cursor_dir: str | Path = DEFAULT_CURSOR_DIR) -> Checkpoint:
    path = Path(cursor_dir) / f"{name}.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return Checkpoint(name=name)
    return Checkpoint(
        name=name,
        event_id=str(raw.get("event_id") or ""),
        created_at=int(raw.get("created_at") or 0),
        revision=str(raw.get("revision") or ""),
        updated_at=float(raw.get("updated_at") or 0.0),
    )


def save_checkpoint(checkpoint: Checkpoint, *, cursor_dir: str | Path = DEFAULT_CURSOR_DIR) -> None:
    checkpoint.updated_at = time.time()
    path = Path(cursor_dir) / f"{checkpoint.name}.json"
    _atomic_write(path, json.dumps(checkpoint.as_dict(), indent=2) + "\n")


@dataclass
class ProjectionResult:
    """Outcome of applying one event to a projector."""

    accepted: bool
    changed: bool = False
    reason: str = ""


class Projector:
    """Lifecycle contract for a single projection (§7).

    Subclasses implement :meth:`validate`, :meth:`fold` and either
    :meth:`render` + :meth:`commit` or override :meth:`apply` to own the write.
    The base class provides deterministic ordering, quarantine accounting,
    checkpointing and health.
    """

    #: Stable projection name; also the cursor file stem.
    name: str = "projector"
    #: Content schema version this projector understands (§6.1).
    schema: int = 1

    def __init__(self, *, cursor_dir: str | Path = DEFAULT_CURSOR_DIR) -> None:
        self.cursor_dir = Path(cursor_dir)
        self.health_state = ProjectionHealth(name=self.name, schema=self.schema)
        self.checkpoint = load_checkpoint(self.name, cursor_dir=self.cursor_dir)
        self._quarantine_events: list[dict[str, Any]] = []

    # -- lifecycle -------------------------------------------------------- #

    def validate(self, event: dict[str, Any]) -> Any:
        """Return a normalised fact, or ``None`` to reject the event."""
        raise NotImplementedError

    def fold(self, current: Any, fact: Any) -> Any:
        """Return the next deterministic state for an address/family."""
        raise NotImplementedError

    def render(self, state: Any) -> str | None:
        """Return the projection candidate as text, or ``None`` for no-op."""
        return None

    def commit(self, candidate: str) -> None:
        """Atomically install the rendered projection."""
        raise NotImplementedError

    def clone(self) -> "Projector":
        """Return a fresh, empty projector of the same kind (for :func:`verify`).

        Subclasses that materialise a multi-row projection should override this
        so a relay replay can be refolded from scratch and compared to the live
        store. The base contract is "not supported": :func:`verify` then falls
        back to the render-latest comparison.
        """
        raise NotImplementedError

    def apply(self, event: dict[str, Any]) -> ProjectionResult:
        """Validate → fold → render → commit one event, checkpoint on success.

        Subclasses that own a database-backed projection override this to keep
        the fold and commit in one transaction, but must call
        :meth:`_advance` only after their write succeeds.
        """
        fact = self.validate(event)
        if fact is None:
            self.quarantine(event, "rejected by validate()")
            return ProjectionResult(accepted=False, reason="invalid")
        candidate = self.render(fact)
        if candidate is not None:
            self.commit(candidate)
        self._advance(event)
        return ProjectionResult(accepted=True, changed=candidate is not None)

    # -- bookkeeping ------------------------------------------------------ #

    def _advance(self, event: dict[str, Any]) -> None:
        """Record that ``event`` is now reflected in the projection."""
        revision = _event_revision(event)
        self.checkpoint.event_id = str(event.get("id") or self.checkpoint.event_id)
        self.checkpoint.created_at = int(event.get("created_at") or self.checkpoint.created_at)
        self.checkpoint.revision = revision
        try:
            save_checkpoint(self.checkpoint, cursor_dir=self.cursor_dir)
        except OSError as exc:  # pragma: no cover - disk failure
            logger.error("%s: failed to persist checkpoint: %s", self.name, exc)
        self.health_state.applied_revision = revision
        self.health_state.source_revision = revision
        self.health_state.applied_at = time.time()
        self.health_state.last_error = ""

    def quarantine(self, event: dict[str, Any], reason: str) -> None:
        """Record an invalid event with a bounded reason (§7)."""
        entry = {
            "event_id": str(event.get("id") or ""),
            "kind": int(event.get("kind") or 0),
            "author": str(event.get("pubkey") or ""),
            "reason": reason[:200],
            "quarantined_at": time.time(),
        }
        self._quarantine_events.append(entry)
        self._quarantine_events = self._quarantine_events[-50:]
        self.health_state.quarantined = len(self._quarantine_events)
        logger.warning("%s: quarantined event %s (%s)", self.name, entry["event_id"][:16], entry["reason"])

    def quarantined(self) -> list[dict[str, Any]]:
        return list(self._quarantine_events)

    def health(self) -> ProjectionHealth:
        self.health_state.lag_seconds = max(0.0, time.time() - self.health_state.applied_at) if self.health_state.applied_at else 0.0
        return self.health_state


class JsonCoordinateStore:
    """Atomic JSON store for folded projection coordinates (WP4/WP6).

    Shared by the list and policy projections: entries are keyed by their
    stable event key and persisted atomically (0o600) via :func:`_atomic_write`.
    Which event wins for a key is the fold rule, implemented by each
    subclass's :meth:`put`; the base supplies load/save/get/all_entries.
    """

    #: Entry type; must provide ``from_dict(dict)`` and ``as_dict()``.
    entry_cls: type | None = None

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._entries: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if self.entry_cls is None:  # pragma: no cover - subclass must set it
            raise TypeError(f"{type(self).__name__} requires entry_cls")
        for key, info in (raw or {}).items():
            try:
                self._entries[key] = self.entry_cls.from_dict(info)
            except (TypeError, ValueError):
                logger.warning("ignoring malformed stored entry %s", key)

    def _save(self) -> None:
        payload = {key: entry.as_dict() for key, entry in self._entries.items()}
        _atomic_write(self.path, json.dumps(payload, indent=1, sort_keys=True) + "\n", mode=0o600)

    def get(self, key: str) -> Any | None:
        return self._entries.get(key)

    def all_entries(self) -> list[Any]:
        return list(self._entries.values())


class StoreProjector(Projector):
    """Store-backed projector plumbing shared by list/policy projections.

    Provides the ``current``/``render``/``commit``/``_digest``/``clone``
    boilerplate on top of a :class:`JsonCoordinateStore`; subclasses keep
    their own validation, fold rule and renderer dispatch, and implement
    :meth:`_clone_for` to build a fresh, empty projector of the same kind.
    """

    #: Prefix for the clone's temporary directory (per-subclass).
    _clone_prefix = "verify-"
    #: Backing :class:`JsonCoordinateStore` (set by the subclass __init__).
    store: JsonCoordinateStore
    #: Temp dir owned by the most recent clone; released on garbage collection.
    _tmpdir: tempfile.TemporaryDirectory[str] | None = None

    def clone(self) -> "StoreProjector":
        """Return a fresh, empty projector refolding into a throwaway store.

        The clone owns a private :class:`tempfile.TemporaryDirectory` that is
        released when the clone is garbage-collected, so ``verify`` no longer
        leaks a ``.json`` file per run.
        """
        tmp = tempfile.TemporaryDirectory(prefix=f"{self._clone_prefix}-")
        clone = self._clone_for(Path(tmp.name) / "clone.json")
        clone._tmpdir = tmp  # keep the temp dir alive with the clone
        return clone

    def _clone_for(self, path: Path) -> "StoreProjector":
        raise NotImplementedError

    def current(self) -> str:
        return json.dumps(self._digest(), sort_keys=True)

    def render(self, state: Any) -> str | None:
        return json.dumps(self._digest(), sort_keys=True)

    def commit(self, candidate: str) -> None:  # pragma: no cover - store owns the write
        raise NotImplementedError(f"{type(self).__name__} projection is written by its store")

    def _digest(self) -> dict[str, Any]:
        return {key: entry.as_dict() for key, entry in sorted(self.store._entries.items())}


def _event_revision(event: dict[str, Any]) -> str:
    """Best-effort logical revision label for the checkpoint/health view."""
    try:
        body = json.loads(event.get("content") or "{}")
    except (ValueError, TypeError):
        body = {}
    if isinstance(body, dict) and isinstance(body.get("revision"), int):
        return f"rev:{body['revision']}"
    return f"{int(event.get('created_at') or 0)}:{str(event.get('id') or '')[:12]}"


class ProjectionRegistry:
    """In-process registry of live projector health (API/diagnosis surface)."""

    def __init__(self) -> None:
        self._projectors: dict[str, Projector] = {}

    def register(self, projector: Projector) -> None:
        self._projectors[projector.name] = projector

    def unregister(self, name: str) -> None:
        self._projectors.pop(name, None)

    def snapshot(self) -> list[dict[str, Any]]:
        return [p.health().as_dict() for p in self._projectors.values()]

    def get(self, name: str) -> Projector | None:
        return self._projectors.get(name)


#: Process-wide registry. Each daemon registers its projector(s) at startup so
#: the API service (same host, separate process) reads the persisted cursor and
#: any daemon that exposes status can render this. A cross-process view is
#: provided by :func:`read_status_dir`.
REGISTRY = ProjectionRegistry()


def read_status_dir(cursor_dir: str | Path = DEFAULT_CURSOR_DIR) -> list[dict[str, Any]]:
    """Read all persisted projection cursors (cross-process status view)."""
    directory = Path(cursor_dir)
    rows: list[dict[str, Any]] = []
    if not directory.is_dir():
        return rows
    for path in sorted(directory.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        rows.append(
            {
                "name": str(raw.get("name") or path.stem),
                "applied_revision": str(raw.get("revision") or ""),
                "last_event_id": str(raw.get("event_id") or ""),
                "updated_at": float(raw.get("updated_at") or 0.0),
            }
        )
    return rows


def sort_events(
    events: Iterable[dict[str, Any]],
    *,
    priority: dict[int, int] | None = None,
) -> list[dict[str, Any]]:
    """Deterministic replay order: by creation time, then kind priority.

    Same-second ordering is not guaranteed by the relay, so replay must sort
    before folding; grants must precede the requests they authorise
    (operationsd's ``_REPLAY_PRIORITY`` behaviour, generalised here).
    """
    priority = priority or {}
    return sorted(
        events,
        key=lambda e: (
            int(e.get("created_at") or 0),
            priority.get(int(e.get("kind") or 0), 99),
            str(e.get("id") or ""),
        ),
    )


class ProjectionRuntime:
    """Shared subscribe/replay/backoff loop for a projector (§7).

    ``apply`` is called for each accepted event; the projector owns the write.
    Invalid events are quarantined, not fatal. A relay drop reconnects with
    backoff and the relay replays stored events, so state rebuilds.
    """

    def __init__(
        self,
        relay_url: str,
        *,
        projector: Projector,
        kinds: list[int],
        limit: int | None = None,
        priority: dict[int, int] | None = None,
        ping_interval: float | None = 20.0,
        on_replay: Callable[[list[dict[str, Any]]], None] | None = None,
        prepare_replay: Callable[[list[dict[str, Any]]], None] | None = None,
        apply_in_thread: bool = False,
        stop: "asyncio.Event | None" = None,
        auth_factory: Callable[[], tuple[str, str] | None] | None = None,
        clock: Callable[[], float] = time.time,
        apply: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        self.relay_url = relay_url
        self.projector = projector
        self.kinds = list(kinds)
        self.limit = limit
        self.priority = priority or {}
        self.ping_interval = ping_interval
        self.on_replay = on_replay
        #: Called with the raw replay buffer immediately before it is sorted and
        #: applied (operationsd's terminal-result pre-scan must run first).
        self.prepare_replay = prepare_replay
        #: Run each ``apply`` in a worker thread. Required when apply does
        #: blocking work (synchronous relay round-trips, snapshots) so the
        #: websocket keeps draining during a replay burst; see operationsd.
        self.apply_in_thread = apply_in_thread
        self.stop = stop
        self._auth_factory = auth_factory or default_auth
        self._clock = clock
        #: Optional override of the per-event application (defaults to
        #: ``projector.apply`` via :meth:`_apply`). Lets a daemon that is more
        #: than a pure projection (operationsd: executes as well as folds)
        #: route events through its own dispatcher while still reusing the
        #: shared subscribe/replay/backoff loop.
        self._apply_override = apply

    def _filter(self) -> dict[str, Any]:
        query: dict[str, Any] = {"kinds": self.kinds}
        if self.limit is not None:
            query["limit"] = self.limit
        return query

    def _apply(self, event: dict[str, Any]) -> None:
        if _is_future(event, self._clock):
            self.projector.quarantine(event, "created_at beyond allowed skew")
            return
        if self._apply_override is not None:
            try:
                self._apply_override(event)
            except Exception as exc:  # noqa: BLE001 - one bad event must not stop the projector
                self.projector.quarantine(event, f"apply failed: {exc}")
            return
        try:
            self.projector.apply(event)
        except Exception as exc:  # noqa: BLE001 - one bad event must not stop the projector
            self.projector.quarantine(event, f"apply failed: {exc}")

    async def _dispatch(self, event: dict[str, Any]) -> None:
        if self.apply_in_thread:
            await asyncio.to_thread(self._apply, event)
        else:
            self._apply(event)

    async def run(self) -> None:
        import websockets

        ping_kwargs: dict[str, Any] = {}
        if self.ping_interval is not None:
            ping_kwargs = {"ping_interval": self.ping_interval, "ping_timeout": None}
        while not (self.stop is not None and self.stop.is_set()):
            try:
                async with websockets.connect(self.relay_url, **ping_kwargs) as ws:
                    sub_id = f"nostrhost-{self.projector.name}-" + secrets.token_hex(4)
                    await ws.send(json.dumps(["REQ", sub_id, self._filter()]))
                    self.projector.health_state.connected = True
                    logger.info("%s subscribed to %s", self.projector.name, self.relay_url)
                    replay: list[dict[str, Any]] = []
                    replaying = True
                    async for raw in ws:
                        msg = json.loads(raw)
                        if msg[0] == "AUTH":
                            challenge = msg[1] if len(msg) > 1 else ""
                            auth = self._auth_factory()
                            if auth is not None:
                                auth_ev = _sign_auth_event(auth[0], auth[1], self.relay_url, challenge, sub_id)
                                await ws.send(json.dumps(["AUTH", auth_ev]))
                                await _wait_auth_ok_async(ws, auth_ev["id"])
                                replay = []
                                replaying = True
                                await ws.send(json.dumps(["REQ", sub_id, self._filter()]))
                            continue
                        if msg[0] == "EVENT":
                            if replaying:
                                replay.append(msg[2])
                            else:
                                await self._dispatch(msg[2])
                        elif msg[0] == "EOSE":
                            if self.prepare_replay is not None:
                                self.prepare_replay(list(replay))
                            ordered = sort_events(replay, priority=self.priority)
                            for event in ordered:
                                await self._dispatch(event)
                            if self.on_replay is not None:
                                self.on_replay(ordered)
                            replay.clear()
                            replaying = False
                        elif msg[0] == "CLOSED":
                            logger.warning("%s: relay closed subscription: %s", self.projector.name, msg[2] if len(msg) > 2 else "")
                            break
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - keep the projector alive
                self.projector.health_state.connected = False
                self.projector.health_state.last_error = str(exc)
                logger.error("%s: subscription error: %s; retrying in %ss", self.projector.name, exc, BACKOFF_SECONDS)
                await asyncio.sleep(BACKOFF_SECONDS)


def _is_future(event: dict[str, Any], clock: Callable[[], float]) -> bool:
    try:
        created_at = int(event.get("created_at") or 0)
    except (ValueError, TypeError):
        return False
    return created_at - clock() > MAX_FUTURE_SKEW


def rebuild(
    events: Iterable[dict[str, Any]],
    *,
    projector: Projector,
    priority: dict[int, int] | None = None,
    apply: Callable[[dict[str, Any]], Any] | None = None,
) -> dict[str, Any]:
    """Refold a complete event set into a fresh projection (§7 ``Rebuild``).

    ``apply`` overrides the per-event application for daemons that dispatch
    events themselves (operationsd executes as well as folds); the default is
    ``projector.apply``.
    """
    accepted = 0
    rejected = 0
    for event in sort_events(events, priority=priority):
        if apply is not None:
            result = apply(event)
        else:
            result = projector.apply(event)
        if getattr(result, "accepted", True):
            accepted += 1
        else:
            rejected += 1
    return {"name": projector.name, "accepted": accepted, "rejected": rejected, "health": projector.health().as_dict()}


def verify(projector: Projector, expected: Iterable[dict[str, Any]]) -> list[str]:
    """Report semantic drift between the live projection and a relay replay.

    The authoritative source is the event set: a **fresh clone** of the
    projector refolds ``expected`` and its rendered output is compared to the
    live projection. That catches a missing or stale row anywhere in a
    multi-row projection (identity mapping, capability set), not just the
    newest event. Falls back to the render-latest contract when a projector
    does not implement :meth:`Projector.clone`.
    """
    problems: list[str] = []
    ordered = list(sort_events(expected))
    clone = None
    try:
        clone = projector.clone()
    except NotImplementedError:
        clone = None
    except Exception as exc:  # noqa: BLE001
        problems.append(f"could not clone projector: {exc}")

    if clone is not None:
        for event in ordered:
            clone.apply(event)
        expected_render = clone.render(None)
        current = None
        try:
            if hasattr(projector, "current"):
                current = projector.current()  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            problems.append(f"could not read current projection: {exc}")
        if expected_render is not None and current is not None and expected_render != current:
            problems.append("refolded projection differs from committed projection")
        return problems

    facts = [projector.validate(event) for event in ordered]
    facts = [fact for fact in facts if fact is not None]
    candidate = projector.render(facts[-1] if facts else None)
    current = None
    try:
        if hasattr(projector, "current"):
            current = projector.current()  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001
        problems.append(f"could not read current projection: {exc}")
    if candidate is not None and current is not None and candidate != current:
        problems.append("rendered projection differs from committed projection")
    return problems


def shadow(
    events: Iterable[dict[str, Any]],
    *,
    projector: Projector,
    staging_path: str | Path,
) -> dict[str, Any]:
    """Validate/fold ``events`` and render to ``staging_path`` only.

    Unlike :func:`rebuild`, shadow mode never touches the live projection or
    advances the checkpoint: it is the WP2 comparison mode for validating a
    projector against the legacy store before cutover (§8 Gate B).
    """
    staging = Path(staging_path)
    accepted = 0
    rejected = 0
    state: Any = None
    for event in sort_events(events):
        fact = projector.validate(event)
        if fact is None:
            rejected += 1
            continue
        state = projector.fold(state, fact)
        accepted += 1
    candidate = projector.render(state)
    if candidate is not None:
        _atomic_write(staging, candidate)
    return {
        "name": projector.name,
        "accepted": accepted,
        "rejected": rejected,
        "staging_path": str(staging),
    }


def projection_events_for_health(cursor_dir: str | Path = DEFAULT_CURSOR_DIR) -> list[dict[str, Any]]:
    """Convenience wrapper used by the API/diagnosis to list projection health."""
    return read_status_dir(cursor_dir)
