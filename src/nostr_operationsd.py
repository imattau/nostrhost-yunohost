"""Operation executor / projector (nostr-operationsd) — roadmap §4 / Phase 3.

The vertical slice that proves the architectural claim: *signed Nostr events
drive YunoHost through a controlled execution boundary.*

Consumes the operation chain (kinds 2200–2204) and capability grants
(kind 31100) from the local control relay and, per request:

 1. validates the tool (unknown → auto-reject),
 2. authorises the requester (admin, or granted scope from 31100 events;
    otherwise → auto-reject),
 3. gates on admin approval (kind 2201) unless the tool does not require it,
 4. publishes execution-started (2203) as the server key,
 5. runs the tool through the injected backend (real = fork's safe read-only
    functions),
 6. publishes the result (2204, ok/error) as the server key.

The state machine (nostr_operations_state) is enforced on every step: a
correctly-signed event that isn't a legal transition is ignored, never
applied. The engine is transport-free and fully injectable (publish callback,
executor backend), so the whole flow is testable without a relay or LDAP.

Phase 3 posture: read-only tools only, admin-gated, loopback relay.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable

from .nostr_identity import (
    _init_headless_yunohost,
    _operator_config,
    _require_bootstrapped,
    _sign_auth_event,
    _wait_auth_ok_async,
    default_auth,
)
from .nostr_operations import (
    KIND_CAPABILITY,
    KIND_OPERATION_APPROVAL,
    KIND_OPERATION_REJECTION,
    KIND_OPERATION_REQUEST,
    KIND_EXECUTION_RESULT,
    KIND_EXECUTION_STARTED,
    _derive_pubkey,
    build_execution_result,
    build_execution_started,
    tool_spec,
)
from .nostr_operations_state import InvalidTransition, OpState, next_state

logger = logging.getLogger("nostr-operationsd")


class ExecutorBackend:
    """Duck-typed tool executor. Production is :class:`YnhExecutorBackend`
    (real fork functions); tests inject a fake with the same surface."""

    def execute(self, tool: str, args: dict[str, Any]) -> Any:  # pragma: no cover - interface
        raise NotImplementedError


class YnhExecutorBackend(ExecutorBackend):
    """Real backend: runs the safe read-only tool through the fork's own
    (decorated) functions — the controlled execution boundary."""

    def execute(self, tool: str, args: dict[str, Any]) -> Any:
        spec = tool_spec(tool)
        if spec is None:
            raise ValueError(f"unknown tool {tool!r}")
        return spec.handler(**args)


@dataclass
class OperationRecord:
    """Mutable per-request state held by the engine."""

    request_id: str
    tool: str
    args: dict[str, Any]
    requester: str
    state: OpState = OpState.REQUESTED
    reason: str | None = None
    result: dict[str, Any] | None = None


class OperationEngine:
    """Stateful operation processor. Feed it relay events; it publishes chain
    events through the injected `publish` callable. Idempotent across replay
    (the relay re-sends stored events on reconnect)."""

    def __init__(
        self,
        *,
        publish: Callable[[dict[str, Any]], None],
        server_sk: str,
        admins: tuple[str, ...] | list[str],
        backend: ExecutorBackend | None = None,
        state: Any = None,
    ) -> None:
        self._publish = publish
        self._server_sk = server_sk
        self._server_pubkey = _derive_pubkey(server_sk)
        self._admins = tuple(admins)
        self._backend = backend or YnhExecutorBackend()
        self._state = state  # optional StateRecorder (Stage A: pre/post snapshots)
        self.records: dict[str, OperationRecord] = {}
        self.scopes: dict[str, set[str]] = defaultdict(set)

    # -- event intake ------------------------------------------------------ #

    def handle_event(self, event: dict[str, Any]) -> bool:
        """Dispatch one relay event; returns True when it was consumed."""
        kind = event.get("kind")
        if kind == KIND_OPERATION_REQUEST:
            return self.handle_request(event)
        if kind == KIND_OPERATION_APPROVAL:
            return self.handle_approval(event)
        if kind == KIND_OPERATION_REJECTION:
            return self.handle_rejection(event)
        if kind in (KIND_EXECUTION_STARTED, KIND_EXECUTION_RESULT):
            return self.handle_execution(event)
        if kind == KIND_CAPABILITY:
            return self.handle_capability(event)
        return False

    # -- chain handlers ---------------------------------------------------- #

    def handle_request(self, event: dict[str, Any]) -> bool:
        request_id = event.get("id")
        if not request_id:
            return False
        if request_id in self.records:
            return False  # replay of an already-seen request

        try:
            body = json.loads(event.get("content") or "{}")
        except json.JSONDecodeError:
            body = {}
        tool = str(body.get("tool") or "").strip()
        args = body.get("args") or {}

        requester = event.get("pubkey", "")
        if not tool or not _is_hex64(requester):
            return False

        record = OperationRecord(request_id=request_id, tool=tool, args=args, requester=requester)
        self.records[request_id] = record

        spec = tool_spec(tool)
        if spec is None:
            self._reject(record, f"unknown_tool:{tool}")
            return True

        if not self._authorized(requester, spec.scope):
            self._reject(record, "unauthorized")
            return True

        if not spec.require_approval:
            self._execute(record)  # auto path: REQUESTED -> EXECUTING
        else:
            logger.info("request %s: %s by %s awaiting approval", request_id[:16], tool, requester[:16])
        return True

    def handle_approval(self, event: dict[str, Any]) -> bool:
        record, request_id = self._chain_target(event)
        if record is None or request_id is None:
            return False
        if event.get("pubkey") not in self._admins:
            logger.warning("approval for %s by non-admin ignored", request_id[:16])
            return False
        try:
            next_state(record.state, KIND_OPERATION_APPROVAL)
        except InvalidTransition as exc:
            logger.warning("approval for %s ignored: %s", request_id[:16], exc)
            return False
        record.state = OpState.APPROVED
        self._execute(record)
        return True

    def handle_rejection(self, event: dict[str, Any]) -> bool:
        record, request_id = self._chain_target(event)
        if record is None or request_id is None:
            return False
        if event.get("pubkey") not in self._admins:
            logger.warning("rejection for %s by non-admin ignored", request_id[:16])
            return False
        try:
            next_state(record.state, KIND_OPERATION_REJECTION)
        except InvalidTransition as exc:
            logger.warning("rejection for %s ignored: %s", request_id[:16], exc)
            return False
        record.state = OpState.REJECTED
        reason = None
        try:
            reason = json.loads(event.get("content") or "{}").get("reason")
        except json.JSONDecodeError:
            pass
        record.reason = str(reason or "rejected")
        logger.info("request %s rejected (%s)", request_id[:16], record.reason)
        return True

    def handle_execution(self, event: dict[str, Any]) -> bool:
        """Observe 2203/2204 (ours, or replayed) to keep projection state."""
        record, request_id = self._chain_target(event)
        if record is None or request_id is None:
            return False
        kind = int(event.get("kind") or 0)
        if kind not in (KIND_EXECUTION_STARTED, KIND_EXECUTION_RESULT):
            return False
        ok = True
        body: dict[str, Any] = {}
        if kind == KIND_EXECUTION_RESULT:
            try:
                body = json.loads(event.get("content") or "{}")
            except json.JSONDecodeError:
                body = {}
            ok = bool(body.get("ok"))
        try:
            record.state = next_state(record.state, kind, ok=ok)
        except InvalidTransition as exc:
            logger.warning("%s for %s ignored: %s", kind, request_id[:16], exc)
            return False
        if kind == KIND_EXECUTION_RESULT:
            record.result = body
        return True

    def handle_capability(self, event: dict[str, Any]) -> bool:
        """Project a 31100 grant: subject pubkey -> granted scopes."""
        subject = _d_tag(event)
        if not subject:
            return False
        try:
            body = json.loads(event.get("content") or "{}")
        except json.JSONDecodeError:
            return False
        scopes = body.get("scopes")
        if not isinstance(scopes, list):
            return False
        self.scopes[subject] = {str(s) for s in scopes if isinstance(s, str)}
        logger.info("capability for %s: %s", subject[:16], sorted(self.scopes[subject]))
        return True

    # -- authorisation + execution ---------------------------------------- #

    def _authorized(self, pubkey: str, scope: str) -> bool:
        if pubkey in self._admins:
            return True
        return scope in self.scopes[pubkey]

    def _execute(self, record: OperationRecord) -> None:
        if record.state not in (OpState.REQUESTED, OpState.APPROVED):
            logger.warning("cannot execute %s from %s", record.request_id[:16], record.state.value)
            return
        try:
            record.state = next_state(record.state, KIND_EXECUTION_STARTED)
        except InvalidTransition as exc:
            logger.warning("execution for %s ignored: %s", record.request_id[:16], exc)
            return
        self._publish(build_execution_started(self._server_sk, self._server_pubkey, record.request_id))
        logger.info("executing %s: %s", record.request_id[:16], record.tool)
        if self._state is not None:
            self._state.pre(record.request_id, record.tool, record.args)
        try:
            result = self._backend.execute(record.tool, record.args)
            body: dict[str, Any] = {"ok": True, "result": result}
        except Exception as exc:  # noqa: BLE001 - a failed tool is a 2204, not a crash
            logger.error("execution of %s failed: %s", record.tool, exc)
            body = {"ok": False, "error": str(exc)}
        if self._state is not None:
            self._state.post(record.request_id, record.tool, body["ok"], body)
        self._publish(build_execution_result(self._server_sk, self._server_pubkey, record.request_id, **body))
        record.state = next_state(record.state, KIND_EXECUTION_RESULT, ok=body["ok"])
        record.result = body
        logger.info("request %s -> %s", record.request_id[:16], record.state.value)

    def _reject(self, record: OperationRecord, reason: str) -> None:
        record.state = OpState.REJECTED
        record.reason = reason
        body = {"reason": reason}
        self._publish(build_execution_result(self._server_sk, self._server_pubkey, record.request_id, ok=False, **body))
        logger.info("request %s rejected: %s", record.request_id[:16], reason)

    # -- helpers ----------------------------------------------------------- #

    def _chain_target(self, event: dict[str, Any]) -> tuple[OperationRecord | None, str | None]:
        request_id = _e_tag(event)
        if not request_id:
            return None, None
        return self.records.get(request_id), request_id

    def state(self, request_id: str) -> OpState | None:
        rec = self.records.get(request_id)
        return rec.state if rec else None


def _d_tag(event: dict[str, Any]) -> str | None:
    for tag in event.get("tags") or []:
        if tag and tag[0] == "d" and len(tag) > 1:
            return tag[1]
    return None


def _e_tag(event: dict[str, Any]) -> str | None:
    for tag in event.get("tags") or []:
        if tag and tag[0] == "e" and len(tag) > 1:
            return tag[1]
    return None


def _is_hex64(s: str) -> bool:
    return len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s)


# --------------------------------------------------------------------------- #
# daemon

SUBSCRIBE_KINDS = [
    KIND_OPERATION_REQUEST,
    KIND_OPERATION_APPROVAL,
    KIND_OPERATION_REJECTION,
    KIND_EXECUTION_STARTED,
    KIND_EXECUTION_RESULT,
    KIND_CAPABILITY,
]

# Replay order within the same created_at second: capability grants must be
# projected before the requests they authorise, then requests before the
# approval/rejection/execution events that reference them. The relay's
# fresh-connect replay order is not guaranteed for same-second events, so a
# restart must sort before feeding the engine (otherwise a mid-flight request
# is wrongly re-evaluated before its grant is seen).
_REPLAY_PRIORITY = {
    KIND_CAPABILITY: 0,
    KIND_OPERATION_REQUEST: 1,
    KIND_OPERATION_APPROVAL: 2,
    KIND_OPERATION_REJECTION: 3,
    KIND_EXECUTION_STARTED: 4,
    KIND_EXECUTION_RESULT: 5,
}


def _sorted_replay(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Stable order for a fresh-connect replay: grants before the requests
    they authorise, requests before the approval/rejection/execution events
    that reference them, then by creation time."""
    return sorted(
        events,
        key=lambda e: (int(e.get("created_at") or 0), _REPLAY_PRIORITY.get(int(e.get("kind") or 0), 99)),
    )


async def subscribe_loop(
    relay_url: str,
    *,
    engine: OperationEngine,
    stop: asyncio.Event | None = None,
) -> None:
    """Subscribe to chain + capability kinds and drive the engine. Reconnects
    with backoff; the relay replays stored events so state rebuilds."""
    import websockets

    while not (stop is not None and stop.is_set()):
        try:
            async with websockets.connect(relay_url) as ws:
                sub_id = "nostrhost-operations-" + secrets.token_hex(4)
                await ws.send(json.dumps(["REQ", sub_id, {"kinds": SUBSCRIBE_KINDS}]))
                logger.info("operations executor subscribed to %s", relay_url)
                replay: list[dict[str, Any]] = []
                replaying = True
                async for raw in ws:
                    msg = json.loads(raw)
                    if msg[0] == "AUTH":
                        challenge = msg[1] if len(msg) > 1 else ""
                        auth = default_auth()
                        if auth is not None:
                            auth_ev = _sign_auth_event(auth[0], auth[1], relay_url, challenge, sub_id)
                            await ws.send(json.dumps(["AUTH", auth_ev]))
                            await _wait_auth_ok_async(ws, auth_ev["id"])
                            replay = []
                            replaying = True
                            await ws.send(json.dumps(["REQ", sub_id, {"kinds": SUBSCRIBE_KINDS}]))
                        continue
                    if msg[0] == "EVENT":
                        if replaying:
                            replay.append(msg[2])
                        else:
                            engine.handle_event(msg[2])
                    elif msg[0] == "EOSE":
                        for ev in _sorted_replay(replay):
                            engine.handle_event(ev)
                        replay.clear()
                        replaying = False
                    elif msg[0] == "CLOSED":
                        logger.warning("relay closed subscription: %s", msg[2] if len(msg) > 2 else "")
                        break
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - keep the daemon alive
            logger.error("subscription error: %s; retrying in 5s", exc)
            await asyncio.sleep(5)


def run() -> None:
    """Entry point for bin/nostr-operationsd."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    _init_headless_yunohost()
    _require_bootstrapped()
    cfg = _operator_config()
    engine = OperationEngine(publish=lambda ev: _publish_default(cfg.control_relay, ev), server_sk=cfg.server_sk, admins=cfg.admins)
    try:
        from .nostr_state import StateRecorder, StateRepo, state_dir_from_env

        state = StateRecorder(
            StateRepo(state_dir_from_env(), cfg.server_pubkey),
            capabilities=lambda: {pk: sorted(sc) for pk, sc in engine.scopes.items()},
        )
        engine = OperationEngine(
            publish=lambda ev: _publish_default(cfg.control_relay, ev),
            server_sk=cfg.server_sk,
            admins=cfg.admins,
            state=state,
        )
    except Exception as exc:  # noqa: BLE001 - state history is additive; a broken state layer must not kill the executor
        logger.error("state recorder unavailable (%s); continuing without pre/post snapshots", exc)
        engine = OperationEngine(publish=lambda ev: _publish_default(cfg.control_relay, ev), server_sk=cfg.server_sk, admins=cfg.admins)
    try:
        asyncio.run(subscribe_loop(cfg.control_relay, engine=engine))
    except KeyboardInterrupt:
        pass


def _publish_default(relay_url: str, event: dict[str, Any]) -> None:
    from .nostr_identity import publish_to_relay

    publish_to_relay(relay_url, event)