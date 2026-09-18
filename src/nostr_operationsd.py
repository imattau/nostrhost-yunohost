"""Operation executor / projector (nostr-operationsd) — roadmap §4 / Phase 3.

The vertical slice that proves the architectural claim: *signed Nostr events
drive YunoHost through a controlled execution boundary.*

Consumes the operation chain (kinds 2200–2204) and capability grants
(kind 31100) from the local control relay and, per request:

 1. validates the tool (unknown → auto-reject),
 2. authorises the requester (admin, or granted scope from 31100 events;
    otherwise → auto-reject),
 3. gates on admin approval (kind 2201) unless the tool does not require it
    or the actor is itself an admin (an admin's own request is the approval),
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
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable

from .nostr_identity import (
    _configure_daemon_logging,
    _init_headless_yunohost,
    _is_hex64,
    _operator_config,
    pubkey_is_admin,
    _require_bootstrapped,
    _sign_auth_event,
    _wait_auth_ok_async,
    default_auth,
)
from .nostr_operations import (
    KIND_CAPABILITY,
    KIND_DELEGATION,
    KIND_DELEGATION_REVOCATION,
    KNOWN_SCOPES,
    DELEGATION_MAX_LIFETIME,
    KIND_OPERATION_APPROVAL,
    KIND_OPERATION_REJECTION,
    KIND_OPERATION_REQUEST,
    KIND_EXECUTION_RESULT,
    KIND_EXECUTION_STARTED,
    _derive_pubkey,
    build_execution_progress,
    build_execution_result,
    build_execution_started,
    tool_spec,
)
from .nostr_operations_state import InvalidTransition, OpState, next_state
from .nostrhost.events import _d_tag, _e_tag, _tag_value, query_chain_events

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
        if tool == "package.reconcile":
            from nostrhost.native_providers import NativeOperationExecutor, native_providers
            from .nostr_operations import _safe_package_reconcile

            return _safe_package_reconcile(
                **args,
                _executor=NativeOperationExecutor(native_providers()),
            )
        return spec.handler(**args)


@dataclass
class OperationRecord:
    """Mutable per-request state held by the engine."""

    request_id: str
    tool: str
    args: dict[str, Any]
    requester: str
    actor: str
    state: OpState = OpState.REQUESTED
    reason: str | None = None
    result: dict[str, Any] | None = None
    policy: dict[str, Any] | None = None


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
        restic: Any = None,
        policy: Callable[[str, dict[str, Any], str], dict[str, Any] | bool | None] | None = None,
        policy_owner: str | None = None,
        brokers: tuple[str, ...] | list[str] = (),
        admin_authorizer: Callable[[str], bool] | None = None,
    ) -> None:
        self._publish = publish
        self._server_sk = server_sk
        self._server_pubkey = _derive_pubkey(server_sk)
        self._admins = tuple(admin.lower() for admin in admins)
        self._admin_authorizer = admin_authorizer
        self._brokers = tuple(brokers)
        self._backend = backend or YnhExecutorBackend()
        self._state = state  # optional StateRecorder (Stage A: pre/post snapshots)
        self._restic = restic  # optional ResticClient (Stage B: restore steps)
        self._policy = policy  # optional nostrhost-policy adapter
        self._policy_owner = policy_owner
        self.records: dict[str, OperationRecord] = {}
        self.scopes: dict[str, set[str]] = defaultdict(set)
        self.delegations: dict[str, dict[str, Any]] = {}
        self.revoked_delegations: set[str] = set()
        # Request ids that already reached a terminal execution result (2204).
        # Rebuilt from a fresh-connect replay before any request is re-fed, so
        # a daemon restart can never re-run an already-executed write.
        self.executed: set[str] = set()

    def mark_executed(self, request_ids: set[str]) -> None:
        """Record request ids whose execution already reached a terminal
        result (used when rebuilding state from a relay replay)."""
        self.executed.update(request_ids)

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
        if kind == KIND_DELEGATION:
            return self.handle_delegation(event)
        if kind == KIND_DELEGATION_REVOCATION:
            return self.handle_delegation_revocation(event)
        return False

    # -- chain handlers ---------------------------------------------------- #

    def handle_request(self, event: dict[str, Any]) -> bool:
        request_id = event.get("id")
        if not request_id:
            return False
        if request_id in self.records:
            return False  # replay of an already-seen request
        if request_id in self.executed:
            # This request already ran to a terminal result (a prior daemon
            # run, or a replay rebuild). Never re-execute it: re-feeding its
            # request/approval events on restart must be a no-op.
            return False

        try:
            body = json.loads(event.get("content") or "{}")
        except json.JSONDecodeError:
            body = {}
        tool = str(body.get("tool") or "").strip()
        args = body.get("args") or {}
        catalog_digest = str(body.get("catalog_digest") or "")

        requester = event.get("pubkey", "")
        if not tool or not _is_hex64(requester):
            return False
        actor = _tag_value(event, "actor") or requester
        if not _is_hex64(actor):
            return False

        record = OperationRecord(request_id=request_id, tool=tool, args=args, requester=requester, actor=actor.lower())
        self.records[request_id] = record

        # Bind the `actor` tag to an authorised signer. The MCP adapter signs
        # as a trusted node key and carries the authenticated client's npub in
        # the actor tag, so a request naming a *different* actor than the
        # signing key may only come from an admin or a configured trusted
        # broker. Any other allowlisted writer (agent/notice/publisher — all
        # low-trust) impersonating an admin here would otherwise bypass the
        # scope check below. A broker is a scoped node key that is NOT an
        # admin: it relays the client's actor, so it never needs the operator
        # key (M6), while still not being able to impersonate arbitrary keys.
        if actor != requester and requester not in self._admins and requester not in self._brokers:
            self._reject(record, "unauthorized_actor")
            return True

        spec = tool_spec(tool)
        if spec is None:
            self._reject(record, f"unknown_tool:{tool}")
            return True
        from .nostr_operations import operation_catalog

        if catalog_digest != operation_catalog()["digest"]:
            self._reject(record, "catalog_digest_mismatch")
            return True

        # Authorise the *actor* (defaults to the requester when no actor tag is
        # present). The requester is only the relay-admitted signing key: the
        # MCP adapter publishes as a trusted node key with the client's npub in
        # the actor tag, so the scope must be checked against the actor, not the
        # signer — otherwise every HTTP client inherits the operator's authority
        # (MCP transition Phase 2).
        required_scopes = (spec.scope,) + tuple(spec.required_scopes or ())
        if not all(self._authorized(actor.lower(), scope) for scope in required_scopes):
            self._reject(record, "unauthorized")
            return True

        try:
            record.args = spec.validate_args(record.args)
        except Exception as exc:  # noqa: BLE001 - invalid args are a rejected request
            self._reject(record, f"invalid_args:{exc}")
            return True

        try:
            self._evaluate_policy(record)
        except Exception as exc:  # noqa: BLE001 - policy denial is a rejected request
            self._reject(record, f"policy_denied:{exc}")
            return True

        if not spec.require_approval or self._actor_approves(record):
            self._execute(record)  # auto path: REQUESTED -> EXECUTING
        else:
            logger.info("request %s: %s by %s awaiting approval", request_id[:16], tool, requester[:16])
        return True

    def _actor_approves(self, record: OperationRecord) -> bool:
        """Whether the requesting actor's own authority satisfies the approval
        gate, so an admin's operation auto-executes instead of parking for a
        separate kind-2201 approval.

        The approval step exists to let an admin authorise a *non-admin*
        caller (a delegated agent or a broker-relayed scoped user). When the
        actor is already an admin there is no separate authority left to ask,
        so the admin's own signed request is the approval. YunoHost's current
        ``admins`` group is authoritative for operation approvals; the
        operator has no additional approval privilege over another admin.
        """
        return self._is_approver(record.actor)

    def _is_approver(self, pubkey: str | None) -> bool:
        """Resolve operation approval authority at decision time.

        Static keys remain the bootstrap fallback. The injected resolver adds
        enabled identities linked to current members of the YunoHost
        ``admins`` group without broadening operation-submission scopes.
        """
        if not isinstance(pubkey, str):
            return False
        normalized = pubkey.lower()
        if normalized in self._admins:
            return True
        if self._admin_authorizer is None:
            return False
        try:
            return bool(self._admin_authorizer(normalized))
        except Exception:  # noqa: BLE001 - authorization backend must fail closed
            logger.exception("dynamic admin resolution failed for %s", normalized[:16])
            return False

    def handle_approval(self, event: dict[str, Any]) -> bool:
        record, request_id = self._chain_target(event)
        if request_id is None:
            return False
        if record is None:
            # A request that already reached a terminal result is deliberately
            # not rebuilt into a record on replay, so its approval is a no-op
            # rather than a gap; only warn for a genuinely unknown request.
            if request_id not in self.executed:
                logger.warning("approval for %s ignored: request not in executor state", request_id[:16])
            return False
        if not self._is_approver(event.get("pubkey")):
            logger.warning("approval for %s by non-admin ignored", request_id[:16])
            return False
        try:
            self._evaluate_policy(record)
        except Exception as exc:  # noqa: BLE001 - policy may change while awaiting approval
            self._reject(record, f"policy_denied:{exc}")
            return True
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
        if request_id is None:
            return False
        if record is None:
            if request_id not in self.executed:
                logger.warning("rejection for %s ignored: request not in executor state", request_id[:16])
            return False
        if not self._is_approver(event.get("pubkey")):
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
            self.executed.add(request_id)
        return True

    def handle_capability(self, event: dict[str, Any]) -> bool:
        """Project a 31100 grant: subject pubkey -> granted scopes.

        Only admin-authored grants are authoritative. The relay rejects forged
        31100 at write time too, but the daemon re-checks so a relay policy
        regression cannot silently expand scopes."""
        subject = _d_tag(event)
        if not subject:
            return False
        if event.get("pubkey") not in self._admins:
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

    def handle_delegation(self, event: dict[str, Any]) -> bool:
        try:
            _verify_delegation_event(event)
            delegate = next(t[1] for t in event.get("tags", []) if len(t) >= 2 and t[0] == "p")
            server = next(t[1] for t in event.get("tags", []) if len(t) >= 2 and t[0] == "server")
            expiry = int(next(t[1] for t in event.get("tags", []) if len(t) >= 2 and t[0] == "expiry"))
            scopes = {t[1] for t in event.get("tags", []) if len(t) >= 2 and t[0] == "scope"}
            created_at = int(event["created_at"])
        except (KeyError, StopIteration, TypeError, ValueError, IndexError):
            return False
        if server != self._server_pubkey or not _is_hex64(delegate) or not scopes or not scopes.issubset(KNOWN_SCOPES):
            return False
        now = int(time.time())
        if expiry <= now or expiry - created_at > DELEGATION_MAX_LIFETIME or event["id"] in self.revoked_delegations:
            return False
        if not all(self._direct_authorized(event["pubkey"], scope) for scope in scopes):
            return False
        self.delegations[event["id"]] = {
            "delegator": event["pubkey"], "delegate": delegate, "scopes": scopes, "expiry": expiry
        }
        return True

    def handle_delegation_revocation(self, event: dict[str, Any]) -> bool:
        delegation_id = _e_tag(event)
        if not delegation_id:
            return False
        record = self.delegations.get(delegation_id)
        if record is not None and event.get("pubkey") not in (record["delegator"], *self._admins):
            return False
        if record is None and event.get("pubkey") not in self._admins:
            return False
        try:
            _verify_delegation_event(event, revocation=True)
        except (KeyError, TypeError, ValueError, IndexError):
            return False
        self.revoked_delegations.add(delegation_id)
        self.delegations.pop(delegation_id, None)
        return True

    # -- authorisation + execution ---------------------------------------- #

    def _authorized(self, pubkey: str, scope: str) -> bool:
        if self._direct_authorized(pubkey, scope):
            return True
        now = int(time.time())
        return any(
            d["delegate"] == pubkey and scope in d["scopes"] and d["expiry"] > now
            and self._direct_authorized(d["delegator"], scope)
            for delegation_id, d in self.delegations.items()
            if delegation_id not in self.revoked_delegations
        )

    def _direct_authorized(self, pubkey: str, scope: str) -> bool:
        return pubkey in self._admins or scope in self.scopes[pubkey]

    def _evaluate_policy(self, record: OperationRecord) -> None:
        """Run the host policy adapter before request/approval execution.

        The callback receives the complete tool arguments and actor identity;
        a false result or ``{"allow": false}`` denies the request. A dict
        decision is retained for the audit/result boundary, allowing the
        injected ``nostrhost-policy`` adapter to include its version and plan
        digest without making this daemon depend on that package directly.
        """
        if self._policy is None:
            return
        decision = self._policy(record.tool, dict(record.args), record.actor)
        if decision is False or (isinstance(decision, dict) and decision.get("allow") is False):
            reason = decision.get("reason", "policy rejected operation") if isinstance(decision, dict) else "policy rejected operation"
            raise ValueError(str(reason))
        if isinstance(decision, dict):
            record.policy = dict(decision)

    def _execute(self, record: OperationRecord) -> None:
        if record.state not in (OpState.REQUESTED, OpState.APPROVED):
            logger.warning("cannot execute %s from %s", record.request_id[:16], record.state.value)
            return
        spec = tool_spec(record.tool)
        if spec is None:
            self._reject(record, f"unknown_tool:{record.tool}")
            return
        try:
            record.state = next_state(record.state, KIND_EXECUTION_STARTED)
        except InvalidTransition as exc:
            logger.warning("execution for %s ignored: %s", record.request_id[:16], exc)
            return
        self._publish(build_execution_started(self._server_sk, self._server_pubkey, record.request_id, actor_pubkey=record.actor))
        logger.info("executing %s: %s", record.request_id[:16], record.tool)
        if self._state is not None:
            self._state.pre(record.request_id, record.tool, record.args, actor=record.actor)
        try:
            self._progress(record, "executing", 0.0, f"starting {record.tool}")
            if record.tool == "rollback.apply":
                from .nostr_operations import _run_rollback_apply

                state_repo = getattr(self._state, "repo", None)
                result = _run_rollback_apply(
                    record.args, backend=self._backend, restic=self._restic, repo=state_repo
                )
                operation_ok = bool(result.pop("_ok", True))
            elif record.tool == "state.reconcile":
                from .nostr_operations import _run_reconcile_apply

                state_repo = getattr(self._state, "repo", None)
                result = _run_reconcile_apply(record.args, backend=self._backend, repo=state_repo)
                operation_ok = bool(result.pop("_ok", True))
            else:
                self._progress(record, "executing", 0.5, f"running {record.tool}")
                result = self._backend.execute(record.tool, record.args)
                operation_ok = True
            result = spec.validate_result(result)
            self._progress(record, "executing", 1.0, f"{record.tool} finished")
            body: dict[str, Any] = {"ok": operation_ok, "result": result}
            if record.policy:
                body["policy"] = record.policy
        except Exception as exc:  # noqa: BLE001 - a failed tool is a 2204, not a crash
            logger.error("execution of %s failed: %s", record.tool, exc)
            body = {"ok": False, "error": str(exc)}
        if self._state is not None:
            self._state.post(record.request_id, record.tool, body["ok"], body, actor=record.actor, args=record.args)
            if body.get("ok") and spec.state_impact == "application_data":
                snapshot = getattr(self._state, "last_restic_snapshot", "") or ""
                result_body = body.get("result")
                if snapshot and isinstance(result_body, dict):
                    result_body["restic_snapshot"] = snapshot
        if body.get("ok"):
            try:
                body["result"] = spec.validate_result(body.get("result"))
            except Exception as exc:  # noqa: BLE001 - contract violations fail closed
                logger.error("result contract violation for %s: %s", record.tool, exc)
                body = {"ok": False, "error": "operation result violated its declared contract"}
        from .nostr_operations import operation_catalog

        body["catalog_digest"] = operation_catalog()["digest"]
        self._publish(build_execution_result(self._server_sk, self._server_pubkey, record.request_id, actor_pubkey=record.actor, **body))
        record.state = next_state(record.state, KIND_EXECUTION_RESULT, ok=body["ok"])
        record.result = body
        logger.info("request %s -> %s", record.request_id[:16], record.state.value)

    def _reject(self, record: OperationRecord, reason: str) -> None:
        record.state = OpState.REJECTED
        record.reason = reason
        from .nostr_operations import operation_catalog

        body = {"reason": reason, "catalog_digest": operation_catalog()["digest"]}
        self._publish(build_execution_result(self._server_sk, self._server_pubkey, record.request_id, ok=False, actor_pubkey=record.actor, **body))
        logger.info("request %s rejected: %s", record.request_id[:16], reason)

    def _progress(self, record: OperationRecord, stage: str, progress: float, message: str) -> None:
        """Publish a kind-2205 execution-progress event for ``record``."""
        try:
            self._publish(
                build_execution_progress(
                    self._server_sk,
                    self._server_pubkey,
                    record.request_id,
                    stage=stage,
                    progress=progress,
                    message=message,
                    actor_pubkey=record.actor,
                )
            )
        except Exception as exc:  # noqa: BLE001 - progress is best-effort
            logger.warning("failed to publish progress for %s: %s", record.request_id[:16], exc)

    # -- helpers ----------------------------------------------------------- #

    def _chain_target(self, event: dict[str, Any]) -> tuple[OperationRecord | None, str | None]:
        request_id = _e_tag(event)
        if not request_id:
            return None, None
        return self.records.get(request_id), request_id

    def state(self, request_id: str) -> OpState | None:
        rec = self.records.get(request_id)
        return rec.state if rec else None


def _verify_delegation_event(event: dict[str, Any], *, revocation: bool = False) -> None:
    from nostr_sdk import Event

    if not _is_hex64(str(event.get("id", ""))) or not _is_hex64(str(event.get("pubkey", ""))):
        raise ValueError("invalid delegation event key")
    try:
        parsed = Event.from_json(json.dumps(event))
        if not parsed.verify():
            raise ValueError("delegation event signature or id invalid")
    except Exception as exc:  # noqa: BLE001 - normalize SDK parse/verification errors
        raise ValueError("delegation event signature or id invalid") from exc
    if revocation and event.get("kind") != KIND_DELEGATION_REVOCATION:
        raise ValueError("invalid delegation revocation kind")
    if not revocation and event.get("kind") != KIND_DELEGATION:
        raise ValueError("invalid delegation kind")


# --------------------------------------------------------------------------- #
# daemon

SUBSCRIBE_KINDS = [
    KIND_OPERATION_REQUEST,
    KIND_OPERATION_APPROVAL,
    KIND_OPERATION_REJECTION,
    KIND_EXECUTION_STARTED,
    KIND_EXECUTION_RESULT,
    KIND_CAPABILITY,
    KIND_DELEGATION,
    KIND_DELEGATION_REVOCATION,
]

# The replay REQ asks for the whole chain explicitly: the relay's badger
# backend defaults an unlimited REQ to a small window (MaxLimit/4), so without
# this a restart would rebuild only the newest slice of state and silently
# drop approvals for older in-flight requests.
REPLAY_LIMIT = 20000

# Replay order within the same created_at second: capability grants must be
# projected before the requests they authorise, then requests before the
# approval/rejection/execution events that reference them. The relay's
# fresh-connect replay order is not guaranteed for same-second events, so a
# restart must sort before feeding the engine (otherwise a mid-flight request
# is wrongly re-evaluated before its grant is seen).
_REPLAY_PRIORITY = {
    KIND_CAPABILITY: 0,
    KIND_DELEGATION: 1,
    KIND_DELEGATION_REVOCATION: 2,
    KIND_OPERATION_REQUEST: 3,
    KIND_OPERATION_APPROVAL: 4,
    KIND_OPERATION_REJECTION: 5,
    KIND_EXECUTION_STARTED: 6,
    KIND_EXECUTION_RESULT: 7,
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

    # ping_interval=None: the relay owns the keepalive (it pings every 30s and
    # we auto-pong); if the client also pings, its 20s ping_timeout can fire
    # while the event loop is briefly busy during a replay burst and the client
    # tears the connection down with close 1011 "keepalive ping timeout",
    # kicking the daemon into a reconnect loop.
    while not (stop is not None and stop.is_set()):
        try:
            async with websockets.connect(relay_url, ping_interval=None, ping_timeout=None) as ws:
                sub_id = "nostrhost-operations-" + secrets.token_hex(4)
                await ws.send(json.dumps(["REQ", sub_id, {"kinds": SUBSCRIBE_KINDS, "limit": REPLAY_LIMIT}]))
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
                            await ws.send(json.dumps(["REQ", sub_id, {"kinds": SUBSCRIBE_KINDS, "limit": REPLAY_LIMIT}]))
                        continue
                    if msg[0] == "EVENT":
                        if replaying:
                            replay.append(msg[2])
                        else:
                            # handle_event performs blocking work (synchronous
                            # publish_to_relay round-trips, state snapshots).
                            # Run it in a worker thread so the subscribe
                            # websocket keeps reading and the relay does not
                            # time the connection out during replay bursts.
                            await asyncio.to_thread(engine.handle_event, msg[2])
                    elif msg[0] == "EOSE":
                        # Rebuild the set of already-executed request ids from
                        # the terminal results in this replay BEFORE feeding
                        # the sorted chain, so a daemon restart can never
                        # re-run an approved write (the replayed 2200/2201
                        # would otherwise execute again before the replayed
                        # 2203/2204 arrive).
                        terminal = {
                            eid
                            for ev in replay
                            if int(ev.get("kind") or 0) == KIND_EXECUTION_RESULT
                            for eid in [_e_tag(ev)]
                            if eid
                        }
                        if terminal:
                            engine.mark_executed(terminal)
                        for ev in _sorted_replay(replay):
                            await asyncio.to_thread(engine.handle_event, ev)
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


def preload_capabilities(engine: OperationEngine, relay_url: str) -> None:
    """Project the replaceable capability/delegation grants before the live
    subscription starts.

    The control relay's badger-backed store truncates parameterized-replaceable
    (NIP-33) events when they share a REQ with the 2200-2205 chain kinds (only
    the newest grant is returned), so the combined subscription alone would
    leave every grant but the newest unprojected -> spurious `unauthorized`
    rejections. Queried on their own kinds the relay returns the latest per
    subject, so this loads the whole grant/delegation set first; the live
    subscription still delivers newly published grants. Best-effort.
    """
    for preload_kind in (KIND_CAPABILITY, KIND_DELEGATION, KIND_DELEGATION_REVOCATION):
        try:
            for event in query_chain_events(relay_url, kinds=(preload_kind,), limit=500):
                engine.handle_event(event)
        except Exception as exc:  # noqa: BLE001 - best-effort; the live sub still sees new events
            logger.warning("preload of kind %s failed (%s); grants may be missing until reconnect", preload_kind, exc)


def run() -> None:
    """Entry point for bin/nostr-operationsd."""
    _configure_daemon_logging()
    _init_headless_yunohost()
    _require_bootstrapped()
    cfg = _operator_config()
    restic = _restic_from_config()
    try:
        from .nostrhost_native_policy import build_native_policy_adapter

        policy = build_native_policy_adapter()
    except Exception as exc:  # noqa: BLE001 - policy remains optional on old nodes
        logger.error("native policy adapter unavailable (%s); continuing without policy facts", exc)
        policy = None
    engine = OperationEngine(
        publish=lambda ev: _publish_default(cfg.control_relay, ev), server_sk=cfg.server_sk, admins=cfg.admins,
        restic=restic, policy=policy, policy_owner=cfg.operator_pubkey, brokers=cfg.broker_pubkeys,
        admin_authorizer=lambda pubkey: pubkey_is_admin(pubkey, configured_admins=cfg.admins),
    )
    try:
        from .nostr_state import StateRecorder, StateRepo, state_dir_from_env
        from .nostr_restic import restic_snapshot_hook

        state = StateRecorder(
            StateRepo(state_dir_from_env(), cfg.server_pubkey),
            capabilities=lambda: {pk: sorted(sc) for pk, sc in engine.scopes.items()},
            restic_hook=restic_snapshot_hook() if restic is not None else None,
        )
        engine = OperationEngine(
            publish=lambda ev: _publish_default(cfg.control_relay, ev),
            server_sk=cfg.server_sk,
            admins=cfg.admins,
            state=state,
            restic=restic,
            policy=policy,
            policy_owner=cfg.operator_pubkey,
            brokers=cfg.broker_pubkeys,
            admin_authorizer=lambda pubkey: pubkey_is_admin(pubkey, configured_admins=cfg.admins),
        )
    except Exception as exc:  # noqa: BLE001 - state history is additive; a broken state layer must not kill the executor
        logger.error("state recorder unavailable (%s); continuing without pre/post snapshots", exc)
        engine = OperationEngine(
            publish=lambda ev: _publish_default(cfg.control_relay, ev), server_sk=cfg.server_sk, admins=cfg.admins,
            restic=restic, policy=policy, policy_owner=cfg.operator_pubkey, brokers=cfg.broker_pubkeys,
            admin_authorizer=lambda pubkey: pubkey_is_admin(pubkey, configured_admins=cfg.admins),
        )
    # Preload the replaceable capability/delegation grants with dedicated
    # single-kind queries before the live subscription (see
    # preload_capabilities: the combined chain subscription truncates NIP-33
    # grants to the single newest one, which would reject every other grantee
    # with spurious `unauthorized` errors).
    preload_capabilities(engine, cfg.control_relay)
    try:
        asyncio.run(subscribe_loop(cfg.control_relay, engine=engine))
    except KeyboardInterrupt:
        pass


def _restic_from_config() -> Any:
    """A ResticClient when restic is configured (else None). Restore-required
    rollback steps are then executable through the chain; without it they are
    blocked with a clear report rather than silently skipped."""
    from .nostr_restic import ResticClient, load_restic_config

    conf = load_restic_config()
    if conf is None:
        return None
    return ResticClient(repo=conf.repo, password=conf.password, binary=conf.binary, host=conf.host, tag=conf.tag, timeout=conf.timeout)


def _publish_default(relay_url: str, event: dict[str, Any]) -> None:
    from .nostr_identity import publish_to_relay

    publish_to_relay(relay_url, event)
