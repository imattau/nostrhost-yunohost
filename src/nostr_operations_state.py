"""Operation state machine for the control plane (roadmap §4 / Phase 3).

A correctly *signed* chain event is not automatically a *valid transition*.
This module is the pure, framework-free state machine the executor
(nostr_operationsd) enforces:

    REQUESTED ──2201(approval)──▶ APPROVED ──2203(execution)──▶ EXECUTING ──2204(result)──▶ SUCCEEDED
        │                                                                                       │
        ├──2202(rejection)──▶ REJECTED                                                          or
        └──2203(execution, auto)──▶ EXECUTING ──2204──▶ FAILED

2204's `ok` flag decides SUCCEEDED vs FAILED. Any other transition attempt
raises :class:`InvalidTransition` — the engine ignores it (it never re-uses
an event that isn't a legal next step).
"""

from __future__ import annotations

from enum import Enum

KIND_OPERATION_APPROVAL = 2201
KIND_OPERATION_REJECTION = 2202
KIND_EXECUTION_STARTED = 2203
KIND_EXECUTION_RESULT = 2204


class OpState(str, Enum):
    REQUESTED = "requested"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


TERMINAL = frozenset({OpState.REJECTED, OpState.SUCCEEDED, OpState.FAILED})

# Which chain kind may advance which state (result handled separately).
_TRANSITIONS: dict[OpState, dict[int, OpState]] = {
    OpState.REQUESTED: {
        KIND_OPERATION_APPROVAL: OpState.APPROVED,  # admin approves
        KIND_OPERATION_REJECTION: OpState.REJECTED,  # admin rejects
        KIND_EXECUTION_STARTED: OpState.EXECUTING,  # no-approval auto path
    },
    OpState.APPROVED: {
        KIND_EXECUTION_STARTED: OpState.EXECUTING,
    },
    OpState.EXECUTING: {
        KIND_EXECUTION_RESULT: OpState.SUCCEEDED,  # ok=True decides below
    },
}


class InvalidTransition(ValueError):
    """A chain event does not legally follow the current request state."""


def next_state(current: OpState, chain_kind: int, *, ok: bool = True) -> OpState:
    """Return the state after applying `chain_kind` to `current`, or raise
    :class:`InvalidTransition` when the step is not a legal transition."""
    if current in TERMINAL:
        raise InvalidTransition(f"request already terminal ({current.value})")
    if chain_kind == KIND_EXECUTION_RESULT:
        if current != OpState.EXECUTING:
            raise InvalidTransition(f"result on {current.value} (must be executing)")
        return OpState.SUCCEEDED if ok else OpState.FAILED
    table = _TRANSITIONS.get(current, {})
    nxt = table.get(chain_kind)
    if nxt is None:
        raise InvalidTransition(f"kind {chain_kind} is not a legal step from {current.value}")
    return nxt


def state_machine() -> dict[str, list[str]]:
    """Human-readable transition map (for docs/tests)."""
    out: dict[str, list[str]] = {}
    for state, table in _TRANSITIONS.items():
        out[state.value] = [
            f"{kind}->{nxt.value}" if nxt else f"{kind}->(result decides)"
            for kind, nxt in table.items()
        ]
    return out