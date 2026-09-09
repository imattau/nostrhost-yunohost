"""Tests for the pure operation state machine (nostr_operations_state)."""

from __future__ import annotations

import pytest

from yunohost.nostr_operations_state import (
    KIND_EXECUTION_RESULT,
    KIND_EXECUTION_STARTED,
    KIND_OPERATION_APPROVAL,
    KIND_OPERATION_REJECTION,
    InvalidTransition,
    OpState,
    next_state,
    state_machine,
)


def test_requested_approval_executing_succeeded():
    s = next_state(OpState.REQUESTED, KIND_OPERATION_APPROVAL)
    assert s == OpState.APPROVED
    s = next_state(s, KIND_EXECUTION_STARTED)
    assert s == OpState.EXECUTING
    s = next_state(s, KIND_EXECUTION_RESULT, ok=True)
    assert s == OpState.SUCCEEDED


def test_requested_approval_executing_failed():
    s = next_state(OpState.REQUESTED, KIND_OPERATION_APPROVAL)
    s = next_state(s, KIND_EXECUTION_STARTED)
    s = next_state(s, KIND_EXECUTION_RESULT, ok=False)
    assert s == OpState.FAILED


def test_requested_rejected():
    assert next_state(OpState.REQUESTED, KIND_OPERATION_REJECTION) == OpState.REJECTED


def test_auto_path_no_approval():
    s = next_state(OpState.REQUESTED, KIND_EXECUTION_STARTED)
    assert s == OpState.EXECUTING


@pytest.mark.parametrize(
    "current",
    [OpState.APPROVED, OpState.EXECUTING, OpState.REJECTED, OpState.SUCCEEDED, OpState.FAILED],
)
def test_approval_only_legal_from_requested(current):
    with pytest.raises(InvalidTransition):
        next_state(current, KIND_OPERATION_APPROVAL)


@pytest.mark.parametrize(
    "current",
    [OpState.APPROVED, OpState.EXECUTING, OpState.REJECTED, OpState.SUCCEEDED, OpState.FAILED],
)
def test_rejection_only_legal_from_requested(current):
    with pytest.raises(InvalidTransition):
        next_state(current, KIND_OPERATION_REJECTION)


def test_execution_legal_from_requested_or_approved_only():
    assert next_state(OpState.APPROVED, KIND_EXECUTION_STARTED) == OpState.EXECUTING
    with pytest.raises(InvalidTransition):
        next_state(OpState.REJECTED, KIND_EXECUTION_STARTED)
    with pytest.raises(InvalidTransition):
        next_state(OpState.SUCCEEDED, KIND_EXECUTION_STARTED)


def test_result_only_legal_from_executing():
    for current in (OpState.REQUESTED, OpState.APPROVED, OpState.REJECTED, OpState.SUCCEEDED, OpState.FAILED):
        with pytest.raises(InvalidTransition):
            next_state(current, KIND_EXECUTION_RESULT, ok=True)


def test_terminal_states_are_terminal():
    for terminal in (OpState.REJECTED, OpState.SUCCEEDED, OpState.FAILED):
        for kind in (KIND_OPERATION_APPROVAL, KIND_OPERATION_REJECTION, KIND_EXECUTION_STARTED, KIND_EXECUTION_RESULT):
            with pytest.raises(InvalidTransition):
                next_state(terminal, kind, ok=True)


def test_duplicate_result_raises():
    s = next_state(OpState.REQUESTED, KIND_EXECUTION_STARTED)
    next_state(s, KIND_EXECUTION_RESULT, ok=True)
    with pytest.raises(InvalidTransition):
        next_state(OpState.SUCCEEDED, KIND_EXECUTION_RESULT, ok=True)


def test_state_machine_map_covers_transitions():
    sm = state_machine()
    assert sm["requested"] == ["2201->approved", "2202->rejected", "2203->executing"]
    assert sm["approved"] == ["2203->executing"]
    assert sm["executing"] == ["2204->succeeded"]
    # terminal states have no outgoing transitions and thus no table row
    assert set(sm) == {"requested", "approved", "executing"}