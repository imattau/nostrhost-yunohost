"""Tests for the security-event projector (CROWDSEC-MIGRATION P5)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from yunohost.nostr_notify import SEVERITY_CRITICAL, SEVERITY_WARNING
from yunohost.nostr_security import (
    KIND_SECURITY_EVENT,
    SecurityConfig,
    SecurityProjector,
    SecurityState,
    coalesce,
)


def _alert(alert_id, source, scenario, *, decision_type="ban"):
    return {
        "id": alert_id,
        "created_at": f"2026-09-11T00:00:{alert_id:02d}Z",
        "scenario": scenario,
        "source": {"ip": source, "scope": "Ip", "value": source},
        "decisions": [
            {"id": 1000 + alert_id, "origin": "crowdsec", "type": decision_type, "value": source, "scenario": scenario}
        ],
    }


class FakePublish:
    def __init__(self):
        self.calls = []

    def __call__(self, *, severity, summary, extra):
        self.calls.append({"severity": severity, "summary": summary, "extra": extra})
        return {"id": "fake-event"}


def test_coalesce_folds_duplicate_decisions_for_one_source():
    grouped = coalesce(
        [
            _alert(1, "198.51.100.7", "crowdsecurity/ssh-bf"),
            _alert(2, "198.51.100.7", "crowdsecurity/ssh-slow-bf"),
            _alert(3, "198.51.100.9", "nostrhost/yunohost-auth-bf"),
        ]
    )
    assert set(grouped) == {"198.51.100.7", "198.51.100.9"}
    assert sorted(grouped["198.51.100.7"]["scenarios"]) == [
        "crowdsecurity/ssh-bf",
        "crowdsecurity/ssh-slow-bf",
    ]
    assert grouped["198.51.100.7"]["id"] == 2  # max alert id
    assert len(grouped["198.51.100.7"]["decisions"]) == 2


def test_projector_publishes_one_notice_per_coalesced_source(tmp_path):
    publish = FakePublish()
    state = SecurityState(path=tmp_path / "s.json")
    projector = SecurityProjector(
        alerts_provider=lambda limit: [_alert(1, "198.51.100.7", "crowdsecurity/ssh-bf")],
        publish=publish,
        state=state,
        cfg=SecurityConfig(severity_default=SEVERITY_WARNING, severity_recurring=SEVERITY_CRITICAL),
    )
    result = projector.poll_once()

    assert len(result) == 1
    assert len(publish.calls) == 1
    call = publish.calls[0]
    assert call["severity"] == SEVERITY_WARNING
    assert "198.51.100.7" in call["summary"]
    assert "ssh-bf" in call["summary"]
    assert call["extra"]["source"] == "198.51.100.7"
    assert state.last_alert_id == 1
    assert "198.51.100.7" in state.sources


def test_projector_skips_already_seen_alerts(tmp_path):
    publish = FakePublish()
    state = SecurityState(path=tmp_path / "s.json", last_alert_id=5)
    projector = SecurityProjector(
        alerts_provider=lambda limit: [_alert(3, "198.51.100.7", "crowdsecurity/ssh-bf"), _alert(6, "198.51.100.9", "crowdsecurity/ssh-bf")],
        publish=publish,
        state=state,
    )
    result = projector.poll_once()

    assert len(result) == 1  # only alert id 6 is new
    assert publish.calls[0]["extra"]["source"] == "198.51.100.9"
    assert state.last_alert_id == 6


def test_recurring_source_escalates_to_critical(tmp_path):
    publish = FakePublish()
    state = SecurityState(path=tmp_path / "s.json", sources={"198.51.100.7"})
    projector = SecurityProjector(
        alerts_provider=lambda limit: [_alert(9, "198.51.100.7", "crowdsecurity/ssh-bf")],
        publish=publish,
        state=state,
        cfg=SecurityConfig(severity_default=SEVERITY_WARNING, severity_recurring=SEVERITY_CRITICAL),
    )
    projector.poll_once()

    assert publish.calls[0]["severity"] == SEVERITY_CRITICAL


def test_state_roundtrip(tmp_path):
    state = SecurityState(path=tmp_path / "security.json", last_alert_id=3, sources={"198.51.100.7"})
    state.save()
    loaded = SecurityState.load(tmp_path / "security.json")
    assert loaded.last_alert_id == 3
    assert loaded.sources == {"198.51.100.7"}


def test_publish_event_is_kind_2213():
    # The default publisher routes through publish_notice with kind 2213; a
    # fake must not change the kind, so assert the constant is the security kind.
    assert KIND_SECURITY_EVENT == 2213