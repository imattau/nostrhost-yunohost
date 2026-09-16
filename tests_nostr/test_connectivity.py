from pathlib import Path

import pytest

from nostrhost.connectivity import (
    ConnectivityError,
    apply_config,
    effective,
    load_config,
    plan_config,
    validate_config,
)


def test_defaults_and_inheritance(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("NOSTRHOST_STATE_DIR", str(tmp_path))
    config = load_config()
    resolved = effective(config)
    assert resolved["relays"]["publish"] == config.default_relays
    assert resolved["relays"]["lookup"] == config.default_relays + config.additional_discovery_relays
    assert resolved["sources"]["nsite"] == "system-default"


def test_override_and_clear_round_trip(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("NOSTRHOST_STATE_DIR", str(tmp_path))
    value = load_config().model_dump()
    value["overrides"]["nsite"] = ["wss://sites.example"]
    applied = apply_config(value)
    assert applied["effective"]["relays"]["nsite"] == ["wss://sites.example"]
    value["overrides"]["nsite"] = None
    apply_config(value)
    assert effective()["sources"]["nsite"] == "system-default"


def test_validation_normalises_and_rejects_insecure_urls():
    value = load_config(Path("/does-not-exist")).model_dump()
    value["default_relays"] = ["wss://relay.example/", "wss://relay.example"]
    assert validate_config(value).default_relays == ["wss://relay.example"]
    value["default_relays"] = ["ws://relay.example"]
    with pytest.raises(ConnectivityError):
        validate_config(value)


def test_plan_digest_binds_effective_destinations(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("NOSTRHOST_STATE_DIR", str(tmp_path))
    first = load_config().model_dump()
    second = load_config().model_dump()
    second["default_relays"] = ["wss://different.example"]
    assert plan_config(first)["plan_sha256"] != plan_config(second)["plan_sha256"]
