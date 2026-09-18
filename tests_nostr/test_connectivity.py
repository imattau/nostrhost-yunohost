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


class _FakeCompleted:
    returncode = 0
    stdout = ""
    stderr = ""


def test_apply_persists_config_before_projections(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("NOSTRHOST_STATE_DIR", str(tmp_path))
    import nostrhost.connectivity as connectivity

    def explode(*args, **kwargs):
        raise RuntimeError("projection failed")

    monkeypatch.setattr(connectivity, "_project_nsite", explode)
    monkeypatch.setattr(connectivity, "_project_catalogue", explode)
    value = load_config().model_dump()
    value["default_relays"] = ["wss://sticky.example"]
    with pytest.raises(RuntimeError):
        apply_config(value)
    assert load_config().default_relays == ["wss://sticky.example"]


def test_project_catalogue_restarts_without_blocking(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("NOSTRHOST_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("NOSTRHOST_CATALOGUE_ENV", str(tmp_path / "catalogue.env"))
    env_path = tmp_path / "catalogue.env"
    env_path.write_text("NOSTRHOST_CATALOG_RELAYS=ws://127.0.0.1:4848\n")
    import nostrhost.connectivity as connectivity

    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    monkeypatch.setattr(
        connectivity.subprocess,
        "run",
        lambda *args, **kwargs: (calls.append((args, kwargs)) or _FakeCompleted()),
    )
    config = load_config()
    config.default_relays.append("wss://relay.example")
    connectivity._project_catalogue(config)
    assert calls
    assert calls[0][0][0] == [
        "systemctl",
        "--no-block",
        "try-restart",
        "nostrhost-catalog.service",
    ]
    assert "wss://relay.example" in env_path.read_text(encoding="utf-8")
