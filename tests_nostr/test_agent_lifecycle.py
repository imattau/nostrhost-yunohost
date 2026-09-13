import json
import stat
import tomllib
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from nostrhost import cli as cli_module


def test_agent_init_creates_private_observe_config_without_enable_or_grant(monkeypatch, tmp_path):
    marker = tmp_path / "installed"
    marker.touch()
    config = tmp_path / "etc" / "nostrhost-agent" / "config.json"
    binary = tmp_path / "usr" / "bin" / "nostrhost-agent"
    binary.parent.mkdir(parents=True)
    binary.touch()
    monkeypatch.setattr(cli_module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli_module, "INSTALLED_MARKER", str(marker))
    monkeypatch.setattr(cli_module, "AGENT_CONFIG", str(config))
    monkeypatch.setattr(cli_module, "AGENT_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(cli_module, "AGENT_BINARY", str(binary))
    monkeypatch.setattr(cli_module, "_read_operator_config", lambda: {
        "operator_sk": "1" * 64,
        "server_sk": "2" * 64,
        "control_relay": "ws://127.0.0.1:4848",
    })
    monkeypatch.setattr(cli_module, "_pubkey", lambda _secret: "a" * 64)
    monkeypatch.setattr(cli_module, "_npub", lambda _pubkey: "npub1agent")
    monkeypatch.setattr(cli_module.os, "chown", lambda *_args: None)
    monkeypatch.setattr(cli_module.subprocess, "run", lambda *args, **kwargs: pytest.fail("init must not start or grant"))

    result = CliRunner().invoke(cli_module.build_app(), ["agent", "init", "--output-as", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["configured"] is True
    assert payload["service_enabled"] is False
    assert payload["policy"] == "observe"
    assert payload["agent_pubkey"] == "a" * 64
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
    assert stat.S_IMODE(config.parent.stat().st_mode) == 0o750
    written = json.loads(config.read_text())
    assert written["relay"]["agent_secret_key"] != "1" * 64
    assert written["relay"]["trusted_server_key"] == "a" * 64
    assert written["policy"]["level"] == "observe"
    assert written["observation_queries"] == [{"operation": "service.status"}]


def test_agent_writer_allowlist_update_is_idempotent_and_removable(monkeypatch, tmp_path):
    relay_config = tmp_path / "relay.toml"
    relay_config.write_text('operator_pubkey = "' + "b" * 64 + '"\n[extra]\nvalue = true\n')
    monkeypatch.setattr(cli_module, "RELAY_CONFIG", str(relay_config))
    pubkey = "a" * 64

    assert cli_module._set_agent_relay_writer(pubkey, allowed=True) is True
    assert cli_module._set_agent_relay_writer(pubkey, allowed=True) is False
    assert tomllib.loads(relay_config.read_text())["agent_pubkeys"] == [pubkey]
    assert cli_module._set_agent_relay_writer(pubkey, allowed=False) is True
    assert tomllib.loads(relay_config.read_text())["agent_pubkeys"] == []


def test_agent_enable_validates_adds_writer_and_starts_only_on_explicit_command(monkeypatch, tmp_path):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"relay": {"agent_secret_key": "1" * 64}}))
    config.chmod(0o600)
    binary = tmp_path / "nostrhost-agent"
    binary.touch()
    relay = tmp_path / "relay.toml"
    relay.write_text('operator_pubkey = "' + "b" * 64 + '"\n')
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if command[0] == str(binary):
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    real_stat = type(config).stat

    def fake_stat(path, *args, **kwargs):
        result = real_stat(path, *args, **kwargs)
        if path in (config, config.parent):
            return SimpleNamespace(st_mode=result.st_mode, st_uid=0)
        return result

    monkeypatch.setattr(cli_module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli_module, "AGENT_CONFIG", str(config))
    monkeypatch.setattr(cli_module, "AGENT_BINARY", str(binary))
    monkeypatch.setattr(cli_module, "RELAY_CONFIG", str(relay))
    monkeypatch.setattr(cli_module, "_pubkey", lambda _secret: "a" * 64)
    monkeypatch.setattr(cli_module.subprocess, "run", fake_run)
    monkeypatch.setattr(type(config), "stat", fake_stat)

    result = cli_module._agent_service("enable")

    assert result["action"] == "enable"
    assert tomllib.loads(relay.read_text())["agent_pubkeys"] == ["a" * 64]
    assert commands[0][1:3] == ["--check-config", "--config"]
    assert ["systemctl", "restart", "nostrhost-control.service"] in commands
    assert ["systemctl", "enable", "--now", cli_module.AGENT_SERVICE] in commands


def test_agent_init_refuses_to_replace_existing_config(monkeypatch, tmp_path):
    marker = tmp_path / "installed"
    marker.touch()
    config = tmp_path / "config.json"
    config.write_text("operator-managed")
    monkeypatch.setattr(cli_module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli_module, "INSTALLED_MARKER", str(marker))
    monkeypatch.setattr(cli_module, "AGENT_CONFIG", str(config))
    result = CliRunner().invoke(cli_module.build_app(), ["agent", "init"])
    assert result.exit_code != 0
    assert "refusing to replace" in result.output
    assert config.read_text() == "operator-managed"
