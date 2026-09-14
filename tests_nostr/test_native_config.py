"""Native package [settings] -> YunoHost config panel bridge.

Covers the post-install configuration gap: the generated config_panel.toml
parses through the legacy ConfigPanel machinery, apply validates/persists the
typed values and re-renders the app's managed config files, and the settings
provider installs/removes the panel alongside the engine state.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from nostrhost.native_config import (
    build_config_panel,
    coerce_value,
    read_settings,
    show_values,
    apply_values,
    write_settings,
)
from nostrhost.native_providers import (
    ConfigFileProvider,
    NativeOperationExecutor,
    NativeSettingsProvider,
    PackageProvider,
    installed_package_manifest,
)
from nostrhost.package_engine import Operation, PackageManifest, plan_package, plan_package_removal, validate_package


def _settings_fields() -> dict:
    return {
        "port": {"type": "integer", "default": 8090, "label": "Listen port"},
        "mode": {"type": "enum", "choices": ["safe", "fast"], "default": "safe"},
        "enabled": {"type": "boolean"},
        "name": {"type": "string"},
        "token": {"type": "string", "secret": True},
    }


def _package_with_settings() -> dict:
    return {
        "app": {"id": "configdemo", "version": "0.1"},
        "settings": {
            "fields": _settings_fields(),
            "values": {"port": 8090, "mode": "safe"},
        },
        "service": {"name": "configdemo", "exec": "/opt/configdemo/run.sh"},
        "config": {
            "run": {
                "destination": "/opt/configdemo/run.sh",
                "template_content": "port={{ settings.port }}\nmode={{ settings.mode }}\nenabled={{ settings.get('enabled') }}",
                "mode": 0o755,
            }
        },
    }


# --------------------------------------------------------------------------- #
# config_panel.toml generation


def test_build_config_panel_is_valid_and_typed():
    panel = build_config_panel("configdemo", _settings_fields())
    parsed = tomllib.loads(panel)
    assert parsed["version"] == 1.0
    section = parsed["main"]["main"]
    # No services: native units are not in YunoHost's service registry, so the
    # apply script restarts them instead of the panel framework.
    assert "services" not in parsed["main"]
    assert section["name"] == "Settings"

    assert section["port"] == {"type": "number", "ask": "Listen port", "optional": True, "default": 8090}
    assert section["mode"]["type"] == "select"
    assert section["mode"]["choices"] == ["safe", "fast"]
    assert section["enabled"]["type"] == "boolean"
    # secret fields never appear in the panel; a reserved id like `name` is
    # skipped so it cannot collide with the section's own `name` scalar.
    assert "token" not in section
    assert section["name"] == "Settings"
    assert not isinstance(section.get("name"), dict)


def test_config_panel_machinery_accepts_generated_panel():
    from yunohost.utils.configpanel import ConfigPanelModel

    panel = build_config_panel("configdemo", _settings_fields())
    config = ConfigPanelModel(**tomllib.loads(panel))
    assert config.panels[0].id == "main"
    options = {option.id: option for option in config.options}
    assert set(options) == {"port", "mode", "enabled"}
    assert options["port"].type.value == "number"
    assert options["mode"].type.value == "select"
    assert options["enabled"].type.value == "boolean"
    assert config.services == []


# --------------------------------------------------------------------------- #
# value coercion


def test_coerce_value_validates_and_normalizes():
    assert coerce_value("  hello ", {"type": "string"}) == "hello"
    assert coerce_value("8080", {"type": "integer"}) == 8080
    assert coerce_value("80.5", {"type": "number"}) == 80.5
    assert coerce_value("true", {"type": "boolean"}) is True
    assert coerce_value("False", {"type": "boolean"}) is False
    assert coerce_value("safe", {"type": "enum", "choices": ["safe", "fast"]}) == "safe"
    # cleared optional fields become None
    assert coerce_value("", {"type": "integer"}) is None
    assert coerce_value("", {"type": "boolean"}) is None
    assert coerce_value("", {"type": "enum", "choices": ["safe", "fast"]}) is None
    assert coerce_value("", {"type": "string"}) == ""

    with pytest.raises(ValueError, match="integer"):
        coerce_value("nope", {"type": "integer"})
    with pytest.raises(ValueError, match="boolean"):
        coerce_value("maybe", {"type": "boolean"})
    with pytest.raises(ValueError, match="one of"):
        coerce_value("risky", {"type": "enum", "choices": ["safe", "fast"]})


# --------------------------------------------------------------------------- #
# show / apply through the engine state


def test_apply_values_validates_persists_and_rerenders(tmp_path: Path, monkeypatch):
    packages_state = tmp_path / "packages"
    settings_state = tmp_path / "settings"
    root = tmp_path / "root"
    apps_dir = tmp_path / "apps"

    # Persist the manifest exactly as package.manifest.ensure does.
    package = validate_package(PackageManifest.parse_obj(_package_with_settings()))
    executor = NativeOperationExecutor({"package": PackageProvider(state_dir=packages_state)})
    for operation in plan_package(package):
        if operation.name in {"package.ensure", "package.manifest.ensure"}:
            executor.execute(operation)
    assert installed_package_manifest("configdemo", state_dir=packages_state)

    # The settings provider writes state + the generated panel/script.
    settings_provider = NativeSettingsProvider(state_dir=settings_state, apps_dir=apps_dir)
    settings_op = next(operation for operation in plan_package(package) if operation.name == "settings.ensure")
    settings_provider.apply(settings_op)

    panel_file = apps_dir / "configdemo" / "config_panel.toml"
    script_file = apps_dir / "configdemo" / "scripts" / "config"
    assert panel_file.is_file()
    assert script_file.is_file()
    assert "nostrhost.native_config" in script_file.read_text()
    assert tomllib.loads(panel_file.read_text())["main"]["main"]["port"]["default"] == 8090

    # Initial render of the managed config file.
    config_provider = ConfigFileProvider(root=root)
    for operation in plan_package(package):
        if operation.name == "config.ensure":
            config_provider.apply(operation)
    rendered = (root / "opt/configdemo/run.sh").read_text()
    assert "port=8090" in rendered
    assert "mode=safe" in rendered
    assert "enabled=None" in rendered

    # show returns the current typed values.
    assert show_values("configdemo", state_dir=settings_state) == {
        "port": 8090, "mode": "safe", "enabled": None, "name": None, "token": None,
    }

    # apply a new port + toggle, then re-render must reflect the new values.
    restarts: list[list[str]] = []
    import nostrhost.native_config as native_config

    def _fake_run(cmd, **kwargs):
        restarts.append(list(cmd))
        import subprocess as _sp

        return _sp.CompletedProcess(cmd, 0)

    monkeypatch.setattr(native_config.subprocess, "run", _fake_run)
    result = apply_values(
        "configdemo",
        {"port": "9000", "mode": "fast", "enabled": "true"},
        state_dir=settings_state,
        root=root,
        packages_state_dir=packages_state,
    )
    assert result == {}
    assert restarts == [["systemctl", "reload-or-restart", "configdemo"]]
    assert read_settings("configdemo", state_dir=settings_state)["values"] == {
        "port": 9000, "mode": "fast", "enabled": True,
    }
    rendered = (root / "opt/configdemo/run.sh").read_text()
    assert "port=9000" in rendered
    assert "mode=fast" in rendered
    assert "enabled=True" in rendered

    # invalid input reports per-key errors and changes nothing.
    result = apply_values(
        "configdemo",
        {"port": "not-a-port"},
        state_dir=settings_state,
        root=root,
        packages_state_dir=packages_state,
    )
    assert result == {"validation_errors": {"port": "expected an integer"}}
    assert read_settings("configdemo", state_dir=settings_state)["values"]["port"] == 9000
    assert restarts == [["systemctl", "reload-or-restart", "configdemo"]]


def test_settings_provider_removal_drops_panel(tmp_path: Path):
    packages_state = tmp_path / "packages"
    settings_state = tmp_path / "settings"
    apps_dir = tmp_path / "apps"

    package = validate_package(PackageManifest.parse_obj(_package_with_settings()))
    settings_provider = NativeSettingsProvider(state_dir=settings_state, apps_dir=apps_dir)
    # Directly emulate install: ensure settings (no manifest needed for the
    # removal path).
    settings_provider.apply(
        Operation(
            "settings.ensure", "configdemo:settings",
            {"name": "configdemo", "fields": _settings_fields(), "values": {}},
        )
    )
    panel_file = apps_dir / "configdemo" / "config_panel.toml"
    assert panel_file.is_file()

    removal = next(op for op in plan_package_removal(package) if op.name == "settings.remove")
    settings_provider.apply(removal)
    assert not panel_file.exists()
    assert not (apps_dir / "configdemo" / "scripts" / "config").exists()


def test_show_without_state_returns_none_values(tmp_path: Path):
    assert show_values("ghost", state_dir=tmp_path / "settings") == {}