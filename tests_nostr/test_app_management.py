from __future__ import annotations

import json

import pytest

from nostrhost.app_management import catalogue_lifecycle_plan, carry_forward_compatible_settings, merge_catalogue_and_installed, native_app_removal_plan, native_app_settings, plan_native_settings_update
from nostrhost.package_engine import PackageError, validate_plan_envelope


def _manifest() -> dict:
    return {
        "app": {"id": "example", "version": "1.2.0"},
        "settings": {
            "fields": {
                "mode": {"type": "enum", "label": "Mode", "description": "Runtime mode", "choices": ["safe", "fast"], "default": "safe", "secret": False},
            },
            "values": {"mode": "safe"},
        },
        "config": {
            "service": {
                "destination": "/etc/example.conf",
                "template_content": "mode={{ settings.mode }}\n",
            },
        },
        "service": {"name": "example", "exec": "/usr/bin/example"},
    }


def _write_manifest(state_dir, manifest):
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "example-manifest.json").write_text(json.dumps({"manifest": manifest}))


def test_catalogue_join_keeps_available_installed_and_unlisted_apps():
    rows = merge_catalogue_and_installed(
        {"entries": [
            {"declaration": {"AppID": "available", "Version": "2.0", "Name": "Available"}, "event_id": "a"},
            {"declaration": {"AppID": "installed", "Version": "2.0", "Name": "Installed"}, "event_id": "b"},
        ]},
        {"apps": {
            "installed": {"version": "2.0", "native": True, "name": {"en": "Installed"}},
            "orphan": {"version": "1.0", "name": {"en": "Orphan app"}},
        }},
    )
    by_id = {row["id"]: row for row in rows}
    assert by_id["available"]["status"] == "available"
    assert by_id["installed"]["status"] == "installed"
    assert by_id["orphan"]["status"] == "installed-unlisted"
    assert by_id["orphan"]["installation"]["legacy"] is True


def test_native_settings_update_returns_render_and_restart_plan(tmp_path):
    _write_manifest(tmp_path, _manifest())
    view = native_app_settings("example", state_dir=str(tmp_path))
    assert view["fields"][0]["label"] == "Mode"
    assert view["values"] == {"mode": "safe"}

    plan = plan_native_settings_update("example", {"mode": "fast"}, state_dir=str(tmp_path))
    operations = validate_plan_envelope({key: value for key, value in plan.items() if key != "settings_diff"})
    config = next(operation for operation in operations if operation.name == "config.ensure")
    restart = next(operation for operation in operations if operation.name == "service.restart")
    assert config.args["context"]["settings"] == {"mode": "fast"}
    assert restart.depends_on == (config.resource,)
    assert {"key": "mode", "old": "safe", "new": "fast"} in plan["settings_diff"]
    manifest_write = next(operation for operation in operations if operation.name == "package.manifest.ensure")
    assert "example:settings-restart" in manifest_write.depends_on


def test_native_settings_read_never_returns_secret_values(tmp_path):
    manifest = _manifest()
    manifest["settings"]["fields"]["token"] = {"type": "string", "secret": True}
    manifest["settings"]["values"]["token"] = "must-not-leak"
    _write_manifest(tmp_path, manifest)

    view = native_app_settings("example", state_dir=str(tmp_path))

    assert [field["key"] for field in view["fields"]] == ["mode"]
    assert view["values"] == {"mode": "safe"}


@pytest.mark.parametrize("values, message", [
    ({"unknown": True}, "unknown app setting"),
    ({"mode": "unknown"}, "does not match declared type"),
])
def test_native_settings_update_rejects_undeclared_or_invalid_values(tmp_path, values, message):
    _write_manifest(tmp_path, _manifest())
    with pytest.raises(PackageError, match=message):
        plan_native_settings_update("example", values, state_dir=str(tmp_path))


def test_native_settings_update_rejects_non_native_or_invalid_app_id():
    with pytest.raises(PackageError, match="invalid app id"):
        native_app_settings("../etc")
    with pytest.raises(PackageError, match="not installed"):
        native_app_settings("missing")


def test_config_provider_renders_settings_context_atomically(tmp_path):
    from nostrhost.native_providers import ConfigFileProvider

    provider = ConfigFileProvider(root=tmp_path)
    operation = provider.plan({
        "destination": "/etc/example.conf",
        "template_content": "mode={{ settings.mode }}\n",
        "context": {"settings": {"mode": "fast"}},
        "mode": 0o640,
    })[0]
    provider.apply(operation)
    target = tmp_path / "etc/example.conf"
    assert target.read_text() == "mode=fast\n"
    assert _operation_is_satisfied(operation, provider.inspect(operation.args))


def test_compatible_settings_survive_upgrade_and_invalid_choices_reset_to_new_default():
    installed = {
        "settings": {
            "fields": {"mode": {"type": "enum"}, "enabled": {"type": "boolean"}, "old": {"type": "string"}},
            "values": {"mode": "fast", "enabled": True, "old": "value"},
        },
    }
    candidate = {
        "settings": {
            "fields": {
                "mode": {"type": "enum", "choices": ["safe"], "default": "safe"},
                "enabled": {"type": "boolean", "default": False},
                "old": {"type": "integer", "default": 1},
            },
        },
    }
    merged = carry_forward_compatible_settings(installed, candidate)
    assert merged["settings"]["values"] == {"mode": "safe", "enabled": True, "old": 1}


def test_catalogue_upgrade_plan_verifies_source_and_preserves_compatible_settings(monkeypatch):
    installed = _manifest()
    candidate = {
        "app": {"id": "example", "version": "1.3.0"},
        "settings": {"fields": {"mode": {"type": "enum", "choices": ["safe", "fast"], "default": "safe"}}},
    }
    from nostrhost import cli, native_providers

    monkeypatch.setattr(native_providers, "installed_package_manifest", lambda app_id, state_dir=None: installed)
    monkeypatch.setattr(cli, "_coordinate_for", lambda app_id: {"app_id": app_id, "version": "1.3.0", "manifest_sha256": "unused"})
    monkeypatch.setattr(cli, "_load_package_data", lambda source, coordinate: candidate)
    verified = []
    monkeypatch.setattr(cli, "_verify_package", lambda package, coordinate: verified.append((package, coordinate)))

    plan = catalogue_lifecycle_plan("example", "upgrade")
    assert verified and verified[0][0] is candidate
    assert plan["package"] == {"id": "example", "version": "1.3.0"}
    settings_op = next(row for row in plan["operations"] if row["name"] == "settings.ensure")
    assert settings_op["args"]["values"]["mode"] == "safe"


def test_native_removal_plan_uses_only_recorded_manifest(monkeypatch):
    from nostrhost import native_providers

    manifest = _manifest()
    monkeypatch.setattr(native_providers, "installed_package_manifest", lambda app_id, state_dir=None: manifest)
    plan = native_app_removal_plan("example")
    assert plan["package"] == {"id": "example", "version": "1.2.0"}
    assert plan["operations"][-1]["name"] == "package.remove"


def _operation_is_satisfied(operation, actual):
    from nostrhost.package_engine import _operation_satisfied

    return _operation_satisfied(operation, actual)
