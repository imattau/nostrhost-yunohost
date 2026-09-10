"""Tests for the native package model and dry-run planner."""

from pathlib import Path

import pytest

from nostrhost.native_providers import NativeOperationExecutor, native_providers
from nostrhost.package_engine import PackageError, PackageManifest, apply_operation_plan, load_package, migrate_manifest, plan_package


def example() -> dict:
    return {
        "app": {"id": "example", "version": "1.2.0"},
        "source": {"main": {"url": "https://example.org/a.tar.gz", "sha256": "a" * 64}},
        "runtime": {"type": "node", "version": "24"},
        "packages": {"apt": ["ffmpeg"]},
        "user": {"system": True},
        "directories": {"install": {"path": "/opt/example"}, "data": {"path": "/var/lib/example", "backup": True}},
        "service": {"exec": "/opt/example/bin/server", "working_directory": "/var/lib/example"},
        "web": {"upstream": "127.0.0.1:8090", "auth": "nostrhost"},
        "health": {"type": "http", "path": "/health"},
    }


def test_plan_is_typed_and_dependency_ordered():
    plan = plan_package(PackageManifest.parse_obj(example()))
    names = [operation.name for operation in plan]
    assert names == [
        "package.ensure", "package.apt.ensure", "system_user.ensure",
        "directory.ensure", "directory.ensure", "source.fetch", "runtime.ensure",
        "service.ensure", "service.enable", "service.start", "web.route.ensure",
        "health.http.check",
    ]
    assert plan[-1].depends_on == ("example:web",)
    assert plan[0].json_dict()["depends_on"] == []


def test_invalid_source_hash_and_path_are_rejected():
    invalid = example()
    invalid["source"]["main"]["sha256"] = "bad"
    with pytest.raises(ValueError):
        PackageManifest.parse_obj(invalid)
    invalid = example()
    invalid["directories"]["data"]["path"] = "/var/lib/../etc"
    with pytest.raises(ValueError):
        PackageManifest.parse_obj(invalid)


def test_schema_has_native_resource_shape():
    schema = PackageManifest.schema()
    assert "app" in schema["properties"]
    assert "source" in schema["properties"]
    assert schema["additionalProperties"] is False


def test_migration_maps_declarative_v2_resources():
    result = migrate_manifest({
        "id": "converted",
        "version": "2.0",
        "resources": {
            "apt": {"packages": ["ffmpeg"]},
            "install_dir": {"path": "/opt/converted"},
            "data_dir": {"path": "/var/lib/converted"},
        },
    })
    assert result["packages"] == {"apt": ["ffmpeg"]}
    assert result["directories"]["data"]["backup"] is True
    assert "hooks" not in result


def test_migration_rejects_imperative_scripts(tmp_path: Path):
    from nostrhost.package_engine import migrate_manifest_file

    app = tmp_path / "app"
    (app / "scripts").mkdir(parents=True)
    (app / "scripts" / "install").write_text("#!/bin/bash\n")
    (app / "manifest.toml").write_text("id = 'converted'\nversion = '1'\n")
    with pytest.raises(PackageError, match="cannot migrate imperative package scripts"):
        migrate_manifest_file(app / "manifest.toml", tmp_path / "package.toml")


def test_load_package_reports_parse_errors(tmp_path: Path):
    path = tmp_path / "package.toml"
    path.write_text("[app]\nid = 'Bad'\nversion = '1'\n")
    with pytest.raises(PackageError):
        load_package(path)


def test_all_declared_domains_are_plannable():
    raw = example() | {
        "settings": {"values": {"port": 8090}},
        "secrets": {"api_key": {"generate": "random", "length": 32}},
        "backup": {"paths": ["/var/lib/example"], "database": True},
        "hooks": {"post_install": {"python": "hooks.py:post_install"}},
    }
    names = [operation.name for operation in plan_package(PackageManifest.parse_obj(raw))]
    assert {"settings.ensure", "secret.ensure", "backup.register", "hook.python.ensure"} <= set(names)


def test_apply_preflights_native_provider_coverage():
    plan = plan_package(PackageManifest.parse_obj(example()))
    with pytest.raises(PackageError, match="native providers are unavailable"):
        apply_operation_plan(plan, NativeOperationExecutor(native_providers(root=Path("/tmp"))))
