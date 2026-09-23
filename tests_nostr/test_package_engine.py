"""Tests for the native package model and dry-run planner."""

from pathlib import Path

import pytest

from nostrhost.native_providers import NativeOperationExecutor, PackageProvider, native_providers
from nostrhost.package_engine import Operation, PackageError, PackageManifest, _operation_satisfied, apply_operation_plan, apply_reconciled_plan, load_package, migrate_manifest, operation_plan_digest, package_plan_envelope, plan_package, plan_package_removal, reconcile_operation_plan, validate_package, validate_plan_envelope


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
        "package.ensure", "package.manifest.ensure", "package.apt.ensure",
        "system_user.ensure", "directory.ensure", "directory.ensure",
        "source.fetch", "runtime.ensure", "service.ensure", "service.enable",
        "service.start", "web.route.ensure", "health.http.check",
    ]
    assert plan[-1].depends_on == ("example:web",)
    assert plan[0].json_dict()["depends_on"] == []


def test_plan_operation_args_are_json_serializable():
    """Every op's args must survive json.dumps without default=str — the signed
    request serializes the envelope, so a Path (e.g. service.working_directory)
    leaks through build_operation_request and breaks the chain."""
    import json

    plan = plan_package(PackageManifest.parse_obj(example()))
    for operation in plan:
        json.dumps(operation.args)  # must not raise


def test_plan_envelope_binds_manifest_and_operations():
    envelope = package_plan_envelope(example())
    assert envelope["schema"] == 1
    assert envelope["package"] == {"id": "example", "version": "1.2.0"}
    assert envelope["plan_sha256"] == operation_plan_digest(validate_plan_envelope(envelope))

    envelope["operations"][0]["args"]["version"] = "tampered"
    with pytest.raises(PackageError, match="plan digest"):
        validate_plan_envelope(envelope)


def test_plan_envelope_binds_catalogue_provenance():
    provenance = {"app_id": "example", "version": "1.2.0", "repository": "nostr://repo", "revision": "c" * 40}
    envelope = package_plan_envelope(example(), catalogue=provenance)
    assert envelope["catalogue"]["revision"] == "c" * 40
    with pytest.raises(PackageError, match="provenance"):
        package_plan_envelope(example(), catalogue={**provenance, "app_id": "other"})


def test_plan_envelope_binds_npack_provenance(tmp_path):
    payload_root = tmp_path / "payload"
    (payload_root / ".npack").mkdir(parents=True)
    (payload_root / ".npack" / "manifest.json").write_text("{}", encoding="utf-8")
    (payload_root / "var/www/example").mkdir(parents=True)
    (payload_root / "var/www/example/index.html").write_text("<h1>ok</h1>", encoding="utf-8")
    provenance = {
        "publisher": "ab" * 32,
        "name": "example",
        "version": "1.2.0",
        "artifact_sha256": "cd" * 32,
        "payload_root": str(payload_root),
    }
    envelope = package_plan_envelope(example(), npack=provenance)
    assert envelope["npack"]["artifact_sha256"] == "cd" * 32
    sync_ops = [op for op in validate_plan_envelope(envelope) if op.name == "payload.sync"]
    assert len(sync_ops) == 1
    assert sync_ops[0].args["artifact_sha256"] == "cd" * 32

    with pytest.raises(PackageError, match="provenance"):
        package_plan_envelope(example(), npack={**provenance, "name": "other"})
    with pytest.raises(PackageError, match="publisher"):
        package_plan_envelope(example(), npack={**provenance, "publisher": "not-hex"})
    with pytest.raises(PackageError, match="staged artifact"):
        package_plan_envelope(example(), npack={**provenance, "payload_root": str(tmp_path / "missing")})

    envelope["operations"].append({"name": "payload.sync", "resource": "example:payload", "args": {}, "depends_on": [], "risk": "low", "reversible": True})
    envelope["plan_sha256"] = operation_plan_digest([Operation(
        item["name"], item["resource"], item["args"],
        tuple(item.get("depends_on", ())), item.get("risk", "low"),
        bool(item.get("reversible", True)), item.get("reverse"),
        item.get("summary", ""),
    ) for item in envelope["operations"]])
    with pytest.raises(PackageError, match="exactly one"):
        validate_plan_envelope(envelope)


def test_bind_install_values_legacy_domain_path_sugar_syncs_health():
    """A package with no declared install_inputs still accepts --domain/--path
    (legacy sugar), applied directly to [web]/[health]."""
    from nostrhost.package_engine import bind_install_values

    data = example()
    data["web"]["path"] = "/"
    data["health"]["path"] = "/"
    overridden = bind_install_values(data, {}, domain="ditto.example", path="/app")
    assert overridden["web"]["domain"] == "ditto.example"
    assert overridden["web"]["path"] == "/app"
    assert overridden["health"]["path"] == "/app"
    # operates on a copy - the signed manifest itself is never mutated
    assert "domain" not in data["web"]
    assert data["web"]["path"] == "/"
    assert data["health"]["path"] == "/"


def test_bind_install_values_noop_and_requires_web_resource():
    from nostrhost.package_engine import bind_install_values

    data = example()
    assert bind_install_values(data, {}) is data
    without_web = {key: value for key, value in data.items() if key != "web"}
    with pytest.raises(PackageError, match=r"\[web\]"):
        bind_install_values(without_web, {}, domain="example.org")


def test_bind_install_values_maps_domain_sugar_onto_declared_input():
    """--domain maps onto a declared web.domain input instead of the legacy
    fallback when the package declares one."""
    from nostrhost.package_engine import bind_install_values

    data = example()
    data["install_inputs"] = {"domain": {"type": "string", "bind": "web.domain", "required": True}}
    overridden = bind_install_values(data, {}, domain="ditto.example")
    assert overridden["web"]["domain"] == "ditto.example"


def test_bind_install_values_rejects_unknown_and_missing_required():
    from nostrhost.package_engine import bind_install_values

    data = example()
    data["install_inputs"] = {"domain": {"type": "string", "bind": "web.domain", "required": True}}
    with pytest.raises(PackageError, match="missing required"):
        bind_install_values(data, {})
    with pytest.raises(PackageError, match="unexpected install value"):
        bind_install_values(data, {"domain": "d.example", "bogus": "x"})


def test_bind_install_values_config_context():
    from nostrhost.package_engine import bind_install_values

    data = example()
    data["config"] = {"index": {"destination": "/opt/example/index.html", "template_content": "hi {{ name }}"}}
    data["install_inputs"] = {"greeting_name": {"type": "string", "bind": "config.context", "constraints": {"config": "index", "key": "name"}}}
    overridden = bind_install_values(data, {"greeting_name": "World"})
    assert overridden["config"]["index"]["context"] == {"name": "World"}


def test_bind_install_values_permissions_and_ports():
    from nostrhost.package_engine import bind_install_values

    data = example()
    data["permissions"] = {"main": {"url": "/"}}
    data["ports"] = {"named": {"web": 8090}}
    data["install_inputs"] = {
        "who": {"type": "string", "bind": "permissions.allowed", "constraints": {"permission": "main"}},
        "port": {"type": "integer", "bind": "ports.named", "constraints": {"port": "web"}},
    }
    overridden = bind_install_values(data, {"who": "all_users", "port": 9090})
    assert overridden["permissions"]["main"]["allowed"] == "all_users"
    assert overridden["ports"]["named"]["web"] == 9090


def test_bind_install_values_secret_supplied_never_enters_package_data(tmp_path):
    from nostrhost.package_engine import bind_install_values

    data = example()
    data["config"] = {"index": {"destination": "/opt/example/index.html", "template_content": "key={{ api_key }}"}}
    data["install_inputs"] = {
        "api_key": {
            "type": "string",
            "bind": "secret.supplied",
            "required": True,
            "sensitive": True,
            "constraints": {"config": "index", "key": "api_key"},
        }
    }
    credential_dir = tmp_path / "credentials"
    overridden = bind_install_values(data, {"api_key": "s3cr3t"}, credential_dir=credential_dir)
    ref = overridden["config"]["index"]["context"]["api_key"]
    assert ref == "secret:install-example/api_key"
    assert "s3cr3t" not in str(overridden)
    assert (credential_dir / "install-example" / "api_key").read_text(encoding="utf-8") == "s3cr3t"


def test_install_input_sensitive_must_bind_secret_supplied():
    data = example()
    data["install_inputs"] = {"bad": {"type": "string", "bind": "web.domain", "sensitive": True}}
    with pytest.raises(ValueError, match="secret.supplied"):
        PackageManifest.parse_obj(data)


def test_install_input_must_reference_declared_resource():
    data = example()
    data["install_inputs"] = {"who": {"type": "string", "bind": "permissions.allowed", "constraints": {"permission": "main"}}}
    with pytest.raises(ValueError, match="undeclared permission"):
        PackageManifest.parse_obj(data)


def test_safe_package_plan_applies_install_time_web_override():
    """package.plan must accept the install-time domain/path (ditto's manifest
    ships without [web].domain), matching the CLI's own override path."""
    from yunohost.nostr_operations import OperationError, _safe_package_plan

    from nostrhost.package_engine import bind_install_values

    data = example()
    data["web"]["path"] = "/"
    data["health"]["path"] = "/"
    envelope = _safe_package_plan(package=data, domain="ditto.example", path="/")
    expected = package_plan_envelope(bind_install_values(data, {}, domain="ditto.example", path="/"))
    assert envelope["plan_sha256"] == expected["plan_sha256"]

    without_web = {key: value for key, value in data.items() if key != "web"}
    with pytest.raises(OperationError, match=r"\[web\]"):
        _safe_package_plan(package=without_web, domain="ditto.example")


def test_removal_plan_reverses_only_owned_resources():
    package = PackageManifest.parse_obj(example() | {
        "settings": {"values": {"mode": "safe"}},
        "backup": {"paths": ["/var/lib/example"], "database": False},
    })
    plan = plan_package_removal(package)
    names = [operation.name for operation in plan]
    assert names[0] == "backup.unregister"
    assert names[-1] == "package.remove"
    assert "package.apt.remove" not in names
    assert "runtime.remove" not in names
    assert all(operation.depends_on == ((plan[index - 1].resource,) if index else ()) for index, operation in enumerate(plan))


def test_plan_distinguishes_filesystem_access_from_portal_permissions():
    raw = example() | {
        "access": {"data": {"path": "/var/lib/example", "owner": "example"}},
        "permissions": {"main": {"url": "/", "allowed": ["all_users"]}},
    }
    plan = plan_package(PackageManifest.parse_obj(raw))
    assert [operation.name for operation in plan].count("access.ensure") == 1
    permission = next(operation for operation in plan if operation.name == "permission.ensure")
    assert permission.args["app"] == "example"
    assert permission.args["show_tile"] is True


def test_invalid_source_hash_and_path_are_rejected():
    invalid = example()
    invalid["source"]["main"]["sha256"] = "bad"
    with pytest.raises(ValueError):
        PackageManifest.parse_obj(invalid)
    invalid = example()
    invalid["directories"]["data"]["path"] = "/var/lib/../etc"
    with pytest.raises(ValueError):
        PackageManifest.parse_obj(invalid)


def test_source_architecture_variant_is_selected_for_plan(monkeypatch):
    import nostrhost.package_engine as engine

    monkeypatch.setattr(engine.host_platform, "machine", lambda: "x86_64")
    package = PackageManifest.parse_obj({
        "app": {"id": "example", "version": "1"},
        "source": {"main": {"variants": {"amd64": {"url": "https://example.test/amd64.tar", "sha256": "a" * 64}, "arm64": {"url": "https://example.test/arm64.tar", "sha256": "b" * 64}}}},
    })
    operation = next(operation for operation in plan_package(package) if operation.name == "source.fetch")
    assert operation.args["url"].endswith("amd64.tar") and operation.args["sha256"] == "a" * 64


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


def test_migration_maps_all_native_declarative_domains():
    result = migrate_manifest({
        "id": "converted",
        "version": "2.0",
        "resources": {
            "ports": {"main": {"port": 8080}},
            "permissions": {"main": {"url": "/", "allowed": ["all_users"], "show_tile": True}},
            "database": {"type": "postgresql", "name": "converted"},
            "nodejs": {"version": "24"},
            "config": {"main": {"destination": "/etc/converted.conf", "content": "ok\n"}},
            "settings": {"values": {"mode": "safe"}},
            "backup": {"paths": ["/var/lib/converted"], "database": True},
        },
    })
    assert result["ports"] == {"named": {"main": 8080}}
    assert result["permissions"]["main"]["allowed"] == ["all_users"]
    assert result["database"]["type"] == "postgresql"
    assert result["runtime"] == {"type": "node", "version": "24", "prefix": None}
    assert result["config"]["main"]["content"] == "ok\n"


def test_migration_preserves_source_variants_and_user_groups():
    result = migrate_manifest({
        "id": "converted",
        "resources": {
            "sources": {"main": {"variants": {"amd64": {"url": "https://example.test/a", "sha256": "a" * 64}}}},
            "system_user": {"username": "converted", "groups": ["video"]},
        },
    })
    assert result["source"]["main"]["variants"]["amd64"]["sha256"] == "a" * 64
    assert result["user"]["groups"] == ["video"]


def test_migration_rejects_imperative_scripts(tmp_path: Path):
    from nostrhost.package_engine import migrate_manifest_file

    app = tmp_path / "app"
    (app / "scripts").mkdir(parents=True)
    (app / "scripts" / "install").write_text("#!/bin/bash\n")
    (app / "manifest.toml").write_text("id = 'converted'\nversion = '1'\n")
    with pytest.raises(PackageError, match="cannot migrate imperative package scripts"):
        migrate_manifest_file(app / "manifest.toml", tmp_path / "package.toml")


def test_migration_rejects_config_lifecycle_script(tmp_path: Path):
    from nostrhost.package_engine import migrate_manifest_file

    app = tmp_path / "app"
    (app / "scripts").mkdir(parents=True)
    (app / "scripts" / "config").write_text("#!/bin/bash\n")
    (app / "manifest.toml").write_text("id = 'converted'\nversion = '1'\n")
    with pytest.raises(PackageError, match="config"):
        migrate_manifest_file(app / "manifest.toml", tmp_path / "package.toml")


def test_load_package_reports_parse_errors(tmp_path: Path):
    path = tmp_path / "package.toml"
    path.write_text("[app]\nid = 'Bad'\nversion = '1'\n")
    with pytest.raises(PackageError):
        load_package(path)


def test_semantic_validation_rejects_unsafe_service_and_upstream():
    invalid = example()
    invalid["service"]["exec"] = "relative/server"
    with pytest.raises(PackageError, match="service.exec"):
        validate_package(PackageManifest.parse_obj(invalid))
    invalid = example()
    invalid["web"]["upstream"] = "not a backend"
    with pytest.raises(PackageError, match="web.upstream"):
        validate_package(PackageManifest.parse_obj(invalid))


def test_semantic_validation_requires_explicit_database_backup_choice():
    invalid = example() | {"database": {"type": "postgresql"}, "backup": {"paths": ["/var/lib/example"], "database": False}}
    with pytest.raises(PackageError, match="backup.database"):
        validate_package(PackageManifest.parse_obj(invalid))


def test_all_declared_domains_are_plannable():
    raw = example() | {
        "settings": {"values": {"port": 8090}},
        "secrets": {"api_key": {"generate": "random", "length": 32}},
        "backup": {"paths": ["/var/lib/example"], "database": True},
        "hooks": {"post_install": {"python": "hooks.py:post_install"}},
    }
    names = [operation.name for operation in plan_package(PackageManifest.parse_obj(raw))]
    assert {"settings.ensure", "secret.ensure", "backup.register", "hook.python.ensure"} <= set(names)


def test_settings_are_typed_and_defaults_are_materialized():
    raw = {
        "app": {"id": "example", "version": "1"},
        "settings": {
            "fields": {
                "port": {"type": "integer", "default": 8090},
                "mode": {"type": "enum", "choices": ["safe", "fast"]},
            },
            "values": {"mode": "safe"},
        },
    }
    package = PackageManifest.parse_obj(raw)
    assert package.settings.values["port"] == 8090
    operation = next(operation for operation in plan_package(package) if operation.name == "settings.ensure")
    assert operation.args["values"] == {"mode": "safe", "port": 8090}


def test_settings_reject_wrong_type_and_plaintext_secret():
    with pytest.raises(ValueError, match="does not match declared type"):
        PackageManifest.parse_obj({"app": {"id": "example", "version": "1"}, "settings": {"fields": {"port": {"type": "integer"}}, "values": {"port": "8090"}}})
    with pytest.raises(ValueError, match="secret resource"):
        PackageManifest.parse_obj({"app": {"id": "example", "version": "1"}, "settings": {"fields": {"token": {"type": "string", "secret": True}}, "values": {"token": "plaintext"}}})


def test_apply_preflights_native_provider_coverage():
    plan = plan_package(PackageManifest.parse_obj(example()))
    with pytest.raises(PackageError, match="native providers are unavailable"):
        apply_operation_plan(plan, NativeOperationExecutor(native_providers(root=Path("/tmp"))))


def test_reconciliation_skips_directory_when_observed_state_matches(tmp_path: Path):
    target = tmp_path / "var/lib/example"
    target.mkdir(parents=True)
    target.chmod(0o750)
    plan = [
        Operation("package.ensure", "example", {"id": "example", "version": "1"}),
        Operation("directory.ensure", "example:directory:data", {"path": "/var/lib/example", "mode": 0o750}, depends_on=("example",)),
    ]
    executor = NativeOperationExecutor(native_providers(root=tmp_path))
    pending, skipped = reconcile_operation_plan(plan, executor)
    assert [operation.name for operation in pending] == ["package.ensure"]
    assert skipped == ["example:directory:data"]
    assert len(apply_reconciled_plan(plan, executor)) == 1


def test_reconciliation_skips_package_when_version_matches(tmp_path: Path):
    provider = PackageProvider(state_dir=tmp_path / "packages")
    desired = {"id": "example", "version": "1"}
    provider.apply(Operation("package.ensure", "example", desired))
    operation = Operation("package.ensure", "example", desired)
    assert _operation_satisfied(operation, provider.inspect(desired))

    provider.apply(Operation("package.remove", "example", {"id": "example"}))
    assert provider.inspect(desired)["exists"] is False


def test_reapply_is_idempotent_when_dependency_resource_is_skipped(tmp_path: Path):
    """A second reconcile whose provider-ensure op is already satisfied must
    not deadlock: the skipped resource is seeded as satisfied, so dependent
    pending operations (manifest, ...) proceed."""
    plan = [
        Operation("package.ensure", "example", {"id": "example", "version": "1"}),
        Operation("package.manifest.ensure", "example", {"id": "example", "version": "1", "manifest": {"app": {"id": "example"}}}, depends_on=("example",)),
    ]
    executor = NativeOperationExecutor({"package": PackageProvider(state_dir=tmp_path)})
    first = apply_reconciled_plan(plan, executor)
    assert len(first) == 2
    second = apply_reconciled_plan(plan, executor)
    assert [row["operation"] for row in second] == ["package.manifest.ensure"]


def test_reconciliation_detects_config_and_service_drift(tmp_path: Path):
    from nostrhost.native_providers import ConfigFileProvider, ServiceProvider

    config = ConfigFileProvider(root=tmp_path)
    config.apply(config.plan({"destination": "/etc/example.conf", "content": "old\n", "mode": 0o640})[0])
    desired_config = Operation("config.ensure", "example:config:main", {"destination": "/etc/example.conf", "content": "new\n", "mode": 0o640})
    assert not _operation_satisfied(desired_config, config.inspect(desired_config.args))

    service = ServiceProvider(unit_dir=tmp_path, command=lambda *_args, **_kwargs: None)
    service.apply(service.plan({"name": "example", "exec": "/bin/true"})[0])
    desired_service = {"name": "example", "exec": "/bin/false"}
    assert not _operation_satisfied(Operation("service.ensure", "example:service", desired_service), service.inspect(desired_service))


def test_reconciliation_skips_verified_cached_source(tmp_path: Path):
    import hashlib

    from nostrhost.native_providers import SourceProvider

    payload = b"verified source"
    url = "https://example.test/source.tar.gz"
    provider = SourceProvider(root=tmp_path, cache_dir=tmp_path / "cache", downloader=lambda _url, destination: destination.write_bytes(payload))
    desired = {"url": url, "sha256": hashlib.sha256(payload).hexdigest()}
    provider.apply(provider.plan(desired)[0])
    operation = Operation("source.fetch", url, desired)
    assert _operation_satisfied(operation, provider.inspect(desired))


def test_reconciliation_does_not_skip_uninstalled_single_apt_package():
    from nostrhost.native_providers import AptProvider

    class Package:
        def __init__(self, installed: bool):
            self.is_installed = installed

    class Cache:
        def __init__(self, installed: bool):
            self.package = Package(installed)

        def __contains__(self, name: str):
            return name == "ffmpeg"

        def __getitem__(self, name: str):
            assert name == "ffmpeg"
            return self.package

    operation = Operation("package.apt.ensure", "example:apt:ffmpeg", {"package": "ffmpeg"})
    absent = AptProvider(cache_factory=lambda: Cache(False))
    present = AptProvider(cache_factory=lambda: Cache(True))

    assert not _operation_satisfied(operation, absent.inspect(operation.args))
    assert _operation_satisfied(operation, present.inspect(operation.args))


def test_reconciliation_skips_unchanged_extracted_source(tmp_path: Path):
    import hashlib
    import tarfile

    from nostrhost.native_providers import SourceProvider

    archive = tmp_path / "source.tar"
    payload = tmp_path / "payload.txt"
    payload.write_text("native")
    with tarfile.open(archive, "w") as tar:
        tar.add(payload, arcname="payload.txt")
    url = "https://example.test/source.tar"
    desired = {"url": url, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "destination": "/opt/example"}
    provider = SourceProvider(root=tmp_path, cache_dir=tmp_path / "cache", downloader=lambda _url, destination: destination.write_bytes(archive.read_bytes()))
    provider.apply(provider.plan(desired)[0])
    assert _operation_satisfied(Operation("source.fetch", url, desired), provider.inspect(desired))


def test_package_plan_carries_explicit_template_root(tmp_path: Path):
    raw = {"app": {"id": "example", "version": "1"}, "config": {"main": {"destination": "/etc/example.conf", "template": "templates/app.j2"}}}
    operation = next(operation for operation in plan_package(PackageManifest.parse_obj(raw), template_root=tmp_path) if operation.name == "config.ensure")
    assert operation.args["_template_root"] == str(tmp_path)


# --------------------------------------------------------------------------- #
# multi-tenant-runtime installation class


def runtime_instance_example() -> dict:
    return {
        "app": {"id": "example", "version": "1"},
        "installation_class": "multi-tenant-runtime",
        "runtime_instance": {
            "exec": "/opt/example/bin/server",
            "state_directory": "example",
            "socket_path_template": "/run/example/%i.sock",
            "internal_port": 8090,
        },
        "web": {"domain": "example.test", "route_mode": "per-user-socket", "auth": "nostrhost"},
    }


def test_installation_class_defaults_to_shared():
    package = PackageManifest.parse_obj(example())
    assert package.installation_class == "shared"
    assert package.runtime_instance is None
    assert package.web.route_mode == "static"


def test_multi_tenant_runtime_requires_runtime_instance_resource():
    invalid = {"app": {"id": "example", "version": "1"}, "installation_class": "multi-tenant-runtime"}
    with pytest.raises(ValueError, match="requires a \\[runtime_instance\\] resource"):
        PackageManifest.parse_obj(invalid)


def test_multi_tenant_runtime_forbids_service_and_user():
    base = runtime_instance_example()
    with pytest.raises(ValueError, match="cannot declare \\[service\\]"):
        PackageManifest.parse_obj(base | {"service": {"exec": "/opt/example/bin/server"}})
    with pytest.raises(ValueError, match="cannot declare \\[user\\]"):
        PackageManifest.parse_obj(base | {"user": {"name": "example"}})


def test_runtime_instance_requires_multi_tenant_runtime_class():
    invalid = {
        "app": {"id": "example", "version": "1"},
        "runtime_instance": {
            "exec": "/opt/example/bin/server",
            "state_directory": "example",
            "socket_path_template": "/run/example/%i.sock",
            "internal_port": 8090,
        },
    }
    with pytest.raises(ValueError, match="requires installation_class"):
        PackageManifest.parse_obj(invalid)


def test_runtime_instance_socket_path_template_requires_percent_i():
    invalid = runtime_instance_example()
    invalid["runtime_instance"]["socket_path_template"] = "/run/example/fixed.sock"
    with pytest.raises(ValueError, match="'%i' instance specifier"):
        PackageManifest.parse_obj(invalid)


def test_runtime_instance_state_directory_must_be_relative():
    invalid = runtime_instance_example()
    invalid["runtime_instance"]["state_directory"] = "/var/lib/example"
    with pytest.raises(ValueError, match="must be relative"):
        PackageManifest.parse_obj(invalid)


def test_web_route_mode_per_user_socket_requires_runtime_instance():
    invalid = example() | {"web": {**example()["web"], "route_mode": "per-user-socket"}}
    with pytest.raises(PackageError, match="requires installation_class"):
        validate_package(PackageManifest.parse_obj(invalid))


def test_web_route_mode_per_user_socket_forbids_static_upstream():
    invalid = runtime_instance_example()
    invalid["web"]["upstream"] = "127.0.0.1:8090"
    with pytest.raises(PackageError, match="cannot declare a static web.upstream"):
        validate_package(PackageManifest.parse_obj(invalid))


def test_multi_tenant_runtime_plans_template_level_operations_only():
    package = validate_package(PackageManifest.parse_obj(runtime_instance_example()))
    plan = plan_package(package)
    names = [operation.name for operation in plan]
    assert names == [
        "package.ensure", "package.manifest.ensure",
        "runtime_instance.template.ensure", "runtime_instance.socket.enable",
        "runtime_instance.reaper.ensure", "web.route.ensure",
    ]
    # Template-level only: no operation resource is keyed by a concrete
    # username - install time never enumerates the app's current members.
    assert all("@" not in operation.resource for operation in plan)
    template = next(operation for operation in plan if operation.name == "runtime_instance.template.ensure")
    assert template.args["socket_path_template"] == "/run/example/%i.sock"
    socket_enable = next(operation for operation in plan if operation.name == "runtime_instance.socket.enable")
    assert socket_enable.depends_on == ("example:runtime_instance",)
    reaper = next(operation for operation in plan if operation.name == "runtime_instance.reaper.ensure")
    assert reaper.depends_on == ("example:runtime_instance:socket",)
    web = next(operation for operation in plan if operation.name == "web.route.ensure")
    assert web.depends_on == ("example:runtime_instance:socket",)
    assert web.args["socket_path_template"] == "/run/example/%i.sock"


def test_health_socket_check_targets_the_socket_template_unit():
    raw = runtime_instance_example() | {"health": {"type": "socket"}}
    package = validate_package(PackageManifest.parse_obj(raw))
    plan = plan_package(package)
    health = next(operation for operation in plan if operation.name == "health.socket.check")
    assert health.args["unit"] == "example@.socket"
    assert health.depends_on == ("example:web",)


def test_health_path_validation_is_skipped_for_socket_type():
    raw = runtime_instance_example() | {"health": {"type": "socket", "path": "not-absolute"}}
    # Must not raise: health.path is only meaningful for type "http".
    validate_package(PackageManifest.parse_obj(raw))
