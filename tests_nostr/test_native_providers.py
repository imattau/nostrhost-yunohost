from pathlib import Path
import hashlib

import pytest

from nostrhost.native_providers import AccessProvider, AptProvider, BackupProvider, CaddyProvider, ConfigFileProvider, DatabaseProvider, DirectoryProvider, JsonStateProvider, NativeOperationExecutor, PortProvider, PostgresProvider, ProviderError, RuntimeProvider, SecretProvider, ServiceProvider, SourceProvider, SysusersProvider, TimerProvider, TmpfilesProvider, native_providers


def test_directory_provider_uses_python_filesystem_apis(tmp_path: Path):
    provider = DirectoryProvider(root=tmp_path)
    operation = provider.plan({"path": "/var/lib/example", "mode": 0o750})[0]
    result = provider.apply(operation)
    target = tmp_path / "var/lib/example"
    assert target.is_dir()
    assert result["changed"] is True
    assert target.stat().st_mode & 0o7777 == 0o750


def test_directory_provider_removes_only_empty_declared_directory(tmp_path: Path):
    provider = DirectoryProvider(root=tmp_path)
    ensure = provider.plan({"path": "/var/lib/example", "mode": 0o750})[0]
    provider.apply(ensure)
    remove = provider.remove({"path": "/var/lib/example"})[0]
    assert provider.apply(remove)["changed"]
    assert not (tmp_path / "var/lib/example").exists()


def test_source_provider_verifies_and_extracts_without_shell(tmp_path: Path):
    archive = tmp_path / "source.tar.gz"
    import tarfile

    payload = tmp_path / "payload.txt"
    payload.write_text("native")
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(payload, arcname="payload.txt")

    def download(_url: str, destination: Path) -> None:
        destination.write_bytes(archive.read_bytes())

    destination = tmp_path / "var/lib/example"
    provider = SourceProvider(root=tmp_path, cache_dir=tmp_path / "cache", downloader=download)
    operation = provider.plan({"url": "https://example.test/source.tar.gz", "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "destination": "/var/lib/example", "extract": True})[0]
    assert provider.apply(operation)["verified"] is True
    assert (destination / "payload.txt").read_text() == "native"


def test_source_provider_rejects_hash_mismatch(tmp_path: Path):
    provider = SourceProvider(root=tmp_path, cache_dir=tmp_path / "cache", downloader=lambda _url, destination: destination.write_bytes(b"wrong"))
    operation = provider.plan({"url": "https://example.test/source", "sha256": "a" * 64})[0]
    with pytest.raises(ProviderError, match="hash mismatch"):
        provider.apply(operation)


def test_source_provider_removes_cached_archive(tmp_path: Path):
    provider = SourceProvider(root=tmp_path, cache_dir=tmp_path / "cache", downloader=lambda _url, destination: destination.write_bytes(b"source"))
    desired = {"url": "https://example.test/source", "sha256": hashlib.sha256(b"source").hexdigest()}
    provider.apply(provider.plan(desired)[0])
    remove = provider.remove(desired)[0]
    result = provider.apply(remove)
    assert result["changed"] and not Path(result["path"]).exists()


def test_source_provider_rejects_archive_links(tmp_path: Path):
    archive = tmp_path / "unsafe.tar"
    import tarfile

    with tarfile.open(archive, "w") as tar:
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tar.addfile(link)

    provider = SourceProvider(root=tmp_path, cache_dir=tmp_path / "cache", downloader=lambda _url, destination: destination.write_bytes(archive.read_bytes()))
    operation = provider.plan({"url": "https://example.test/unsafe.tar", "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "destination": "/var/lib/example", "extract": True})[0]
    with pytest.raises(ProviderError, match="link or special"):
        provider.apply(operation)


def test_runtime_provider_validates_version_with_bounded_arguments():
    calls = []

    class Result:
        stdout = "v24.2.0\n"
        stderr = ""

    provider = RuntimeProvider(command=lambda args, **kwargs: (calls.append((args, kwargs)) or Result()), executable_lookup=lambda name: f"/usr/bin/{name}")
    operation = provider.plan({"type": "node", "version": "24"})[0]
    result = provider.apply(operation)
    assert result["matches"] and result["version"] == "24.2.0"
    assert calls[0][0] == ["/usr/bin/node", "--version"]


def test_runtime_provider_rejects_missing_runtime():
    provider = RuntimeProvider(executable_lookup=lambda _name: None)
    with pytest.raises(ProviderError, match="not installed"):
        provider.apply(provider.plan({"type": "go", "version": "1.24"})[0])


def test_service_provider_renders_hardened_unit(tmp_path: Path):
    provider = ServiceProvider(unit_dir=tmp_path, command=lambda *_args, **_kwargs: None)
    operation = provider.plan({"name": "example", "exec": "/opt/example/server", "user": "example", "security": {}})[0]
    provider.apply(operation)
    unit = (tmp_path / "example.service").read_text()
    assert "ExecStart=/opt/example/server" in unit
    assert "NoNewPrivileges=yes" in unit
    assert "ProtectSystem=strict" in unit
    assert "PrivateTmp=yes" in unit


def test_service_provider_rejects_unsafe_unit_names(tmp_path: Path):
    provider = ServiceProvider(unit_dir=tmp_path)
    operation = provider.plan({"name": "../bad", "exec": "/bin/true"})[0]
    with pytest.raises(ProviderError, match="unsafe systemd unit"):
        provider.apply(operation)


def test_service_provider_uses_bounded_systemctl_arguments(tmp_path: Path):
    calls = []
    provider = ServiceProvider(unit_dir=tmp_path, command=lambda args, **kwargs: calls.append((args, kwargs)))
    operation = provider.plan({"name": "example", "exec": "/bin/true"})[0]
    operation = operation.__class__("service.start", operation.resource, {"name": "example"})
    assert provider.apply(operation)["action"] == "start"
    assert calls == [(["systemctl", "start", "example"], {"check": True})]


def test_service_provider_removes_unit_and_reloads_systemd(tmp_path: Path):
    calls = []
    provider = ServiceProvider(unit_dir=tmp_path, command=lambda args, **kwargs: calls.append((args, kwargs)))
    ensure = provider.plan({"name": "example", "exec": "/bin/true"})[0]
    provider.apply(ensure)
    remove = provider.remove({"name": "example"})[0]
    provider.apply(remove)
    assert not (tmp_path / "example.service").exists()
    assert calls[-1] == (["systemctl", "daemon-reload"], {"check": True})


def test_native_executor_dispatches_only_registered_provider(tmp_path: Path):
    executor = NativeOperationExecutor(native_providers(root=tmp_path, unit_dir=tmp_path))
    operation = DirectoryProvider(root=tmp_path).plan({"path": "/opt/example", "mode": 0o750})[0]
    assert executor.execute(operation)["changed"] is True
    with pytest.raises(ProviderError, match="no native provider"):
        executor.execute(operation.__class__("unknown.ensure", "example:unknown", {}))


def test_apt_provider_uses_python_apt_shape():
    class Package:
        is_installed = False
        def mark_install(self): self.is_installed = True
    class Cache(dict):
        def commit(self): self.committed = True
    cache = Cache(ffmpeg=Package())
    provider = AptProvider(cache_factory=lambda: cache)
    result = provider.apply(provider.plan({"packages": ["ffmpeg"]})[0])
    assert result["changed"] and cache["ffmpeg"].is_installed and cache.committed


def test_postgres_provider_uses_parameterized_existence_query():
    class Cursor:
        def execute(self, query, args): self.call = (query, args)
        def fetchone(self): return None
        def __enter__(self): return self
        def __exit__(self, *args): pass
    class Connection:
        def __init__(self): self.cursor_obj = Cursor()
        def cursor(self): return self.cursor_obj
        def __enter__(self): return self
        def __exit__(self, *args): pass
    connection = Connection()
    result = PostgresProvider(connection_factory=lambda: connection).inspect({"name": "example_db"})
    assert result == {"name": "example_db", "exists": False}
    assert connection.cursor_obj.call[1] == ("example_db",)


def test_postgres_provider_removes_database_with_native_driver():
    class Cursor:
        def execute(self, query, args=None): self.call = (query, args)
        def __enter__(self): return self
        def __exit__(self, *args): pass
    class Connection:
        def cursor(self): return Cursor()
        def __enter__(self): return self
        def __exit__(self, *args): pass
    connection = Connection()
    provider = PostgresProvider(connection_factory=lambda: connection)
    operation = provider.remove({"name": "example_db"})[0]
    assert provider.apply(operation)["changed"]


def test_database_provider_dispatches_mysql_without_postgres_fallback():
    class Cursor:
        def execute(self, query, args=None): self.call = (query, args)
        def fetchone(self): return None
        def __enter__(self): return self
        def __exit__(self, *args): pass
    class Connection:
        def __init__(self): self.cursor_obj = Cursor()
        def cursor(self): return self.cursor_obj
        def __enter__(self): return self
        def __exit__(self, *args): pass
    connection = Connection()
    provider = DatabaseProvider(mysql_connection_factory=lambda: connection)
    result = provider.apply(provider.plan({"type": "mysql", "name": "example_db"})[0])
    assert result == {"name": "example_db", "changed": True}
    assert connection.cursor_obj.call == ("CREATE DATABASE `example_db`", None)


def test_caddy_provider_validates_and_loads_json():
    class Response:
        def raise_for_status(self): pass
    class Client:
        def post(self, path, *, json): self.call = (path, json); return Response()
    client = Client()
    provider = CaddyProvider(client=client, config_builder=lambda args: {"apps": {"http": {"routes": [args]}}})
    result = provider.apply(provider.plan({"domain": "example.test", "upstream": "127.0.0.1:8090"})[0])
    assert result["loaded"] and client.call[0] == "/load"


def test_caddy_provider_requires_explicit_route_removal_builder():
    class Response:
        def raise_for_status(self): pass
    class Client:
        def post(self, path, *, json): self.call = (path, json); return Response()
    provider = CaddyProvider(client=Client(), config_builder=lambda args: {"ensure": args})
    operation = provider.remove({"domain": "example.test", "upstream": "127.0.0.1:8090"})[0]
    with pytest.raises(ProviderError, match="removal builder"):
        provider.apply(operation)


def test_caddy_provider_uses_native_route_removal_builder():
    class Response:
        def raise_for_status(self): pass
    class Client:
        def post(self, path, *, json): self.call = (path, json); return Response()
    client = Client()
    provider = CaddyProvider(client=client, config_builder=lambda args: {"ensure": args}, remove_config_builder=lambda args: {"remove": args["domain"]})
    operation = provider.remove({"domain": "example.test", "upstream": "127.0.0.1:8090"})[0]
    assert provider.apply(operation)["loaded"]
    assert client.call[1] == {"remove": "example.test"}


def test_systemd_definitions_are_rendered_and_applied_with_bounded_commands(tmp_path: Path):
    calls = []
    command = lambda args, **kwargs: calls.append((args, kwargs))
    tmpfiles = TmpfilesProvider(root=tmp_path, command=command)
    tmpfiles.apply(tmpfiles.plan({"path": "/var/lib/example", "mode": 0o750})[0])
    sysusers = SysusersProvider(root=tmp_path, command=command)
    sysusers.apply(sysusers.plan({"name": "example"})[0])
    assert list((tmp_path / "etc/tmpfiles.d").glob("nostrhost-*.conf"))
    assert (tmp_path / "etc/sysusers.d/nostrhost-example.conf").is_file()
    tmpfile = next((tmp_path / "etc/tmpfiles.d").glob("nostrhost-*.conf"))
    assert calls == [
        (["systemd-tmpfiles", "--create", str(tmpfile)], {"check": True}),
        (["systemd-sysusers", str(tmp_path / "etc/sysusers.d/nostrhost-example.conf")], {"check": True}),
    ]


def test_sysusers_removal_removes_declaration_without_deleting_account(tmp_path: Path):
    provider = SysusersProvider(root=tmp_path, command=lambda *_args, **_kwargs: None)
    ensure = provider.plan({"name": "example"})[0]
    provider.apply(ensure)
    remove = provider.remove({"name": "example"})[0]
    result = provider.apply(remove)
    assert result["changed"]
    assert not (tmp_path / "etc/sysusers.d/nostrhost-example.conf").exists()


def test_secret_provider_generates_mode_600_credential(tmp_path: Path):
    provider = SecretProvider(credential_dir=tmp_path / "credentials")
    operation = provider.plan({"name": "database_password", "length": 32})[0]
    result = provider.apply(operation)
    target = Path(result["credential"])
    assert target.is_file() and target.stat().st_mode & 0o777 == 0o600
    first = target.read_text()
    provider.apply(operation)
    assert target.read_text() == first


def test_secret_provider_removes_credential(tmp_path: Path):
    provider = SecretProvider(credential_dir=tmp_path / "credentials")
    ensure = provider.plan({"name": "api_key", "length": 16})[0]
    provider.apply(ensure)
    remove = provider.remove({"name": "api_key"})[0]
    assert provider.apply(remove)["changed"]
    assert not (tmp_path / "credentials/api_key").exists()


def test_timer_provider_disables_and_removes_units(tmp_path: Path):
    calls = []
    provider = TimerProvider(unit_dir=tmp_path, command=lambda args, **kwargs: calls.append((args, kwargs)))
    ensure = provider.plan({"name": "example", "exec": "/bin/true", "on_calendar": "daily"})[0]
    provider.apply(ensure)
    remove = provider.remove({"name": "example"})[0]
    provider.apply(remove)
    assert not (tmp_path / "example.timer").exists()
    assert not (tmp_path / "example.service").exists()
    assert calls[-1] == (["systemctl", "disable", "--now", "example.timer"], {"check": True})


def test_json_state_provider_unregisters_state_atomically(tmp_path: Path):
    provider = JsonStateProvider(state_dir=tmp_path, resource_type="backup")
    ensure = provider.plan({"name": "example", "paths": ["/var/lib/example"]})[0]
    provider.apply(ensure)
    target = tmp_path / "example.json"
    assert target.is_file() and '"paths"' in target.read_text()
    remove = provider.remove({"name": "example"})[0]
    assert provider.apply(remove)["changed"]
    assert not target.exists()


def test_backup_provider_persists_validated_manifest(tmp_path: Path):
    provider = BackupProvider(state_dir=tmp_path)
    operation = provider.plan({"name": "example", "paths": ["/var/lib/example"], "database": True})[0]
    provider.apply(operation)
    assert '"format": "nostrhost-backup-v1"' in (tmp_path / "example.json").read_text()


def test_backup_provider_rejects_relative_paths(tmp_path: Path):
    provider = BackupProvider(state_dir=tmp_path)
    operation = provider.plan({"name": "example", "paths": ["relative/data"]})[0]
    with pytest.raises(ProviderError, match="backup paths"):
        provider.apply(operation)


def test_port_provider_checks_bind_availability():
    class Probe:
        def bind(self, address): self.address = address
        def close(self): pass
    provider = PortProvider(socket_factory=lambda *_args: Probe())
    operation = provider.plan({"name": "http", "port": 1})[0]
    result = provider.apply(operation)
    assert result["port"] == 1
    assert isinstance(result["available"], bool)


def test_directory_provider_resolves_numeric_ownership(tmp_path: Path):
    calls = []
    provider = DirectoryProvider(root=tmp_path, chown=lambda *args: calls.append(args))
    operation = provider.plan({"path": "/var/lib/example", "mode": 0o750, "owner": "root", "group": "root"})[0]
    assert provider.apply(operation)["changed"] is True
    assert calls and calls[0][1:] == (0, 0)


def test_access_provider_enforces_mode_and_ownership(tmp_path: Path):
    target = tmp_path / "var/lib/example"
    target.mkdir(parents=True)
    provider = AccessProvider(root=tmp_path, chown=lambda *args: None)
    operation = provider.plan({"path": "/var/lib/example", "owner": "root", "mode": 0o750})[0]
    result = provider.apply(operation)
    assert result["changed"] and target.stat().st_mode & 0o7777 == 0o750


def test_config_provider_renders_inline_content_atomically(tmp_path: Path):
    provider = ConfigFileProvider(root=tmp_path)
    operation = provider.plan({"destination": "/etc/example.conf", "content": "port=8090\n", "mode": 0o640})[0]
    result = provider.apply(operation)
    target = tmp_path / "etc/example.conf"
    assert result["changed"] and target.read_text() == "port=8090\n"
    assert target.stat().st_mode & 0o7777 == 0o640


def test_config_provider_renders_strict_jinja_template(tmp_path: Path):
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "app.conf.j2").write_text("domain={{ domain }}\nport={{ port }}\n")
    provider = ConfigFileProvider(root=tmp_path, template_root=templates)
    operation = provider.plan({"destination": "/etc/example.conf", "template": "app.conf.j2", "context": {"domain": "example.test", "port": 8090}})[0]
    provider.apply(operation)
    assert (tmp_path / "etc/example.conf").read_text() == "domain=example.test\nport=8090"


def test_config_provider_rejects_template_traversal(tmp_path: Path):
    provider = ConfigFileProvider(root=tmp_path, template_root=tmp_path)
    operation = provider.plan({"destination": "/etc/example.conf", "template": "../secret"})[0]
    with pytest.raises(ProviderError, match="relative"):
        provider.apply(operation)


def test_config_provider_removes_managed_file(tmp_path: Path):
    provider = ConfigFileProvider(root=tmp_path)
    ensure = provider.plan({"destination": "/etc/example.conf", "content": "managed\n"})[0]
    provider.apply(ensure)
    remove = provider.remove({"destination": "/etc/example.conf"})[0]
    assert provider.apply(remove)["changed"]
    assert not (tmp_path / "etc/example.conf").exists()
