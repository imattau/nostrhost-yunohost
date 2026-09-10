from pathlib import Path
import hashlib

import pytest

from nostrhost.native_providers import AptProvider, CaddyProvider, ConfigFileProvider, DirectoryProvider, NativeOperationExecutor, PortProvider, PostgresProvider, ProviderError, SecretProvider, ServiceProvider, SourceProvider, SysusersProvider, TmpfilesProvider, native_providers


def test_directory_provider_uses_python_filesystem_apis(tmp_path: Path):
    provider = DirectoryProvider(root=tmp_path)
    operation = provider.plan({"path": "/var/lib/example", "mode": 0o750})[0]
    result = provider.apply(operation)
    target = tmp_path / "var/lib/example"
    assert target.is_dir()
    assert result["changed"] is True
    assert target.stat().st_mode & 0o7777 == 0o750


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


def test_service_provider_renders_hardened_unit(tmp_path: Path):
    provider = ServiceProvider(unit_dir=tmp_path)
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


def test_caddy_provider_validates_and_loads_json():
    class Response:
        def raise_for_status(self): pass
    class Client:
        def post(self, path, *, json): self.call = (path, json); return Response()
    client = Client()
    provider = CaddyProvider(client=client, config_builder=lambda args: {"apps": {"http": {"routes": [args]}}})
    result = provider.apply(provider.plan({"domain": "example.test", "upstream": "127.0.0.1:8090"})[0])
    assert result["loaded"] and client.call[0] == "/load"


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


def test_secret_provider_generates_mode_600_credential(tmp_path: Path):
    provider = SecretProvider(credential_dir=tmp_path / "credentials")
    operation = provider.plan({"name": "database_password", "length": 32})[0]
    result = provider.apply(operation)
    target = Path(result["credential"])
    assert target.is_file() and target.stat().st_mode & 0o777 == 0o600
    first = target.read_text()
    provider.apply(operation)
    assert target.read_text() == first


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
