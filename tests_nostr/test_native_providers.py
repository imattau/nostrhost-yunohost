from pathlib import Path
import hashlib

import pytest

from nostrhost.native_providers import AptProvider, CaddyProvider, DirectoryProvider, NativeOperationExecutor, PostgresProvider, ProviderError, ServiceProvider, SourceProvider, native_providers


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


def test_native_executor_dispatches_only_registered_provider(tmp_path: Path):
    executor = NativeOperationExecutor(native_providers(root=tmp_path, unit_dir=tmp_path))
    operation = DirectoryProvider(root=tmp_path).plan({"path": "/opt/example", "mode": 0o750})[0]
    assert executor.execute(operation)["changed"] is True
    with pytest.raises(ProviderError, match="no native provider"):
        executor.execute(operation.__class__("timer.ensure", "example:timer", {}))


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
