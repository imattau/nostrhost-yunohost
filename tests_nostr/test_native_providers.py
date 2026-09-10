from pathlib import Path
import hashlib

import pytest

from nostrhost.native_providers import AccessProvider, AptProvider, BackupProvider, CaddyProvider, ConfigFileProvider, DatabaseProvider, DirectoryProvider, FpmProvider, HealthProvider, HookProvider, JsonStateProvider, MongoProvider, NativeOperationExecutor, PermissionProvider, PolicyProvider, PortProvider, PostgresProvider, ProviderError, RedisProvider, RuntimeProvider, SecretProvider, ServiceProvider, SourceProvider, SysusersProvider, TimerProvider, TmpfilesProvider, native_providers
from nostrhost.package_engine import Operation


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


def test_source_provider_supports_strip_components_and_file_rename(tmp_path: Path):
    archive = tmp_path / "source.tar"
    import tarfile

    payload = b"native"
    with tarfile.open(archive, "w") as tar:
        info = tarfile.TarInfo("release-1.0/bin/app")
        info.size = len(payload)
        tar.addfile(info, __import__("io").BytesIO(payload))

    provider = SourceProvider(root=tmp_path, cache_dir=tmp_path / "cache", downloader=lambda _url, destination: destination.write_bytes(archive.read_bytes()))
    desired = {"url": "https://example.test/source.tar", "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "destination": "/opt/example", "format": "tar", "strip_components": 2}
    provider.apply(provider.plan(desired)[0])
    assert (tmp_path / "opt/example/app").read_bytes() == payload

    file_provider = SourceProvider(root=tmp_path, cache_dir=tmp_path / "cache2", downloader=lambda _url, destination: destination.write_bytes(payload))
    file_desired = {"url": "https://example.test/app.bin", "sha256": hashlib.sha256(payload).hexdigest(), "destination": "/opt/file", "extract": False, "format": "file", "rename": "app.bin"}
    file_provider.apply(file_provider.plan(file_desired)[0])
    assert (tmp_path / "opt/file/app.bin").read_bytes() == payload


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


def test_runtime_provider_supports_ruby_and_isolated_prefix():
    calls = []

    class Result:
        stdout = "ruby 3.3.0p0\n"
        stderr = ""

    provider = RuntimeProvider(command=lambda args, **kwargs: (calls.append(args) or Result()), executable_lookup=lambda name: name)
    result = provider.apply(provider.plan({"type": "ruby", "version": "3.3", "prefix": "/opt/example-runtime"})[0])
    assert result["matches"]
    assert calls == [["/opt/example-runtime/bin/ruby", "--version"]]


def test_runtime_provider_invokes_explicit_installer_then_rechecks():
    installed = False
    calls = []

    class Result:
        stdout = "Python 3.12.4\n"
        stderr = ""

    def lookup(name):
        return "/usr/bin/python3" if installed else None

    def install(desired):
        nonlocal installed
        installed = True
        calls.append(desired)

    provider = RuntimeProvider(command=lambda *args, **kwargs: Result(), executable_lookup=lookup, installer=install)
    result = provider.apply(provider.plan({"type": "python", "version": "3.12"})[0])
    assert result["matches"] and calls == [{"type": "python", "version": "3.12"}]


def test_fpm_provider_renders_owned_pool_and_reloads_matching_service(tmp_path: Path):
    calls = []
    provider = FpmProvider(root=tmp_path, command=lambda args, **kwargs: calls.append((args, kwargs)))
    desired = {"app": "example", "version": "8.2", "socket": "/run/php/example.sock", "user": "example", "group": "example", "max_children": 12}
    provider.apply(provider.plan(desired)[0])
    target = tmp_path / "etc/php/8.2/fpm/pool.d/nostrhost-example.conf"
    assert target.is_file() and "pm.max_children = 12" in target.read_text()
    assert calls == [(["systemctl", "reload", "php8.2-fpm"], {"check": True})]
    provider.apply(provider.remove(desired)[0])
    assert not target.exists()


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
    assert result == {"name": "example_db", "users": [], "changed": True}


def test_postgres_provider_creates_declared_user_and_grants():
    class Cursor:
        def __init__(self): self.calls = []
        def execute(self, query, args=None): self.calls.append((query, args))
        def fetchone(self): return None
        def __enter__(self): return self
        def __exit__(self, *args): pass
    class Connection:
        def __init__(self): self.cursor_obj = Cursor()
        def cursor(self): return self.cursor_obj
        def __enter__(self): return self
        def __exit__(self, *args): pass
    connection = Connection()
    provider = PostgresProvider(connection_factory=lambda: connection, credential_reader=lambda name: f"secret:{name}")
    desired = {"type": "postgresql", "name": "example_db", "users": {"app": {"name": "app", "password_secret": "db_password", "privileges": ["CONNECT"]}}}
    provider.apply(provider.plan(desired)[0])
    assert ('CREATE ROLE "app" LOGIN PASSWORD %s', ("secret:db_password",)) in connection.cursor_obj.calls
    assert ('GRANT CONNECT ON DATABASE "example_db" TO "app"', None) in connection.cursor_obj.calls


def test_database_provider_uses_bounded_dump_and_restore_commands(tmp_path: Path):
    calls = []
    provider = PostgresProvider(command=lambda args, **kwargs: calls.append((args, kwargs)))
    dump = Operation("database.dump", "example_db", {"name": "example_db", "output": str(tmp_path / "db.dump")})
    restore = Operation("database.restore", "example_db", {"name": "example_db", "input": str(tmp_path / "db.dump")})
    provider.apply(dump)
    provider.apply(restore)
    assert calls == [
        (["pg_dump", "--dbname", "example_db", "--format", "custom", "--file", str(tmp_path / "db.dump")], {"check": True}),
        (["pg_restore", "--dbname", "example_db", str(tmp_path / "db.dump")], {"check": True}),
    ]


def test_native_provider_factory_routes_database_commands_through_injected_runner(tmp_path: Path):
    calls = []
    providers = native_providers(command=lambda argv, **kwargs: calls.append((argv, kwargs)))
    providers["database"].apply(Operation("database.dump", "example_db", {"type": "postgresql", "name": "example_db", "output": str(tmp_path / "db.dump")}))
    assert calls == [(["pg_dump", "--dbname", "example_db", "--format", "custom", "--file", str(tmp_path / "db.dump")], {"check": True})]


def test_database_dump_rejects_traversal_path():
    provider = PostgresProvider(command=lambda *_args, **_kwargs: None)
    operation = Operation("database.dump", "example_db", {"name": "example_db", "output": "/var/lib/../etc/db.dump"})
    with pytest.raises(ProviderError, match="cannot contain '..'"):
        provider.apply(operation)


def test_mongo_provider_creates_declared_user():
    class Database:
        def __init__(self): self.calls = []
        def command(self, *args, **kwargs): self.calls.append((args, kwargs))
    class Client:
        def __init__(self): self.database = Database()
        def list_database_names(self): return []
        def __getitem__(self, name): assert name == "example"; return self.database
        def close(self): pass
    client = Client()
    provider = MongoProvider(client_factory=lambda: client, credential_reader=lambda _: "password")
    operation = provider.plan({"type": "mongodb", "name": "example", "users": {"app": {"name": "app", "password_secret": "db_password", "privileges": ["readWrite"]}}})[0]
    provider.apply(operation)
    assert client.database.calls == [(('createUser', 'app'), {"pwd": "password", "roles": ["readWrite"]})]


def test_redis_provider_validates_logical_database_without_mutating_keys():
    class Client:
        def __init__(self): self.pings = 0
        def ping(self): self.pings += 1
        def close(self): pass
    client = Client()
    provider = RedisProvider(client_factory=lambda index: client)
    operation = provider.plan({"type": "redis", "name": "4"})[0]
    result = provider.apply(operation)
    assert result == {"name": "4", "index": 4, "changed": False}
    assert client.pings == 1


def test_caddy_provider_ensures_route_via_admin_api():
    class Client:
        def __init__(self):
            self.ensured = []
        def get_config(self):
            return {"apps": {"http": {}}}
        def ensure_route(self, route):
            self.ensured.append(route)
            return route["@id"]
        def delete_route(self, route_id):
            raise AssertionError("delete not expected")
    client = Client()
    provider = CaddyProvider(client=client, config_builder=lambda args: {"@id": "nostrhost-web:" + args["app"], "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": args["upstream"]}]}]})
    result = provider.apply(provider.plan({"domain": "example.test", "upstream": "127.0.0.1:8090", "app": "test"})[0])
    assert result["ensured"] and result["route_id"] == "nostrhost-web:test"
    assert client.ensured[0]["@id"] == "nostrhost-web:test"


def test_caddy_provider_removes_route_by_id():
    class Client:
        def __init__(self):
            self.deleted = []
        def get_config(self):
            return {"apps": {"http": {}}}
        def ensure_route(self, route):
            return route["@id"]
        def delete_route(self, route_id):
            self.deleted.append(route_id)
    client = Client()
    provider = CaddyProvider(client=client, config_builder=lambda args: {"@id": "nostrhost-web:" + args["app"], "handle": []})
    operation = provider.remove({"domain": "example.test", "upstream": "127.0.0.1:8090", "app": "test"})[0]
    assert provider.apply(operation)["removed"]
    assert client.deleted == ["nostrhost-web:test"]


def test_build_web_route_reverse_proxy():
    from nostrhost.caddy_admin import build_web_route

    route = build_web_route({"app": "demo", "domain": "example.test", "path": "/demo/", "upstream": "127.0.0.1:8123", "auth": "none"})
    assert route["@id"] == "nostrhost-web:demo"
    assert route["match"] == [{"host": ["example.test"]}, {"path": ["/demo/*"]}]
    assert route["handle"] == [
        {"handler": "rewrite", "strip_path_prefix": "/demo"},
        {"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:8123"}]},
    ]


def test_build_web_route_forward_auth_and_file_server():
    from nostrhost.caddy_admin import build_web_route

    route = build_web_route({"app": "demo", "domain": "example.test", "path": "/demo/", "file_root": "/var/www/demo", "auth": "nostrhost"})
    handlers = route["handle"]
    auth = handlers[0]
    assert auth["handler"] == "reverse_proxy"
    assert auth["rewrite"]["uri"] == "/nostr/auth-request"
    # 2xx handle_response: delete client copies, then re-set from authd
    headers_routes = [h for h in auth["handle_response"][0]["routes"] if h["handle"][0]["handler"] == "headers"]
    request_ops = [h["request"] for entry in headers_routes for h in entry["handle"] if "request" in h]
    assert {"delete": ["X-Remote-User"]} in request_ops
    # forward_auth runs first (original URI for permission matching), then the
    # prefix strip, then the static backend.
    assert handlers[1] == {"handler": "rewrite", "strip_path_prefix": "/demo"}
    assert handlers[2] == {"handler": "file_server", "root": "/var/www/demo"}


def test_build_web_route_rejects_invalid_upstream():
    from nostrhost.caddy_admin import CaddyError, build_web_route

    with pytest.raises(CaddyError, match="host:port"):
        build_web_route({"app": "demo", "domain": "example.test", "path": "/demo/", "upstream": "not-a-port", "auth": "none"})


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


def test_sysusers_provider_declares_requested_groups(tmp_path: Path):
    provider = SysusersProvider(root=tmp_path, command=lambda *_args, **_kwargs: None)
    provider.apply(provider.plan({"name": "example", "groups": ["example-workers"]})[0])
    definition = (tmp_path / "etc/sysusers.d/nostrhost-example.conf").read_text()
    assert "g example-workers -" in definition
    assert "u example" in definition


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


def test_hook_provider_registers_reference_without_executing(tmp_path: Path):
    provider = HookProvider(state_dir=tmp_path)
    desired = {"name": "example-post_install", "reference": "hooks.py:post_install"}
    operation = provider.plan(desired)[0]
    result = provider.apply(operation)
    assert result["changed"]
    assert "hooks.py:post_install" in (tmp_path / "example-post_install.json").read_text()


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


def test_health_provider_retries_with_bounded_attempts():
    class Response:
        status_code = 503
        is_success = False
    class Client:
        def __init__(self): self.calls = 0
        def get(self, path, *, timeout): self.calls += 1; return Response()
    client = Client()
    result = HealthProvider(client=client).inspect({"path": "/health", "timeout": 2, "retries": 2})
    assert result == {"status_code": 503, "healthy": False, "attempts": 3}
    assert client.calls == 3


def test_health_provider_retries_transport_failure_then_succeeds():
    class Response:
        status_code = 200
        is_success = True
    class Client:
        def __init__(self): self.calls = 0
        def get(self, path, *, timeout):
            self.calls += 1
            if self.calls == 1:
                raise OSError("connection refused")
            return Response()
    client = Client()
    result = HealthProvider(client=client).inspect({"path": "/health", "retries": 2})
    assert result == {"status_code": 200, "healthy": True, "attempts": 2}


def test_policy_provider_writes_and_removes_managed_policy(tmp_path: Path):
    provider = PolicyProvider(root=tmp_path)
    desired = {"type": "fail2ban", "name": "example", "content": "[example]\nenabled=true\n"}
    provider.apply(provider.plan(desired)[0])
    target = tmp_path / "etc/fail2ban/jail.d/nostrhost-example.local"
    assert target.read_text() == desired["content"]
    provider.apply(provider.remove(desired)[0])
    assert not target.exists()


def test_permission_provider_reconciles_portal_permission():
    state = {}

    class API:
        syncs = 0

        def info(self, name):
            if name not in state:
                raise KeyError(name)
            return state[name].copy()

        def create(self, name, **kwargs):
            state[name] = {
                "url": kwargs["url"],
                "additional_urls": kwargs["additional_urls"],
                "allowed": kwargs["allowed"],
                "auth_header": kwargs["auth_header"],
                "auth_request": False,
                "show_tile": kwargs["show_tile"],
                "protected": kwargs["protected"],
            }

        def update(self, name, *, add, remove, show_tile, protected, **kwargs):
            state[name]["allowed"] = [group for group in state[name]["allowed"] if group not in remove] + add
            state[name]["show_tile"] = show_tile
            state[name]["protected"] = protected

        def url(self, name, *, url, set_url, auth_header, **kwargs):
            state[name].update(url=url, additional_urls=set_url, auth_header=auth_header)

        def delete(self, name, **kwargs):
            del state[name]

        def sync(self):
            self.syncs += 1

        def set_auth_request(self, name, enabled):
            state[name]["auth_request"] = enabled

    api = API()
    provider = PermissionProvider(api=api)
    desired = {"app": "example", "name": "main", "url": "/", "allowed": ["all_users"], "show_tile": True, "auth_request": True, "additional_urls": []}
    ensure = provider.plan(desired)[0]
    provider.apply(ensure)
    assert provider.inspect(desired)["allowed"] == ["all_users"]

    desired["allowed"] = ["admins"]
    provider.apply(provider.plan(desired)[0])
    assert provider.inspect(desired)["allowed"] == ["admins"]
    assert api.syncs == 2

    provider.apply(provider.remove(desired)[0])
    assert provider.inspect(desired)["exists"] is False


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
