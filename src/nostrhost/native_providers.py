"""Native providers for the first executable resource domains.

Providers are deliberately dependency-injected: tests can use a temporary
root and fake download/systemd functions, while production can use the same
bounded implementation with ``/`` as its root.
"""

from __future__ import annotations

import hashlib
import os
import grp
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Callable

from .package_engine import Operation, Provider


class ProviderError(RuntimeError):
    """A native provider could not apply an operation safely."""


class PackageProvider:
    """Package identity bookkeeping; resource mutations belong to providers."""

    def apply(self, operation: Operation) -> dict[str, Any]:
        return {"package": operation.args["id"], "version": operation.args["version"], "changed": False}


def _safe_name(value: str) -> str:
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.@:-]*", value):
        raise ProviderError(f"unsafe systemd unit name: {value!r}")
    return value


def _target(root: Path, absolute: str | Path) -> Path:
    path = Path(absolute)
    if not path.is_absolute() or ".." in path.parts:
        raise ProviderError(f"provider path must be absolute and normalized: {path}")
    return root / path.relative_to("/")


class DirectoryProvider:
    resource_type = "directory"

    def __init__(self, *, root: Path = Path("/"), chown: Callable[..., Any] | None = None) -> None:
        self.root = root
        self.chown = chown or os.chown

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        path = _target(self.root, desired["path"])
        return {"exists": path.is_dir(), "mode": path.stat().st_mode & 0o7777 if path.exists() else None}

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        return [Operation("directory.ensure", desired["path"], desired, reverse="directory.remove", summary=f"ensure directory {desired['path']}")]

    def apply(self, operation: Operation) -> dict[str, Any]:
        path = _target(self.root, operation.args["path"])
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, operation.args["mode"])
        if operation.args.get("owner") or operation.args.get("group"):
            try:
                uid = pwd.getpwnam(operation.args["owner"]).pw_uid if operation.args.get("owner") else -1
                gid = grp.getgrnam(operation.args["group"]).gr_gid if operation.args.get("group") else -1
                self.chown(path, uid, gid)
            except KeyError as exc:
                raise ProviderError(f"unknown directory owner or group: {exc.args[0]}") from exc
        return {"path": str(path), "changed": True}

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        return [Operation("directory.remove", desired["path"], {"path": desired["path"]}, reverse="directory.ensure", summary=f"remove directory {desired['path']}")]


class ConfigFileProvider:
    """Render declared configuration files with Jinja2 and atomic writes."""

    resource_type = "config"

    def __init__(self, *, root: Path = Path("/"), template_root: Path | None = None, chown: Callable[..., Any] | None = None) -> None:
        self.root = root
        self.template_root = template_root
        self.chown = chown or os.chown

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        target = _target(self.root, desired["destination"])
        return {"destination": str(target), "exists": target.is_file(), "mode": target.stat().st_mode & 0o7777 if target.exists() else None}

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        return [Operation("config.ensure", desired["destination"], desired, reverse="config.remove", summary=f"render config {desired['destination']}")]

    @staticmethod
    def _template_name(value: str) -> str:
        path = Path(value)
        if path.is_absolute() or ".." in path.parts:
            raise ProviderError("config template must be relative and cannot contain '..'")
        return value

    def apply(self, operation: Operation) -> dict[str, Any]:
        args = operation.args
        target = _target(self.root, args["destination"])
        if operation.name == "config.remove":
            target.unlink(missing_ok=True)
            return {"destination": str(target), "changed": True}
        if args.get("content") is not None:
            content = args["content"]
        else:
            if self.template_root is None:
                raise ProviderError("a template root is required for template-backed config")
            import jinja2

            name = self._template_name(args["template"])
            template_path = (self.template_root / name).resolve()
            if not str(template_path).startswith(str(self.template_root.resolve()) + os.sep):
                raise ProviderError("config template escapes the template root")
            if not template_path.is_file():
                raise ProviderError(f"config template does not exist: {name}")
            environment = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=False)
            content = environment.from_string(template_path.read_text(encoding="utf-8")).render(args.get("context", {}))

        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            temporary.write_text(content, encoding="utf-8")
            os.chmod(temporary, args.get("mode", 0o640))
            if args.get("owner") or args.get("group"):
                try:
                    uid = pwd.getpwnam(args["owner"]).pw_uid if args.get("owner") else -1
                    gid = grp.getgrnam(args["group"]).gr_gid if args.get("group") else -1
                    self.chown(temporary, uid, gid)
                except KeyError as exc:
                    raise ProviderError(f"unknown config owner or group: {exc.args[0]}") from exc
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
        return {"destination": str(target), "changed": True}

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        return [Operation("config.remove", desired["destination"], {"destination": desired["destination"]}, reverse="config.ensure", summary=f"remove config {desired['destination']}")]


class TmpfilesProvider(DirectoryProvider):
    """Declare managed directories through systemd-tmpfiles."""

    def __init__(self, *, root: Path = Path("/"), definition_dir: Path = Path("/etc/tmpfiles.d"), command: Callable[..., Any] | None = None) -> None:
        super().__init__(root=root)
        self.definition_dir = _target(root, definition_dir)
        self.command = command or subprocess.run

    def apply(self, operation: Operation) -> dict[str, Any]:
        args = operation.args
        path = Path(args["path"])
        resource_name = operation.resource.rsplit(":", 1)[-1]
        name = hashlib.sha256(str(path).encode()).hexdigest()[:12] if resource_name.startswith("/") else _safe_name(resource_name)
        self.definition_dir.mkdir(parents=True, exist_ok=True)
        file = self.definition_dir / f"nostrhost-{name}.conf"
        file.write_text(f"d {path} {args['mode']:04o} {args.get('owner') or '-'} {args.get('group') or '-'} -\n", encoding="utf-8")
        self.command(["systemd-tmpfiles", "--create", str(file)], check=True)
        return {"path": str(path), "definition": str(file), "changed": True}


class SysusersProvider:
    """Declare service accounts through systemd-sysusers."""

    def __init__(self, *, root: Path = Path("/"), definition_dir: Path = Path("/etc/sysusers.d"), command: Callable[..., Any] | None = None) -> None:
        self.definition_dir = _target(root, definition_dir)
        self.command = command or subprocess.run

    @staticmethod
    def _name(value: str) -> str:
        if not re.fullmatch(r"[a-z_][a-z0-9_-]*", value):
            raise ProviderError(f"unsafe system user name: {value!r}")
        return value

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        name = self._name(desired["name"])
        return {"name": name, "definition": (self.definition_dir / f"nostrhost-{name}.conf").is_file()}

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        return [Operation("system_user.ensure", desired["name"], desired, reverse="system_user.remove", summary=f"declare system user {desired['name']}")]

    def apply(self, operation: Operation) -> dict[str, Any]:
        args = operation.args
        name = self._name(args["name"])
        self.definition_dir.mkdir(parents=True, exist_ok=True)
        file = self.definition_dir / f"nostrhost-{name}.conf"
        home = args.get("home") or f"/var/lib/{name}"
        description = args.get("description") or "NostrHost service account"
        file.write_text(f'u {name} - "{description}" {home}\n', encoding="utf-8")
        self.command(["systemd-sysusers", str(file)], check=True)
        return {"name": name, "definition": str(file), "changed": True}

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        return [Operation("system_user.remove", desired["name"], {"name": desired["name"]}, reverse="system_user.ensure", summary="remove system user declaration")]


class SecretProvider:
    """Store generated credentials in a mode-600 systemd credential source."""

    def __init__(self, *, credential_dir: Path = Path("/var/lib/nostrhost/credentials")) -> None:
        self.credential_dir = credential_dir

    @staticmethod
    def _name(value: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9_.-]+", value):
            raise ProviderError(f"unsafe credential name: {value!r}")
        return value

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        name = self._name(desired["name"])
        return {"name": name, "exists": (self.credential_dir / name).is_file()}

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        return [Operation("secret.ensure", desired["name"], desired, risk="high", reverse="secret.remove", summary=f"ensure systemd credential {desired['name']}")]

    def apply(self, operation: Operation) -> dict[str, Any]:
        name = self._name(operation.args["name"])
        self.credential_dir.mkdir(parents=True, exist_ok=True)
        target = self.credential_dir / name
        if not target.exists():
            target.write_text(secrets.token_urlsafe(operation.args.get("length", 32)), encoding="utf-8")
            os.chmod(target, 0o600)
        return {"name": name, "credential": str(target), "changed": True}

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        return [Operation("secret.remove", desired["name"], {"name": desired["name"]}, risk="high", reverse="secret.ensure", summary="remove systemd credential")]


class PortProvider:
    """Check bind availability without invoking netstat/lsof shell commands."""

    def __init__(self, *, socket_factory: Callable[..., Any] | None = None) -> None:
        self.socket_factory = socket_factory

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        import socket

        port = int(desired["port"])
        probe = (self.socket_factory or socket.socket)(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return {"port": port, "available": False}
        finally:
            probe.close()
        return {"port": port, "available": True}

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        return [Operation("port.validate", desired["name"], desired, summary=f"validate port {desired['port']}")]

    def apply(self, operation: Operation) -> dict[str, Any]:
        result = self.inspect(operation.args)
        if not result["available"]:
            raise ProviderError(f"port is unavailable: {result['port']}")
        return result

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        return []


class SourceProvider:
    resource_type = "source"

    def __init__(self, *, root: Path = Path("/"), cache_dir: Path = Path("/var/cache/nostrhost/packages"), downloader: Callable[[str, Path], None] | None = None) -> None:
        self.root = root
        self.cache_dir = cache_dir if cache_dir.is_absolute() else root / cache_dir
        self.downloader = downloader or self._download

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        destination = desired.get("destination")
        path = _target(self.root, destination) if destination else self.cache_dir / hashlib.sha256(desired["url"].encode()).hexdigest()
        return {"exists": path.exists(), "path": str(path)}

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        return [Operation("source.fetch", desired["url"], desired, risk="medium", reverse="source.remove", summary=f"fetch and verify source {desired['url']}")]

    def apply(self, operation: Operation) -> dict[str, Any]:
        args = operation.args
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="nostrhost-source-", dir=self.cache_dir) as temporary:
            archive = Path(temporary) / "source"
            self.downloader(args["url"], archive)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            if digest.lower() != args["sha256"].lower():
                raise ProviderError(f"source hash mismatch: expected {args['sha256']}, got {digest}")
            destination = args.get("destination")
            if destination:
                target = _target(self.root, destination)
                target.mkdir(parents=True, exist_ok=True)
                if args.get("extract", True):
                    self._extract(archive, target)
                else:
                    shutil.copy2(archive, target / "source")
                return {"path": str(target), "verified": True}
            cached = self.cache_dir / hashlib.sha256(args["url"].encode()).hexdigest()
            shutil.copy2(archive, cached)
            return {"path": str(cached), "verified": True}

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        return [Operation("source.remove", desired["url"], {"url": desired["url"]}, reverse="source.fetch", summary="remove cached source")]

    @staticmethod
    def _download(url: str, destination: Path) -> None:
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - packaging provides httpx
            raise ProviderError("httpx is required for native source downloads") from exc
        with httpx.stream("GET", url, follow_redirects=True, timeout=900) as response:
            response.raise_for_status()
            with destination.open("wb") as output:
                for chunk in response.iter_bytes():
                    output.write(chunk)

    @staticmethod
    def _extract(archive: Path, destination: Path) -> None:
        base = destination.resolve()

        def safe_target(name: str) -> Path:
            target = (destination / name).resolve()
            if target != base and base not in target.parents:
                raise ProviderError("archive contains a path traversal entry")
            return target

        if tarfile.is_tarfile(archive):
            with tarfile.open(archive) as tar:
                for member in tar.getmembers():
                    safe_target(member.name)
                    if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                        raise ProviderError("archive contains a link or special file")
                tar.extractall(destination)
        elif zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as archive_file:
                for member in archive_file.infolist():
                    safe_target(member.filename)
                    if stat.S_IFMT(member.external_attr >> 16) != stat.S_IFREG and not member.is_dir():
                        raise ProviderError("archive contains a link or special file")
                archive_file.extractall(destination)
        else:
            raise ProviderError("source is not a supported tar or zip archive")


class ServiceProvider:
    resource_type = "service"

    def __init__(self, *, unit_dir: Path = Path("/etc/systemd/system"), command: Callable[..., Any] | None = None) -> None:
        self.unit_dir = unit_dir
        self.command = command or subprocess.run

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        name = _safe_name(desired.get("name") or "nostrhost-app")
        return {"unit": str(self.unit_dir / f"{name}.service"), "exists": (self.unit_dir / f"{name}.service").is_file()}

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        return [Operation("service.ensure", desired.get("name", "nostrhost-app"), desired, risk="medium", reverse="service.remove", summary="render hardened systemd service")]

    def apply(self, operation: Operation) -> dict[str, Any]:
        args = operation.args
        name = _safe_name(args.get("name") or operation.resource.split(":")[-1])
        action = operation.name.rsplit(".", 1)[-1]
        if action in {"enable", "disable", "start", "stop", "restart"}:
            self.command(["systemctl", action, name], check=True)
            return {"service": name, "action": action, "changed": True}
        self.unit_dir.mkdir(parents=True, exist_ok=True)
        unit = self.render_unit(name, args)
        destination = self.unit_dir / f"{name}.service"
        temporary = destination.with_suffix(".service.tmp")
        temporary.write_text(unit, encoding="utf-8")
        os.chmod(temporary, 0o644)
        temporary.replace(destination)
        return {"unit": str(destination), "changed": True}

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        return [Operation("service.remove", desired.get("name", "nostrhost-app"), {"name": desired.get("name", "nostrhost-app")}, reverse="service.ensure", summary="remove systemd service")]

    @staticmethod
    def render_unit(name: str, args: dict[str, Any]) -> str:
        environment = "\n".join(f'Environment="{key}={value}"' for key, value in sorted(args.get("environment", {}).items()))
        security = args.get("security", {})
        lines = ["[Unit]", f"Description=NostrHost service {name}", "After=network-online.target", "", "[Service]", "Type=simple", f"ExecStart={args['exec']}", f"User={args.get('user') or name}"]
        if args.get("working_directory"):
            lines.append(f"WorkingDirectory={args['working_directory']}")
        lines.extend([f"Restart={args.get('restart', 'on-failure')}", f"PrivateTmp={'yes' if security.get('private_tmp', True) else 'no'}", f"ProtectSystem={security.get('protect_system', 'strict')}", f"ProtectHome={'yes' if security.get('protect_home', True) else 'no'}", f"NoNewPrivileges={'yes' if security.get('no_new_privileges', True) else 'no'}"])
        if environment:
            lines.append(environment)
        for credential, path in sorted(args.get("credentials", {}).items()):
            lines.append(f"LoadCredential={credential}:{path}")
        lines.extend(["", "[Install]", "WantedBy=multi-user.target", ""])
        return "\n".join(lines)


class TimerProvider:
    """Render a systemd service/timer pair and activate it with systemctl."""

    def __init__(self, *, unit_dir: Path = Path("/etc/systemd/system"), command: Callable[..., Any] | None = None) -> None:
        self.unit_dir = unit_dir
        self.command = command or subprocess.run

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        name = _safe_name(desired.get("name", "nostrhost-timer"))
        return {"timer": str(self.unit_dir / f"{name}.timer"), "exists": (self.unit_dir / f"{name}.timer").is_file()}

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        return [Operation("timer.ensure", desired.get("name", "nostrhost-timer"), desired, risk="medium", reverse="timer.remove", summary="render and enable systemd timer")]

    def apply(self, operation: Operation) -> dict[str, Any]:
        args = operation.args
        name = _safe_name(args.get("name") or operation.resource.split(":")[-1])
        self.unit_dir.mkdir(parents=True, exist_ok=True)
        (self.unit_dir / f"{name}.service").write_text(f"[Unit]\nDescription=NostrHost timer action {name}\n\n[Service]\nType=oneshot\nExecStart={args['exec']}\n", encoding="utf-8")
        timer = self.unit_dir / f"{name}.timer"
        timer.write_text(f"[Unit]\nDescription=NostrHost timer {name}\n\n[Timer]\nOnCalendar={args['on_calendar']}\nPersistent={'yes' if args.get('persistent', True) else 'no'}\nUnit={name}.service\n\n[Install]\nWantedBy=timers.target\n", encoding="utf-8")
        self.command(["systemctl", "enable", "--now", f"{name}.timer"], check=True)
        return {"timer": str(timer), "changed": True}

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        name = desired.get("name", "nostrhost-timer")
        return [Operation("timer.remove", name, {"name": name}, risk="medium", reverse="timer.ensure", summary="remove systemd timer")]


class HealthProvider:
    resource_type = "health"

    def __init__(self, *, client: Any = None) -> None:
        self.client = client

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        if self.client is None:
            raise ProviderError("an httpx client is required for native health checks")
        response = self.client.get(desired["path"], timeout=desired.get("timeout", 10))
        return {"status_code": response.status_code, "healthy": response.is_success}

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        return [Operation("health.http.check", desired["path"], desired, reversible=False, summary="check HTTP health endpoint")]

    def apply(self, operation: Operation) -> dict[str, Any]:
        result = self.inspect(operation.args)
        if not result["healthy"]:
            raise ProviderError(f"health check returned HTTP {result['status_code']}")
        return result

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        return []


class JsonStateProvider:
    """Persist typed settings or backup declarations as semantic state."""

    def __init__(self, *, state_dir: Path, resource_type: str) -> None:
        self.state_dir = state_dir
        self.resource_type = resource_type

    def apply(self, operation: Operation) -> dict[str, Any]:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        name = _safe_name(operation.resource.replace(":", "-"))
        target = self.state_dir / f"{name}.json"
        temporary = target.with_suffix(".tmp")
        import json
        temporary.write_text(json.dumps(operation.args, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o640)
        temporary.replace(target)
        return {"state": str(target), "changed": True}


class AptProvider:
    resource_type = "package.apt"

    def __init__(self, *, cache_factory: Callable[[], Any] | None = None) -> None:
        self.cache_factory = cache_factory

    def _cache(self) -> Any:
        if self.cache_factory:
            return self.cache_factory()
        try:
            import apt
        except ImportError as exc:  # pragma: no cover - Debian runtime dependency
            raise ProviderError("python-apt is required for native apt resources") from exc
        return apt.Cache()

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        cache = self._cache()
        packages = desired.get("packages", [desired.get("package")])
        return {"installed": [name for name in packages if name and name in cache and cache[name].is_installed]}

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        packages = desired.get("packages", [desired.get("package")])
        return [Operation("package.apt.ensure", ":".join(packages), {"packages": packages}, risk="medium", reverse="package.apt.remove", summary=f"ensure apt packages {', '.join(packages)}")]

    def apply(self, operation: Operation) -> dict[str, Any]:
        cache = self._cache()
        packages = operation.args["packages"]
        for name in packages:
            if name not in cache:
                raise ProviderError(f"apt package is unavailable: {name}")
            cache[name].mark_install()
        cache.commit()
        return {"packages": packages, "changed": True}

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        packages = desired.get("packages", [desired.get("package")])
        return [Operation("package.apt.remove", ":".join(packages), {"packages": packages}, reverse="package.apt.ensure", summary=f"remove apt packages {', '.join(packages)}")]


class PostgresProvider:
    resource_type = "database"

    def __init__(self, *, connection_factory: Callable[[], Any] | None = None) -> None:
        self.connection_factory = connection_factory

    def _connection(self) -> Any:
        if self.connection_factory:
            return self.connection_factory()
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - optional Debian runtime dependency
            raise ProviderError("psycopg is required for native PostgreSQL resources") from exc
        return psycopg.connect("dbname=postgres", autocommit=True)

    @staticmethod
    def _name(value: str) -> str:
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", value):
            raise ProviderError(f"unsafe PostgreSQL database name: {value!r}")
        return value

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        name = self._name(desired.get("name") or "nostrhost")
        with self._connection() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,))
            return {"name": name, "exists": cursor.fetchone() is not None}

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        name = self._name(desired.get("name") or "nostrhost")
        return [Operation("database.ensure", name, {"type": "postgresql", "name": name, "backup": desired.get("backup", True)}, risk="high", reverse="database.remove", summary=f"ensure PostgreSQL database {name}")]

    def apply(self, operation: Operation) -> dict[str, Any]:
        name = self._name(operation.args["name"])
        with self._connection() as connection, connection.cursor() as cursor:
            cursor.execute(f'CREATE DATABASE "{name}"')
        return {"name": name, "changed": True}

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        name = self._name(desired.get("name") or "nostrhost")
        return [Operation("database.remove", name, {"name": name}, risk="high", reverse="database.ensure", summary=f"remove PostgreSQL database {name}")]


class CaddyProvider:
    resource_type = "web.route"

    def __init__(self, *, client: Any, config_builder: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        self.client = client
        self.config_builder = config_builder

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        response = self.client.get("/config")
        response.raise_for_status()
        return {"config": response.json()}

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        return [Operation("web.route.ensure", desired.get("domain") or desired["upstream"], desired, risk="medium", reverse="web.route.remove", summary="validate and load Caddy JSON configuration")]

    def apply(self, operation: Operation) -> dict[str, Any]:
        config = self.config_builder(operation.args)
        response = self.client.post("/load", json=config)
        response.raise_for_status()
        return {"loaded": True, "domain": operation.args.get("domain")}

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        return [Operation("web.route.remove", desired.get("domain") or desired["upstream"], desired, risk="medium", reverse="web.route.ensure", summary="remove Caddy route")]


class NativeOperationExecutor:
    """Apply only operations backed by registered native providers."""

    def __init__(self, providers: dict[str, Provider]) -> None:
        self.providers = providers

    def provider_for(self, operation: Operation) -> Provider | PackageProvider | None:
        operation_type = operation.name.rsplit(".", 1)[0]
        provider = self.providers.get(operation_type)
        if provider is None and operation.name.startswith("package.apt."):
            provider = self.providers.get("package.apt")
        if provider is None and operation.name.startswith("health.http."):
            provider = self.providers.get("health")
        if provider is None and operation.name == "package.ensure":
            provider = self.providers.get("package")
        return provider

    def can_execute(self, operation: Operation) -> bool:
        return self.provider_for(operation) is not None

    def execute(self, operation: Operation) -> Any:
        provider = self.provider_for(operation)
        if provider is None:
            raise ProviderError(f"no native provider registered for {operation.name}")
        return provider.apply(operation)


def native_providers(*, root: Path = Path("/"), cache_dir: Path = Path("/var/cache/nostrhost/packages"), unit_dir: Path = Path("/etc/systemd/system"), template_root: Path | None = None, command: Callable[..., Any] | None = None, apt_cache_factory: Callable[[], Any] | None = None, postgres_connection_factory: Callable[[], Any] | None = None, caddy_client: Any = None, caddy_config_builder: Callable[[dict[str, Any]], dict[str, Any]] | None = None, health_client: Any = None) -> dict[str, Provider]:
    """Build the default provider set without global state or shell wrappers."""
    providers: dict[str, Provider] = {
        "package": PackageProvider(),
        "directory": TmpfilesProvider(root=root, command=command) if root == Path("/") else DirectoryProvider(root=root),
        "config": ConfigFileProvider(root=root, template_root=template_root),
        "source": SourceProvider(root=root, cache_dir=cache_dir),
        "service": ServiceProvider(unit_dir=unit_dir, command=command),
        "package.apt": AptProvider(cache_factory=apt_cache_factory),
        "database": PostgresProvider(connection_factory=postgres_connection_factory),
        "system_user": SysusersProvider(root=root, command=command),
        "secret": SecretProvider(credential_dir=(root / "var/lib/nostrhost/credentials") if root != Path("/") else Path("/var/lib/nostrhost/credentials")),
        "port": PortProvider(),
        "timer": TimerProvider(unit_dir=unit_dir, command=command),
        "health": HealthProvider(client=health_client),
        "settings": JsonStateProvider(state_dir=(root / "var/lib/nostrhost/state/settings") if root != Path("/") else Path("/var/lib/nostrhost/state/settings"), resource_type="settings"),
        "backup": JsonStateProvider(state_dir=(root / "var/lib/nostrhost/state/backups") if root != Path("/") else Path("/var/lib/nostrhost/state/backups"), resource_type="backup"),
    }
    if caddy_client is not None and caddy_config_builder is not None:
        providers["web.route"] = CaddyProvider(client=caddy_client, config_builder=caddy_config_builder)
    return providers
