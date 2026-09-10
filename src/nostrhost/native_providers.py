"""Native providers for the first executable resource domains.

Providers are deliberately dependency-injected: tests can use a temporary
root and fake download/systemd functions, while production can use the same
bounded implementation with ``/`` as its root.
"""

from __future__ import annotations

import hashlib
import json
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
        if operation.name == "directory.remove":
            try:
                path.rmdir()
            except FileNotFoundError:
                return {"path": str(path), "changed": False}
            except OSError as exc:
                raise ProviderError(f"directory is not empty or cannot be removed: {path}") from exc
            return {"path": str(path), "changed": True}
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


class AccessProvider(DirectoryProvider):
    """Apply declared ownership and mode using native stat/chown/chmod APIs."""

    resource_type = "access"

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        path = _target(self.root, desired["path"])
        if not path.exists():
            return {"exists": False, "path": str(path)}
        item = path.stat()
        owner = pwd.getpwuid(item.st_uid).pw_name
        group = grp.getgrgid(item.st_gid).gr_name
        return {"exists": True, "path": str(path), "owner": owner, "group": group, "mode": item.st_mode & 0o7777}

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        return [Operation("access.ensure", desired["path"], desired, reverse="access.remove", summary=f"enforce access policy on {desired['path']}")]

    def apply(self, operation: Operation) -> dict[str, Any]:
        path = _target(self.root, operation.args["path"])
        if operation.name == "access.remove":
            return {"path": str(path), "changed": False}
        if not path.exists():
            raise ProviderError(f"access target does not exist: {path}")
        targets = path.rglob("*") if operation.args.get("recursive") else [path]
        targets = [path, *targets] if operation.args.get("recursive") else [path]
        try:
            uid = pwd.getpwnam(operation.args["owner"]).pw_uid if operation.args.get("owner") else -1
            gid = grp.getgrnam(operation.args["group"]).gr_gid if operation.args.get("group") else -1
        except KeyError as exc:
            raise ProviderError(f"unknown access owner or group: {exc.args[0]}") from exc
        for target in targets:
            os.chmod(target, operation.args["mode"])
            self.chown(target, uid, gid)
        return {"path": str(path), "changed": True, "count": len(targets)}

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        return [Operation("access.remove", desired["path"], desired, reverse="access.ensure", summary=f"remove access policy from {desired['path']}")]


class PermissionProvider:
    """Reconcile an application's Portal/SSO permission without shell helpers."""

    resource_type = "permission"

    def __init__(self, api: Any = None) -> None:
        self.api = api

    def _api(self) -> Any:
        if self.api is None:
            self.api = self._default_api()
        return self.api

    @staticmethod
    def _default_api() -> Any:
        from yunohost.app import app_ssowatconf
        from yunohost.permission import (
            _sync_permissions_with_ldap,
            permission_create,
            permission_delete,
            permission_url,
            user_permission_info,
            user_permission_update,
        )
        from yunohost.app import app_setting

        class Api:
            info = staticmethod(user_permission_info)
            create = staticmethod(permission_create)
            delete = staticmethod(permission_delete)
            url = staticmethod(permission_url)
            update = staticmethod(user_permission_update)

            @staticmethod
            def sync() -> None:
                _sync_permissions_with_ldap()
                app_ssowatconf()

            @staticmethod
            def set_auth_request(name: str, enabled: bool) -> None:
                app, permission = name.split(".", 1)
                settings = app_setting(app, "_permissions") or {}
                settings.setdefault(permission, {})["auth_request"] = enabled
                app_setting(app, "_permissions", settings)

        return Api()

    @staticmethod
    def _permission(desired: dict[str, Any]) -> str:
        app = _safe_name(str(desired.get("app", "")))
        name = _safe_name(str(desired.get("name", "")))
        return f"{app}.{name}"

    @staticmethod
    def _allowed(desired: dict[str, Any]) -> list[str]:
        allowed = desired.get("allowed")
        return sorted([allowed] if isinstance(allowed, str) else list(allowed or []))

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        permission = self._permission(desired)
        try:
            info = dict(self._api().info(permission))
        except Exception:
            return {"permission": permission, "exists": False}
        return {
            "permission": permission,
            "exists": True,
            "url": info.get("url"),
            "additional_urls": sorted(info.get("additional_urls", [])),
            "allowed": sorted(info.get("allowed", [])),
            "auth_header": info.get("auth_header", True),
            "auth_request": info.get("auth_request", False),
            "show_tile": info.get("show_tile", False),
            "protected": info.get("protected", False),
        }

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        permission = self._permission(desired)
        return [Operation("permission.ensure", permission, desired, risk="medium", reverse="permission.remove", summary=f"ensure Portal permission {permission}")]

    def apply(self, operation: Operation) -> dict[str, Any]:
        desired = operation.args
        permission = self._permission(desired)
        if operation.name == "permission.remove":
            self._api().delete(permission, force=True, sync_perm=False)
            self._api().sync()
            return {"permission": permission, "changed": True}

        actual = self.inspect(desired)
        allowed = self._allowed(desired)
        if not actual["exists"]:
            self._api().create(
                permission,
                allowed=allowed,
                url=desired.get("url"),
                additional_urls=desired.get("additional_urls", []),
                auth_header=desired.get("auth_header", True),
                show_tile=desired.get("show_tile"),
                protected=desired.get("protected", False),
                sync_perm=False,
            )
        else:
            current = actual.get("allowed", [])
            self._api().update(
                permission,
                add=[group for group in allowed if group not in current],
                remove=[group for group in current if group not in allowed],
                show_tile=desired.get("show_tile"),
                protected=desired.get("protected", False),
                sync_perm=False,
                log_success_as_debug=True,
            )
            self._api().url(
                permission,
                url=desired.get("url"),
                set_url=desired.get("additional_urls", []),
                auth_header=desired.get("auth_header", True),
                sync_perm=False,
            )
        self._api().set_auth_request(permission, bool(desired.get("auth_request", False)))
        self._api().sync()
        return {"permission": permission, "changed": True}

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        permission = self._permission(desired)
        return [Operation("permission.remove", permission, desired, risk="medium", reverse="permission.ensure", summary=f"remove Portal permission {permission}")]


class ConfigFileProvider:
    """Render declared configuration files with Jinja2 and atomic writes."""

    resource_type = "config"

    def __init__(self, *, root: Path = Path("/"), template_root: Path | None = None, chown: Callable[..., Any] | None = None) -> None:
        self.root = root
        self.template_root = template_root
        self.chown = chown or os.chown

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        target = _target(self.root, desired["destination"])
        result = {"destination": str(target), "exists": target.is_file(), "mode": target.stat().st_mode & 0o7777 if target.exists() else None}
        if target.is_file():
            result["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
        if desired.get("content") is not None:
            result["desired_sha256"] = hashlib.sha256(desired["content"].encode()).hexdigest()
        return result

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
            template_root = Path(args.get("_template_root")) if args.get("_template_root") else self.template_root
            if template_root is None:
                raise ProviderError("a template root is required for template-backed config")
            import jinja2

            name = self._template_name(args["template"])
            template_path = (template_root / name).resolve()
            if not str(template_path).startswith(str(template_root.resolve()) + os.sep):
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
        if operation.name == "system_user.remove":
            definition = self.definition_dir / f"nostrhost-{name}.conf"
            definition.unlink(missing_ok=True)
            return {"name": name, "definition": str(definition), "changed": True}
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
        if operation.name == "secret.remove":
            target.unlink(missing_ok=True)
            return {"name": name, "credential": str(target), "changed": True}
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
        result = {"exists": path.exists(), "path": str(path)}
        if path.is_file():
            result["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        if destination:
            provenance = path / ".nostrhost-source.json"
            if provenance.is_file():
                try:
                    result.update(json.loads(provenance.read_text(encoding="utf-8")))
                except (OSError, json.JSONDecodeError):
                    result["provenance_valid"] = False
        return result

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        return [Operation("source.fetch", desired["url"], desired, risk="medium", reverse="source.remove", summary=f"fetch and verify source {desired['url']}")]

    def apply(self, operation: Operation) -> dict[str, Any]:
        args = operation.args
        if operation.name == "source.remove":
            cached = self.cache_dir / hashlib.sha256(args["url"].encode()).hexdigest()
            cached.unlink(missing_ok=True)
            return {"path": str(cached), "changed": True}
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
                (target / ".nostrhost-source.json").write_text(json.dumps({"url": args["url"], "sha256": args["sha256"]}, sort_keys=True) + "\n", encoding="utf-8")
                return {"path": str(target), "verified": True}
            cached = self.cache_dir / hashlib.sha256(args["url"].encode()).hexdigest()
            shutil.copy2(archive, cached)
            return {"path": str(cached), "verified": True}

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        return [Operation("source.remove", desired["url"], {"url": desired["url"], "destination": desired.get("destination")}, reverse="source.fetch", summary="remove cached source")]

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


class RuntimeProvider:
    """Validate a declared runtime through its version command.

    Installation is intentionally not hidden behind a provider. Runtime
    packages are selected by the host policy (usually an apt resource); this
    provider verifies that the requested executable is actually available.
    """

    resource_type = "runtime"
    executables = {"node": "node", "python": "python3", "go": "go", "composer": "composer"}

    def __init__(self, *, command: Callable[..., Any] | None = None, executable_lookup: Callable[[str], str | None] | None = None) -> None:
        self.command = command or subprocess.run
        self.executable_lookup = executable_lookup or shutil.which

    def _executable(self, runtime_type: str) -> str:
        try:
            name = self.executables[runtime_type]
        except KeyError as exc:
            raise ProviderError(f"unsupported runtime: {runtime_type}") from exc
        executable = self.executable_lookup(name)
        if not executable:
            raise ProviderError(f"runtime executable is not installed: {name}")
        return executable

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        executable = self._executable(desired["type"])
        result = self.command([executable, "--version"], check=True, capture_output=True, text=True)
        output = f"{result.stdout}\n{result.stderr}".strip()
        requested = desired["version"].lstrip("v")
        versions = re.findall(r"(?<![\d.])\d+(?:\.\d+)*", output)
        detected = next((version for version in versions if version == requested or version.startswith(f"{requested}.")), None)
        return {"type": desired["type"], "executable": executable, "version": detected or (versions[0] if versions else None), "matches": detected is not None}

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        return [Operation("runtime.ensure", desired["type"], desired, risk="medium", reverse="runtime.remove", summary=f"validate {desired['type']} runtime {desired['version']}")]

    def apply(self, operation: Operation) -> dict[str, Any]:
        result = self.inspect(operation.args)
        if not result["matches"]:
            raise ProviderError(f"runtime version mismatch: requested {operation.args['version']}, detected {result['version']}")
        result["changed"] = False
        return result

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        return []


class ServiceProvider:
    resource_type = "service"

    def __init__(self, *, unit_dir: Path = Path("/etc/systemd/system"), command: Callable[..., Any] | None = None) -> None:
        self.unit_dir = unit_dir
        self.command = command or subprocess.run

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        name = _safe_name(desired.get("name") or "nostrhost-app")
        unit = self.unit_dir / f"{name}.service"
        result = {"unit": str(unit), "exists": unit.is_file()}
        if unit.is_file():
            result["sha256"] = hashlib.sha256(unit.read_bytes()).hexdigest()
            result["desired_sha256"] = hashlib.sha256(self.render_unit(name, desired).encode()).hexdigest()
        return result

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        return [Operation("service.ensure", desired.get("name", "nostrhost-app"), desired, risk="medium", reverse="service.remove", summary="render hardened systemd service")]

    def apply(self, operation: Operation) -> dict[str, Any]:
        args = operation.args
        name = _safe_name(args.get("name") or operation.resource.split(":")[-1])
        action = operation.name.rsplit(".", 1)[-1]
        if action in {"enable", "disable", "start", "stop", "restart"}:
            self.command(["systemctl", action, name], check=True)
            return {"service": name, "action": action, "changed": True}
        if action == "remove":
            destination = self.unit_dir / f"{name}.service"
            destination.unlink(missing_ok=True)
            self.command(["systemctl", "daemon-reload"], check=True)
            return {"unit": str(destination), "changed": True}
        self.unit_dir.mkdir(parents=True, exist_ok=True)
        unit = self.render_unit(name, args)
        destination = self.unit_dir / f"{name}.service"
        temporary = destination.with_suffix(".service.tmp")
        temporary.write_text(unit, encoding="utf-8")
        os.chmod(temporary, 0o644)
        temporary.replace(destination)
        self.command(["systemctl", "daemon-reload"], check=True)
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
        if operation.name == "timer.remove":
            self.command(["systemctl", "disable", "--now", f"{name}.timer"], check=True)
            for suffix in (".timer", ".service"):
                (self.unit_dir / f"{name}{suffix}").unlink(missing_ok=True)
            return {"timer": str(self.unit_dir / f"{name}.timer"), "changed": True}
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
        attempts = desired.get("retries", 0) + 1
        last_status = None
        last_error = None
        for attempt in range(attempts):
            try:
                response = self.client.get(desired["path"], timeout=desired.get("timeout", 10))
            except Exception as exc:
                last_error = str(exc) or exc.__class__.__name__
                continue
            last_status = response.status_code
            if response.is_success:
                return {"status_code": response.status_code, "healthy": True, "attempts": attempt + 1}
        result = {"status_code": last_status, "healthy": False, "attempts": attempts}
        if last_error:
            result["error"] = last_error
        return result

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        return [Operation("health.http.check", desired["path"], desired, reversible=False, summary="check HTTP health endpoint")]

    def apply(self, operation: Operation) -> dict[str, Any]:
        result = self.inspect(operation.args)
        if not result["healthy"]:
            detail = result.get("error") or f"HTTP {result['status_code']}"
            raise ProviderError(f"health check failed after {result['attempts']} attempt(s): {detail}")
        return result

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        return []


class PolicyProvider:
    """Render host policy snippets without invoking policy-manager shells."""

    resource_type = "policy"
    directories = {"fail2ban": Path("/etc/fail2ban/jail.d"), "logrotate": Path("/etc/logrotate.d")}

    def __init__(self, *, root: Path = Path("/")) -> None:
        self.root = root

    def _target(self, args: dict[str, Any]) -> Path:
        try:
            directory = self.directories[args["type"]]
        except KeyError as exc:
            raise ProviderError(f"unsupported policy type: {args.get('type')}") from exc
        return _target(self.root, directory) / f"nostrhost-{_safe_name(args['name'])}{'.local' if args['type'] == 'fail2ban' else ''}"

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        target = self._target(desired)
        return {"path": str(target), "exists": target.is_file(), "sha256": hashlib.sha256(target.read_bytes()).hexdigest() if target.is_file() else None}

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        return [Operation("policy.ensure", desired["name"], desired, risk="medium", reverse="policy.remove", summary=f"install {desired['type']} policy")]

    def apply(self, operation: Operation) -> dict[str, Any]:
        target = self._target(operation.args)
        if operation.name == "policy.remove":
            target.unlink(missing_ok=True)
            return {"path": str(target), "changed": True}
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(operation.args["content"], encoding="utf-8")
        os.chmod(temporary, 0o640)
        temporary.replace(target)
        return {"path": str(target), "changed": True}

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        return [Operation("policy.remove", desired["name"], desired, reverse="policy.ensure", summary="remove host policy")]


class JsonStateProvider:
    """Persist typed settings or backup declarations as semantic state."""

    def __init__(self, *, state_dir: Path, resource_type: str) -> None:
        self.state_dir = state_dir
        self.resource_type = resource_type

    def _target(self, operation: Operation) -> Path:
        name = _safe_name(operation.resource.replace(":", "-"))
        return self.state_dir / f"{name}.json"

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        resource = desired.get("resource", self.resource_type)
        name = _safe_name(str(desired.get("name", resource)).replace(":", "-"))
        target = self.state_dir / f"{name}.json"
        return {"state": str(target), "exists": target.is_file()}

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        return [Operation(f"{self.resource_type}.register", desired["name"], desired, reverse=f"{self.resource_type}.unregister", summary=f"register {self.resource_type} state")]

    def apply(self, operation: Operation) -> dict[str, Any]:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        target = self._target(operation)
        if operation.name.endswith(".unregister") or operation.name.endswith(".remove"):
            target.unlink(missing_ok=True)
            return {"state": str(target), "changed": True}
        temporary = target.with_suffix(".tmp")
        temporary.write_text(json.dumps(operation.args, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o640)
        temporary.replace(target)
        return {"state": str(target), "changed": True}

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        return [Operation(f"{self.resource_type}.unregister", desired["name"], desired, reverse=f"{self.resource_type}.register", summary=f"unregister {self.resource_type} state")]


class BackupProvider(JsonStateProvider):
    """Register backup inputs without owning the Restic data plane."""

    resource_type = "backup"

    def __init__(self, *, state_dir: Path) -> None:
        super().__init__(state_dir=state_dir, resource_type="backup")

    def apply(self, operation: Operation) -> dict[str, Any]:
        if not operation.name.endswith(".unregister"):
            paths = operation.args.get("paths", [])
            if any(not Path(path).is_absolute() or ".." in Path(path).parts for path in paths):
                raise ProviderError("backup paths must be absolute and cannot contain '..'")
            operation = Operation(operation.name, operation.resource, {**operation.args, "format": "nostrhost-backup-v1"}, operation.depends_on, operation.risk, operation.reversible, operation.reverse, operation.summary)
        return super().apply(operation)


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
            if operation.name == "database.remove":
                cursor.execute(f'DROP DATABASE IF EXISTS "{name}"')
                return {"name": name, "changed": True}
            cursor.execute(f'CREATE DATABASE "{name}"')
        return {"name": name, "changed": True}

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        name = self._name(desired.get("name") or "nostrhost")
        return [Operation("database.remove", name, {"name": name}, risk="high", reverse="database.ensure", summary=f"remove PostgreSQL database {name}")]


class MySQLProvider(PostgresProvider):
    """Native MySQL/MariaDB database provider using a DB-API driver."""

    def _connection(self) -> Any:
        if self.connection_factory:
            return self.connection_factory()
        try:
            import pymysql
        except ImportError as exc:  # pragma: no cover - optional Debian runtime dependency
            raise ProviderError("PyMySQL is required for native MySQL resources") from exc
        return pymysql.connect(database="mysql", autocommit=True)

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        name = self._name(desired.get("name") or "nostrhost")
        with self._connection() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = %s", (name,))
            return {"name": name, "exists": cursor.fetchone() is not None}

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        name = self._name(desired.get("name") or "nostrhost")
        return [Operation("database.ensure", name, {"type": "mysql", "name": name, "backup": desired.get("backup", True)}, risk="high", reverse="database.remove", summary=f"ensure MySQL database {name}")]

    def apply(self, operation: Operation) -> dict[str, Any]:
        name = self._name(operation.args["name"])
        with self._connection() as connection, connection.cursor() as cursor:
            if operation.name == "database.remove":
                cursor.execute(f"DROP DATABASE IF EXISTS `{name}`")
                return {"name": name, "changed": True}
            cursor.execute(f"CREATE DATABASE `{name}`")
        return {"name": name, "changed": True}


class DatabaseProvider:
    """Dispatch database resources to their explicitly selected DB-API driver."""

    resource_type = "database"

    def __init__(self, *, postgres_connection_factory: Callable[[], Any] | None = None, mysql_connection_factory: Callable[[], Any] | None = None) -> None:
        self.providers = {
            "postgresql": PostgresProvider(connection_factory=postgres_connection_factory),
            "mysql": MySQLProvider(connection_factory=mysql_connection_factory),
        }

    def _provider(self, desired: dict[str, Any]) -> PostgresProvider | MySQLProvider:
        try:
            return self.providers[desired["type"]]
        except KeyError as exc:
            raise ProviderError(f"unsupported database type: {desired.get('type')}") from exc

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        return self._provider(desired).inspect(desired, actual)

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        return self._provider(desired).plan(desired, actual)

    def apply(self, operation: Operation) -> dict[str, Any]:
        return self._provider(operation.args).apply(operation)

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        return self._provider(desired).remove(desired)


class CaddyProvider:
    resource_type = "web.route"

    def __init__(self, *, client: Any, config_builder: Callable[[dict[str, Any]], dict[str, Any]], remove_config_builder: Callable[[dict[str, Any]], dict[str, Any]] | None = None) -> None:
        self.client = client
        self.config_builder = config_builder
        self.remove_config_builder = remove_config_builder

    def inspect(self, desired: dict[str, Any], actual: Any = None) -> dict[str, Any]:
        response = self.client.get("/config")
        response.raise_for_status()
        return {"config": response.json()}

    def plan(self, desired: dict[str, Any], actual: Any = None) -> list[Operation]:
        return [Operation("web.route.ensure", desired.get("domain") or desired["upstream"], desired, risk="medium", reverse="web.route.remove", summary="validate and load Caddy JSON configuration")]

    def apply(self, operation: Operation) -> dict[str, Any]:
        if operation.name == "web.route.remove":
            if self.remove_config_builder is None:
                raise ProviderError("a Caddy route removal builder is required for native removal")
            config = self.remove_config_builder(operation.args)
        else:
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


def native_providers(*, root: Path = Path("/"), cache_dir: Path = Path("/var/cache/nostrhost/packages"), unit_dir: Path = Path("/etc/systemd/system"), template_root: Path | None = None, command: Callable[..., Any] | None = None, apt_cache_factory: Callable[[], Any] | None = None, postgres_connection_factory: Callable[[], Any] | None = None, mysql_connection_factory: Callable[[], Any] | None = None, caddy_client: Any = None, caddy_config_builder: Callable[[dict[str, Any]], dict[str, Any]] | None = None, caddy_remove_config_builder: Callable[[dict[str, Any]], dict[str, Any]] | None = None, health_client: Any = None) -> dict[str, Provider]:
    """Build the default provider set without global state or shell wrappers."""
    providers: dict[str, Provider] = {
        "package": PackageProvider(),
        "directory": TmpfilesProvider(root=root, command=command) if root == Path("/") else DirectoryProvider(root=root),
        "access": AccessProvider(root=root),
        "permission": PermissionProvider(),
        "config": ConfigFileProvider(root=root, template_root=template_root),
        "source": SourceProvider(root=root, cache_dir=cache_dir),
        "runtime": RuntimeProvider(command=command),
        "service": ServiceProvider(unit_dir=unit_dir, command=command),
        "package.apt": AptProvider(cache_factory=apt_cache_factory),
        "database": DatabaseProvider(postgres_connection_factory=postgres_connection_factory, mysql_connection_factory=mysql_connection_factory),
        "system_user": SysusersProvider(root=root, command=command),
        "secret": SecretProvider(credential_dir=(root / "var/lib/nostrhost/credentials") if root != Path("/") else Path("/var/lib/nostrhost/credentials")),
        "port": PortProvider(),
        "timer": TimerProvider(unit_dir=unit_dir, command=command),
        "health": HealthProvider(client=health_client),
        "policy": PolicyProvider(root=root),
        "settings": JsonStateProvider(state_dir=(root / "var/lib/nostrhost/state/settings") if root != Path("/") else Path("/var/lib/nostrhost/state/settings"), resource_type="settings"),
        "backup": BackupProvider(state_dir=(root / "var/lib/nostrhost/state/backups") if root != Path("/") else Path("/var/lib/nostrhost/state/backups")),
    }
    if caddy_client is not None and caddy_config_builder is not None:
        providers["web.route"] = CaddyProvider(client=caddy_client, config_builder=caddy_config_builder, remove_config_builder=caddy_remove_config_builder)
    return providers
