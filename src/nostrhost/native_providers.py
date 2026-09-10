"""Native providers for the first executable resource domains.

Providers are deliberately dependency-injected: tests can use a temporary
root and fake download/systemd functions, while production can use the same
bounded implementation with ``/`` as its root.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Callable

from .package_engine import Operation, Provider


class ProviderError(RuntimeError):
    """A native provider could not apply an operation safely."""


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

    def __init__(self, *, root: Path = Path("/")) -> None:
        self.root = root

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
            raise ProviderError("name-to-id ownership resolution is delegated to the user provider")
        return {"path": str(path), "changed": True}

    def verify(self, desired: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(desired)

    def remove(self, desired: dict[str, Any]) -> list[Operation]:
        return [Operation("directory.remove", desired["path"], {"path": desired["path"]}, reverse="directory.ensure", summary=f"remove directory {desired['path']}")]


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
        if tarfile.is_tarfile(archive):
            with tarfile.open(archive) as tar:
                for member in tar.getmembers():
                    target = (destination / member.name).resolve()
                    if not str(target).startswith(str(destination.resolve()) + os.sep):
                        raise ProviderError("archive contains a path traversal entry")
                tar.extractall(destination)
        elif zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as archive_file:
                for member in archive_file.infolist():
                    target = (destination / member.filename).resolve()
                    if not str(target).startswith(str(destination.resolve()) + os.sep):
                        raise ProviderError("archive contains a path traversal entry")
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
        lines.extend(["", "[Install]", "WantedBy=multi-user.target", ""])
        return "\n".join(lines)


class NativeOperationExecutor:
    """Apply only operations backed by registered native providers."""

    def __init__(self, providers: dict[str, Provider]) -> None:
        self.providers = providers

    def execute(self, operation: Operation) -> Any:
        operation_type = operation.name.rsplit(".", 1)[0]
        provider = self.providers.get(operation_type)
        if provider is None:
            raise ProviderError(f"no native provider registered for {operation.name}")
        return provider.apply(operation)


def native_providers(*, root: Path = Path("/"), cache_dir: Path = Path("/var/cache/nostrhost/packages"), unit_dir: Path = Path("/etc/systemd/system"), command: Callable[..., Any] | None = None) -> dict[str, Provider]:
    """Build the default provider set without global state or shell wrappers."""
    return {
        "directory": DirectoryProvider(root=root),
        "source": SourceProvider(root=root, cache_dir=cache_dir),
        "service": ServiceProvider(unit_dir=unit_dir, command=command),
    }
