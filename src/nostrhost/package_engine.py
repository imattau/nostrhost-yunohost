"""Typed, declarative package planning for NostrHost.

This module deliberately stops at planning.  Providers describe the bounded
operations that a future privileged executor may apply; parsing a package
never mutates the host.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar, Literal, Protocol

try:  # Keep the package stable on both the declared v1 and transitional v2 hosts.
    from pydantic.v1 import BaseModel, Field, validator
except ImportError:  # pragma: no cover - exercised on Pydantic v1 installations
    from pydantic import BaseModel, Field, validator


class PackageError(ValueError):
    """A package is syntactically or semantically invalid."""


class AppResource(BaseModel):
    id: str = Field(..., min_length=1)
    version: str = Field(..., min_length=1)

    @validator("id")
    def valid_id(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", value):
            raise ValueError("app id must be a lowercase name")
        return value


class SourceResource(BaseModel):
    id: str = "main"
    url: str = Field(..., min_length=1)
    sha256: str = Field(..., min_length=64, max_length=64)
    extract: bool = True
    destination: Path | None = None

    @validator("sha256")
    def valid_hash(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise ValueError("sha256 must be a 64-character hexadecimal digest")
        return value


class PackagesResource(BaseModel):
    apt: list[str] = Field(default_factory=list)

    @validator("apt")
    def valid_names(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)) or any(not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", p) for p in value):
            raise ValueError("apt package names must be unique Debian package names")
        return value


class UserResource(BaseModel):
    name: str | None = None
    system: bool = True
    description: str = ""
    home: Path | None = None


class DirectoryResource(BaseModel):
    path: Path
    owner: str | None = None
    group: str | None = None
    mode: int = Field(0o750, ge=0, le=0o7777)
    backup: bool = False

    @validator("path")
    def absolute_path(cls, value: Path) -> Path:
        if not value.is_absolute() or ".." in PurePosixPath(value).parts:
            raise ValueError("directory paths must be absolute and cannot contain '..'")
        return value


class RuntimeResource(BaseModel):
    type: Literal["node", "python", "go", "composer"]
    version: str = Field(..., min_length=1)


class DatabaseResource(BaseModel):
    type: Literal["postgresql", "mysql"]
    name: str | None = None
    backup: bool = True


class ServiceSecurity(BaseModel):
    private_tmp: bool = True
    protect_system: Literal["strict", "full", "yes", "no"] = "strict"
    protect_home: bool = True
    no_new_privileges: bool = True


class ServiceResource(BaseModel):
    name: str | None = None
    exec: str = Field(..., min_length=1)
    user: str | None = None
    working_directory: Path | None = None
    restart: Literal["no", "on-failure", "always"] = "on-failure"
    environment: dict[str, str] = Field(default_factory=dict)
    security: ServiceSecurity = Field(default_factory=ServiceSecurity)


class WebResource(BaseModel):
    domain: str | None = None
    upstream: str = Field(..., min_length=1)
    auth: Literal["none", "nostrhost"] = "none"
    https: Literal["automatic", "required", "disabled"] = "automatic"


class HealthResource(BaseModel):
    type: Literal["http"] = "http"
    path: str = "/health"
    timeout: int = Field(10, gt=0, le=300)


class BackupResource(BaseModel):
    paths: list[Path] = Field(default_factory=list)
    database: bool = False


class SettingResource(BaseModel):
    values: dict[str, Any] = Field(default_factory=dict)


class SecretResource(BaseModel):
    generate: Literal["password", "random"] = "random"
    length: int = Field(32, gt=0, le=4096)


class HookResource(BaseModel):
    python: str | None = None
    legacy: str | None = None

    @validator("python")
    def python_reference(cls, value: str | None) -> str | None:
        if value and (":" not in value or value.startswith("/") or ".." in PurePosixPath(value.split(":", 1)[0]).parts):
            raise ValueError("Python hooks must use a relative module:function reference")
        return value

    @validator("legacy")
    def legacy_reference(cls, value: str | None) -> str | None:
        if value and (value.startswith("/") or ".." in PurePosixPath(value).parts):
            raise ValueError("legacy hooks must use a relative script path")
        return value


class PackageManifest(BaseModel):
    app: AppResource
    sources: dict[str, SourceResource] = Field(default_factory=dict, alias="source")
    runtime: RuntimeResource | None = None
    packages: PackagesResource = Field(default_factory=PackagesResource)
    user: UserResource | None = None
    directories: dict[str, DirectoryResource] = Field(default_factory=dict)
    database: DatabaseResource | None = None
    service: ServiceResource | None = None
    web: WebResource | None = None
    health: HealthResource | None = None
    backup: BackupResource | None = None
    settings: SettingResource = Field(default_factory=SettingResource)
    secrets: dict[str, SecretResource] = Field(default_factory=dict)
    hooks: dict[str, HookResource] = Field(default_factory=dict)

    @validator("sources", "directories", "secrets", "hooks")
    def unique_ids(cls, value: dict[str, Any]) -> dict[str, Any]:
        if any(not re.fullmatch(r"[a-z][a-z0-9_-]*", key) for key in value):
            raise ValueError("resource identifiers must be lowercase names")
        return value

    @validator("service")
    def service_user(cls, value: ServiceResource | None, values: dict[str, Any]) -> ServiceResource | None:
        if value and value.user and values.get("user") and value.user != values["user"].name:
            raise ValueError("service.user must match the declared system user")
        return value

    class Config:
        extra = "forbid"
        allow_population_by_field_name = True


@dataclass(frozen=True)
class Operation:
    """Executor-neutral operation envelope."""

    name: str
    resource: str
    args: dict[str, Any]
    depends_on: tuple[str, ...] = ()
    risk: Literal["low", "medium", "high"] = "low"
    reversible: bool = True
    reverse: str | None = None
    summary: str = ""

    def json_dict(self) -> dict[str, Any]:
        return asdict(self) | {"depends_on": list(self.depends_on)}


class Provider(Protocol):
    resource_type: ClassVar[str]

    def inspect(self, desired: Any, actual: Any = None) -> Any: ...
    def plan(self, desired: Any, actual: Any = None) -> list[Operation]: ...
    def apply(self, operation: Operation) -> Any: ...
    def verify(self, desired: Any) -> Any: ...
    def remove(self, desired: Any) -> list[Operation]: ...


def _op(name: str, resource: str, args: dict[str, Any], *, deps: tuple[str, ...] = (), risk: Literal["low", "medium", "high"] = "low", reverse: str | None = None, summary: str = "", reversible: bool | None = None) -> Operation:
    return Operation(name, resource, args, deps, risk, reverse is not None if reversible is None else reversible, reverse, summary)


def plan_package(package: PackageManifest) -> list[Operation]:
    """Create a stable install plan from desired state only."""
    app = package.app.id
    plan: list[Operation] = []
    package_op = _op("package.ensure", app, {"id": app, "version": package.app.version}, reverse="package.remove", summary=f"register package {app}")
    plan.append(package_op)
    for name in package.packages.apt:
        plan.append(_op("package.apt.ensure", f"{app}:apt:{name}", {"package": name}, deps=(package_op.resource,), risk="medium", reverse="package.apt.remove", summary=f"ensure apt package {name}"))
    user_op: Operation | None = None
    if package.user:
        user = package.user.name or app
        user_op = _op("system_user.ensure", f"{app}:user", {"name": user, "system": package.user.system, "home": str(package.user.home) if package.user.home else None}, deps=(package_op.resource,), reverse="system_user.remove", summary=f"ensure system user {user}")
        plan.append(user_op)
    for name, directory in package.directories.items():
        deps = (user_op.resource,) if user_op else (package_op.resource,)
        plan.append(_op("directory.ensure", f"{app}:directory:{name}", {"path": str(directory.path), "owner": directory.owner or (package.user.name if package.user else None), "group": directory.group, "mode": directory.mode, "backup": directory.backup}, deps=deps, reverse="directory.remove", summary=f"ensure directory {directory.path}"))
    for name, source in package.sources.items():
        plan.append(_op("source.fetch", f"{app}:source:{name}", {"url": source.url, "sha256": source.sha256, "extract": source.extract, "destination": str(source.destination) if source.destination else None}, deps=(package_op.resource,), risk="medium", reverse="source.remove", summary=f"fetch and verify source {name}"))
    if package.runtime:
        plan.append(_op("runtime.ensure", f"{app}:runtime", package.runtime.dict(), deps=(package_op.resource,), risk="medium", reverse="runtime.remove", summary=f"ensure {package.runtime.type} {package.runtime.version}"))
    if package.database:
        plan.append(_op("database.ensure", f"{app}:database", package.database.dict(), deps=(package_op.resource,), risk="high", reverse="database.remove", summary=f"ensure {package.database.type} database"))
    if package.service:
        deps = tuple(op.resource for op in plan if op.resource.startswith((f"{app}:directory:", f"{app}:source:")))
        deps += tuple(resource for resource in (f"{app}:runtime", f"{app}:database") if any(op.resource == resource for op in plan))
        deps = deps or (package_op.resource,)
        service = package.service.dict()
        service["user"] = service.get("user") or (package.user.name if package.user else app)
        plan.append(_op("service.ensure", f"{app}:service", service, deps=deps, risk="medium", reverse="service.remove", summary=f"render service {package.service.name or app}"))
        plan.append(_op("service.enable", f"{app}:service:enable", {"name": package.service.name or app}, deps=(f"{app}:service",), reverse="service.disable", summary="enable service"))
        plan.append(_op("service.start", f"{app}:service:start", {"name": package.service.name or app}, deps=(f"{app}:service:enable",), risk="medium", reverse="service.stop", summary="start service"))
    if package.web:
        deps = (f"{app}:service:start",) if package.service else (package_op.resource,)
        plan.append(_op("web.route.ensure", f"{app}:web", package.web.dict(), deps=deps, risk="medium", reverse="web.route.remove", summary="ensure web route"))
    if package.health:
        deps = (f"{app}:web",) if package.web else ((f"{app}:service:start",) if package.service else (package_op.resource,))
        plan.append(_op("health.http.check", f"{app}:health", package.health.dict(), deps=deps, risk="low", reversible=False, summary="check application health"))
    if package.settings.values:
        plan.append(_op("settings.ensure", f"{app}:settings", {"values": package.settings.values}, deps=(package_op.resource,), summary="ensure typed application settings"))
    for name, secret in package.secrets.items():
        plan.append(_op("secret.ensure", f"{app}:secret:{name}", {"name": name, "generate": secret.generate, "length": secret.length}, deps=(package_op.resource,), risk="high", reverse="secret.remove", summary=f"ensure secret {name}"))
    if package.backup:
        plan.append(_op("backup.register", f"{app}:backup", {"paths": [str(path) for path in package.backup.paths], "database": package.backup.database}, deps=(package_op.resource,), summary="register backup resources"))
    for name, hook in package.hooks.items():
        operation = "hook.python.ensure" if hook.python else "hook.legacy.ensure"
        plan.append(_op(operation, f"{app}:hook:{name}", {"reference": hook.python or hook.legacy}, deps=(package_op.resource,), risk="high" if hook.legacy else "medium", reversible=False, summary=f"register {name} hook"))
    return plan


def load_package(path: Path) -> PackageManifest:
    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
        return PackageManifest.parse_obj(raw)
    except (OSError, tomllib.TOMLDecodeError, ValueError) as exc:
        raise PackageError(f"invalid package {path}: {exc}") from exc


def schema() -> dict[str, Any]:
    return PackageManifest.schema()


def migrate_manifest(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert the supported v2 resource vocabulary to native package.toml."""
    resources = raw.get("resources", {})
    app_id = raw.get("id", "app")
    out: dict[str, Any] = {"app": {"id": app_id, "version": raw.get("version", "0")}}
    if resources.get("apt", {}).get("packages"):
        out["packages"] = {"apt": resources["apt"]["packages"]}
    if resources.get("sources"):
        out["source"] = {key: {k: v for k, v in value.items() if k in {"url", "sha256", "extract"}} for key, value in resources["sources"].items()}
    if resources.get("system_user"):
        out["user"] = {"name": resources["system_user"].get("username", app_id), "system": True}
    if resources.get("install_dir"):
        out.setdefault("directories", {})["install"] = {"path": resources["install_dir"].get("path", f"/var/www/{app_id}")}
    if resources.get("data_dir"):
        out.setdefault("directories", {})["data"] = {"path": resources["data_dir"].get("path", f"/var/lib/{app_id}"), "backup": True}
    return out


def migrate_manifest_file(source: Path, destination: Path) -> None:
    with source.open("rb") as stream:
        raw = tomllib.load(stream)
    converted = migrate_manifest(raw)
    scripts = source.parent / "scripts"
    for name in ("install", "upgrade", "remove", "backup", "restore"):
        if (scripts / name).is_file():
            converted.setdefault("hooks", {})[name] = {"legacy": f"scripts/{name}"}
    destination.write_text(_toml_dump(converted), encoding="utf-8")


def _toml_dump(value: dict[str, Any]) -> str:
    """Small deterministic TOML writer for migration output."""
    lines: list[str] = []
    def emit(table: str, data: dict[str, Any]) -> None:
        if table:
            lines.append(f"[{table}]")
        for key, item in data.items():
            if isinstance(item, dict):
                continue
            lines.append(f"{key} = {json.dumps(item, default=str)}")
        for key, item in data.items():
            if isinstance(item, dict):
                emit(f"{table}.{key}" if table else key, item)
    emit("", value)
    return "\n".join(lines) + "\n"
