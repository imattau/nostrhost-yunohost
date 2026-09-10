"""Typed, declarative package planning for NostrHost.

This module deliberately stops at planning.  Providers describe the bounded
operations that a future privileged executor may apply; parsing a package
never mutates the host.
"""

from __future__ import annotations

import json
import hashlib
import re
import socket
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar, Literal, Protocol

try:  # Keep the package stable on both the declared v1 and transitional v2 hosts.
    from pydantic.v1 import BaseModel, Field, root_validator, validator
except ImportError:  # pragma: no cover - exercised on Pydantic v1 installations
    from pydantic import BaseModel, Field, root_validator, validator


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


class PortsResource(BaseModel):
    named: dict[str, int] = Field(default_factory=dict)

    @validator("named")
    def valid_ports(cls, value: dict[str, int]) -> dict[str, int]:
        if len(value) != len(set(value.values())) or any(not 1 <= port <= 65535 for port in value.values()):
            raise ValueError("ports must be unique integers between 1 and 65535")
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


class AccessResource(BaseModel):
    path: Path
    owner: str | None = None
    group: str | None = None
    mode: int = Field(0o750, ge=0, le=0o7777)
    recursive: bool = False

    @validator("path")
    def absolute_path(cls, value: Path) -> Path:
        if not value.is_absolute() or ".." in PurePosixPath(value).parts:
            raise ValueError("access paths must be absolute and cannot contain '..'")
        return value

    @root_validator
    def has_owner_or_group(cls, values: dict[str, Any]) -> dict[str, Any]:
        if not (values.get("owner") or values.get("group")):
            raise ValueError("access resources require an owner or group")
        return values


class ConfigFileResource(BaseModel):
    destination: Path
    content: str | None = None
    template: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    mode: int = Field(0o640, ge=0, le=0o7777)
    owner: str | None = None
    group: str | None = None

    @validator("destination")
    def absolute_destination(cls, value: Path) -> Path:
        if not value.is_absolute() or ".." in PurePosixPath(value).parts:
            raise ValueError("config destinations must be absolute and cannot contain '..'")
        return value

    @root_validator
    def valid_source(cls, values: dict[str, Any]) -> dict[str, Any]:
        content = values.get("content")
        template = values.get("template")
        if (content is None) == (template is None):
            raise ValueError("config file requires exactly one of content or template")
        if template and (template.startswith("/") or ".." in PurePosixPath(template).parts):
            raise ValueError("config templates must be relative and cannot contain '..'")
        if content is None and template is None:
            raise ValueError("config file requires content or template")
        return values


class RuntimeResource(BaseModel):
    type: Literal["node", "python", "go", "composer"]
    version: str = Field(..., min_length=1)
    prefix: Path | None = None

    @validator("prefix")
    def absolute_prefix(cls, value: Path | None) -> Path | None:
        if value is not None and (not value.is_absolute() or ".." in PurePosixPath(value).parts):
            raise ValueError("runtime prefixes must be absolute and cannot contain '..'")
        return value


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
    retries: int = Field(0, ge=0, le=5)


class TimerResource(BaseModel):
    on_calendar: str = Field(..., min_length=1)
    exec: str = Field(..., min_length=1)
    persistent: bool = True


class BackupResource(BaseModel):
    paths: list[Path] = Field(default_factory=list)
    database: bool = False


class PolicyResource(BaseModel):
    type: Literal["fail2ban", "logrotate"]
    name: str = Field(..., min_length=1)
    content: str = Field(..., min_length=1)

    @validator("name")
    def safe_name(cls, value: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", value):
            raise ValueError("policy name must be a safe filename")
        return value


class SettingResource(BaseModel):
    values: dict[str, Any] = Field(default_factory=dict)


class SecretResource(BaseModel):
    generate: Literal["password", "random"] = "random"
    length: int = Field(32, gt=0, le=4096)


class HookResource(BaseModel):
    python: str = Field(..., min_length=1)

    @validator("python")
    def python_reference(cls, value: str | None) -> str | None:
        if value and (":" not in value or value.startswith("/") or ".." in PurePosixPath(value.split(":", 1)[0]).parts):
            raise ValueError("Python hooks must use a relative module:function reference")
        return value

class PackageManifest(BaseModel):
    app: AppResource
    sources: dict[str, SourceResource] = Field(default_factory=dict, alias="source")
    runtime: RuntimeResource | None = None
    packages: PackagesResource = Field(default_factory=PackagesResource)
    ports: PortsResource = Field(default_factory=PortsResource)
    user: UserResource | None = None
    directories: dict[str, DirectoryResource] = Field(default_factory=dict)
    permissions: dict[str, AccessResource] = Field(default_factory=dict)
    config: dict[str, ConfigFileResource] = Field(default_factory=dict)
    database: DatabaseResource | None = None
    service: ServiceResource | None = None
    web: WebResource | None = None
    health: HealthResource | None = None
    timer: TimerResource | None = None
    backup: BackupResource | None = None
    policies: dict[str, PolicyResource] = Field(default_factory=dict)
    settings: SettingResource = Field(default_factory=SettingResource)
    secrets: dict[str, SecretResource] = Field(default_factory=dict)
    hooks: dict[str, HookResource] = Field(default_factory=dict)

    @validator("sources", "directories", "permissions", "config", "secrets", "hooks", "policies")
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


def plan_package(package: PackageManifest, *, template_root: Path | None = None) -> list[Operation]:
    """Create a stable install plan from desired state only."""
    app = package.app.id
    plan: list[Operation] = []
    package_op = _op("package.ensure", app, {"id": app, "version": package.app.version}, reverse="package.remove", summary=f"register package {app}")
    plan.append(package_op)
    for name in package.packages.apt:
        plan.append(_op("package.apt.ensure", f"{app}:apt:{name}", {"package": name}, deps=(package_op.resource,), risk="medium", reverse="package.apt.remove", summary=f"ensure apt package {name}"))
    for name, port in package.ports.named.items():
        plan.append(_op("port.validate", f"{app}:port:{name}", {"name": name, "port": port}, deps=(package_op.resource,), summary=f"validate port {port}"))
    user_op: Operation | None = None
    if package.user:
        user = package.user.name or app
        user_op = _op("system_user.ensure", f"{app}:user", {"name": user, "system": package.user.system, "home": str(package.user.home) if package.user.home else None}, deps=(package_op.resource,), reverse="system_user.remove", summary=f"ensure system user {user}")
        plan.append(user_op)
    for name, directory in package.directories.items():
        deps = (user_op.resource,) if user_op else (package_op.resource,)
        plan.append(_op("directory.ensure", f"{app}:directory:{name}", {"path": str(directory.path), "owner": directory.owner or (package.user.name if package.user else None), "group": directory.group, "mode": directory.mode, "backup": directory.backup}, deps=deps, reverse="directory.remove", summary=f"ensure directory {directory.path}"))
    for name, access in package.permissions.items():
        deps = (user_op.resource,) if user_op else (package_op.resource,)
        plan.append(_op("access.ensure", f"{app}:access:{name}", {"path": str(access.path), "owner": access.owner, "group": access.group, "mode": access.mode, "recursive": access.recursive}, deps=deps, reverse="access.remove", summary=f"enforce access policy on {access.path}"))
    for name, source in package.sources.items():
        plan.append(_op("source.fetch", f"{app}:source:{name}", {"url": source.url, "sha256": source.sha256, "extract": source.extract, "destination": str(source.destination) if source.destination else None}, deps=(package_op.resource,), risk="medium", reverse="source.remove", summary=f"fetch and verify source {name}"))
    for name, config in package.config.items():
        config_args = {**config.dict(), "destination": str(config.destination)}
        if template_root is not None:
            config_args["_template_root"] = str(template_root)
        plan.append(_op("config.ensure", f"{app}:config:{name}", config_args, deps=(package_op.resource,), reverse="config.remove", summary=f"render config {config.destination}"))
    if package.runtime:
        plan.append(_op("runtime.ensure", f"{app}:runtime", package.runtime.dict(), deps=(package_op.resource,), risk="medium", reverse="runtime.remove", summary=f"ensure {package.runtime.type} {package.runtime.version}"))
    if package.database:
        plan.append(_op("database.ensure", f"{app}:database", package.database.dict(), deps=(package_op.resource,), risk="high", reverse="database.remove", summary=f"ensure {package.database.type} database"))
    if package.service:
        deps = tuple(op.resource for op in plan if op.resource.startswith((f"{app}:directory:", f"{app}:source:", f"{app}:config:")))
        deps += tuple(resource for resource in (f"{app}:runtime", f"{app}:database") if any(op.resource == resource for op in plan))
        deps = deps or (package_op.resource,)
        service = package.service.dict()
        service["name"] = package.service.name or app
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
    if package.timer:
        deps = (f"{app}:service:start",) if package.service else (package_op.resource,)
        plan.append(_op("timer.ensure", f"{app}:timer", package.timer.dict(), deps=deps, risk="medium", reverse="timer.remove", summary="render and enable systemd timer"))
    if package.settings.values:
        plan.append(_op("settings.ensure", f"{app}:settings", {"values": package.settings.values}, deps=(package_op.resource,), summary="ensure typed application settings"))
    for name, secret in package.secrets.items():
        plan.append(_op("secret.ensure", f"{app}:secret:{name}", {"name": name, "generate": secret.generate, "length": secret.length}, deps=(package_op.resource,), risk="high", reverse="secret.remove", summary=f"ensure secret {name}"))
    if package.backup:
        plan.append(_op("backup.register", f"{app}:backup", {"paths": [str(path) for path in package.backup.paths], "database": package.backup.database}, deps=(package_op.resource,), summary="register backup resources"))
    for name, policy in package.policies.items():
        plan.append(_op("policy.ensure", f"{app}:policy:{name}", policy.dict(), deps=(package_op.resource,), risk="medium", reverse="policy.remove", summary=f"install {policy.type} policy {policy.name}"))
    for name, hook in package.hooks.items():
        plan.append(_op("hook.python.ensure", f"{app}:hook:{name}", {"reference": hook.python}, deps=(package_op.resource,), risk="medium", reversible=False, summary=f"register {name} hook"))
    return plan


def validate_package(package: PackageManifest) -> PackageManifest:
    """Apply cross-resource safety checks after Pydantic field validation."""
    if package.service:
        executable = package.service.exec
        if not executable.startswith("/") or ".." in PurePosixPath(executable).parts:
            raise PackageError("service.exec must be an absolute path without '..'")
        if package.service.working_directory and not package.service.working_directory.is_absolute():
            raise PackageError("service.working_directory must be absolute")
    if package.web:
        host, separator, port = package.web.upstream.rpartition(":")
        if not separator or not host or not port.isdigit() or not 1 <= int(port) <= 65535:
            raise PackageError("web.upstream must be host:port with a valid port")
        if host not in {"localhost", "127.0.0.1", "::1"}:
            try:
                socket.inet_aton(host)
            except OSError:
                if not re.fullmatch(r"[a-zA-Z0-9.-]+", host):
                    raise PackageError("web.upstream host is invalid")
    if package.health and not package.health.path.startswith("/"):
        raise PackageError("health.path must be absolute")
    if package.backup:
        if any(not path.is_absolute() or ".." in PurePosixPath(path).parts for path in package.backup.paths):
            raise PackageError("backup paths must be absolute and cannot contain '..'")
        if package.database and package.backup.database is False:
            raise PackageError("database resources must opt in or out explicitly in backup.database")
    if package.service and package.user and package.service.user and package.service.user != (package.user.name or package.app.id):
        raise PackageError("service.user must match the declared package user")
    return package


def operation_from_dict(value: dict[str, Any]) -> Operation:
    """Restore an executor-neutral operation received over the control plane."""
    required = {"name", "resource", "args"}
    if not required <= value.keys() or not isinstance(value["args"], dict):
        raise PackageError("operation requires name, resource, and object args")
    return Operation(
        name=value["name"], resource=value["resource"], args=value["args"],
        depends_on=tuple(value.get("depends_on", ())), risk=value.get("risk", "low"),
        reversible=bool(value.get("reversible", True)), reverse=value.get("reverse"),
        summary=value.get("summary", ""),
    )


def apply_operation_plan(plan: list[Operation], executor: Any) -> list[Any]:
    """Apply a validated plan in dependency order through one executor."""
    if hasattr(executor, "can_execute"):
        unsupported = [operation.name for operation in plan if not executor.can_execute(operation)]
        if unsupported:
            raise PackageError("native providers are unavailable for: " + ", ".join(unsupported))
    pending = list(plan)
    completed: set[str] = set()
    results: list[Any] = []
    while pending:
        ready = next((operation for operation in pending if set(operation.depends_on) <= completed), None)
        if ready is None:
            raise PackageError("operation plan contains an unknown dependency or cycle")
        results.append(executor.execute(ready))
        completed.add(ready.resource)
        pending.remove(ready)
    return results


def _operation_satisfied(operation: Operation, actual: Any) -> bool:
    """Return true only for state that providers inspect completely enough to skip."""
    if not isinstance(actual, dict):
        return False
    if operation.name == "directory.ensure":
        return actual.get("exists") is True and actual.get("mode") == operation.args.get("mode")
    if operation.name == "access.ensure":
        return (
            actual.get("exists") is True
            and actual.get("mode") == operation.args.get("mode")
            and (not operation.args.get("owner") or actual.get("owner") == operation.args["owner"])
            and (not operation.args.get("group") or actual.get("group") == operation.args["group"])
        )
    if operation.name == "package.apt.ensure":
        return set(operation.args.get("packages", [])) <= set(actual.get("installed", []))
    if operation.name == "runtime.ensure":
        return actual.get("matches") is True
    if operation.name == "config.ensure":
        return (
            actual.get("exists") is True
            and actual.get("mode") == operation.args.get("mode")
            and operation.args.get("content") is not None
            and actual.get("sha256") == hashlib.sha256(operation.args["content"].encode()).hexdigest()
        )
    if operation.name == "service.ensure":
        return actual.get("exists") is True and actual.get("sha256") == actual.get("desired_sha256")
    if operation.name == "policy.ensure":
        return actual.get("exists") is True and actual.get("sha256") == hashlib.sha256(operation.args["content"].encode()).hexdigest()
    if operation.name == "database.ensure":
        return actual.get("exists") is True
    if operation.name == "source.fetch":
        return (
            actual.get("exists") is True
            and actual.get("sha256", "").lower() == operation.args.get("sha256", "").lower()
            and (operation.args.get("destination") is None or actual.get("url") == operation.args.get("url"))
        )
    if operation.name == "secret.ensure":
        return actual.get("exists") is True
    if operation.name in {"settings.ensure", "backup.register"}:
        return actual.get("exists") is True
    if operation.name == "system_user.ensure":
        return actual.get("definition") is True
    return False


def reconcile_operation_plan(plan: list[Operation], executor: Any) -> tuple[list[Operation], list[str]]:
    """Inspect safe resources and return the operations still requiring apply.

    Operations whose providers cannot prove satisfaction remain in the plan.
    This deliberately avoids treating an existing service/config/source as
    current without content or checksum verification.
    """
    if hasattr(executor, "can_execute"):
        unsupported = [operation.name for operation in plan if not executor.can_execute(operation)]
        if unsupported:
            raise PackageError("native providers are unavailable for: " + ", ".join(unsupported))
    pending: list[Operation] = []
    skipped: list[str] = []
    for operation in plan:
        provider = executor.provider_for(operation) if hasattr(executor, "provider_for") else None
        actual = provider.inspect(operation.args) if provider is not None and hasattr(provider, "inspect") else None
        if _operation_satisfied(operation, actual):
            skipped.append(operation.resource)
        else:
            pending.append(operation)
    return pending, skipped


def apply_reconciled_plan(plan: list[Operation], executor: Any) -> list[Any]:
    """Inspect, skip satisfied resources, then apply remaining operations."""
    pending, skipped = reconcile_operation_plan(plan, executor)
    if hasattr(executor, "can_execute"):
        unsupported = [operation.name for operation in pending if not executor.can_execute(operation)]
        if unsupported:
            raise PackageError("native providers are unavailable for: " + ", ".join(unsupported))
    pending_resources = {operation.resource for operation in pending}
    pending = [
        Operation(operation.name, operation.resource, operation.args,
                  tuple(dep for dep in operation.depends_on if dep in pending_resources),
                  operation.risk, operation.reversible, operation.reverse, operation.summary)
        for operation in pending
    ]
    return apply_operation_plan(pending, executor)


def load_package(path: Path) -> PackageManifest:
    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
        return validate_package(PackageManifest.parse_obj(raw))
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
    scripts = source.parent / "scripts"
    unsupported = [name for name in ("install", "upgrade", "remove", "backup", "restore") if (scripts / name).is_file()]
    if unsupported:
        raise PackageError(
            "cannot migrate imperative package scripts ("
            + ", ".join(unsupported)
            + "); convert the package to declarative resources or Python hooks first"
        )
    with source.open("rb") as stream:
        raw = tomllib.load(stream)
    converted = migrate_manifest(raw)
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
