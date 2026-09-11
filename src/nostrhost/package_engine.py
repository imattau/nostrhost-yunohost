"""Typed, declarative package planning for NostrHost.

This module deliberately stops at planning.  Providers describe the bounded
operations that a future privileged executor may apply; parsing a package
never mutates the host.
"""

from __future__ import annotations

import json
import hashlib
import platform as host_platform
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


class SourceVariant(BaseModel):
    url: str = Field(..., min_length=1)
    sha256: str = Field(..., min_length=64, max_length=64)

    @validator("sha256")
    def valid_hash(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise ValueError("sha256 must be a 64-character hexadecimal digest")
        return value


class SourceResource(BaseModel):
    id: str = "main"
    url: str | None = Field(None, min_length=1)
    sha256: str | None = Field(None, min_length=64, max_length=64)
    extract: bool = True
    destination: Path | None = None
    format: Literal["auto", "tar", "zip", "file"] = "auto"
    rename: str | None = None
    strip_components: int = Field(0, ge=0, le=16)
    platform: str | None = None
    variants: dict[str, SourceVariant] = Field(default_factory=dict)

    @validator("rename")
    def safe_rename(cls, value: str | None) -> str | None:
        if value is not None and (not value or Path(value).name != value):
            raise ValueError("source rename must be a filename")
        return value

    @validator("sha256")
    def valid_hash(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise ValueError("sha256 must be a 64-character hexadecimal digest")
        return value

    @root_validator
    def has_source(cls, values: dict[str, Any]) -> dict[str, Any]:
        if not values.get("variants") and not (values.get("url") and values.get("sha256")):
            raise ValueError("source requires url/sha256 or architecture variants")
        return values


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
    groups: list[str] = Field(default_factory=list)


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


class PermissionResource(BaseModel):
    url: str | None = None
    additional_urls: list[str] = Field(default_factory=list)
    allowed: str | list[str] | None = None
    auth_header: bool = True
    auth_request: bool = False
    show_tile: bool | None = None
    protected: bool = False

    @validator("url")
    def valid_url(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("permission urls must not be empty")
        return value

    @validator("additional_urls")
    def unique_urls(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)) or any(not url.strip() for url in value):
            raise ValueError("permission additional_urls must be unique and non-empty")
        return value

    @root_validator
    def default_tile(cls, values: dict[str, Any]) -> dict[str, Any]:
        if values.get("show_tile") is None:
            values["show_tile"] = bool(values.get("url"))
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
    type: Literal["node", "python", "go", "ruby", "composer", "php"]
    version: str = Field(..., min_length=1)
    prefix: Path | None = None

    @validator("prefix")
    def absolute_prefix(cls, value: Path | None) -> Path | None:
        if value is not None and (not value.is_absolute() or ".." in PurePosixPath(value).parts):
            raise ValueError("runtime prefixes must be absolute and cannot contain '..'")
        return value


class PhpFpmResource(BaseModel):
    version: str = Field(..., min_length=1)
    socket: Path
    user: str
    group: str
    max_children: int = Field(10, gt=0, le=10000)

    @validator("socket")
    def absolute_socket(cls, value: Path) -> Path:
        if not value.is_absolute() or ".." in PurePosixPath(value).parts:
            raise ValueError("PHP-FPM sockets must be absolute and cannot contain '..'")
        return value

    @validator("user", "group")
    def safe_identity(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z_][a-z0-9_-]*[$]?", value):
            raise ValueError("PHP-FPM user and group must be safe system identities")
        return value


class DatabaseUserResource(BaseModel):
    name: str = Field(..., min_length=1, max_length=63)
    password_secret: str | None = None
    host: str = "%"
    privileges: list[str] = Field(default_factory=list)

    @validator("name")
    def valid_name(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", value):
            raise ValueError("database user names must be lowercase identifiers")
        return value

    @validator("password_secret")
    def valid_secret(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[a-z][a-z0-9_-]*", value):
            raise ValueError("database password_secret must be a safe secret name")
        return value


class DatabaseResource(BaseModel):
    type: Literal["postgresql", "mysql", "mongodb", "redis"]
    name: str | None = None
    backup: bool = True
    users: dict[str, DatabaseUserResource] = Field(default_factory=dict)

    @validator("users")
    def unique_user_names(cls, value: dict[str, DatabaseUserResource]) -> dict[str, DatabaseUserResource]:
        if len({user.name for user in value.values()}) != len(value):
            raise ValueError("database user names must be unique")
        return value

    @root_validator
    def valid_backend_options(cls, values: dict[str, Any]) -> dict[str, Any]:
        if values.get("type") == "redis" and values.get("users"):
            raise ValueError("Redis resources cannot declare database users")
        if values.get("type") == "redis" and values.get("name") is not None:
            try:
                if not 0 <= int(values["name"]) <= 15:
                    raise ValueError
            except (TypeError, ValueError) as exc:
                raise ValueError("Redis database name must be a database index between 0 and 15") from exc
        return values


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
    credentials: dict[str, Path] = Field(default_factory=dict)
    security: ServiceSecurity = Field(default_factory=ServiceSecurity)

    @validator("credentials")
    def absolute_credentials(cls, value: dict[str, Path]) -> dict[str, Path]:
        if any(not path.is_absolute() or ".." in PurePosixPath(path).parts for path in value.values()):
            raise ValueError("service credential paths must be absolute and cannot contain '..'")
        return value


class WebResource(BaseModel):
    domain: str | None = None
    path: str = "/"
    upstream: str | None = Field(default=None, min_length=1)
    file_root: str | None = None
    auth: Literal["none", "nostrhost"] = "none"
    https: Literal["automatic", "required", "disabled"] = "automatic"

    @validator("path")
    def path_starts_with_slash(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("web.path must start with '/'")
        return value

    @validator("file_root")
    def absolute_file_root(cls, value: str | None) -> str | None:
        if value is not None and (not value.startswith("/") or ".." in PurePosixPath(value).parts):
            raise ValueError("web.file_root must be an absolute path without '..'")
        return value


class HealthResource(BaseModel):
    type: Literal["http"] = "http"
    path: str = "/health"
    timeout: int = Field(10, gt=0, le=300)
    retries: int = Field(0, ge=0, le=5)


class TimerResource(BaseModel):
    on_calendar: str = Field(..., min_length=1)
    exec: str = Field(..., min_length=1)
    persistent: bool = True

    @validator("exec")
    def absolute_exec(cls, value: str) -> str:
        if not value.startswith("/") or ".." in PurePosixPath(value).parts:
            raise ValueError("timer.exec must be an absolute path without '..'")
        return value


class BackupResource(BaseModel):
    paths: list[Path] = Field(default_factory=list)
    database: bool = False


class PolicyResource(BaseModel):
    type: Literal["logrotate", "crowdsec"]
    name: str = Field(..., min_length=1)
    content: str = Field(..., min_length=1)

    @validator("name")
    def safe_name(cls, value: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", value):
            raise ValueError("policy name must be a safe filename")
        return value


class SettingField(BaseModel):
    type: Literal["string", "integer", "number", "boolean", "enum"]
    default: Any = None
    choices: list[str] = Field(default_factory=list)
    secret: bool = False

    @root_validator
    def valid_field(cls, values: dict[str, Any]) -> dict[str, Any]:
        if values.get("type") == "enum" and not values.get("choices"):
            raise ValueError("enum settings require choices")
        if values.get("type") != "enum" and values.get("choices"):
            raise ValueError("only enum settings may declare choices")
        return values


class SettingResource(BaseModel):
    fields: dict[str, SettingField] = Field(default_factory=dict)
    values: dict[str, Any] = Field(default_factory=dict)

    @root_validator
    def validate_values(cls, values: dict[str, Any]) -> dict[str, Any]:
        fields = values.get("fields", {})
        settings = values.get("values", {})
        for name, definition in fields.items():
            if name not in settings and definition.default is not None:
                settings[name] = definition.default
        unknown = set(settings) - set(fields)
        if unknown and fields:
            raise ValueError("settings values must be declared in settings.fields: " + ", ".join(sorted(unknown)))
        for name, definition in fields.items():
            if name not in settings:
                continue
            value = settings[name]
            valid = {
                "string": isinstance(value, str),
                "integer": isinstance(value, int) and not isinstance(value, bool),
                "number": isinstance(value, (int, float)) and not isinstance(value, bool),
                "boolean": isinstance(value, bool),
                "enum": isinstance(value, str) and value in definition.choices,
            }[definition.type]
            if not valid:
                raise ValueError(f"setting {name} does not match declared type {definition.type}")
            if definition.secret:
                raise ValueError(f"secret setting {name} must use a secret resource")
        return values


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
    fpm: PhpFpmResource | None = None
    packages: PackagesResource = Field(default_factory=PackagesResource)
    ports: PortsResource = Field(default_factory=PortsResource)
    user: UserResource | None = None
    directories: dict[str, DirectoryResource] = Field(default_factory=dict)
    access: dict[str, AccessResource] = Field(default_factory=dict)
    permissions: dict[str, PermissionResource] = Field(default_factory=dict)
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

    @validator("sources", "directories", "access", "permissions", "config", "secrets", "hooks", "policies")
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


PLAN_SCHEMA = 1


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def operation_plan_digest(plan: list[Operation]) -> str:
    """Return the stable digest that binds a plan to an approval request."""
    return hashlib.sha256(_canonical_json([operation.json_dict() for operation in plan])).hexdigest()


def package_plan_envelope(package_data: dict[str, Any], *, catalogue: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build the control-plane envelope for one validated native package."""
    if not isinstance(package_data, dict):
        raise PackageError("package plan requires an object")
    package = validate_package(PackageManifest.parse_obj(package_data))
    plan = plan_package(package)
    envelope = {
        "schema": PLAN_SCHEMA,
        "package": {"id": package.app.id, "version": package.app.version},
        "manifest_sha256": hashlib.sha256(_canonical_json(package_data)).hexdigest(),
        "plan_sha256": operation_plan_digest(plan),
        "operations": [operation.json_dict() for operation in plan],
    }
    if catalogue is not None:
        if not isinstance(catalogue, dict):
            raise PackageError("catalogue provenance must be an object")
        native = catalogue.get("native") if isinstance(catalogue.get("native"), dict) else catalogue
        if native.get("app_id") != package.app.id or native.get("version") != package.app.version:
            raise PackageError("catalogue provenance does not match package identity")
        envelope["catalogue"] = {
            key: native[key]
            for key in ("app_id", "version", "repository", "revision", "manifest_sha256", "content_sha256", "architectures", "package_path", "event_id")
            if key in native
        }
    return envelope


def validate_plan_envelope(envelope: dict[str, Any]) -> list[Operation]:
    """Validate an approved plan envelope before handing it to providers."""
    if not isinstance(envelope, dict) or envelope.get("schema") != PLAN_SCHEMA:
        raise PackageError("unsupported or missing native package plan schema")
    operations = envelope.get("operations")
    if not isinstance(operations, list) or not operations:
        raise PackageError("native package plan envelope requires operations")
    plan = [operation_from_dict(item) for item in operations]
    if envelope.get("plan_sha256") != operation_plan_digest(plan):
        raise PackageError("native package plan digest does not match operations")
    package = envelope.get("package")
    if not isinstance(package, dict) or not package.get("id") or not package.get("version"):
        raise PackageError("native package plan envelope requires package id and version")
    catalogue = envelope.get("catalogue")
    if catalogue is not None:
        if not isinstance(catalogue, dict) or catalogue.get("app_id") != package["id"] or catalogue.get("version") != package["version"]:
            raise PackageError("native package plan catalogue provenance does not match package identity")
    return plan


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
        plan.append(_op("package.apt.ensure", f"{app}:apt:{name}", {"package": name}, deps=(package_op.resource,), risk="medium", reversible=False, summary=f"ensure apt package {name}"))
    for name, port in package.ports.named.items():
        plan.append(_op("port.validate", f"{app}:port:{name}", {"name": name, "port": port}, deps=(package_op.resource,), summary=f"validate port {port}"))
    user_op: Operation | None = None
    if package.user:
        user = package.user.name or app
        user_op = _op("system_user.ensure", f"{app}:user", {"name": user, "system": package.user.system, "home": str(package.user.home) if package.user.home else None, "groups": package.user.groups}, deps=(package_op.resource,), reverse="system_user.remove", summary=f"ensure system user {user}")
        plan.append(user_op)
    for name, directory in package.directories.items():
        deps = (user_op.resource,) if user_op else (package_op.resource,)
        plan.append(_op("directory.ensure", f"{app}:directory:{name}", {"path": str(directory.path), "owner": directory.owner or (package.user.name if package.user else None), "group": directory.group, "mode": directory.mode, "backup": directory.backup}, deps=deps, reverse="directory.remove", summary=f"ensure directory {directory.path}"))
    for name, access in package.access.items():
        deps = (user_op.resource,) if user_op else (package_op.resource,)
        plan.append(_op("access.ensure", f"{app}:access:{name}", {"path": str(access.path), "owner": access.owner, "group": access.group, "mode": access.mode, "recursive": access.recursive}, deps=deps, reverse="access.remove", summary=f"enforce access policy on {access.path}"))
    for name, source in package.sources.items():
        selected = source
        if source.variants:
            architecture = {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "armhf", "i386": "i386"}.get(host_platform.machine(), host_platform.machine())
            try:
                variant = source.variants[architecture]
            except KeyError as exc:
                raise PackageError(f"source {name} has no variant for architecture {architecture}") from exc
            selected = source.copy(update={"url": variant.url, "sha256": variant.sha256})
        plan.append(_op("source.fetch", f"{app}:source:{name}", {"url": selected.url, "sha256": selected.sha256, "extract": selected.extract, "destination": str(selected.destination) if selected.destination else None, "format": selected.format, "rename": selected.rename, "strip_components": selected.strip_components, "platform": selected.platform}, deps=(package_op.resource,), risk="medium", reverse="source.remove", summary=f"fetch and verify source {name}"))
    for name, config in package.config.items():
        config_args = {**config.dict(), "destination": str(config.destination)}
        if template_root is not None:
            config_args["_template_root"] = str(template_root)
        plan.append(_op("config.ensure", f"{app}:config:{name}", config_args, deps=(package_op.resource,), reverse="config.remove", summary=f"render config {config.destination}"))
    if package.runtime:
        plan.append(_op("runtime.ensure", f"{app}:runtime", package.runtime.dict(), deps=(package_op.resource,), risk="medium", reversible=False, summary=f"ensure {package.runtime.type} {package.runtime.version}"))
    if package.fpm:
        deps = (f"{app}:runtime",) if package.runtime else (package_op.resource,)
        plan.append(_op("fpm.ensure", f"{app}:fpm", {**package.fpm.dict(), "app": app}, deps=deps, risk="medium", reverse="fpm.remove", summary=f"configure PHP-FPM pool {app}"))
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
        web_args = {**package.web.dict(), "app": app}
        plan.append(_op("web.route.ensure", f"{app}:web", web_args, deps=deps, risk="medium", reverse="web.route.remove", summary="ensure web route"))
    for name, permission in package.permissions.items():
        deps = (f"{app}:web",) if package.web else (package_op.resource,)
        permission_args = {**permission.dict(), "app": app, "name": name}
        plan.append(_op("permission.ensure", f"{app}:permission:{name}", permission_args, deps=deps, risk="medium", reverse="permission.remove", summary=f"ensure Portal permission {app}.{name}"))
    if package.health:
        deps = (f"{app}:web",) if package.web else ((f"{app}:service:start",) if package.service else (package_op.resource,))
        plan.append(_op("health.http.check", f"{app}:health", package.health.dict(), deps=deps, risk="low", reversible=False, summary="check application health"))
    if package.timer:
        deps = (f"{app}:service:start",) if package.service else (package_op.resource,)
        plan.append(_op("timer.ensure", f"{app}:timer", package.timer.dict(), deps=deps, risk="medium", reverse="timer.remove", summary="render and enable systemd timer"))
    if package.settings.values or package.settings.fields:
        plan.append(_op("settings.ensure", f"{app}:settings", {"name": app, "fields": {name: field.dict() for name, field in package.settings.fields.items()}, "values": package.settings.values}, deps=(package_op.resource,), reverse="settings.remove", summary="ensure typed application settings"))
    for name, secret in package.secrets.items():
        plan.append(_op("secret.ensure", f"{app}:secret:{name}", {"name": name, "generate": secret.generate, "length": secret.length}, deps=(package_op.resource,), risk="high", reverse="secret.remove", summary=f"ensure secret {name}"))
    if package.backup:
        plan.append(_op("backup.register", f"{app}:backup", {"name": app, "paths": [str(path) for path in package.backup.paths], "database": package.backup.database}, deps=(package_op.resource,), reverse="backup.unregister", summary="register backup resources"))
    for name, policy in package.policies.items():
        plan.append(_op("policy.ensure", f"{app}:policy:{name}", policy.dict(), deps=(package_op.resource,), risk="medium", reverse="policy.remove", summary=f"install {policy.type} policy {policy.name}"))
    for name, hook in package.hooks.items():
        plan.append(_op("hook.python.ensure", f"{app}:hook:{name}", {"name": f"{app}-{name}", "reference": hook.python}, deps=(package_op.resource,), risk="medium", reversible=False, summary=f"register {name} hook"))
    return plan


def plan_package_removal(package: PackageManifest) -> list[Operation]:
    """Create the safe, reverse-order lifecycle plan for a native package.

    Only operations with an explicit reverse operation are included. Shared
    host dependencies (APT packages and runtimes) stay installed, while
    database removal remains an explicit high-risk operation that callers may
    gate on a backup/restore policy.
    """
    removal: list[Operation] = []
    previous: str | None = None
    for operation in reversed(plan_package(package)):
        if not operation.reversible or not operation.reverse:
            continue
        args = dict(operation.args)
        reverse = operation.reverse
        dependencies = (previous,) if previous else ()
        removal_operation = Operation(
            reverse,
            operation.resource,
            args,
            dependencies,
            operation.risk,
            True,
            operation.name,
            f"reverse: {operation.summary}",
        )
        removal.append(removal_operation)
        previous = operation.resource
    return removal


def validate_package(package: PackageManifest) -> PackageManifest:
    """Apply cross-resource safety checks after Pydantic field validation."""
    if package.fpm and (not package.runtime or package.runtime.type != "php" or package.runtime.version != package.fpm.version):
        raise PackageError("fpm requires a matching php runtime resource")
    if package.service:
        executable = package.service.exec
        if not executable.startswith("/") or ".." in PurePosixPath(executable).parts:
            raise PackageError("service.exec must be an absolute path without '..'")
        if package.service.working_directory and not package.service.working_directory.is_absolute():
            raise PackageError("service.working_directory must be absolute")
    if package.web:
        if not package.web.upstream and not package.web.file_root:
            raise PackageError("web resource needs upstream host:port or file_root")
        if package.web.upstream:
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
    if operation.name == "permission.ensure":
        if not actual or actual.get("exists") is not True:
            return False
        allowed = operation.args.get("allowed")
        expected_allowed = [allowed] if isinstance(allowed, str) else sorted(allowed or [])
        return (
            sorted(actual.get("allowed", [])) == expected_allowed
            and actual.get("url") == operation.args.get("url")
            and sorted(actual.get("additional_urls", [])) == sorted(operation.args.get("additional_urls", []))
            and actual.get("auth_header") == operation.args.get("auth_header")
            and actual.get("auth_request") == operation.args.get("auth_request")
            and actual.get("show_tile") == operation.args.get("show_tile")
            and actual.get("protected") == operation.args.get("protected")
        )
    if operation.name == "package.apt.ensure":
        packages = operation.args.get("packages")
        if packages is None and operation.args.get("package"):
            packages = [operation.args["package"]]
        return bool(packages) and set(packages) <= set(actual.get("installed", []))
    if operation.name == "package.ensure":
        return actual.get("exists") is True and actual.get("version") == operation.args.get("version")
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
        if actual.get("exists") is not True:
            return False
        expected_users = operation.args.get("users", {})
        if expected_users:
            expected_names = sorted(user.get("name", key) for key, user in expected_users.items())
            if sorted(actual.get("users", [])) != expected_names:
                return False
            expected_privileges = {
                user.get("name", key): sorted(user.get("privileges", []))
                for key, user in expected_users.items()
            }
            return actual.get("privileges") == expected_privileges
        return True
    if operation.name == "source.fetch":
        return (
            actual.get("exists") is True
            and actual.get("sha256", "").lower() == operation.args.get("sha256", "").lower()
            and (operation.args.get("destination") is None or actual.get("url") == operation.args.get("url"))
        )
    if operation.name == "secret.ensure":
        return actual.get("exists") is True
    if operation.name in {"settings.ensure", "backup.register", "hook.python.ensure"}:
        return actual.get("exists") is True and (
            operation.name not in {"settings.ensure", "hook.python.ensure"}
            or actual.get("sha256") == actual.get("desired_sha256")
        )
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
        source_fields = {"url", "sha256", "extract", "destination", "format", "rename", "strip_components", "platform"}
        out["source"] = {}
        for key, value in resources["sources"].items():
            entry = {field: value[field] for field in source_fields if field in value}
            if value.get("variants"):
                entry["variants"] = {
                    architecture: {field: variant[field] for field in ("url", "sha256") if field in variant}
                    for architecture, variant in value["variants"].items()
                }
            out["source"][key] = entry
    if resources.get("system_user"):
        out["user"] = {
            "name": resources["system_user"].get("username", app_id),
            "system": True,
            "groups": resources["system_user"].get("groups", []),
        }
    if resources.get("install_dir"):
        out.setdefault("directories", {})["install"] = {"path": resources["install_dir"].get("path", f"/var/www/{app_id}")}
    if resources.get("data_dir"):
        out.setdefault("directories", {})["data"] = {"path": resources["data_dir"].get("path", f"/var/lib/{app_id}"), "backup": True}
    if resources.get("ports"):
        ports = {}
        for name, value in resources["ports"].items():
            ports[name] = value if isinstance(value, int) else value.get("port")
        out["ports"] = {"named": {name: port for name, port in ports.items() if port is not None}}
    if resources.get("permissions"):
        out["permissions"] = {
            name: {key: value for key, value in details.items() if key in {"url", "additional_urls", "allowed", "auth_header", "auth_request", "show_tile", "protected"}}
            for name, details in resources["permissions"].items()
        }
    if resources.get("access"):
        out["access"] = resources["access"]
    if resources.get("database"):
        out["database"] = {key: value for key, value in resources["database"].items() if key in {"type", "name", "backup", "users"}}
    for runtime_type in ("nodejs", "python", "go", "ruby", "composer", "php"):
        if resources.get(runtime_type):
            out["runtime"] = {"type": "node" if runtime_type == "nodejs" else runtime_type, "version": resources[runtime_type]["version"], "prefix": resources[runtime_type].get("prefix")}
            break
    if resources.get("config"):
        out["config"] = {
            name: {key: value for key, value in details.items() if key in {"destination", "content", "template", "context", "mode", "owner", "group"}}
            for name, details in resources["config"].items()
        }
    for resource_name, native_name in (("service", "service"), ("web", "web"), ("health", "health"), ("timer", "timer"), ("backup", "backup"), ("settings", "settings")):
        if resources.get(resource_name):
            out[native_name] = resources[resource_name]
    return out


def migrate_manifest_file(source: Path, destination: Path) -> None:
    scripts = source.parent / "scripts"
    unsupported = [
        name for name in
        ("install", "upgrade", "remove", "backup", "restore", "change_url", "config", "check_process", "diagnosis")
        if (scripts / name).is_file()
    ]
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
