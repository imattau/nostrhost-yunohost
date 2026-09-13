"""Human- and agent-facing tools for authoring native package manifests."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any, Optional

import typer
try:  # Match the package engine on both Bookworm Pydantic v1 and newer hosts.
    from pydantic.v1 import ValidationError
except ImportError:  # pragma: no cover - native Pydantic v1 on Debian 12
    from pydantic import ValidationError

from .package_engine import (
    PackageError,
    PackageManifest,
    plan_package,
    schema as package_schema,
    validate_package,
)

app = typer.Typer(
    name="nostrhost-package",
    help="Scaffold, validate, and explain native NostrHost packages.",
    no_args_is_help=True,
)

PACKAGE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]*$")

WEB_TEMPLATE = '''\
[app]
id = "{package_id}"
version = "0.1.0"

[directories.install]
path = "/var/www/{package_id}"
mode = 0o755

[config.index]
destination = "/var/www/{package_id}/index.html"
mode = 0o644
content = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{package_id}</title></head>
<body><main><h1>{package_id}</h1></main></body></html>
"""

[web]
domain = "example.test"
path = "/{package_id}/"
file_root = "/var/www/{package_id}"
auth = "nostrhost"
https = "automatic"

[permissions.main]
url = "/"
allowed = ["all_users"]
auth_request = true

[health]
type = "http"
path = "/{package_id}/"
timeout = 10
retries = 2

[backup]
paths = ["/var/www/{package_id}"]
database = false
'''

FIELD_GUIDANCE = {
    "app": "Required package identity and version. Keep the id stable across releases.",
    "source": "Verified upstream archives. Every source requires a SHA-256 digest, including each platform variant.",
    "runtime": "A host-managed language runtime and version; use an explicit prefix only for an isolated runtime.",
    "fpm": "PHP-FPM pool configuration. Declare a matching PHP runtime as well.",
    "packages": "APT dependencies owned by the host package manager; shared packages are retained on app removal.",
    "ports": "Named, unique TCP/UDP port allocations requested by the package.",
    "user": "Optional system account owned by this package. Services should use this declared identity.",
    "directories": "Absolute package-owned paths, access modes, and backup intent.",
    "access": "Filesystem ownership and mode changes on existing paths; declare an owner or group explicitly.",
    "permissions": "Portal access policy for the package's web routes; this is distinct from filesystem access.",
    "config": "Managed configuration files with exactly one content or template source.",
    "database": "A package-owned database and its users/grants. State explicitly whether database data is backed up.",
    "service": "A systemd service with an absolute executable path and an optional declared system user.",
    "web": "A Caddy route to an upstream or static file root. Use a registered domain and package route.",
    "dns": "Records owned by this app inside the zone for the declared web domain.",
    "health": "A bounded HTTP health check used to verify the resulting service or web route.",
    "timer": "A systemd timer and absolute executable for recurring package work.",
    "backup": "Filesystem paths and database inputs registered with the backup plane.",
    "policies": "Typed host security/log rotation policies rendered through registered providers.",
    "settings": "Typed non-secret package settings and defaults. Store credentials with secrets instead.",
    "secrets": "Generated secret resources; never embed secret values in the manifest.",
    "hooks": "Restricted Python hook references for behavior not expressible as a resource; hooks are not shell snippets.",
}

MINIMAL_TEMPLATE = '''\
[app]
id = "{package_id}"
version = "0.1.0"
'''


def _diagnostic(code: str, path: list[str | int], message: str, hint: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"code": code, "path": path, "message": message}
    if hint:
        result["hint"] = hint
    return result


def validate_manifest_data(raw: dict[str, Any]) -> tuple[PackageManifest | None, list[dict[str, Any]]]:
    """Validate decoded TOML data using the same rules as the authoring CLI."""
    try:
        package = validate_package(PackageManifest.parse_obj(raw))
    except ValidationError as exc:
        errors = [
            _diagnostic(
                f"package.{error.get('type', 'invalid').replace('.', '_')}",
                list(error.get("loc", [])),
                str(error.get("msg", "Invalid value")),
                "Compare this field with `nostrhost-package schema` and the package examples.",
            )
            for error in exc.errors()
        ]
        return None, errors
    except PackageError as exc:
        return None, [_diagnostic("package.resource_constraint", [], str(exc))]
    return package, []


def validate_manifest_text(content: str) -> tuple[PackageManifest | None, list[dict[str, Any]]]:
    """Parse and validate a manifest supplied as text without touching disk."""
    try:
        raw = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        return None, [_diagnostic("package.toml_syntax", [], str(exc), "Check the reported line and column in package.toml.")]
    return validate_manifest_data(raw)


def package_schema_document() -> dict[str, Any]:
    """Return the canonical JSON Schema document shared by CLI and HTTP API."""
    result = package_schema()
    result["$schema"] = "http://json-schema.org/draft-07/schema#"
    result["$id"] = "https://github.com/imattau/nostrhost/blob/main/schema/package.schema.json"
    result["description"] = "Declarative NostrHost package manifest. Validation is read-only; privileged changes require a separately approved plan."
    for field, description in FIELD_GUIDANCE.items():
        if field in result.get("properties", {}):
            result["properties"][field]["description"] = description
    return result


def package_plan_document(package: PackageManifest, *, template_root: Path | None = None) -> dict[str, Any]:
    """Return the stable CLI/API plan envelope for one validated manifest."""
    operations = [operation.json_dict() for operation in plan_package(package, template_root=template_root)]
    return {
        "schema": 1,
        "package": {"id": package.app.id, "version": package.app.version},
        "operation_count": len(operations),
        "operations": operations,
    }


def _load_and_validate(path: Path) -> tuple[PackageManifest | None, list[dict[str, Any]]]:
    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except FileNotFoundError:
        return None, [_diagnostic("package.file_not_found", [], f"Package file not found: {path}")]
    except tomllib.TOMLDecodeError as exc:
        return None, [_diagnostic("package.toml_syntax", [], str(exc), "Check the reported line and column in package.toml.")]
    except OSError as exc:
        return None, [_diagnostic("package.file_read", [], str(exc))]

    return validate_manifest_data(raw)


@app.command("schema")
def show_schema(output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write the schema to a file.")) -> None:
    """Print the machine-readable package.toml schema as JSON."""
    result = package_schema_document()
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        typer.echo(rendered, nl=False)


@app.command("init")
def init_package(
    package_id: str = typer.Argument(..., help="Lowercase package id."),
    directory: Path = typer.Option(Path("."), "--directory", "-d", help="Parent directory for the new package."),
    template: str = typer.Option("web", "--template", help="Scaffold pattern: web or minimal."),
) -> None:
    """Create a native package scaffold with safe, reviewable defaults."""
    if not PACKAGE_ID.fullmatch(package_id):
        typer.echo(json.dumps(_diagnostic("package.invalid_id", ["app", "id"], "Package id must use lowercase letters, digits, '_' or '-' and start with a letter or digit."), sort_keys=True), err=True)
        raise typer.Exit(2)
    templates = {"web": WEB_TEMPLATE, "minimal": MINIMAL_TEMPLATE}
    if template not in templates:
        typer.echo(json.dumps(_diagnostic("package.unknown_template", [], f"Unknown template: {template}", "Choose one of: minimal, web."), sort_keys=True), err=True)
        raise typer.Exit(2)
    target = directory / package_id / "package.toml"
    if target.exists():
        typer.echo(json.dumps(_diagnostic("package.already_exists", [], f"Refusing to overwrite {target}"), sort_keys=True), err=True)
        raise typer.Exit(2)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(templates[template].format(package_id=package_id), encoding="utf-8")
    typer.echo(json.dumps({"created": str(target), "template": template, "next": [f"nostrhost-package validate {target}", f"nostrhost-package plan {target} --json"]}, indent=2, sort_keys=True))


@app.command("validate")
def validate_manifest(
    package_file: Path = typer.Argument(..., help="Path to package.toml."),
    as_json: bool = typer.Option(False, "--json", help="Return stable machine-readable diagnostics."),
) -> None:
    """Validate TOML syntax, typed resources, and cross-resource rules."""
    package, diagnostics = _load_and_validate(package_file)
    if as_json:
        typer.echo(json.dumps({"schema": 1, "valid": not diagnostics, "package": ({"id": package.app.id, "version": package.app.version} if package else None), "diagnostics": diagnostics}, indent=2, sort_keys=True))
    elif diagnostics:
        for item in diagnostics:
            location = ".".join(map(str, item["path"])) or "package"
            typer.echo(f"ERROR {item['code']} at {location}: {item['message']}")
            if item.get("hint"):
                typer.echo(f"  hint: {item['hint']}")
    else:
        typer.echo(f"Valid package: {package.app.id} {package.app.version}")
    if diagnostics:
        raise typer.Exit(1)


@app.command("plan")
def plan_manifest(
    package_file: Path = typer.Argument(..., help="Path to package.toml."),
    as_json: bool = typer.Option(False, "--json", help="Return a stable JSON plan for tools and agents."),
) -> None:
    """Validate and produce a deterministic, non-mutating resource plan."""
    package, diagnostics = _load_and_validate(package_file)
    if diagnostics or package is None:
        typer.echo(json.dumps({"schema": 1, "valid": False, "diagnostics": diagnostics}, indent=2, sort_keys=True), err=True)
        raise typer.Exit(1)
    result = package_plan_document(package, template_root=package_file.parent)
    if as_json:
        typer.echo(json.dumps(result, indent=2, sort_keys=True, default=str))
    else:
        typer.echo(f"Plan for {package.app.id} {package.app.version} ({result['operation_count']} operations)")
        for index, operation in enumerate(result["operations"], 1):
            risk = operation.get("risk", "low")
            reversible = "reversible" if operation.get("reversible", True) else "not reversible"
            typer.echo(f"{index:02d}. {operation['name']} [{risk}; {reversible}] {operation['resource']}: {operation['summary']}")


@app.command("explain")
def explain_plan(package_file: Path = typer.Argument(..., help="Path to package.toml.")) -> None:
    """Explain planned changes, risk, ownership, and reversibility in plain language."""
    package, diagnostics = _load_and_validate(package_file)
    if diagnostics or package is None:
        typer.echo(json.dumps({"schema": 1, "valid": False, "diagnostics": diagnostics}, indent=2, sort_keys=True), err=True)
        raise typer.Exit(1)
    operations = package_plan_document(package, template_root=package_file.parent)["operations"]
    typer.echo(f"{package.app.id} {package.app.version} requests {len(operations)} resource changes:")
    for operation in operations:
        risk = operation.get("risk", "low")
        reverse = operation.get("reverse")
        owner = operation.get("resource", "package")
        detail = f"It is {risk} risk and " + ("can be reversed." if reverse else "has no automatic reverse operation.")
        typer.echo(f"- {operation['summary']} (owned by {owner}). {detail}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
