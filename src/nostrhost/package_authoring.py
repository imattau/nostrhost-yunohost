"""Human- and agent-facing tools for authoring native package manifests."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
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
    _canonical_json,
    plan_package,
    schema as package_schema,
    validate_package,
)

app = typer.Typer(
    name="nostrhost-package",
    help="Scaffold, validate, plan, and package native NostrHost packages.",
    no_args_is_help=True,
)

# Path inside an .npk archive that carries the canonical native manifest, so
# the resource engine can reconstruct the plan envelope from a verified
# artifact without re-fetching the original repository. npack skips the
# .npack metadata directory when installing, so this never leaks into the
# staged payload.
NPK_NATIVE_MANIFEST = ".npack/nostrhost/manifest.json"

# Loose SemVer the way npack expects it; npack rejects non-SemVer versions.
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)($|[+-].*$)")

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
    "settings": "Typed non-secret package settings and defaults. Store credentials with secrets instead. Post-install, these fields become the app's config panel (app.config.read/set, webadmin); values flow into managed config templates as the `settings` context.",
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


def _validate_revision(revision: str) -> None:
    """Reject a revision git could misparse as an option, or that carries
    whitespace/control characters (the same option-injection hardening the
    catalogue's own remote-preview clone applies)."""
    if revision.startswith("-"):
        raise ValueError(f"invalid revision {revision!r}: must not start with '-'")
    if any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in revision):
        raise ValueError(f"invalid revision {revision!r}: contains whitespace or control characters")


def fetch_manifest_from_repository(repository: str, revision: str = "", package_path: str = "") -> dict[str, Any]:
    """Shallow-clone a package.toml manifest straight from its repository, so
    authoring a package can start from "here is where it lives" instead of
    hand-pasting the manifest - the same "paste a repo, we fetch the
    manifest" method the legacy custom-app-install screen has always used
    (app_manifest/_extract_app_from_gitrepo in app.py/utils/app_utils.py),
    adapted to read this project's native package.toml resource schema
    instead of the legacy manifest.toml/manifest.json one (see
    catalog.declare's docstring for why those two schemas are incompatible
    and the native catalogue CLI's own remote-preview clone can't be reused
    for this either). Returns the raw (unvalidated-shape) TOML data alongside
    the same diagnostics `validate_manifest_text` would produce, and the
    commit the manifest was read at.
    """
    if not repository.startswith("https://"):
        raise ValueError("repository must be an https:// URL")
    if revision:
        _validate_revision(revision)
    if package_path and (package_path.startswith("/") or ".." in package_path.split("/")):
        raise ValueError("package_path must be a relative path without '..' segments")

    content, commit = _clone_and_read_manifest(repository, revision, package_path)
    package, diagnostics = validate_manifest_text(content)
    raw = tomllib.loads(content)
    return {
        "package": raw,
        "valid": package is not None,
        "diagnostics": diagnostics,
        "commit": commit,
    }


def _clone_and_read_manifest(repository: str, revision: str, package_path: str) -> tuple[str, str]:
    """Shallow-clone `repository` (any git-cloneable location - the caller
    validates it is an https:// URL before this point) and return
    (package.toml content, commit).

    Reuses the same clone helpers the legacy custom-app-install flow has
    always used (_git_clone_light, _make_tmp_workdir_for_app in
    yunohost.utils.app_utils - see app.app_manifest /
    _extract_app_from_gitrepo) instead of a bespoke git subprocess call:
    that gives this the same default-branch resolution, shallow-fetch
    mechanics, and revision cache the legacy app-install path already
    relies on. Split out from fetch_manifest_from_repository so tests can
    exercise the clone/read mechanics against a local repository without
    weakening the production https:// requirement.
    """
    from shutil import rmtree

    from yunohost.utils.app_utils import _git_clone_light, _make_tmp_workdir_for_app

    workdir = _make_tmp_workdir_for_app()
    try:
        try:
            commit = _git_clone_light(workdir, repository, branch=revision or None)
        except Exception as exc:
            raise ValueError(f"could not clone {repository}: {exc}") from exc

        manifest_dir = Path(workdir) / package_path if package_path else Path(workdir)
        manifest_file = manifest_dir / "package.toml"
        if not manifest_file.is_file():
            where = f"{package_path}/package.toml" if package_path else "package.toml"
            raise ValueError(f"{where} not found in {repository}" + (f"@{revision}" if revision else ""))
        content = manifest_file.read_text(encoding="utf-8")
    finally:
        rmtree(workdir, ignore_errors=True)

    return content, commit


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


def _npack_command(npack_bin: str) -> str:
    """Resolve the npack binary; honour $NPACK_BIN, else use the PATH name."""
    return npack_bin or os.environ.get("NPACK_BIN", "npack")


def _npack_version(npack_bin: str) -> str:
    try:
        result = subprocess.run(
            [_npack_command(npack_bin), "--version"], text=True, capture_output=True, check=False
        )
    except OSError as exc:
        raise PackageError(f"could not run npack: {exc}") from exc
    return result.stdout.strip() or result.stderr.strip()


def build_npk_artifact(
    package_data: dict[str, Any],
    *,
    payload_dir: Path | None,
    output: Path,
    publisher: str,
    name: str | None = None,
    version: str | None = None,
    os_name: str | None = None,
    arch: str | None = None,
    npack_bin: str = "",
    repo: str | None = None,
    commit: str | None = None,
) -> dict[str, Any]:
    """Build a deterministic .npk artifact from a validated native manifest.

    The payload directory is copied into the archive root at host-relative
    paths (the same layout the resource engine expects when it stages a
    verified artifact). The canonical native manifest is embedded under
    ``.npack/nostrhost/manifest.json`` so a later install can reconstruct the
    plan envelope from the artifact alone; npack skips the ``.npack`` metadata
    directory when installing, so the manifest never becomes part of the
    staged payload.

    ``repo``/``commit`` are signed into the npack release's own ``repo``/
    ``commit`` fields (npack supports them; ``npack init`` just has no flag
    for them, so they're patched into ``.npack/manifest.json`` the same way
    ``install_inputs`` is below). ``repo`` must be a NIP-34 kind:30617
    address (``30617:<pubkey>:<identifier>``) - npack's own release signing
    rejects any other format (``validate_repo_reference`` in
    ``sign_release_event``), so a plain URL will fail at build time, not
    silently produce an unattestable release. Without ``repo``/``commit``,
    nostrhost-catalog's npack-release ingestion
    (``protocol.ParseFromNpackRelease``) has nothing to attest against - CI
    attestations are inherently scoped to a specific commit - so a release
    with neither is simply never attestable, not broken.

    Returns ``{artifact, sha256, publisher, name, version, os, arch,
    npack, embedded_manifest}``. Requires the ``npack`` binary (see
    ``_npack_command``) and produces its sha256 via ``npack hash``.
    """
    if publisher.startswith("npub1") or re.fullmatch(r"[0-9a-fA-F]{64}", publisher):
        pass
    else:
        raise PackageError("publisher must be an npub or a 64-character hexadecimal public key")
    package = validate_package(PackageManifest.parse_obj(package_data))
    artifact_name = name or package.app.id
    artifact_version = version or package.app.version
    if not SEMVER.fullmatch(artifact_version):
        raise PackageError(
            f"npk version must be SemVer, got {artifact_version!r}; "
            "pass --version with a valid version (for example 1.0.0)"
        )
    if payload_dir is not None and not payload_dir.is_dir():
        raise PackageError(f"payload directory not found: {payload_dir}")
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    bin_path = _npack_command(npack_bin)
    try:
        npack_version = _npack_version(bin_path)
    except PackageError:
        raise
    init_args = ["init"]
    pack_args = ["pack"]
    for extra, where in ((init_args, "init"), (pack_args, "pack")):
        if not subprocess.run([bin_path, *extra, "--help"], text=True, capture_output=True, check=False).returncode == 0:
            raise PackageError(f"npack does not support `npack {extra[0]}`; update the bundled npack binary")

    with tempfile.TemporaryDirectory(prefix="nostrhost-npk-") as temporary:
        staging = Path(temporary)
        if payload_dir is not None:
            shutil.copytree(payload_dir, staging / "payload", symlinks=True)
        else:
            (staging / "payload").mkdir()
        metadata = staging / "payload" / ".npack"
        metadata.mkdir(parents=True, exist_ok=True)

        init = subprocess.run(
            [
                bin_path,
                "init",
                str(staging / "payload"),
                "--name",
                artifact_name,
                "--version",
                artifact_version,
                "--publisher",
                publisher,
                *(("--os", os_name) if os_name else ()),
                *(("--arch", arch) if arch else ()),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if init.returncode != 0:
            raise PackageError(f"npack init failed: {init.stderr.strip() or init.stdout.strip()}")

        # Project package.toml's [install_inputs.*] into npack's own signed
        # app.install_inputs descriptor array (see docs/package-setup.md in
        # the npack submodule). npack transports/validates presence only -
        # `bind` (which resource field a value fills) is nostrhost-local and
        # never leaves this manifest; only id/type/required/sensitive/
        # description/constraints are signed into the release.
        npack_manifest_path = metadata / "manifest.json"
        try:
            npack_manifest = json.loads(npack_manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PackageError(f"cannot read npack manifest after init: {exc}") from exc
        npack_manifest.setdefault("app", {})["install_inputs"] = [
            {
                "id": input_id,
                "value_type": f"nostrhost:{field['type']}",
                "required": bool(field.get("required", False)),
                "sensitive": bool(field.get("sensitive", False)),
                "description": field.get("description") or None,
                "constraints": field.get("constraints") or {},
            }
            for input_id, field in package_data.get("install_inputs", {}).items()
        ]
        if repo is not None:
            npack_manifest["repo"] = repo
        if commit is not None:
            npack_manifest["commit"] = commit
        npack_manifest_path.write_text(json.dumps(npack_manifest), encoding="utf-8")

        embedded = metadata / "nostrhost" / "manifest.json"
        embedded.parent.mkdir(parents=True, exist_ok=True)
        embedded.write_bytes(_canonical_json(package_data))

        pack = subprocess.run(
            [bin_path, "pack", str(staging / "payload"), "--output", str(output)],
            text=True,
            capture_output=True,
            check=False,
        )
        if pack.returncode != 0:
            raise PackageError(f"npack pack failed: {pack.stderr.strip() or pack.stdout.strip()}")

        digest = subprocess.run(
            [bin_path, "hash", str(output)], text=True, capture_output=True, check=False
        )
        if digest.returncode != 0:
            raise PackageError(f"npack hash failed: {digest.stderr.strip() or digest.stdout.strip()}")
        artifact_sha256 = digest.stdout.strip()

    return {
        "artifact": str(output),
        "sha256": artifact_sha256,
        "publisher": publisher,
        "name": artifact_name,
        "version": artifact_version,
        "os": os_name,
        "arch": arch,
        "npack": npack_version,
        "embedded_manifest": NPK_NATIVE_MANIFEST,
    }


@app.command("build-npk")
def build_npk(
    package_file: Path = typer.Argument(..., help="Path to package.toml."),
    payload: Optional[Path] = typer.Option(None, "--payload", "-p", help="Directory copied into the archive at host-relative paths (web/app payload)."),
    output: Path = typer.Option(Path("package.npk"), "--output", "-o", help="Output .npk artifact path."),
    publisher: str = typer.Option(..., "--publisher", help="Publisher npub or 64-character hex public key."),
    name: Optional[str] = typer.Option(None, "--name", help="npack package name (default: the manifest app id)."),
    version: Optional[str] = typer.Option(None, "--version", help="SemVer release version (default: the manifest app version)."),
    os_name: Optional[str] = typer.Option(None, "--os", help="Target OS override (default: host)."),
    arch: Optional[str] = typer.Option(None, "--arch", help="Target architecture override (default: host)."),
    npack_bin: str = typer.Option("", "--npack", help="Path to the npack binary (default: $NPACK_BIN or npack on PATH)."),
    repo: Optional[str] = typer.Option(None, "--repo", help="Source repository as a NIP-34 kind:30617 address '30617:<pubkey>:<identifier>' (npack itself rejects any other format), signed into the release (required for nostrhost-catalog attestation to apply to this release)."),
    commit: Optional[str] = typer.Option(None, "--commit", help="Source commit, signed into the release (required for nostrhost-catalog attestation to apply to this release)."),
) -> None:
    """Build a deterministic, content-addressed .npk artifact for a package."""
    package, diagnostics = _load_and_validate(package_file)
    if diagnostics or package is None:
        typer.echo(json.dumps({"schema": 1, "valid": False, "diagnostics": diagnostics}, indent=2, sort_keys=True), err=True)
        raise typer.Exit(1)
    try:
        with package_file.open("rb") as stream:
            package_data = tomllib.load(stream)
        result = build_npk_artifact(
            package_data,
            payload_dir=payload,
            output=output,
            publisher=publisher,
            name=name,
            version=version,
            os_name=os_name,
            arch=arch,
            npack_bin=npack_bin,
            repo=repo,
            commit=commit,
        )
    except PackageError as exc:
        typer.echo(json.dumps({"schema": 1, "valid": False, "error": str(exc)}, indent=2, sort_keys=True))
        raise typer.Exit(1)
    typer.echo(json.dumps(result, indent=2, sort_keys=True))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
