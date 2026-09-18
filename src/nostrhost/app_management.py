"""Native application inventory and settings planning helpers."""

from __future__ import annotations

import copy
import os
import re
from pathlib import Path
from typing import Any

from .package_engine import PackageError, Operation, operation_plan_digest, package_plan_envelope, validate_plan_envelope

_APP_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")


def _app_id(value: str) -> str:
    if not isinstance(value, str) or value in {".", ".."} or not _APP_ID.fullmatch(value):
        raise PackageError("invalid app id")
    return value


def merge_catalogue_and_installed(catalogue: dict[str, Any], installed: dict[str, Any]) -> list[dict[str, Any]]:
    """Join trusted catalogue records and local installations without hiding orphans."""
    installed_apps = installed.get("apps", {}) if isinstance(installed, dict) else {}
    if not isinstance(installed_apps, dict):
        installed_apps = {}

    entries: dict[str, dict[str, Any]] = {}
    raw_entries = catalogue.get("entries", []) if isinstance(catalogue, dict) else []
    for item in raw_entries if isinstance(raw_entries, list) else []:
        declaration = item.get("declaration") if isinstance(item, dict) else None
        if not isinstance(declaration, dict):
            continue
        app_id = declaration.get("AppID") or declaration.get("app_id")
        if not isinstance(app_id, str) or not _APP_ID.fullmatch(app_id):
            continue
        # The projection can contain one accepted declaration per publisher.
        # Keep a deterministic record when multiple trusted publishers publish
        # the same app ID; catalogue resolution remains authoritative for install.
        previous = entries.get(app_id)
        created_at = item.get("created_at", 0)
        previous_created_at = previous.get("catalogue_created_at", 0) if previous else -1
        if previous and (created_at, str(item.get("event_id", ""))) <= (
            previous_created_at,
            str(previous.get("catalogue", {}).get("event_id", "")),
        ):
            continue
        entries[app_id] = {
            "id": app_id,
            "name": declaration.get("Name") or declaration.get("name") or app_id,
            "description": declaration.get("Description") or declaration.get("description") or "",
            "category": declaration.get("Category") or declaration.get("category") or "",
            "catalogue_version": declaration.get("Version") or declaration.get("version"),
            "catalogue": {
                "publisher": declaration.get("Publisher") or declaration.get("publisher"),
                "repository": declaration.get("Repository") or declaration.get("repository"),
                "revision": declaration.get("Commit") or declaration.get("commit"),
                "manifest_sha256": declaration.get("ManifestHash") or declaration.get("manifest_sha256"),
                "content_sha256": declaration.get("ContentHash") or declaration.get("content_sha256"),
                "package_path": declaration.get("PackagePath") or declaration.get("package_path", "package.toml"),
                "event_id": item.get("event_id"),
            },
            "catalogue_created_at": created_at,
        }

    for app_id, local in installed_apps.items():
        if not isinstance(app_id, str) or not _APP_ID.fullmatch(app_id) or not isinstance(local, dict):
            continue
        entry = entries.setdefault(app_id, {"id": app_id, "name": app_id, "description": "", "category": "", "catalogue_version": None, "catalogue": None})
        entry["installed"] = True
        entry["installed_version"] = local.get("version")
        entry["installation"] = {
            "native": bool(local.get("native")),
            "source": local.get("source") or local.get("repository"),
            "legacy": not bool(local.get("native")),
        }
        entry["movable"] = bool(local.get("movable"))
        # The app's served URL (domain + path), present for both native and
        # legacy entries; the management UI uses it to default the change-url
        # form's domain/path fields.
        entry["domain_path"] = local.get("domain_path") or None
        names = local.get("name")
        if entry.get("catalogue") is None:
            entry["name"] = names.get("en", app_id) if isinstance(names, dict) else (names or app_id)

    output: list[dict[str, Any]] = []
    for app_id, entry in entries.items():
        installed_here = entry.get("installed", False)
        catalog_version = entry.get("catalogue_version")
        installed_version = entry.get("installed_version")
        if not installed_here:
            status = "available"
        elif catalog_version and installed_version == catalog_version:
            status = "installed"
        elif catalog_version and installed_version:
            status = "version-differs"
        else:
            status = "installed-unlisted"
        output.append({**entry, "status": status, "installed": installed_here})
    return sorted(output, key=lambda row: (str(row.get("name", "")).casefold(), row["id"]))


def app_catalog_logo_urls() -> dict[str, str]:
    """Map app id -> portal logo URL from the YunoHost app catalogue.

    The catalogue stores a content hash per app; the logo itself is served at
    ``/nostrhost/sso/applogos/<hash>.png`` (see caddy_admin.build_portal_routes).
    Best-effort: the catalogue may be unavailable (before postinstall, or with
    no native projection), in which case callers fall back to a monogram.
    """
    if not os.path.exists("/etc/yunohost/installed"):
        return {}
    try:
        from yunohost.app_catalog import _load_apps_catalog

        apps = (_load_apps_catalog() or {}).get("apps", {})
    except Exception:  # noqa: BLE001 - logos are cosmetic
        return {}
    logos: dict[str, str] = {}
    for app_id, info in apps.items():
        if not isinstance(info, dict):
            continue
        logo_hash = info.get("logo_hash")
        if logo_hash:
            logos[str(app_id)] = f"/nostrhost/sso/applogos/{logo_hash}.png"
    return logos


def attach_app_logos(
    entries: list[dict[str, Any]],
    logos: dict[str, str],
) -> None:
    """Attach a ``logo`` URL to id-keyed app entries, in place.

    ``logos`` maps app id -> served logo URL (see ``app_catalog_logo_urls``).
    Falls back to the base id of a multi-instance app (``foo__2`` -> ``foo``)
    so every instance shares its catalogue logo. No-op for an empty map.
    """
    if not logos:
        return
    for entry in entries:
        app_id = entry.get("id")
        if not isinstance(app_id, str):
            continue
        logo = logos.get(app_id) or logos.get(app_id.split("__")[0])
        if logo:
            entry["logo"] = logo


def native_app_settings(app_id: str, *, state_dir: str | None = None) -> dict[str, Any]:
    """Read editable, non-secret settings declared by an installed native app."""
    app_id = _app_id(app_id)
    from .native_providers import installed_package_manifest

    manifest = installed_package_manifest(app_id, state_dir=Path(state_dir) if state_dir else None)
    if manifest is None or (manifest.get("app") or {}).get("id") != app_id:
        raise PackageError(f"native app {app_id!r} is not installed")
    settings = manifest.get("settings") or {}
    fields = settings.get("fields") or {}
    values = settings.get("values") or {}
    if not isinstance(fields, dict) or not isinstance(values, dict):
        raise PackageError("installed native app has invalid settings state")
    return {
        "app": {"id": app_id, "version": (manifest.get("app") or {}).get("version")},
        "fields": [
            {"key": key, **definition}
            for key, definition in sorted(fields.items())
            if isinstance(definition, dict) and not definition.get("secret")
        ],
        "values": {
            key: copy.deepcopy(value)
            for key, value in values.items()
            if isinstance(fields.get(key), dict) and not fields[key].get("secret")
        },
    }


def carry_forward_compatible_settings(installed: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    """Preserve user values across an upgrade only when the new field accepts them."""
    result = copy.deepcopy(candidate)
    old_settings = installed.get("settings") or {}
    new_settings = result.setdefault("settings", {})
    fields = new_settings.get("fields") or {}
    old_values = old_settings.get("values") or {}
    values = new_settings.setdefault("values", {})
    for key, field in fields.items():
        if isinstance(field, dict) and key not in values and field.get("default") is not None:
            values[key] = field["default"]
    for key, value in old_values.items():
        old_field = (old_settings.get("fields") or {}).get(key, {})
        new_field = fields.get(key, {})
        if not isinstance(new_field, dict) or new_field.get("secret") or old_field.get("type") != new_field.get("type"):
            continue
        value_type = new_field.get("type")
        valid = {
            "string": isinstance(value, str),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "number": isinstance(value, (int, float)) and not isinstance(value, bool),
            "boolean": isinstance(value, bool),
            "enum": isinstance(value, str) and value in new_field.get("choices", []),
        }.get(value_type, False)
        if valid:
            values[key] = value
    return result


def _check_domain_path_availability(
    app_id: str, domain: str, path: str, full_domain: bool, *, other_manifests: list[tuple[str, dict[str, Any]]]
) -> None:
    """Reject a domain/path placement that collides with another installed app.

    Two apps may share a domain only if neither claims it exclusively
    (``full_domain``) and they don't claim the exact same path. Used by both
    install (a fresh app has no existing route yet) and change-url (moving
    an existing one) so the two can't diverge on what's allowed.
    """
    if not domain:
        return
    domain = domain.rstrip("/")
    path = "/" + path.strip("/") if path.strip("/") else "/"
    for other_id, other_manifest in other_manifests:
        if other_id == app_id:
            continue
        other_web = other_manifest.get("web")
        if not isinstance(other_web, dict):
            continue
        other_domain = str(other_web.get("domain") or "").rstrip("/")
        if other_domain != domain:
            continue
        other_path = "/" + str(other_web.get("path") or "/").strip("/") if str(other_web.get("path") or "/").strip("/") else "/"
        other_full_domain = bool(other_web.get("full_domain"))
        if full_domain or other_full_domain:
            raise PackageError(
                f"{domain} is not available: {other_id!r} already uses it"
                f"{' exclusively (full_domain)' if other_full_domain else ''} and "
                f"{app_id!r} {'requires the whole domain' if full_domain else 'would collide with it'}"
            )
        if other_path == path:
            raise PackageError(f"{domain}{path} is already used by installed app {other_id!r}")


def plan_native_change_url(app_id: str, domain: str, path: str, *, state_dir: str | None = None) -> dict[str, Any]:
    """Build a server-derived package plan that moves a native app's web route.

    An installed app's own domain/path live at ``manifest.web.domain`` /
    ``manifest.web.path`` (WebResource), not under ``settings``. Reconciling
    a package re-emits ``web.route.ensure``/``permission.ensure`` from
    whatever ``web`` currently holds, and Caddy routes are keyed by app id
    (not domain+path), so writing a new domain/path here and reconciling
    moves the app's route in place - the same shape as
    ``plan_native_settings_update``, just mutating ``web`` instead of
    ``settings.values``.
    """
    app_id = _app_id(app_id)
    domain = str(domain or "").strip().rstrip("/")
    path = "/" + str(path or "/").strip("/") if str(path or "/").strip("/") else "/"
    if not domain:
        raise PackageError("change-url requires a non-empty domain")
    from .native_providers import installed_package_manifest

    manifest = installed_package_manifest(app_id, state_dir=Path(state_dir) if state_dir else None)
    if manifest is None or (manifest.get("app") or {}).get("id") != app_id:
        raise PackageError(f"native app {app_id!r} is not installed")
    web = manifest.get("web")
    if not isinstance(web, dict):
        raise PackageError(f"native app {app_id!r} has no web route to move")
    current_domain = str(web.get("domain") or "").rstrip("/")
    current_path = "/" + str(web.get("path") or "/").strip("/") if str(web.get("path") or "/").strip("/") else "/"
    if (domain, path) == (current_domain, current_path):
        raise PackageError("new domain/path is identical to the current one")

    from .cli import _iter_installed_manifests

    _check_domain_path_availability(
        app_id, domain, path, bool(web.get("full_domain")), other_manifests=_iter_installed_manifests()
    )

    updated = copy.deepcopy(manifest)
    updated["web"]["domain"] = domain
    updated["web"]["path"] = path

    try:
        envelope = package_plan_envelope(updated)
        operations = [Operation(**{**row, "depends_on": tuple(row.get("depends_on", ()))}) for row in envelope["operations"]]
    except (TypeError, ValueError) as exc:
        raise PackageError(f"invalid change-url plan: {exc}") from exc

    envelope["operations"] = [operation.json_dict() for operation in operations]
    envelope["plan_sha256"] = operation_plan_digest(operations)
    envelope["url_diff"] = {
        "old": {"domain": current_domain, "path": current_path},
        "new": {"domain": domain, "path": path},
    }
    validate_plan_envelope({key: value for key, value in envelope.items() if key != "url_diff"})
    return envelope


def catalogue_lifecycle_plan(app_id: str, action: str) -> dict[str, Any]:
    """Resolve and verify a trusted catalogue package for install or upgrade."""
    app_id = _app_id(app_id)
    if action not in {"install", "upgrade"}:
        raise PackageError("unsupported catalogue lifecycle action")
    from .cli import _coordinate_for, _load_package_data, _plan_envelope, _verify_package
    from .native_providers import installed_package_manifest

    installed = installed_package_manifest(app_id)
    if action == "install":
        from .cli import _TOOL_HANDLERS

        installed_apps = _TOOL_HANDLERS["app.list"]().get("apps", {})
        if app_id in installed_apps:
            raise PackageError(f"app {app_id!r} is already installed")
    if action == "upgrade" and installed is None:
        raise PackageError(f"native app {app_id!r} is not installed")
    coordinate = _coordinate_for(app_id)
    if not coordinate:
        raise PackageError(f"app {app_id!r} is not in the trusted native catalogue")
    try:
        package = _load_package_data(None, coordinate)
        _verify_package(package, coordinate)
        if package.get("app", {}).get("id") != app_id:
            raise PackageError("catalogue package id does not match the requested app")
        if action == "upgrade":
            installed_version = (installed.get("app") or {}).get("version")
            if installed_version == package.get("app", {}).get("version"):
                raise PackageError(f"native app {app_id!r} is already at the catalogue version")
            package = carry_forward_compatible_settings(installed, package)
        if action == "install":
            web = package.get("web")
            if isinstance(web, dict) and web.get("domain"):
                from .cli import _iter_installed_manifests

                _check_domain_path_availability(
                    app_id,
                    str(web.get("domain") or ""),
                    str(web.get("path") or "/"),
                    bool(web.get("full_domain")),
                    other_manifests=_iter_installed_manifests(),
                )
        return _plan_envelope(package, coordinate)
    except PackageError:
        raise
    except Exception as exc:  # noqa: BLE001 - surface fetch/parse failures as bounded API errors
        raise PackageError(f"could not build {action} plan for {app_id!r}: {exc}") from exc


def native_app_removal_plan(app_id: str) -> dict[str, Any]:
    """Build a removal plan only from the locally recorded native manifest."""
    app_id = _app_id(app_id)
    from .native_providers import installed_package_manifest
    from .package_engine import PackageManifest, plan_package_removal, validate_package

    manifest = installed_package_manifest(app_id)
    if manifest is None or (manifest.get("app") or {}).get("id") != app_id:
        raise PackageError(f"native app {app_id!r} is not installed")
    try:
        package = validate_package(PackageManifest.parse_obj(manifest))
        operations = plan_package_removal(package)
    except (TypeError, ValueError) as exc:
        raise PackageError(f"installed manifest for {app_id!r} cannot be removed safely: {exc}") from exc
    return {
        "schema": 1,
        "package": {"id": app_id, "version": package.app.version},
        "manifest_sha256": "",
        "plan_sha256": operation_plan_digest(operations),
        "operations": [operation.json_dict() for operation in operations],
    }


def plan_native_settings_update(app_id: str, values: dict[str, Any], *, state_dir: str | None = None) -> dict[str, Any]:
    """Build a server-derived package plan for a partial native settings update."""
    app_id = _app_id(app_id)
    if not isinstance(values, dict) or not values:
        raise PackageError("settings update requires a non-empty values object")
    from .native_providers import installed_package_manifest

    manifest = installed_package_manifest(app_id, state_dir=Path(state_dir) if state_dir else None)
    if manifest is None or (manifest.get("app") or {}).get("id") != app_id:
        raise PackageError(f"native app {app_id!r} is not installed")
    updated = copy.deepcopy(manifest)
    settings = updated.get("settings") or {}
    fields = settings.get("fields") or {}
    if not isinstance(fields, dict) or not fields:
        raise PackageError(f"native app {app_id!r} has no configurable settings")
    unknown = set(values) - set(fields)
    if unknown:
        raise PackageError("unknown app setting(s): " + ", ".join(sorted(unknown)))
    for key in values:
        if fields[key].get("secret"):
            raise PackageError(f"setting {key!r} is secret and cannot use the generic settings interface")
    current = settings.setdefault("values", {})
    changed = {key: value for key, value in values.items() if current.get(key) != value}
    if not changed:
        raise PackageError("settings are unchanged")
    current.update(changed)
    updated["settings"] = settings

    try:
        envelope = package_plan_envelope(updated)
        operations = [Operation(**{**row, "depends_on": tuple(row.get("depends_on", ()))}) for row in envelope["operations"]]
    except (TypeError, ValueError) as exc:
        raise PackageError(f"invalid app settings: {exc}") from exc

    # Settings are consumed by package-declared config templates. A service
    # restart is explicit and ordered after the rendered files, so the plan
    # preview shows the operational effect before approval.
    service = updated.get("service")
    if service and updated.get("config"):
        service_name = service.get("name") or app_id
        config_resources = tuple(operation.resource for operation in operations if operation.name == "config.ensure")
        operations.append(Operation(
            "service.restart",
            f"{app_id}:settings-restart",
            {"name": service_name},
            depends_on=config_resources or (f"{app_id}:service:start",),
            risk="medium",
            reversible=True,
            reverse="service.restart",
            summary=f"restart {service_name} after applying app settings",
        ))
        manifest_index = next(index for index, operation in enumerate(operations) if operation.name == "package.manifest.ensure")
        manifest_operation = operations[manifest_index]
        operations[manifest_index] = Operation(
            **{
                **manifest_operation.__dict__,
                "depends_on": tuple(dict.fromkeys((*manifest_operation.depends_on, f"{app_id}:settings-restart"))),
            }
        )
    envelope["operations"] = [operation.json_dict() for operation in operations]
    envelope["plan_sha256"] = operation_plan_digest(operations)
    envelope["settings_diff"] = [
        {"key": key, "old": (manifest.get("settings") or {}).get("values", {}).get(key), "new": value}
        for key, value in sorted(changed.items())
    ]
    validate_plan_envelope({key: value for key, value in envelope.items() if key != "settings_diff"})
    return envelope
