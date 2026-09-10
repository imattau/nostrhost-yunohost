"""Read-only bridge from the native Nostr catalogue projection to YunoHost.

The Go synchronizer owns event validation and trust. This adapter only reads
its derived JSON projection and maps accepted declarations into the shape
the existing installer/catalogue consumers already understand.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

DEFAULT_NATIVE_CATALOG_STATE = "/var/lib/nostrhost/catalogue.json"
ATTESTATION_MODE_ENV = "NOSTRHOST_CATALOG_ATTESTATION_MODE"


def native_catalog_state_path() -> Path:
    return Path(os.environ.get("NOSTRHOST_CATALOG_STATE", DEFAULT_NATIVE_CATALOG_STATE))


def load_native_catalog(path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    """Return trusted native declarations in YunoHost app-catalog format.

    Missing or malformed state is treated as an unavailable optional source;
    the established YunoHost catalogue remains authoritative in that case.
    """
    state_path = Path(path or native_catalog_state_path())
    try:
        raw = json.loads(state_path.read_text())
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {}
    attestations = raw.get("attestations", []) if isinstance(raw, dict) else []
    if isinstance(raw, dict):
        raw = raw.get("entries", [])
    if not isinstance(raw, list):
        return {}

    apps: dict[str, dict[str, Any]] = {}
    mode = os.environ.get(ATTESTATION_MODE_ENV, "off").strip().lower()
    if mode not in {"off", "prefer", "require"}:
        mode = "off"
    for item in raw:
        if not isinstance(item, dict):
            continue
        declaration = item.get("declaration")
        if not isinstance(declaration, dict):
            continue
        app_id = declaration.get("AppID")
        repository = declaration.get("Repository")
        version = declaration.get("Version")
        commit = declaration.get("Commit")
        if not all(isinstance(value, str) and value for value in (app_id, repository, version, commit)):
            continue
        verified = _has_passing_attestation(declaration, attestations)
        if mode == "require" and not verified:
            continue
        apps[app_id] = {
            "manifest": {
                "id": app_id,
                "version": version,
                "name": {"en": declaration.get("Name") or app_id},
                "description": {"en": declaration.get("Description") or ""},
                "integration": {"architectures": declaration.get("Architectures") or []},
            },
            "level": -1,
            "state": "working",
            "git": {
                "url": repository,
                "branch": "main",
                "revision": commit,
                **({"path": declaration["PackagePath"]} if declaration.get("PackagePath") else {}),
            },
            "repository": "nostrhost",
            "source": "nostr",
            "native": {
                "app_id": app_id,
                "version": version,
                "repository": repository,
                "revision": commit,
                "manifest_sha256": declaration.get("ManifestHash", ""),
                "content_sha256": declaration.get("ContentHash", ""),
                "architectures": declaration.get("Architectures") or [],
                "package_path": declaration.get("PackagePath", "package.toml"),
                "event_id": item.get("event_id", ""),
            },
            **({"nostr_verified": verified} if mode == "prefer" else {}),
        }
    return apps


def native_catalog_coordinate(app_id: str, path: str | Path | None = None) -> dict[str, Any] | None:
    """Return signed package provenance for the resource-engine handoff."""
    entry = load_native_catalog(path).get(app_id)
    if not entry or not isinstance(entry.get("native"), dict):
        return None
    native = entry["native"]
    return {
        "app_id": native.get("app_id", app_id),
        "version": native.get("version"),
        "repository": native.get("repository"),
        "revision": native.get("revision"),
        "package_path": native.get("package_path", "package.toml"),
        "manifest_sha256": native.get("manifest_sha256", ""),
        "content_sha256": native.get("content_sha256", ""),
        "architectures": native.get("architectures", []),
        "event_id": native.get("event_id", ""),
    }


def _has_passing_attestation(declaration: dict[str, Any], attestations: Any) -> bool:
    """Match persisted daemon attestations to the complete declaration identity."""
    if not isinstance(attestations, list):
        return False
    for item in attestations:
        if not isinstance(item, dict):
            continue
        attestation = item.get("attestation")
        if not isinstance(attestation, dict):
            continue
        if (
            attestation.get("AppID") == declaration.get("AppID")
            and attestation.get("Repository") == declaration.get("Repository")
            and attestation.get("Commit") == declaration.get("Commit")
            and attestation.get("ManifestHash") == declaration.get("ManifestHash")
            and attestation.get("ContentHash") == declaration.get("ContentHash")
            and attestation.get("Result") == "pass"
        ):
            return True
    return False
