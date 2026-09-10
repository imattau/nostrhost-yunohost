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
    if not isinstance(raw, list):
        return {}

    apps: dict[str, dict[str, Any]] = {}
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
            "git": {"url": repository, "revision": commit},
            "repository": "nostrhost",
            "source": "nostr",
        }
    return apps
