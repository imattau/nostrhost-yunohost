"""Compatibility-file rendering for the WP4 list projection.

The list projection is authoritative; these helpers keep the *derived*
compatibility files other services already read in sync, and are pure
functions of one :class:`~nostrhost.list_projection.ListEntry`:

* ``trusted-publishers`` → the ``NOSTRHOST_CATALOG_PUBLISHERS`` line in
  ``/etc/nostrhost/catalogue.env`` (the catalogue synchroniser's trust list);
* ``portal-settings`` → merges the server admin's portal appearance keys into
  each per-domain ``/etc/nostrhost/portal/<domain>.json`` **without** touching
  the ``apps`` key (which stays owned by the permission projection).

The other families need no derived file: approved repositories and blocked
relays are merged at read time, and user preferences are read on demand.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("nostr-list-render")

CATALOGUE_ENV = "/etc/nostrhost/catalogue.env"
PORTAL_SETTINGS_DIR = "/etc/nostrhost/portal"

#: Keys in a portal-settings document that are legitimate portal appearance
#: settings; anything else is ignored so a settings document cannot smuggle
#: arbitrary keys into the portal file.
PORTAL_SETTING_KEYS = frozenset(
    {
        "portal_logo",
        "portal_theme",
        "portal_tile_theme",
        "portal_title",
        "show_other_domains_apps",
        "enable_public_apps_page",
        "portal_allow_edit_email",
        "portal_allow_edit_email_alias",
        "portal_allow_edit_email_forward",
        "mandatory_restrictions",
    }
)


def render_entry(entry: Any) -> None:
    """Dispatch one changed coordinate to its family renderer."""
    if entry.coordinate == "nostrhost:trusted-publishers":
        render_trusted_publishers(entry.entries)
    elif entry.coordinate == "nostrhost:portal-settings":
        render_portal_settings(entry.settings)


def render_trusted_publishers(pubkeys: list[str], *, path: str | Path = CATALOGUE_ENV) -> None:
    """Rewrite the trusted-publisher line of ``catalogue.env`` in place."""
    target = Path(path)
    lines: list[str] = []
    if target.is_file():
        lines = target.read_text(encoding="utf-8").splitlines()
    rendered = f"NOSTRHOST_CATALOG_PUBLISHERS={','.join(pubkeys)}"
    found = False
    for index, line in enumerate(lines):
        if line.startswith("NOSTRHOST_CATALOG_PUBLISHERS="):
            lines[index] = rendered
            found = True
            break
    if not found:
        lines.append(rendered)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(target, 0o600)


def render_portal_settings(
    settings: dict[str, Any],
    *,
    portal_dir: str | Path = PORTAL_SETTINGS_DIR,
) -> None:
    """Merge appearance keys into every per-domain portal file.

    The per-domain ``apps`` key is preserved verbatim: it belongs to the
    permission projection, not to the operator's appearance settings.
    """
    base = Path(portal_dir)
    if not base.is_dir():
        return
    clean = {key: value for key, value in settings.items() if key in PORTAL_SETTING_KEYS}
    for path in sorted(base.glob("*.json")):
        try:
            current = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.warning("ignoring unreadable portal settings file %s", path)
            continue
        if not isinstance(current, dict):
            continue
        merged = dict(current)
        merged.update(clean)
        _atomic_write_json(path, merged)


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    payload = json.dumps(data, sort_keys=True, indent=4).encode() + b"\n"
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".portal-")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
