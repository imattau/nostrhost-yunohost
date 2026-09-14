"""Native permission projection for the Caddy authd (SSOwat retirement).

The authd (``nostr_login.auth_request_route``) needs the permission map that
SSOwat used to read from ``/etc/ssowat/conf.json``. With SSOwat retired, the
permission *source of truth* is YunoHost's own permission system
(``user_permission_list`` + app settings); this module rebuilds the same
``permissions`` projection as a root-owned, world-readable JSON file the
portal-api (running as an unprivileged user) can read cheaply -- the same
architecture as the old SSOwat conf, minus the SSOwat dependency.

The ``PermissionProvider`` regenerates the projection after every native
permission operation; the authd reads it with a fallback to the legacy
``/etc/ssowat/conf.json`` during the transition.

Membership additionally merges in NIP-51 permission-list grants (see
``nostrhost.nip51_permissions``, roadmap §25 Phase 2) -- additively, on top
of the LDAP-sourced membership, never replacing it. See
``docs/LDAP-RETIREMENT.md``.
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("nostr-permissions")

DEFAULT_PROJECTION = Path("/etc/nostrhost/permissions.json")

PORTAL_SETTINGS_DIR = "/etc/nostrhost/portal"

WELL_KNOWN_PUBLIC_URIS = (
    r"re:^[^/]*/502\.html$",
    r"re:^[^/]*/\.well-known/ynh-diagnosis/.*$",
    r"re:^[^/]*/\.well-known/acme-challenge/.*$",
    r"re:^[^/]*/\.well-known/autoconfig/mail/config-v1\.1\.xml.*$",
)


def _as_bool(value: Any) -> bool:
    return value not in (False, "False", "false", "0", 0, None)


def build_permissions_projection() -> dict[str, Any]:
    """Rebuild the permission map the authd consumes, mirroring
    ``app_ssowatconf``'s permission section without writing the SSOwat conf."""
    from yunohost.app import _get_app_settings
    from yunohost.domain import domain_list
    from yunohost.permission import user_permission_list

    domains = domain_list()["domains"]

    permissions: dict[str, Any] = {
        "core_skipped": {
            "users": [],
            "auth_header": False,
            "public": True,
            "uris": [
                *(f"{domain}/admin" for domain in domains),
                *(f"{domain}/nostrhost/api" for domain in domains),
                *(f"{domain}/nostrhost/portalapi" for domain in domains),
                *WELL_KNOWN_PUBLIC_URIS,
            ],
        }
    }

    all_permissions = user_permission_list(
        full=True, ignore_system_perms=True, absolute_urls=True
    )["permissions"]

    for perm_name, perm_info in all_permissions.items():
        uris = list(
            filter(None, [perm_info.get("url"), *perm_info.get("additional_urls", [])])
        )
        if not uris:
            continue

        app_id = perm_name.split(".")[0]
        auth_header = False
        try:
            app_settings = _get_app_settings(app_id)
            if _as_bool(perm_info.get("auth_header")):
                auth_header = app_settings.get("auth_header", "basic-with-password")
        except Exception as exc:  # app not installed yet / settings unavailable
            logger.warning("skipping auth_header resolution for %s: %s", perm_name, exc)

        permissions[perm_name] = {
            "users": perm_info.get("corresponding_users", []),
            "auth_header": auth_header,
            "auth_request": _as_bool(perm_info.get("auth_request", False)),
            "public": "visitors" in (perm_info.get("allowed") or []),
            "uris": uris,
        }

    _merge_nip51_grants(permissions)

    return {"permissions": permissions}


def _merge_nip51_grants(permissions: dict[str, Any]) -> None:
    """Best-effort merge of NIP-51 permission-list grants into ``permissions``.

    Never raises: an unavailable identity store or permission-grant store
    (e.g. before either has been initialised on a fresh install) must not
    break the LDAP-sourced projection this function is called from.
    """
    try:
        from nostrhost.nip51_permissions import PermissionStore, merge_projection
        from yunohost.nostr_identity import resolve_pubkey

        merge_projection(permissions, PermissionStore(), resolve_pubkey=resolve_pubkey)
    except Exception as exc:  # noqa: BLE001 - additive projection must not break the build
        logger.debug("skipping NIP-51 permission merge: %s", exc)


def build_portal_projection() -> dict[str, dict[str, dict[str, Any]]]:
    """Build the per-portal-domain ``apps`` dict the portal SPA renders.

    Mirrors ``app_ssowatconf``'s portal section: one entry per permission with
    a URL and ``show_tile`` set, carrying ``label``/``users``/``public``/
    ``url``/``description``/``order`` plus ``hide_from_public`` and ``logo``
    when declared. Grouped by the top-level portal domain so the portal SPA
    (which fetches ``/public``) can serve each domain's tiles.
    """
    from yunohost.app import _get_manifest_of_app, _load_apps_catalog
    from yunohost.domain import domain_list
    from yunohost.permission import user_permission_list

    portal_domains = domain_list(exclude_subdomains=True)["domains"]

    all_permissions = user_permission_list(
        full=True, ignore_system_perms=True, absolute_urls=True
    )["permissions"]

    # Apps can opt out of the catalog lookup during postinstall (no network).
    try:
        apps_catalog = _load_apps_catalog()["apps"] if os.path.exists("/etc/yunohost/installed") else {}
    except Exception as exc:  # noqa: BLE001 - default logo is optional
        logger.warning("skipping catalog logo lookup: %s", exc)
        apps_catalog = {}

    portal_domains_apps: dict[str, dict[str, dict[str, Any]]] = {
        domain: {} for domain in portal_domains
    }

    for perm_name, perm_info in all_permissions.items():
        uris = list(
            filter(None, [perm_info.get("url"), *perm_info.get("additional_urls", [])])
        )
        # No URL -> nothing to tile; show_tile falsy -> hidden from the portal.
        if not uris or not perm_info.get("show_tile", False):
            continue

        app_id = perm_name.split(".")[0]
        app_domain = uris[0].split("/")[0]
        app_portal_domain = next(
            domain for domain in portal_domains if domain in app_domain
        )

        app_portal_info: dict[str, Any] = {
            "label": perm_info["label"],
            "users": perm_info["corresponding_users"],
            "public": "visitors" in (perm_info.get("allowed") or []),
            "url": uris[0],
            "description": perm_info.get("description")
            or _get_manifest_of_app(app_id)["description"],
            "order": perm_info.get("order", 100),
        }
        if perm_info.get("hide_from_public"):
            app_portal_info["hide_from_public"] = True

        # Logo may be customized via the perm setting, otherwise the default
        # logo from the main permission or the catalog.
        app_base_id = app_id.split("__")[0]
        logo_hash = (
            perm_info.get("logo_hash")
            or all_permissions.get(f"{app_id}.main", {}).get("logo_hash")
            or apps_catalog.get(app_base_id, {}).get("logo_hash")
        )
        if logo_hash:
            app_portal_info["logo"] = f"/nostrhost/sso/applogos/{logo_hash}.png"

        portal_domains_apps[app_portal_domain][perm_name] = app_portal_info

    return portal_domains_apps


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    import json

    path.parent.mkdir(parents=True, exist_ok=True)
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


def write_portal_projection(
    portal_domains_apps: dict[str, dict[str, dict[str, Any]]] | None = None,
) -> None:
    """Write the per-domain portal settings files to ``PORTAL_SETTINGS_DIR``.

    The ``apps`` key is regenerated from the permission projection; every
    other key already in a domain's file (theme/title/intro written by the
    domain config panel) is preserved. Stale files for removed domains are
    cleaned up, mirroring what ``app_ssowatconf`` used to do for the retired
    ``/etc/yunohost/portal`` location.
    """
    from yunohost.settings import settings_get
    from yunohost.utils.file_utils import read_json

    import json

    if portal_domains_apps is None:
        portal_domains_apps = build_portal_projection()

    portal_email_settings = {
        k: v
        for k, v in settings_get("security.portal", export=True).items()
        if "allow_edit_email" in k
    }

    base = Path(PORTAL_SETTINGS_DIR)

    for domain, apps in portal_domains_apps.items():
        portal_settings: dict[str, Any] = {}
        portal_settings_path = base / f"{domain}.json"
        if portal_settings_path.exists():
            portal_settings.update(read_json(str(portal_settings_path)))
        portal_settings.update(portal_email_settings)
        # Never override anything other than "apps": the file is shared with
        # the domain config panel's portal options.
        portal_settings["apps"] = apps
        payload = json.dumps(portal_settings, sort_keys=True, indent=4).encode() + b"\n"
        try:
            if portal_settings_path.exists() and portal_settings_path.read_bytes() == payload:
                continue
        except OSError:
            pass
        _atomic_write_json(portal_settings_path, portal_settings)

    # Cleanup stale files from possibly old domains.
    for setting_file in base.iterdir():
        if setting_file.name.endswith(".json"):
            domain = setting_file.name[: -len(".json")]
            if domain not in portal_domains_apps:
                setting_file.unlink()


def write_permissions_projection(
    path: Path = DEFAULT_PROJECTION, *, on_change: bool = True
) -> bool:
    """Atomically write the projection JSON, world-readable.

    Also regenerates the portal ``apps`` projection (``write_portal_projection``)
    so the authd map and the portal tiles never drift. The portal projection is
    refreshed on every call -- before the ``on_change`` early return -- because
    its content (show_tile, labels, urls) can change independently of the authd
    map's serialized form. Returns True when the file was (re)written, False
    when it already matched (``on_change``). Never raises on a stale/no-op
    rebuild.
    """
    import json

    projection = build_permissions_projection()
    payload = json.dumps(projection, indent=1, sort_keys=True).encode() + b"\n"

    # The portal tiles are a presentation of the same permission map; a
    # failure here must not break the authd's critical projection.
    try:
        write_portal_projection()
    except Exception as exc:  # noqa: BLE001 - portal projection is non-critical
        logger.error("failed to regenerate portal projection: %s", exc)

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if on_change and path.exists() and path.read_bytes() == payload:
            return False
    except OSError:
        pass

    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".permissions-")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    logger.info("wrote permission projection to %s", path)
    return True
