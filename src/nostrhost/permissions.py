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


def write_permissions_projection(
    path: Path = DEFAULT_PROJECTION, *, on_change: bool = True
) -> bool:
    """Atomically write the projection JSON, world-readable.

    Returns True when the file was (re)written, False when it already matched
    (``on_change``). Never raises on a stale/no-op rebuild.
    """
    import json

    projection = build_permissions_projection()
    payload = json.dumps(projection, indent=1, sort_keys=True).encode() + b"\n"

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
