"""Portal settings + session routes for the portal-api (authd, 127.0.0.1:6788).

The portal SPA fetches its boot settings from ``/nostrhost/portalapi/public``
and the signed-in user from ``/nostrhost/portalapi/me``. With SSOwat and the
moulinette portal-api retired, the portal-api serves these straight from the
native permission projection (``nostrhost.permissions``) + the native account
store — no LDAP, no on-disk portal settings file required. The per-domain
``apps`` projection (and the domain config panel's portal options) live under
``/etc/nostrhost/portal`` (written by ``nostrhost.permissions.write_portal_projection``).
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("nostr-portal-settings")

PORTAL_SETTINGS_DIR = "/etc/nostrhost/portal"


def _host_domain(host: str) -> str:
    head, _, tail = host.rpartition(":")
    return head if tail.isdigit() else host


def _default_settings(domain: str) -> dict[str, Any]:
    return {
        "apps": {},
        "public": False,
        "portal_logo": "",
        "portal_theme": "system",
        "portal_tile_theme": "simple",
        "portal_title": "NostrHost",
        "show_other_domains_apps": True,
        "domain": domain,
        "portal_allow_edit_email": False,
        "portal_allow_edit_email_alias": False,
        "portal_allow_edit_email_forward": False,
    }


def _portal_settings(domain: str, username: str | None = None) -> dict[str, Any]:
    """Build the portal settings/apps dict for ``domain``.

    Mirrors the retired ``portal._get_portal_settings``: load the per-domain
    settings file if present (domain config panel writes it), then overlay the
    native permission projection's apps, filtered by visibility.
    """
    import glob
    from pathlib import Path

    from yunohost.utils.file_utils import read_json

    settings = _default_settings(domain)

    portal_settings_path = Path(f"{PORTAL_SETTINGS_DIR}/{domain}.json")
    if portal_settings_path.exists():
        settings.update(read_json(str(portal_settings_path)))
        settings["public"] = bool(settings.pop("enable_public_apps_page", False))

    apps: dict[str, Any] = settings.pop("apps", {})
    settings["apps"] = {}

    if settings["show_other_domains_apps"]:
        for path in glob.glob(f"{PORTAL_SETTINGS_DIR}/*.json"):
            if path != str(portal_settings_path):
                path_dict = read_json(path)
                apps.update(path_dict.get("apps", {}))

    if username:
        settings["apps"] = {
            app: infos
            for app, infos in apps.items()
            if username in infos.get("users", []) or infos.get("public")
        }
    elif settings["public"]:
        settings["apps"] = {
            app: infos
            for app, infos in apps.items()
            if infos.get("public") and not infos.get("hide_from_public")
        }

    settings["apps"] = dict(
        sorted(
            settings["apps"].items(),
            key=lambda v: (v[1].get("order", 100), v[0]),
        )
    )
    return settings


def portal_public_route():
    """GET /nostrhost/portalapi/public — boot settings for the portal SPA.

    Always public (the login page itself needs it); when the visitor is not
    signed in, drop the per-user intro and never leak the users list.
    """
    from bottle import request

    from yunohost.nostr_account import _session_username

    domain = _host_domain(request.get_header("host") or "")
    settings = _portal_settings(domain, username=_session_username())

    for infos in settings["apps"].values():
        infos.pop("users", None)

    return settings


def portal_me_route():
    """GET /nostrhost/portalapi/me — the signed-in user (or 401)."""
    from bottle import HTTPResponse, request

    from yunohost.nostr_account import _session_username
    from yunohost.nostrhost.accounts import user_get

    username = _session_username()
    if not username:
        raise HTTPResponse("not signed in", 401)

    record = user_get(username) or {}
    domain = _host_domain(request.get_header("host") or "")
    apps = _portal_settings(domain, username=username)["apps"]
    for infos in apps.values():
        infos.pop("users", None)

    groups = list(record.get("groups", []))
    for skip in ("all_users", "admins", "visitors"):
        if skip in groups:
            groups.remove(skip)

    return {
        "username": username,
        "fullname": record.get("fullname", username),
        "mail": (record.get("mail") or [None])[0],
        "mailalias": list(record.get("mail", []))[1:],
        "mailforward": [],
        "admin": bool(record.get("admin", False)),
        "groups": groups,
        "apps": apps,
    }