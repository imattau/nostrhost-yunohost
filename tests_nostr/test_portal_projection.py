"""Portal projection: the per-domain ``apps`` dict the portal SPA renders.

With SSOwat retired, the portal settings live under ``/etc/nostrhost/portal``
(written by ``nostrhost.permissions.write_portal_projection`` from the same
permission list the Caddy authd projection reads). These tests cover the
build/write/read round-trip without touching real YunoHost state.
"""

from __future__ import annotations

import json

import pytest


def _fake_permissions() -> dict:
    return {
        "alpha.main": {
            "label": "Alpha",
            "url": "nostrhost.test/alpha",
            "additional_urls": [],
            "auth_header": True,
            "auth_request": False,
            "show_tile": True,
            "protected": False,
            "allowed": ["all_users", "visitors"],
            "corresponding_users": ["dave", "erin"],
            "order": 3,
            "logo_hash": "abc123",
        },
        "beta.main": {
            "label": "Beta",
            "url": "nostrhost.test/beta",
            "additional_urls": [],
            "auth_header": True,
            "show_tile": False,
            "allowed": ["all_users"],
            "corresponding_users": ["dave"],
        },
        "gamma.main": {
            "label": "Gamma",
            "url": None,
            "additional_urls": [],
            "auth_header": False,
            "show_tile": True,
            "allowed": ["all_users"],
            "corresponding_users": [],
        },
        "delta.main": {
            "label": "Delta",
            "url": "sub.lostcause.test/delta",
            "additional_urls": [],
            "auth_header": True,
            "show_tile": True,
            "description": "custom desc",
            "hide_from_public": True,
            "allowed": [],
            "corresponding_users": [],
        },
    }


def _install_yunohost_fakes(monkeypatch) -> None:
    """Wire the lazy yunohost imports used by the projection builders."""
    import yunohost.app as app_mod
    import yunohost.domain as domain_mod
    import yunohost.permission as perm_mod

    all_domains = ["nostrhost.test", "sub.lostcause.test", "other.lostcause.test"]
    portal_domains = ["nostrhost.test", "lostcause.test"]

    def fake_domain_list(*, exclude_subdomains=False):
        return {"domains": portal_domains if exclude_subdomains else all_domains}

    def fake_user_permission_list(*, full=False, ignore_system_perms=False, absolute_urls=False):
        return {"permissions": _fake_permissions()}

    def fake_manifest(app_id):
        return {"description": f"{app_id} catalog description"}

    def fake_catalog():
        return {"apps": {"alpha": {"logo_hash": "cataloghash"}}}

    monkeypatch.setattr(domain_mod, "domain_list", fake_domain_list)
    monkeypatch.setattr(perm_mod, "user_permission_list", fake_user_permission_list)
    monkeypatch.setattr(app_mod, "_get_manifest_of_app", fake_manifest)
    monkeypatch.setattr(app_mod, "_load_apps_catalog", fake_catalog)


def test_build_portal_projection_filters_and_groups(monkeypatch):
    _install_yunohost_fakes(monkeypatch)

    from nostrhost.permissions import build_portal_projection

    result = build_portal_projection()

    # show_tile=False and no-url perms are filtered out.
    assert set(result["nostrhost.test"]) == {"alpha.main"}
    assert "beta.main" not in result["nostrhost.test"]
    assert "gamma.main" not in result["nostrhost.test"]

    alpha = result["nostrhost.test"]["alpha.main"]
    assert alpha == {
        "label": "Alpha",
        "users": ["dave", "erin"],
        "public": True,
        "url": "nostrhost.test/alpha",
        "description": "alpha catalog description",
        "order": 3,
        "logo": "/nostrhost/sso/applogos/abc123.png",
    }

    # Subdomain URL is grouped under the top-level portal domain.
    assert set(result["lostcause.test"]) == {"delta.main"}
    delta = result["lostcause.test"]["delta.main"]
    assert delta["public"] is False
    assert delta["hide_from_public"] is True
    assert delta["description"] == "custom desc"


def test_build_portal_projection_logo_falls_back_to_main_perm(monkeypatch):
    _install_yunohost_fakes(monkeypatch)
    import os

    import yunohost.permission as perm_mod

    # Catalog lookup is gated on the real-server /etc/yunohost/installed marker.
    orig_exists = os.path.exists
    monkeypatch.setattr(
        os.path,
        "exists",
        lambda p: True if p == "/etc/yunohost/installed" else orig_exists(p),
    )

    perms = _fake_permissions()
    perms["alpha.main"]["logo_hash"] = None
    perms["alpha.main"]["hide_from_public"] = True
    monkeypatch.setattr(
        perm_mod, "user_permission_list", lambda **kw: {"permissions": perms}
    )

    from nostrhost.permissions import build_portal_projection

    result = build_portal_projection()
    # No perm logo -> catalog default for the base id.
    assert result["nostrhost.test"]["alpha.main"]["logo"] == "/nostrhost/sso/applogos/cataloghash.png"


def test_write_portal_projection_preserves_options_and_cleans_stale(tmp_path, monkeypatch):
    _install_yunohost_fakes(monkeypatch)
    import yunohost.settings as settings_mod

    from nostrhost import permissions

    monkeypatch.setattr(permissions, "PORTAL_SETTINGS_DIR", str(tmp_path))

    (tmp_path / "nostrhost.test.json").write_text(
        json.dumps({"portal_title": "Mine", "apps": {"stale.main": {}}}),
        encoding="utf-8",
    )
    (tmp_path / "removed.test.json").write_text(
        json.dumps({"apps": {"old.main": {}}}), encoding="utf-8"
    )

    monkeypatch.setattr(
        settings_mod,
        "settings_get",
        lambda *a, **kw: {
            "security.portal.portal_allow_edit_email": "yes",
            "security.portal.portal_allow_edit_email_alias": "no",
            "misc.network.dns_exposure": "both",
        },
    )

    permissions.write_portal_projection()

    native = json.loads((tmp_path / "nostrhost.test.json").read_text())
    assert native["portal_title"] == "Mine"  # config-panel option preserved
    assert native["apps"]["alpha.main"]["label"] == "Alpha"
    assert native["security.portal.portal_allow_edit_email"] == "yes"
    assert "stale.main" not in native["apps"]

    assert not (tmp_path / "removed.test.json").exists()  # stale domain cleaned up


def test_write_permissions_projection_regenerates_portal(monkeypatch, tmp_path):
    from nostrhost import permissions

    calls = []

    monkeypatch.setattr(
        permissions,
        "build_permissions_projection",
        lambda: {"permissions": {"core_skipped": {"users": []}}},
    )
    monkeypatch.setattr(
        permissions, "write_portal_projection", lambda *a, **kw: calls.append(True)
    )

    out = tmp_path / "permissions.json"
    changed = permissions.write_permissions_projection(path=out, on_change=False)

    assert changed is True
    assert json.loads(out.read_text())["permissions"]["core_skipped"]["users"] == []
    assert calls == [True]


def test_write_permissions_projection_regenerates_portal_even_when_unchanged(
    monkeypatch, tmp_path
):
    """The portal projection (show_tile, labels, urls) can drift independently
    of the authd map, so it must refresh even when permissions.json matches."""
    from nostrhost import permissions

    calls = []
    out = tmp_path / "permissions.json"
    out.write_bytes(
        json.dumps({"permissions": {"core_skipped": {"users": []}}}, indent=1, sort_keys=True).encode()
        + b"\n"
    )

    monkeypatch.setattr(
        permissions,
        "build_permissions_projection",
        lambda: {"permissions": {"core_skipped": {"users": []}}},
    )
    monkeypatch.setattr(
        permissions, "write_portal_projection", lambda *a, **kw: calls.append(True)
    )

    # on_change=True + identical file -> early return, but portal still refreshed.
    assert permissions.write_permissions_projection(path=out) is False
    assert calls == [True]


def test_write_permissions_projection_survives_portal_failure(monkeypatch, tmp_path, caplog):
    from nostrhost import permissions

    def _boom():
        raise RuntimeError("portal write failed")

    monkeypatch.setattr(
        permissions,
        "build_permissions_projection",
        lambda: {"permissions": {}},
    )
    monkeypatch.setattr(permissions, "write_portal_projection", _boom)

    out = tmp_path / "permissions.json"
    # The authd projection must still be written even if the portal side fails.
    assert permissions.write_permissions_projection(path=out, on_change=False) is True
    assert "failed to regenerate portal projection" in caplog.text


def test_portal_settings_reads_native_dir(tmp_path, monkeypatch):
    from nostrhost import portal_settings

    monkeypatch.setattr(portal_settings, "PORTAL_SETTINGS_DIR", str(tmp_path))

    (tmp_path / "nostrhost.test.json").write_text(
        json.dumps(
            {
                "portal_title": "Native",
                "show_other_domains_apps": False,
                "apps": {
                    "alpha.main": {"label": "Alpha", "users": ["dave"], "public": False},
                    "beta.main": {"label": "Beta", "users": [], "public": True},
                },
            }
        ),
        encoding="utf-8",
    )

    # No signed-in user and not a public portal -> no apps exposed.
    settings = portal_settings._portal_settings("nostrhost.test")
    assert settings["portal_title"] == "Native"
    assert settings["apps"] == {}

    # Signed-in user sees only apps they're a member of (plus public ones).
    for_me = portal_settings._portal_settings("nostrhost.test", username="dave")
    assert set(for_me["apps"]) == {"alpha.main", "beta.main"}
    for_other = portal_settings._portal_settings("nostrhost.test", username="erin")
    assert set(for_other["apps"]) == {"beta.main"}