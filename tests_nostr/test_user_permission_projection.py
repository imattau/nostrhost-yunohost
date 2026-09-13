"""_regen_native_permissions_projection is the fix for a real staleness gap
(roadmap §25 phase 3): user_create/delete/update/import and
user_permission_update() all regenerated the legacy /etc/ssowat/conf.json
via app_ssowatconf() but never refreshed the native
/etc/nostrhost/permissions.json the Caddy authd (and this plan's NIP-51
merge) actually reads -- silently relying on nostr_login's legacy-conf
fallback instead. These tests cover the helper itself; the 5 call sites in
user.py are exercised indirectly by the (moulinette-era, currently
uncollectable) legacy suite -- see docs/LDAP-RETIREMENT.md.
"""

from __future__ import annotations

import sys
import types

import pytest


def test_regen_native_permissions_projection_calls_write(monkeypatch):
    import yunohost.user as user_module

    calls = []
    fake_module = types.ModuleType("nostrhost.permissions")
    fake_module.write_permissions_projection = lambda: calls.append(True)
    monkeypatch.setitem(sys.modules, "nostrhost.permissions", fake_module)

    user_module._regen_native_permissions_projection()

    assert calls == [True]


def test_regen_native_permissions_projection_swallows_errors(monkeypatch, caplog):
    import yunohost.user as user_module

    def _boom():
        raise RuntimeError("projection write failed")

    fake_module = types.ModuleType("nostrhost.permissions")
    fake_module.write_permissions_projection = _boom
    monkeypatch.setitem(sys.modules, "nostrhost.permissions", fake_module)

    user_module._regen_native_permissions_projection()  # must not raise
