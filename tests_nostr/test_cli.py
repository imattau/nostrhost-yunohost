"""Native ``nostrhost`` Typer CLI tests (TOOLS + identity + capability).

The CLI talks to the native functions; here those are monkeypatched so no
real system service, relay, or key material is touched.  Structure/help and
argument parsing are tested against the real command tree.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from nostrhost import cli as cli_module


@pytest.fixture()
def app():
    return cli_module.build_app()


def _invoke(app, argv):
    return CliRunner().invoke(app, argv)


# --------------------------------------------------------------------------- #
# structure / help

def test_help_lists_native_groups(app):
    result = _invoke(app, ["--help"])
    assert result.exit_code == 0
    for group in ("system", "service", "app", "package", "rollback", "state", "identity", "capability"):
        assert group in result.stdout


def test_group_help_lists_commands(app):
    for group, commands in {
        "system": ["version"],
        "service": ["status", "restart", "control"],
        "app": ["list", "remove"],
        "package": ["plan", "reconcile"],
        "identity": ["link", "revoke", "list", "resolve"],
        "capability": ["grant", "delegate", "revoke"],
    }.items():
        result = _invoke(app, [group, "--help"])
        assert result.exit_code == 0
        for command in commands:
            assert command in result.stdout


def test_identity_is_npub_model_not_password():
    # no password/LDAP "user" group on the native surface; identity is npub-based
    app = cli_module.build_app()
    group_names = [g.name for g in app.registered_groups]
    assert "user" not in group_names
    assert "identity" in group_names


# --------------------------------------------------------------------------- #
# TOOLS dispatch (monkeypatched handlers)

def test_system_version_dispatch(app, monkeypatch):
    monkeypatch.setitem(cli_module._TOOL_HANDLERS, "system.version", lambda **k: {"os": "debian", "version": "12"})
    result = _invoke(app, ["system", "version", "--output-as", "json"])
    assert result.exit_code == 0
    assert '"version": "12"' in result.stdout


def test_service_restart_passes_name(app, monkeypatch):
    captured = {}

    def fake_restart(**kwargs):
        captured.update(kwargs)
        return {"service": kwargs["name"], "changed": True}

    monkeypatch.setitem(cli_module._TOOL_HANDLERS, "service.restart", fake_restart)
    result = _invoke(app, ["service", "restart", "caddy", "--output-as", "json"])
    assert result.exit_code == 0
    assert captured.get("name") == "caddy"
    assert '"service": "caddy"' in result.stdout


def test_service_control_action(app, monkeypatch):
    captured = {}

    def fake_control(**kwargs):
        captured.update(kwargs)
        return {"service": kwargs["name"], "action": kwargs["action"]}

    monkeypatch.setitem(cli_module._TOOL_HANDLERS, "service.control", fake_control)
    result = _invoke(app, ["service", "control", "synapse", "restart"])
    assert result.exit_code == 0
    assert captured == {"name": "synapse", "action": "restart"}


def test_app_remove_purge_flag(app, monkeypatch):
    captured = {}

    def fake_remove(**kwargs):
        captured.update(kwargs)
        return {"app": kwargs["app"]}

    monkeypatch.setitem(cli_module._TOOL_HANDLERS, "app.remove", fake_remove)
    result = _invoke(app, ["app", "remove", "immich", "--purge"])
    assert result.exit_code == 0
    assert captured == {"app": "immich", "purge": True}


def test_tool_error_exit_1(app, monkeypatch):
    def boom(**kwargs):
        raise cli_module.OperationError("boom")

    monkeypatch.setitem(cli_module._TOOL_HANDLERS, "service.restart", boom)
    result = _invoke(app, ["service", "restart", "caddy"])
    assert result.exit_code == 1
    assert "boom" in result.stderr


def test_package_plan_reads_file(app, monkeypatch, tmp_path):
    captured = {}
    manifest = {"app": {"id": "example", "version": "1.0.0"}}
    path = tmp_path / "pkg.json"
    path.write_text(json.dumps(manifest))

    def fake_plan(package, catalogue=None):
        captured["package"] = package
        captured["catalogue"] = catalogue
        return {"operations": []}

    monkeypatch.setitem(cli_module._TOOL_HANDLERS, "package.plan", fake_plan)
    result = _invoke(app, ["package", "plan", str(path)])
    assert result.exit_code == 0
    assert captured["package"] == manifest
    assert captured["catalogue"] is None


# --------------------------------------------------------------------------- #
# identity (npub user model)

def test_identity_link_passes_npub(app, monkeypatch):
    captured = {}

    def fake_link(username, pubkey_or_npub, **kwargs):
        captured.update({"username": username, "pubkey_or_npub": pubkey_or_npub, **kwargs})
        return {"kind": 31102, "pubkey": "abcd"}

    monkeypatch.setattr(cli_module, "link_identity", fake_link)
    result = _invoke(app, ["identity", "link", "alice", "npub1test", "--signer-type", "nip07", "--output-as", "json"])
    assert result.exit_code == 0
    assert captured["username"] == "alice"
    assert captured["pubkey_or_npub"] == "npub1test"
    assert captured["signer_type"] == "nip07"
    assert captured["enabled"] is True
    assert '"kind": 31102' in result.stdout


def test_identity_link_disabled(app, monkeypatch):
    captured = {}

    def fake_link(username, pubkey_or_npub, **kwargs):
        captured.update(kwargs)
        return {"kind": 31102}

    monkeypatch.setattr(cli_module, "link_identity", fake_link)
    _invoke(app, ["identity", "link", "alice", "npub1test", "--disabled"])
    assert captured["enabled"] is False


def test_identity_list_username(app, monkeypatch):
    captured = {}

    def fake_list_for_username(username):
        captured["username"] = username
        return []

    monkeypatch.setattr(cli_module, "list_identities_for_username", fake_list_for_username)
    result = _invoke(app, ["identity", "list", "--username", "alice"])
    assert result.exit_code == 0
    assert captured["username"] == "alice"


def test_identity_revoke(app, monkeypatch):
    captured = {}

    def fake_revoke(pubkey_or_npub, **kwargs):
        captured["pubkey_or_npub"] = pubkey_or_npub
        return {"kind": 31102}

    monkeypatch.setattr(cli_module, "revoke_identity", fake_revoke)
    _invoke(app, ["identity", "revoke", "npub1test"])
    assert captured["pubkey_or_npub"] == "npub1test"


# --------------------------------------------------------------------------- #
# capability

def test_capability_grant_scopes(app, monkeypatch):
    captured = {}

    def fake_grant(pubkey, scopes, **kwargs):
        captured.update({"pubkey": pubkey, "scopes": scopes, **kwargs})
        return {"kind": 31100}

    monkeypatch.setattr(cli_module, "grant_capability", fake_grant)
    result = _invoke(app, ["capability", "grant", "abcd", "apps.read", "services.write", "--type", "admin"])
    assert result.exit_code == 0
    assert captured["pubkey"] == "abcd"
    assert captured["scopes"] == ["apps.read", "services.write"]
    assert captured["type_"] == "admin"


def test_capability_delegate_expires_at(app, monkeypatch):
    captured = {}

    def fake_delegate(pubkey, scopes, expires_at, **kwargs):
        captured.update({"pubkey": pubkey, "scopes": scopes, "expires_at": expires_at})
        return {"kind": 27236}

    monkeypatch.setattr(cli_module, "delegate_capability", fake_delegate)
    _invoke(app, ["capability", "delegate", "abcd", "apps.read", "--expires-at", "1750000000"])
    assert captured["pubkey"] == "abcd"
    assert captured["scopes"] == ["apps.read"]
    assert captured["expires_at"] == 1750000000


# --------------------------------------------------------------------------- #
# globals / exit codes

def test_global_output_as_before_command(app, monkeypatch):
    monkeypatch.setitem(cli_module._TOOL_HANDLERS, "system.version", lambda **k: {"version": "1"})
    result = _invoke(app, ["--output-as", "json", "system", "version"])
    assert result.exit_code == 0
    assert '"version": "1"' in result.stdout


def test_unknown_command_usage_error(app):
    result = _invoke(app, ["nope"])
    assert result.exit_code == 2


def test_main_entry_prints_help(capsys):
    code = cli_module.main(["--help"])
    assert code == 0
    assert "Usage:" in capsys.readouterr().out
