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
    for group in ("system", "service", "app", "package", "rollback", "state", "identity", "capability", "agent", "postinstall", "backup"):
        assert group in result.stdout


def test_group_help_lists_commands(app):
    for group, commands in {
        "system": ["version", "regen-conf"],
        "service": ["status", "restart", "control"],
        "app": ["list", "install", "upgrade", "remove", "change-url", "backup", "restore"],
        "package": ["plan", "reconcile"],
        "identity": ["link", "revoke", "list", "resolve"],
        "capability": ["grant", "delegate", "revoke"],
        "agent": ["init", "status", "enable", "disable"],
        "backup": ["create", "list"],
    }.items():
        result = _invoke(app, [group, "--help"])
        assert result.exit_code == 0
        for command in commands:
            assert command in result.stdout


def test_identity_is_npub_model_not_password():
    # Identity on the native surface is npub-based (the `identity` group), not
    # a password/LDAP login CLI. The `user` group exists separately for the
    # native YunoHost account/group/permission operations (MCP Phase 5) — it is
    # not the legacy user-management shell.
    app = cli_module.build_app()
    group_names = [g.name for g in app.registered_groups]
    assert "identity" in group_names
    assert "user" in group_names
    assert "capability" in group_names


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


def test_cli_identity_dict_uses_username():
    """The CLI's own _identity_dict copy must read the Identity dataclass's
    'username' field (api.py's copy was fixed earlier; the cli.py copy still
    read 'ynh_username' and crashed `nostrhost identity list` with
    'Identity' object has no attribute 'ynh_username')."""
    from types import SimpleNamespace

    ident = SimpleNamespace(pubkey="ab" * 32, username="bob", signer_type="passkey", label="Phone", enabled=True, created_at=0, last_used=0)
    out = cli_module._identity_dict(ident)
    assert out["username"] == "bob"
    assert out["signer_type"] == "passkey"


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


def test_reconcile_routes_replays_configured_mcp_endpoint(app, monkeypatch):
    captured = {}
    monkeypatch.setattr(cli_module, "_iter_installed_manifests", lambda: [])
    monkeypatch.setattr(
        "nostrhost.mcp_endpoint.read_endpoint_config",
        lambda: {"domain": "nmcp.example.com", "port": 8930},
    )
    monkeypatch.setattr(
        "nostrhost.mcp_endpoint.configure_route",
        lambda domain, **kwargs: captured.update(domain=domain, kwargs=kwargs) or "nostrhost-web:mcp",
    )

    result = _invoke(app, ["app", "reconcile-routes", "--output-as", "json"])

    assert result.exit_code == 0
    assert captured["domain"] == "nmcp.example.com"
    assert captured["kwargs"] == {"port": 8930}
    data = json.loads(result.stdout)
    assert data["reconciled"]["mcp"] == {"ok": True, "configured": True, "domain": "nmcp.example.com"}


def test_reconcile_routes_skips_mcp_when_unconfigured(app, monkeypatch):
    monkeypatch.setattr(cli_module, "_iter_installed_manifests", lambda: [])
    monkeypatch.setattr("nostrhost.mcp_endpoint.read_endpoint_config", lambda: None)

    result = _invoke(app, ["app", "reconcile-routes", "--output-as", "json"])

    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["reconciled"]["mcp"] == {"ok": True, "configured": False}


# --------------------------------------------------------------------------- #
# app install-npk: informational vs. --require-attestation trust gate

STAGED = {"publisher": "ab" * 32, "name": "myapp", "version": "1.0.0"}


def test_attest_release_is_informational_by_default(monkeypatch):
    monkeypatch.setattr("nostrhost.native_ops._safe_catalog_attest_release", lambda **_: {"verified": False, "accepted": True})
    result = cli_module._attest_release(STAGED, relay="", require=False, trusted_verifiers=None)
    assert result == {"verified": False, "accepted": True}


def test_attest_release_swallows_lookup_failure_when_not_required(monkeypatch):
    def fail(**_):
        raise RuntimeError("relay unreachable")

    monkeypatch.setattr("nostrhost.native_ops._safe_catalog_attest_release", fail)
    result = cli_module._attest_release(STAGED, relay="", require=False, trusted_verifiers=None)
    assert result == {"error": "relay unreachable"}


def test_attest_release_blocks_when_required_and_unverified(monkeypatch):
    monkeypatch.setattr("nostrhost.native_ops._safe_catalog_attest_release", lambda **_: {"verified": False, "accepted": False})
    with pytest.raises(cli_module.NostrHostError, match="not verified"):
        cli_module._attest_release(STAGED, relay="", require=True, trusted_verifiers=["cd" * 32])


def test_attest_release_blocks_on_lookup_failure_when_required(monkeypatch):
    def fail(**_):
        raise RuntimeError("relay unreachable")

    monkeypatch.setattr("nostrhost.native_ops._safe_catalog_attest_release", fail)
    with pytest.raises(cli_module.NostrHostError, match="cannot determine attestation trust"):
        cli_module._attest_release(STAGED, relay="", require=True, trusted_verifiers=["cd" * 32])


def test_attest_release_passes_when_required_and_verified(monkeypatch):
    monkeypatch.setattr("nostrhost.native_ops._safe_catalog_attest_release", lambda **_: {"verified": True, "accepted": True})
    result = cli_module._attest_release(STAGED, relay="", require=True, trusted_verifiers=["cd" * 32])
    assert result == {"verified": True, "accepted": True}


def test_upgrade_npk_reads_staged_app_id_and_defaults_domain_path(app, monkeypatch):
    """app upgrade-npk must look up the installed manifest by the *staged*
    release's own app.id (not the coordinate argument), default domain/path
    to what's currently installed, and carry forward compatible settings -
    the same rules app upgrade (catalogue) already documents."""
    staged = {"publisher": "ab" * 32, "name": "myapp", "version": "2.0.0", "payload_root": "/tmp/staged", "artifact_sha256": "cd" * 32}
    package_data = {"app": {"id": "myapp", "version": "2.0.0"}, "web": {"domain": "new.example", "path": "/"}}
    installed = {"app": {"id": "myapp", "version": "1.0.0"}, "web": {"domain": "old.example", "path": "/old"}}

    monkeypatch.setattr("nostrhost.npk.stage", lambda coordinate, **kw: staged)
    monkeypatch.setattr("nostrhost.npk.load_embedded_manifest", lambda payload_root: package_data)
    monkeypatch.setattr("nostrhost.native_ops.trusted_publisher_list", lambda: [])
    monkeypatch.setattr(cli_module, "_installed_manifest", lambda app_id: installed if app_id == "myapp" else (_ for _ in ()).throw(AssertionError(app_id)))

    carry_calls = []

    def fake_carry(inst, cand):
        carry_calls.append(inst)
        return cand

    monkeypatch.setattr("nostrhost.app_management.carry_forward_compatible_settings", fake_carry)

    bind_calls = {}

    def fake_bind(data, *, set_values=None, domain=None, path=None):
        bind_calls["domain"] = domain
        bind_calls["path"] = path
        return data

    monkeypatch.setattr(cli_module, "_bind_install_values", fake_bind)

    envelope = {"package": {"id": "myapp", "version": "2.0.0"}, "plan_sha256": "x", "operations": []}
    monkeypatch.setattr(cli_module, "_plan_envelope", lambda pd, catalogue=None, npack=None: envelope)
    monkeypatch.setattr(cli_module, "_run_lifecycle", lambda tool, args, *, state: {"ok": True, "result": {}})

    result = _invoke(app, ["app", "upgrade-npk", "myapp-coordinate", "--output-as", "json"])

    assert result.exit_code == 0, result.stdout
    assert bind_calls["domain"] == "old.example"
    assert bind_calls["path"] == "/old"
    assert carry_calls == [installed]
    data = json.loads(result.stdout)
    assert data["previous_version"] == "1.0.0"


def test_app_remove_native_cleans_npack_store(app, monkeypatch):
    manifest = {"app": {"id": "example", "version": "1.0.0"}}
    monkeypatch.setattr("nostrhost.native_providers.installed_package_manifest", lambda app_id: manifest)
    monkeypatch.setattr(cli_module, "_run_lifecycle", lambda tool, args, *, state: {"ok": True, "result": {"results": []}})
    cleaned = []

    def fake_remove_staged(name, **kwargs):
        cleaned.append(name)
        return {"publisher": "ab" * 32, "name": name, "version": "1.0.0"}

    monkeypatch.setattr("nostrhost.npk.remove_staged", fake_remove_staged)

    result = _invoke(app, ["app", "remove", "example", "--output-as", "json"])
    assert result.exit_code == 0, result.stdout
    data = json.loads(result.stdout)
    assert cleaned == ["example"]
    assert data["action"] == "removed"
    assert data["npack_store"]["name"] == "example"
