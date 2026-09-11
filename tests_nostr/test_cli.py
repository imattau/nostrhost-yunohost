"""Stage 4: native ``nostrhost`` Typer CLI tests (the moulinette CLI replacement).

Dispatch is exercised against the real operation catalog with an injected
module factory (no moulinette, no live yunohost stack), via Typer's
CliRunner.  Output modes and exit codes follow the yunohost/click conventions
(0 ok, 1 error, 2 usage).
"""

from __future__ import annotations

import types
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nostrhost.cli import build_app
from nostrhost.operations import OperationRegistry

SHARE = Path(__file__).resolve().parent.parent / "share"


def _fake_user_module() -> types.ModuleType:
    module = types.ModuleType("user")

    def user_create(username, password, fullname=None, domain=None, mailbox_quota="0", loginShell="/bin/bash"):
        return {"ok": True, "username": username, "fullname": fullname, "quota": mailbox_quota}

    def user_group_add(groupname, usernames):
        return {"group": groupname, "members": list(usernames)}

    module.user_create = user_create
    module.user_group_add = user_group_add
    return module


def _fake_firewall_module() -> types.ModuleType:
    module = types.ModuleType("firewall")

    def firewall_allow(protocol, port, ipv4_only=False, ipv6_only=False, no_upnp=False, no_reload=False):
        return {"protocol": protocol, "port": port, "ipv4_only": ipv4_only, "ipv6_only": ipv6_only}

    module.firewall_allow = firewall_allow
    return module


@pytest.fixture(scope="module")
def registry():
    modules = {"user": _fake_user_module(), "firewall": _fake_firewall_module()}
    return OperationRegistry.from_actionsmap(
        [SHARE / "actionsmap.yml", SHARE / "actionsmap-portal.yml"],
        module_factory=lambda mod: modules[mod],
    )


@pytest.fixture(scope="module")
def app(registry):
    return build_app(registry)


def _invoke(app, argv, registry):
    return CliRunner().invoke(app, argv)


# --------------------------------------------------------------------------- #
# help / structure

def test_help_lists_categories(app):
    result = _invoke(app, ["--help"], None)
    assert result.exit_code == 0
    for category in ("user", "app", "domain", "backup", "firewall"):
        assert category in result.stdout


def test_category_help_lists_actions_and_subcategories(app):
    result = _invoke(app, ["user", "--help"], None)
    assert result.exit_code == 0
    assert "create" in result.stdout
    assert "group" in result.stdout


def test_action_help_lists_options(app):
    result = _invoke(app, ["user", "create", "--help"], None)
    assert result.exit_code == 0
    for option in ("--password", "--fullname", "--domain", "--mailbox-quota"):
        assert option in result.stdout


def test_app_provides_completion(app):
    result = _invoke(app, ["--help"], None)
    assert "--install-completion" in result.stdout


# --------------------------------------------------------------------------- #
# dispatch + output modes + exit codes

def test_run_json_output_after_command(registry, app):
    result = _invoke(app, ["user", "create", "alice", "-p", "s3cret", "-F", "Alice", "--output-as", "json"], registry)
    assert result.exit_code == 0
    assert '"username": "alice"' in result.stdout


def test_run_json_output_before_command(registry, app):
    result = _invoke(app, ["--output-as", "json", "user", "create", "alice", "-p", "s3cret", "-F", "Alice"], registry)
    assert result.exit_code == 0
    assert '"username": "alice"' in result.stdout


def test_run_plain_output(registry, app):
    result = _invoke(app, ["user", "create", "alice", "-p", "s3cret", "-F", "A", "--output-as", "plain"], registry)
    assert result.exit_code == 0
    assert "#username" in result.stdout and "alice" in result.stdout


def test_run_none_output(registry, app):
    result = _invoke(app, ["user", "create", "alice", "-p", "s3cret", "-F", "A", "--output-as", "none"], registry)
    assert result.exit_code == 0
    assert result.stdout == ""


def test_run_pretty_output_default(registry, app):
    result = _invoke(app, ["user", "create", "alice", "-p", "s3cret", "-F", "Alice"], registry)
    assert result.exit_code == 0
    assert "username: alice" in result.stdout


def test_run_subcategory_nargs(registry, app):
    result = _invoke(app, ["user", "group", "add", "staff", "alice", "bob", "--output-as", "json"], registry)
    assert result.exit_code == 0
    assert '"members": ["alice", "bob"]' in result.stdout


def test_run_flag_argument(registry, app):
    result = _invoke(app, ["firewall", "allow", "TCP", "443", "--ipv4-only", "--output-as", "json"], registry)
    assert result.exit_code == 0
    assert '"ipv4_only": true' in result.stdout


def test_run_missing_required_option(registry, app):
    result = _invoke(app, ["user", "create", "alice", "-F", "Alice"], registry)
    assert result.exit_code == 1
    assert "argument_required" in result.stderr


def test_run_pattern_violation(registry, app):
    result = _invoke(app, ["user", "create", "alice", "-p", "x", "-F", "A"], registry)
    assert result.exit_code == 1
    assert "error:" in result.stderr


def test_run_unknown_command_usage_error(app):
    result = _invoke(app, ["nope"], None)
    assert result.exit_code == 2


def test_run_unimplemented_operation_rejected():
    reg = OperationRegistry.from_actionsmap([SHARE / "actionsmap.yml", SHARE / "actionsmap-portal.yml"])
    app = build_app(reg)
    result = CliRunner().invoke(app, ["portal", "register"])
    assert result.exit_code == 1
    assert "not implemented" in result.stderr


# --------------------------------------------------------------------------- #
# programmatic entry

def test_main_entry_exits_0_on_help(capsys):
    from nostrhost.cli import main

    code = main(["--help"])
    assert code == 0
    assert "Usage:" in capsys.readouterr().out
