"""Stage 3: OperationRegistry tests (the ActionsMap replacement).

These run without moulinette or a live ``yunohost`` stack: the registry's
dispatch mechanics are exercised with an injected module factory (the pattern
used across ``tests_nostr``), while catalog parsing, lookups, request-model
generation and scope/risk are verified against the real action maps.
"""

from __future__ import annotations

import json
import types
from pathlib import Path

import pytest

from nostrhost.core import NostrHostValidationError
from nostrhost.operations import (
    OperationError,
    OperationNotImplementedError,
    OperationRegistry,
    OperationResolutionError,
)

SHARE = Path(__file__).resolve().parent.parent / "share"


@pytest.fixture(scope="module")
def registry() -> OperationRegistry:
    return OperationRegistry.from_actionsmap([SHARE / "actionsmap.yml", SHARE / "actionsmap-portal.yml"])


# --------------------------------------------------------------------------- #
# catalog / lookup

def test_registry_loads_real_action_maps(registry):
    assert len(registry.operations()) == 135
    assert len(registry.with_api_route()) == 104
    assert len(registry.executable_operations()) == 132


def test_unimplemented_stubs_flagged(registry):
    for name in ("portal.apps", "portal.reset_password", "portal.register"):
        op = registry.by_name(name)
        assert op is not None and not op.implemented
        assert not registry.is_implemented(name)


def test_module_overrides_applied(registry):
    assert registry.by_name("app.catalog").module == "app_catalog"
    assert registry.by_name("app.catalog").function == "app_catalog"
    assert registry.by_name("app.search").module == "app_catalog"
    assert registry.by_name("app.search").function == "app_search"


def test_lookup_by_name_cli_and_route(registry):
    assert registry.by_name("user.create").api.method == "POST"
    assert registry.by_cli_path(["user", "group", "add"]).name == "user.group.add"
    assert registry.by_route("PUT", "/users/groups/<groupname>/add/<usernames>").name == "user.group.add"
    assert registry.by_name("nope") is None
    assert registry.by_cli_path(["nope"]) is None
    assert registry.by_route("GET", "/nope") is None


def test_modules_summary(registry):
    counts = registry.modules()
    assert counts["user"] == 24
    assert counts["app"] == 20
    assert counts["app_catalog"] == 2


# --------------------------------------------------------------------------- #
# scope / risk

def test_scope_classification(registry):
    assert registry.scope("user.create") == "users.write"
    assert registry.scope("app.list") == "apps.read"
    assert registry.scope("domain.add") == "domains.write"
    assert registry.scope("log.list") == "logs.read"
    assert registry.scope("portal.me") == "portal.read"


def test_risk_classification(registry):
    assert registry.risk("app.remove") == "high"
    assert registry.risk("user.update") == "high"
    assert registry.risk("app.list") == "low"
    assert registry.risk("user.create") == "medium"


# --------------------------------------------------------------------------- #
# request models / validation

def test_request_model_user_create(registry):
    model = registry.request_model("user.create")
    fields = model.__fields__
    assert fields["username"].required is True
    assert fields["password"].required is True
    assert "secret" in fields["password"].field_info.extra
    assert fields["mailbox_quota"].get_default() == "0"
    assert fields["loginShell"].get_default() == "/bin/bash"
    assert "secret" not in fields["username"].field_info.extra


def test_request_model_flags_are_bools(registry):
    model = registry.request_model("tools.postinstall")
    fields = model.__fields__
    assert fields["ignore_dyndns"].annotation is bool
    assert fields["force_diskspace"].annotation is bool
    assert fields["i_have_read_terms_of_services"].annotation is bool
    assert fields["password"].required is True


def test_request_model_is_cached(registry):
    assert registry.request_model("user.create") is registry.request_model("user.create")


def test_json_schema_emitted(registry):
    schema = registry.request_json_schema("user.create")
    assert "properties" in schema
    assert "username" in schema["properties"]
    assert "required" in schema


def test_validate_accepts_valid_request(registry):
    data = registry.validate("user.create", {"username": "alice", "password": "s3cret", "fullname": "Alice"})
    assert data["username"] == "alice"
    assert data["mailbox_quota"] == "0"


def test_validate_rejects_missing_required(registry):
    with pytest.raises(NostrHostValidationError):
        registry.validate("user.create", {"username": "alice", "password": "s3cret"})


def test_validate_enforces_pattern(registry):
    with pytest.raises(NostrHostValidationError):
        registry.validate("user.create", {"username": "BAD!!", "password": "s3cret", "fullname": "Alice"})


def test_validate_rejects_bad_choice(registry):
    # firewall.allow declares protocol choices in the action map
    op = registry.by_name("firewall.allow")
    assert op is not None and op.args
    with pytest.raises(NostrHostValidationError):
        registry.validate("firewall.allow", {"protocol": "tcp", "port": "1"})


# --------------------------------------------------------------------------- #
# resolve / execute

def _fake_modules() -> dict[str, types.ModuleType]:
    user = types.ModuleType("user")

    def user_create(username, password, fullname=None, domain=None, mailbox_quota="0", loginShell="/bin/bash"):
        return {"username": username, "fullname": fullname, "quota": mailbox_quota}

    user.user_create = user_create
    return {"user": user}


def test_execute_with_injected_module():
    reg = OperationRegistry.from_actionsmap(
        [SHARE / "actionsmap.yml", SHARE / "actionsmap-portal.yml"],
        module_factory=lambda mod: _fake_modules()[mod],
    )
    result = reg.execute("user.create", {"username": "alice", "password": "s3cret", "fullname": "Alice"})
    assert result["username"] == "alice"
    assert result["fullname"] == "Alice"


def test_execute_kwargs_form():
    reg = OperationRegistry.from_actionsmap(
        [SHARE / "actionsmap.yml", SHARE / "actionsmap-portal.yml"],
        module_factory=lambda mod: _fake_modules()[mod],
    )
    result = reg.execute("user.create", username="bob", password="pw12345", fullname="Bob")
    assert result["username"] == "bob"


def test_execute_rejects_both_request_and_kwargs():
    reg = OperationRegistry.from_actionsmap(
        [SHARE / "actionsmap.yml", SHARE / "actionsmap-portal.yml"],
        module_factory=lambda mod: _fake_modules()[mod],
    )
    with pytest.raises(OperationError, match="not both"):
        reg.execute("user.create", {"username": "a", "password": "pw12345", "fullname": "A"}, username="x")


def test_execute_rejects_unimplemented(registry):
    with pytest.raises(OperationNotImplementedError):
        registry.execute("portal.register", {})


def test_execute_unknown_operation(registry):
    with pytest.raises(OperationError, match="unknown operation"):
        registry.execute("nope.thing", {})


def test_resolve_missing_module():
    reg = OperationRegistry.from_actionsmap(
        [SHARE / "actionsmap.yml", SHARE / "actionsmap-portal.yml"],
        module_factory=lambda mod: (_ for _ in ()).throw(ImportError(f"no {mod}")),
    )
    with pytest.raises(OperationResolutionError):
        reg.resolve("user.create")


def test_resolve_missing_function():
    reg = OperationRegistry.from_actionsmap(
        [SHARE / "actionsmap.yml", SHARE / "actionsmap-portal.yml"],
        module_factory=lambda mod: types.ModuleType(mod),
    )
    with pytest.raises(OperationResolutionError, match="no function"):
        reg.resolve("user.create")


# --------------------------------------------------------------------------- #
# from_json

def test_from_json(tmp_path):
    from nostrhost.operations import OperationRegistry as Reg

    catalog = Reg.from_actionsmap([SHARE / "actionsmap.yml"]).catalog
    payload = catalog.to_dict()
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(payload))
    rebuilt = OperationRegistry.from_json(path)
    assert len(rebuilt.operations()) == len(catalog.operations)
    assert rebuilt.by_name("user.create").module == "user"
