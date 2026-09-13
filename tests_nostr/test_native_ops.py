"""Tests for the broadened native safe-tool surface (MCP transition Phase 0).

These exercise the ``nostrhost/native_ops.py`` handlers' bounded-argument
contract (strict args, no passthrough, OperationError on extras) and the
schema-driven ``ToolSpec.validate_args`` path, following the fake-module
pattern from test_nostr_operations.py for the lazy yunohost imports.
"""

from __future__ import annotations

import sys
from types import ModuleType

import pytest

from yunohost.nostr_operations import (
    OperationError,
    tool_spec,
)
from yunohost.nostrhost import native_ops


def _install_fake(monkeypatch, name: str, **attrs) -> ModuleType:
    module = ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    monkeypatch.setitem(sys.modules, name, module)
    return module


def test_native_tools_registered_with_scope_and_approval():
    expectations = {
        "system.status": ("server.read", False),
        "app.install": ("apps.install", True),
        "app.upgrade": ("apps.upgrade", True),
        "app.change_url": ("apps.upgrade", True),
        "app.config.read": ("apps.config.read", False),
        "app.config.set": ("apps.config.write", True),
        "backup.create": ("backups.create", True),
        "backup.list": ("backups.read", False),
        "backup.restore": ("backups.restore", True),
        "user.list": ("users.read", False),
        "user.create": ("users.write", True),
        "user.delete": ("users.delete", True),
        "system.upgrade": ("system.upgrade", True),
        "firewall.list": ("firewall.read", False),
        "firewall.open": ("firewall.write", True),
        "firewall.close": ("firewall.write", True),
        "firewall.reload": ("firewall.write", True),
        "diagnosis.run": ("diagnosis.read", False),
        # Phase 5 backlog surface.
        "updates.check": ("system.update", False),
        "updates.refresh": ("system.update", False),
        "system.migrations": ("system.update", False),
        "system.migrate": ("system.migrate", True),
        "service.history": ("services.read", False),
        "logs.read": ("logs.read", False),
        "logs.web": ("logs.read", False),
        "backup.delete": ("backups.delete", True),
        "domain.cert.info": ("domains.read", False),
        "domain.cert.install": ("domains.write", True),
        "user.update": ("users.write", True),
        "user.group.list": ("users.read", False),
        "user.group.create": ("users.write", True),
        "user.group.update": ("users.write", True),
        "user.group.delete": ("users.delete", True),
        "user.permission.list": ("users.read", False),
        "user.permission.info": ("users.read", False),
        "user.permission.add": ("users.write", True),
        "user.permission.remove": ("users.write", True),
        "user.permission.update": ("users.write", True),
        "catalog.verify": ("catalog.verify", False),
        "audit.list": ("audit.read", True),
        "audit.get": ("audit.read", True),
    }
    for name, (scope, approval) in expectations.items():
        spec = tool_spec(name)
        assert spec is not None, name
        assert spec.scope == scope, name
        assert spec.require_approval is approval, name
        assert spec.input_model is not None, name


def test_validate_args_rejects_unknown_keys():
    spec = tool_spec("app.install")
    with pytest.raises(OperationError):
        spec.validate_args({"app": "myapp", "bogus": 1})


def test_validate_args_requires_required_fields():
    spec = tool_spec("app.install")
    with pytest.raises(OperationError):
        spec.validate_args({"label": "x"})  # missing required 'app'


def test_validate_args_coerces_types():
    spec = tool_spec("firewall.open")
    validated = spec.validate_args({"port": "8080", "protocol": "tcp", "comment": "web"})
    assert validated == {"port": "8080", "protocol": "tcp", "comment": "web", "upnp": False}


def test_validate_args_plain_tool():
    spec = tool_spec("system.version")
    assert spec.input_model is None
    assert spec.validate_args({}) == {}
    with pytest.raises(OperationError):
        spec.validate_args(None)


def test_app_install_requires_app(monkeypatch):
    _install_fake(monkeypatch, "yunohost.app", app_install=lambda **kw: None)
    with pytest.raises(OperationError):
        native_ops._safe_app_install(app="  ")


def test_app_install_delegates_to_yunohost(monkeypatch):
    calls = []
    _install_fake(monkeypatch, "yunohost.app", app_install=lambda **kw: calls.append(kw))
    result = native_ops._safe_app_install(app="myapp", label="My App", force=True)
    assert result == {"app": "myapp"}
    assert calls[0]["app"] == "myapp"
    assert calls[0]["force"] is True
    assert calls[0]["no_remove_on_failure"] is False


def test_app_install_rejects_extra_args(monkeypatch):
    _install_fake(monkeypatch, "yunohost.app", app_install=lambda **kw: None)
    with pytest.raises(OperationError):
        native_ops._safe_app_install(app="myapp", surprise=True)


def test_app_upgrade_requires_app(monkeypatch):
    _install_fake(monkeypatch, "yunohost.app", app_upgrade=lambda **kw: None)
    with pytest.raises(OperationError):
        native_ops._safe_app_upgrade(app="")


def test_system_upgrade_validates_target(monkeypatch):
    _install_fake(monkeypatch, "yunohost.tools", tools_upgrade=lambda **kw: None)
    with pytest.raises(OperationError):
        native_ops._safe_system_upgrade(target="kernel")
    assert native_ops._safe_system_upgrade(target="system") == {"target": "system"}


def test_backup_create_bounds_arguments(monkeypatch):
    calls = []
    _install_fake(monkeypatch, "yunohost.backup", backup_create=lambda **kw: calls.append(kw))
    result = native_ops._safe_backup_create(apps=["myapp"], system=["yunohost"])
    assert result["apps"] == ["myapp"] and result["system"] == ["yunohost"]
    assert calls[0]["apps"] == ["myapp"]
    with pytest.raises(OperationError):
        native_ops._safe_backup_create(apps=["x"], something_else=True)


def test_firewall_open_validates_protocol(monkeypatch):
    _install_fake(monkeypatch, "yunohost.firewall", firewall_open=lambda **kw: None)
    with pytest.raises(OperationError):
        native_ops._safe_firewall_open(port="8080", protocol="sctp")
    assert native_ops._safe_firewall_open(port="8080", protocol="tcp") == {"port": "8080", "protocol": "tcp"}


def test_user_create_requires_fields(monkeypatch):
    _install_fake(monkeypatch, "yunohost.user", user_create=lambda **kw: None)
    with pytest.raises(OperationError):
        native_ops._safe_user_create(username="alice", domain="x", password="pw")
    result = native_ops._safe_user_create(username="alice", domain="x", password="pw", fullname="Alice")
    assert result["username"] == "alice"


def test_diagnosis_run_rejects_extra(monkeypatch):
    _install_fake(
        monkeypatch,
        "yunohost.diagnosis",
        diagnosis_run=lambda **kw: None,
        diagnosis_show=lambda **kw: {"items": []},
    )
    with pytest.raises(OperationError):
        native_ops._safe_diagnosis_run(categories=[], bogus=True)
    assert native_ops._safe_diagnosis_run(categories=["network"]) == {"items": []}


def test_operation_catalog_covers_native_tools():
    from yunohost.nostr_operations import operation_catalog

    names = {entry["name"] for entry in operation_catalog()}
    assert {"app.install", "system.status", "firewall.open"} <= names
