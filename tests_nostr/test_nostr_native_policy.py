from __future__ import annotations

from datetime import datetime, timezone
import sys
import types

from yunohost.nostrhost_native_policy import NativePolicyAdapter, _backup_created_at, _native_policy_key


class Rule:
    require_confirmation = True
    require_owner_signature = True


def test_native_plan_maps_removal_to_remove_policy():
    plan = {"operations": [{"name": "package.remove"}]}
    assert _native_policy_key("package.reconcile", {"plan": plan}) == "apps.remove"


def test_phase5_policy_keys():
    # user.group.update escalates to the owner-co-signed admins tier.
    assert _native_policy_key("user.group.update", {"groupname": "admins"}) == "users.admin_access"
    assert _native_policy_key("user.group.update", {"groupname": "devs"}) == "users.write"
    assert _native_policy_key("user.update", {}) == "users.write"
    assert _native_policy_key("user.group.create", {}) == "users.write"
    assert _native_policy_key("user.group.delete", {}) == "users.delete"
    assert _native_policy_key("user.permission.add", {}) == "users.permissions"
    assert _native_policy_key("user.permission.remove", {}) == "users.permissions"
    assert _native_policy_key("user.permission.update", {}) == "users.permissions"
    assert _native_policy_key("system.migrate", {}) == "system.migrate"
    assert _native_policy_key("backup.delete", {}) == "backups.delete"
    assert _native_policy_key("domain.cert.install", {}) == "domains.cert"
    assert _native_policy_key("audit.list", {}) == "audit.read"
    assert _native_policy_key("audit.get", {}) == "audit.read"
    # Read-only / unlisted ops fall through to their tool name (no rule -> allow).
    assert _native_policy_key("logs.read", {}) == "logs.read"
    assert _native_policy_key("service.history", {}) == "service.history"


def test_native_policy_checks_shared_hard_requirements():
    checks = []

    def free_space(rule, *, free_bytes):
        checks.append(("space", free_bytes))

    def recent_backup(rule, *, archive_created_at, now):
        checks.append(("backup", archive_created_at, now))

    # Patch the shared functions at their import point without requiring a
    # full YunoHost runtime; the adapter's contract is what is under test.
    import nostrhost_policy.policy.rules as rules

    old_space, old_backup = rules.check_free_space, rules.check_recent_backup
    rules.check_free_space, rules.check_recent_backup = free_space, recent_backup
    try:
        adapter = NativePolicyAdapter(
            {"apps.upgrade": Rule()},
            free_bytes=lambda: 123,
            backup_created_at=lambda: {"nightly": 456.0},
            now=lambda: 789.0,
        )
        result = adapter("package.reconcile", {"plan": {"operations": []}}, "a" * 64)
    finally:
        rules.check_free_space, rules.check_recent_backup = old_space, old_backup

    assert result["policy_key"] == "apps.upgrade"
    assert result["owner_signature_required"] is True
    assert checks == [("space", 123), ("backup", {"nightly": 456.0}, 789.0)]


def test_backup_created_at_normalizes_yunohost_datetime(monkeypatch):
    backup = types.ModuleType("yunohost.backup")
    backup.backup_list = lambda with_info=True: {"archives": {"nightly": {"created_at": datetime(2026, 1, 1, tzinfo=timezone.utc)}}}
    monkeypatch.setitem(sys.modules, "yunohost.backup", backup)
    assert _backup_created_at()["nightly"] == datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
