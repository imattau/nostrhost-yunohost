"""Option A: the ``admins`` group is authoritative for admin status.

Regression coverage for "user added to the admins group but has no admin
privileges": group membership must confer admin status (via the account
``admin`` flag and a group-membership fallback) across every admin surface.

Store-level tests run against a tmp ``accounts.json``; the
``user_group_update`` integration test exercises the real decorated
operation with the real native store and no-op real-group helpers.
"""

from __future__ import annotations

import json
import types

import pytest

from nostrhost.core import Moulinette
from yunohost.nostrhost import accounts

# --------------------------------------------------------------------------- #
# store helpers

def _write_store(tmp_path, users, groups) -> None:
    path = tmp_path / "accounts.json"
    path.write_text(json.dumps({"users": users, "groups": groups}))
    accounts.ACCOUNTS_STORE = path


@pytest.fixture(autouse=True)
def _reset_store(monkeypatch):
    # Each test writes its own store; keep the module from leaking across tests.
    monkeypatch.setattr(accounts, "ACCOUNTS_STORE", accounts.ACCOUNTS_STORE)


# --------------------------------------------------------------------------- #
# user_is_admin / admins(): group membership is authoritative

def test_user_is_admin_true_for_admins_group_member_without_flag(tmp_path, monkeypatch):
    """The lostcause case: in the admins group but the record predates the
    flag — membership alone must confer admin."""
    _write_store(
        tmp_path,
        users={"lostcause": {"admin": False}},
        groups={"admins": {"gid": "2001", "members": ["lostcause"]}},
    )
    assert accounts.user_is_admin("lostcause") is True


def test_user_is_admin_false_for_non_member(tmp_path):
    _write_store(
        tmp_path,
        users={"bob": {"admin": False}},
        groups={"admins": {"gid": "2001", "members": []}},
    )
    assert accounts.user_is_admin("bob") is False


def test_user_is_admin_true_for_flagged_admin(tmp_path):
    _write_store(
        tmp_path,
        users={"operator": {"admin": True}},
        groups={"admins": {"gid": "2001", "members": []}},
    )
    assert accounts.user_is_admin("operator") is True


def test_user_is_admin_false_for_unknown_user(tmp_path):
    _write_store(tmp_path, users={}, groups={})
    assert accounts.user_is_admin("ghost") is False


def test_admins_unions_flag_and_group_members(tmp_path):
    _write_store(
        tmp_path,
        users={"operator": {"admin": True}, "member": {"admin": False}},
        groups={"admins": {"gid": "2001", "members": ["member"]}},
    )
    assert sorted(accounts.admins()) == ["member", "operator"]


# --------------------------------------------------------------------------- #
# set_user_admin

def test_set_user_admin_toggles_flag(tmp_path):
    _write_store(tmp_path, users={"alice": {"admin": False}}, groups={})
    accounts.set_user_admin("alice", True)
    assert accounts.user_get("alice")["admin"] is True
    accounts.set_user_admin("alice", False)
    assert accounts.user_get("alice")["admin"] is False


def test_set_user_admin_unknown_user_noop(tmp_path):
    _write_store(tmp_path, users={}, groups={})
    accounts.set_user_admin("ghost", True)  # must not raise
    assert "ghost" not in accounts.users()


# --------------------------------------------------------------------------- #
# user_group_update keeps the account admin flag in lock-step with the group

def _install_user_group_update_harness(monkeypatch, tmp_path):
    """Fake the real-group subprocess layer + operation plumbing so the real
    ``user_group_update`` runs against a tmp native store."""
    from yunohost import log
    from yunohost.user import user_group_update

    import logging

    monkeypatch.setattr(accounts, "add_real_user_to_group", lambda *a, **k: None)
    monkeypatch.setattr(accounts, "remove_real_user_from_group", lambda *a, **k: None)
    monkeypatch.setattr(log, "OPERATIONS_PATH", str(tmp_path / "operations"))
    # The YunoHost logging setup (init_logging) normally adds `logger.success`;
    # absent in the lightweight test env, so no-op it.
    monkeypatch.setattr(
        logging.getLogger("yunohost.user"), "success", lambda *a, **k: None, raising=False
    )
    monkeypatch.setattr(Moulinette, "_interface", types.SimpleNamespace(type="cli"))
    return user_group_update


def test_user_group_update_admins_add_sets_flag_and_remove_clears(tmp_path, monkeypatch):
    _write_store(
        tmp_path,
        users={
            "alice": {"fullname": "Alice", "mail": ["alice@test.local"]},
            "bob": {"fullname": "Bob", "mail": ["bob@test.local"]},
        },
        groups={},
    )
    update = _install_user_group_update_harness(monkeypatch, tmp_path)

    # Promotion: adding to the admins group must set the account admin flag.
    update(groupname="admins", add="alice", sync_perm=False)
    assert accounts.user_is_admin("alice") is True
    assert accounts.user_get("alice")["admin"] is True

    # Another promotion; then demotion of one admin must clear only theirs.
    update(groupname="admins", add="bob", sync_perm=False)
    assert accounts.user_is_admin("bob") is True
    update(groupname="admins", remove="alice", sync_perm=False)
    assert accounts.user_is_admin("alice") is False
    assert accounts.user_get("alice")["admin"] is False
    assert accounts.user_is_admin("bob") is True


def test_user_group_update_admins_remove_last_admin_still_guarded(tmp_path, monkeypatch):
    """The existing last-admin guard keeps the group (and the flag) intact."""
    _write_store(
        tmp_path,
        users={"alice": {"fullname": "Alice", "mail": ["alice@test.local"]}},
        groups={"admins": {"gid": "2001", "members": ["alice"]}},
    )
    update = _install_user_group_update_harness(monkeypatch, tmp_path)

    from yunohost.utils.error import YunohostValidationError

    with pytest.raises(YunohostValidationError):
        update(groupname="admins", remove="alice", sync_perm=False)
    assert accounts.user_is_admin("alice") is True