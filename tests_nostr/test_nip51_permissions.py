from __future__ import annotations

from dataclasses import dataclass

import pytest

from nostrhost.nip51_permissions import (
    PERMISSION_LIST_KIND,
    PermissionStore,
    merge_projection,
    resolve_usernames,
)

ADMIN = "a" * 64
OTHER = "b" * 64
MEMBER_1 = "1" * 64
MEMBER_2 = "2" * 64


def _event(*, kind=PERMISSION_LIST_KIND, author=ADMIN, d="myapp.main", members=(), public=None, created_at=100, event_id="e1"):
    tags = [["d", d], *(["p", m] for m in members)]
    if public is not None:
        tags.append(["public", "true" if public else "false"])
    return {
        "id": event_id,
        "kind": kind,
        "pubkey": author,
        "created_at": created_at,
        "tags": tags,
        "content": "",
    }


def test_apply_event_stores_membership(tmp_path):
    store = PermissionStore(tmp_path / "grants.json")
    applied = store.apply_event(
        _event(members=[MEMBER_1, MEMBER_2], public=False),
        admin_pubkeys=(ADMIN,),
    )
    assert applied is True
    grant = store.get("myapp.main")
    assert grant is not None
    assert grant.pubkeys == (MEMBER_1, MEMBER_2)
    assert grant.public is False


def test_apply_event_persists_across_instances(tmp_path):
    path = tmp_path / "grants.json"
    PermissionStore(path).apply_event(_event(members=[MEMBER_1]), admin_pubkeys=(ADMIN,))
    reloaded = PermissionStore(path)
    assert reloaded.get("myapp.main").pubkeys == (MEMBER_1,)


def test_apply_event_rejects_wrong_kind(tmp_path):
    store = PermissionStore(tmp_path / "grants.json")
    assert store.apply_event(_event(kind=1), admin_pubkeys=(ADMIN,)) is False
    assert store.get("myapp.main") is None


def test_apply_event_rejects_non_admin_author(tmp_path):
    store = PermissionStore(tmp_path / "grants.json")
    assert store.apply_event(_event(author=OTHER), admin_pubkeys=(ADMIN,)) is False
    assert store.get("myapp.main") is None


def test_apply_event_rejects_missing_d_tag(tmp_path):
    store = PermissionStore(tmp_path / "grants.json")
    event = _event()
    event["tags"] = [t for t in event["tags"] if t[0] != "d"]
    assert store.apply_event(event, admin_pubkeys=(ADMIN,)) is False


def test_apply_event_replaces_membership_on_newer_event(tmp_path):
    store = PermissionStore(tmp_path / "grants.json")
    store.apply_event(_event(members=[MEMBER_1], created_at=100), admin_pubkeys=(ADMIN,))
    store.apply_event(_event(members=[MEMBER_2], created_at=200, event_id="e2"), admin_pubkeys=(ADMIN,))
    grant = store.get("myapp.main")
    assert grant.pubkeys == (MEMBER_2,)
    assert grant.event_id == "e2"


def test_apply_event_ignores_stale_replay(tmp_path):
    store = PermissionStore(tmp_path / "grants.json")
    store.apply_event(_event(members=[MEMBER_2], created_at=200, event_id="e2"), admin_pubkeys=(ADMIN,))
    # An older event for the same permission arrives during relay replay.
    applied = store.apply_event(_event(members=[MEMBER_1], created_at=100, event_id="e1"), admin_pubkeys=(ADMIN,))
    assert applied is True  # accepted (no error), but ignored
    assert store.get("myapp.main").pubkeys == (MEMBER_2,)


def test_apply_event_dedupes_repeated_pubkeys(tmp_path):
    store = PermissionStore(tmp_path / "grants.json")
    store.apply_event(_event(members=[MEMBER_1, MEMBER_1, MEMBER_2]), admin_pubkeys=(ADMIN,))
    assert store.get("myapp.main").pubkeys == (MEMBER_1, MEMBER_2)


@dataclass
class _FakeIdentity:
    username: str


def test_resolve_usernames_skips_unlinked_pubkeys(tmp_path):
    store = PermissionStore(tmp_path / "grants.json")
    store.apply_event(_event(members=[MEMBER_1, MEMBER_2]), admin_pubkeys=(ADMIN,))
    grant = store.get("myapp.main")

    def resolve(pubkey: str):
        return _FakeIdentity(username="alice") if pubkey == MEMBER_1 else None

    assert resolve_usernames(grant, resolve_pubkey=resolve) == ["alice"]


def test_resolve_usernames_survives_resolver_errors(tmp_path):
    store = PermissionStore(tmp_path / "grants.json")
    store.apply_event(_event(members=[MEMBER_1]), admin_pubkeys=(ADMIN,))
    grant = store.get("myapp.main")

    def resolve(pubkey: str):
        raise RuntimeError("identity store unavailable")

    assert resolve_usernames(grant, resolve_pubkey=resolve) == []


def test_merge_projection_unions_with_existing_ldap_users(tmp_path):
    store = PermissionStore(tmp_path / "grants.json")
    store.apply_event(_event(members=[MEMBER_1]), admin_pubkeys=(ADMIN,))
    permissions = {
        "myapp.main": {"users": ["bob"], "public": False, "uris": ["example.org/myapp"]},
    }

    merge_projection(permissions, store, resolve_pubkey=lambda pk: _FakeIdentity(username="alice"))

    assert permissions["myapp.main"]["users"] == ["alice", "bob"]
    assert permissions["myapp.main"]["public"] is False


def test_merge_projection_sets_public_but_never_unsets_it(tmp_path):
    store = PermissionStore(tmp_path / "grants.json")
    store.apply_event(_event(members=[], public=True), admin_pubkeys=(ADMIN,))
    permissions = {"myapp.main": {"users": [], "public": False, "uris": []}}

    merge_projection(permissions, store, resolve_pubkey=lambda pk: None)

    assert permissions["myapp.main"]["public"] is True


def test_merge_projection_skips_permissions_not_in_ldap_projection(tmp_path):
    store = PermissionStore(tmp_path / "grants.json")
    store.apply_event(_event(d="uninstalled_app.main", members=[MEMBER_1]), admin_pubkeys=(ADMIN,))
    permissions: dict = {}

    merge_projection(permissions, store, resolve_pubkey=lambda pk: _FakeIdentity(username="alice"))

    assert permissions == {}
