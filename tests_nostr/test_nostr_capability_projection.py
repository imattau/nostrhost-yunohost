"""WP3 tests: the persisted, rebuildable capability/authorization projection.

Covers the fold and authorization semantics, durability, replay rebuild,
validation/quarantine, the executor integration (persist + mirror) and the
freshness guard the HTTP authorizer relies on.
"""

from __future__ import annotations

import json
import time

from conftest import new_key
from yunohost.nostr_operations import (
    build_capability,
    build_delegation,
    build_delegation_revocation,
)
from yunohost.nostr_capability_projection import (
    CapabilityProjection,
    CapabilityProjector,
    capabilities_are_fresh,
    load_capabilities,
    rebuild_from_events,
    save_capabilities,
)
from yunohost.nostr_operationsd import OperationEngine


# --------------------------------------------------------------------------- #
# projection value semantics


def test_projection_direct_scope_and_admin_bypass():
    projection = CapabilityProjection(scopes={"aa" * 32: ["services.read", "logs.read"]})
    assert projection.direct_authorized("aa" * 32, "services.read")
    assert not projection.direct_authorized("aa" * 32, "system.upgrade")
    # A configured admin is authorized regardless of any grant.
    assert projection.direct_authorized("bb" * 32, "system.upgrade", admins=["bb" * 32])


def test_projection_delegation_requires_live_delegator_authority():
    delegator = "aa" * 32
    delegate = "bb" * 32
    projection = CapabilityProjection(
        scopes={delegator: ["logs.read"]},
        delegations={
            "d" * 64: {
                "delegator": delegator,
                "delegate": delegate,
                "scopes": ["logs.read"],
                "expiry": int(time.time()) + 3600,
            }
        },
    )
    assert projection.authorized(delegate, "logs.read")
    # Removing the delegator's own scope instantly removes derived access.
    projection.scopes.pop(delegator)
    assert not projection.authorized(delegate, "logs.read")


def test_projection_expired_and_revoked_delegations_deny():
    delegator, delegate = "aa" * 32, "bb" * 32
    base = {
        "delegator": delegator,
        "delegate": delegate,
        "scopes": ["logs.read"],
    }
    expired = CapabilityProjection(
        scopes={delegator: ["logs.read"]},
        delegations={"e" * 64: {**base, "expiry": int(time.time()) - 1}},
    )
    assert not expired.authorized(delegate, "logs.read")
    revoked = CapabilityProjection(
        scopes={delegator: ["logs.read"]},
        delegations={"e" * 64: {**base, "expiry": int(time.time()) + 3600}},
        revoked=["e" * 64],
    )
    assert not revoked.authorized(delegate, "logs.read")


def test_projection_round_trips_through_dict():
    projection = CapabilityProjection(
        scopes={"aa" * 32: ["logs.read"]},
        delegations={"d" * 64: {"delegator": "aa" * 32, "delegate": "bb" * 32, "scopes": ["logs.read"], "expiry": 42}},
        revoked=["f" * 64],
        revision="123:abcdef",
        updated_at=123.0,
    )
    restored = CapabilityProjection.from_dict(json.loads(projection.render()))
    assert restored.scopes == projection.scopes
    assert restored.delegations == projection.delegations
    assert restored.revoked == projection.revoked
    assert restored.revision == "123:abcdef"


# --------------------------------------------------------------------------- #
# projector validate/fold/persist


def _projector(tmp_path, admin_pk):
    return CapabilityProjector(
        projection=CapabilityProjection(),
        admin_pubkeys=[admin_pk],
        projection_path=tmp_path / "capabilities.json",
        cursor_dir=tmp_path / "cursors",
    )


def test_projector_persists_grant_on_disk(tmp_path):
    admin_sk, admin_pk = new_key()
    _, subject = new_key()
    projector = _projector(tmp_path, admin_pk)
    event = build_capability(admin_sk, admin_pk, subject, "agent", ["logs.read"])
    result = projector.apply(event)
    assert result.accepted
    on_disk = load_capabilities(tmp_path / "capabilities.json")
    assert on_disk.scopes_for(subject) == ["logs.read"]
    assert on_disk.revision.startswith(f"{event['created_at']}:")
    # The cursor advanced with the projection.
    assert projector.checkpoint.event_id == event["id"]


def test_projector_empty_scopes_is_a_revoke(tmp_path):
    admin_sk, admin_pk = new_key()
    _, subject = new_key()
    projector = _projector(tmp_path, admin_pk)
    grant = build_capability(admin_sk, admin_pk, subject, "agent", ["logs.read"])
    projector.apply(grant)
    revoke = build_capability(admin_sk, admin_pk, subject, "agent", [])
    revoke["created_at"] = grant["created_at"] + 10
    projector.apply(revoke)
    assert load_capabilities(tmp_path / "capabilities.json").scopes_for(subject) == []


def test_projector_quarantines_non_admin_grant(tmp_path):
    _, admin_pk = new_key()
    attacker_sk, attacker_pk = new_key()
    _, subject = new_key()
    projector = _projector(tmp_path, admin_pk)
    result = projector.apply(build_capability(attacker_sk, attacker_pk, subject, "agent", ["system.upgrade"]))
    assert not result.accepted
    assert projector.health().quarantined == 1
    assert load_capabilities(tmp_path / "capabilities.json").scopes_for(subject) == []


def test_projector_delegation_then_revocation(tmp_path):
    admin_sk, admin_pk = new_key()
    _, delegate = new_key()
    projector = _projector(tmp_path, admin_pk)
    projector.server_pubkey = "s" * 64
    projector.apply(build_capability(admin_sk, admin_pk, admin_pk, "admin", ["logs.read"]))
    delegation = build_delegation(admin_sk, admin_pk, delegate, "s" * 64, ["logs.read"], int(time.time()) + 3600)
    assert projector.apply(delegation).accepted
    projection = load_capabilities(tmp_path / "capabilities.json")
    assert projection.authorized(delegate, "logs.read")
    assert projector.apply(build_delegation_revocation(admin_sk, admin_pk, delegation["id"])).accepted
    assert not load_capabilities(tmp_path / "capabilities.json").authorized(delegate, "logs.read")


def test_projector_rejects_delegation_for_wrong_server(tmp_path):
    admin_sk, admin_pk = new_key()
    _, delegate = new_key()
    projector = _projector(tmp_path, admin_pk)
    projector.server_pubkey = "s" * 64
    projector.apply(build_capability(admin_sk, admin_pk, admin_pk, "agent", ["logs.read"]))
    bad = build_delegation(admin_sk, admin_pk, delegate, "x" * 64, ["logs.read"], int(time.time()) + 3600)
    assert not projector.apply(bad).accepted
    assert load_capabilities(tmp_path / "capabilities.json").delegations == {}


# --------------------------------------------------------------------------- #
# rebuild + freshness


def test_rebuild_from_events_refolds_and_persists(tmp_path):
    admin_sk, admin_pk = new_key()
    _, subject = new_key()
    first = build_capability(admin_sk, admin_pk, subject, "agent", ["logs.read"])
    second = build_capability(admin_sk, admin_pk, subject, "agent", ["logs.read", "services.read"])
    second["created_at"] = first["created_at"] + 10  # a newer replaceable grant must win
    report = rebuild_from_events(
        [first, second],
        admin_pubkeys=[admin_pk],
        projection_path=tmp_path / "capabilities.json",
        cursor_dir=tmp_path / "cursors",
    )
    assert report["accepted"] == 2
    assert load_capabilities(tmp_path / "capabilities.json").scopes_for(subject) == ["logs.read", "services.read"]


def test_older_replaceable_grant_does_not_clobber_newer(tmp_path):
    admin_sk, admin_pk = new_key()
    _, subject = new_key()
    newer = build_capability(admin_sk, admin_pk, subject, "agent", ["services.read"])
    older = build_capability(admin_sk, admin_pk, subject, "agent", ["logs.read"])
    older["created_at"] = newer["created_at"] - 10
    rebuilt = rebuild_from_events(
        [newer, older],
        admin_pubkeys=[admin_pk],
        projection_path=tmp_path / "capabilities.json",
        cursor_dir=tmp_path / "cursors",
    )
    assert rebuilt["accepted"] == 2
    assert load_capabilities(tmp_path / "capabilities.json").scopes_for(subject) == ["services.read"]


def test_freshness_guard(tmp_path):
    fresh = CapabilityProjection(revision="r", updated_at=time.time())
    assert capabilities_are_fresh(fresh)
    stale = CapabilityProjection(revision="r", updated_at=time.time() - 10_000)
    assert not capabilities_are_fresh(stale)
    assert not capabilities_are_fresh(CapabilityProjection())  # never written


def test_save_capabilities_stamps_revision(tmp_path):
    path = tmp_path / "capabilities.json"
    save_capabilities(CapabilityProjection(scopes={"aa" * 32: ["logs.read"]}), path)
    loaded = load_capabilities(path)
    assert loaded.revision
    assert loaded.scopes_for("aa" * 32) == ["logs.read"]


# --------------------------------------------------------------------------- #
# executor integration


def test_engine_persists_and_mirrors_through_projector(tmp_path):
    admin_sk, admin_pk = new_key()
    _, agent_pk = new_key()
    projector = _projector(tmp_path, admin_pk)
    engine = OperationEngine(
        publish=lambda ev: None,
        server_sk=admin_sk,
        admins=[admin_pk],
        capability_projector=projector,
    )
    engine.handle_event(build_capability(admin_sk, admin_pk, agent_pk, "agent", ["logs.read"]))
    # Mirror for the state recorder / legacy readers …
    assert engine.scopes[agent_pk] == {"logs.read"}
    # … and the durable file for cross-process readers.
    assert load_capabilities(tmp_path / "capabilities.json").scopes_for(agent_pk) == ["logs.read"]


def test_engine_loads_existing_projection_at_construction(tmp_path):
    admin_sk, admin_pk = new_key()
    _, agent_pk = new_key()
    save_capabilities(
        CapabilityProjection(scopes={agent_pk: ["services.read"]}), tmp_path / "capabilities.json"
    )
    projector = CapabilityProjector(
        projection=load_capabilities(tmp_path / "capabilities.json"),
        admin_pubkeys=[admin_pk],
        projection_path=tmp_path / "capabilities.json",
        cursor_dir=tmp_path / "cursors",
    )
    engine = OperationEngine(
        publish=lambda ev: None, server_sk=admin_sk, admins=[admin_pk], capability_projector=projector
    )
    assert engine.scopes[agent_pk] == {"services.read"}


def test_engine_without_projector_keeps_legacy_in_memory_behaviour():
    admin_sk, admin_pk = new_key()
    _, agent_pk = new_key()
    engine = OperationEngine(publish=lambda ev: None, server_sk=admin_sk, admins=[admin_pk])
    engine.handle_event(build_capability(admin_sk, admin_pk, agent_pk, "agent", ["logs.read"]))
    assert engine.scopes[agent_pk] == {"logs.read"}
