"""WP4 tests: NIP-51 list / NIP-78 preference projection.

Covers coordinate ownership, the store fold + replaceable semantics, the
operator-vs-user merge rules, self-service enforcement, family readers and the
compatibility renderers.
"""

from __future__ import annotations

import json

from conftest import new_key
from yunohost.nostr_identity import _sign_event
from yunohost.nostrhost.list_projection import (
    KIND_APP_DATA,
    KIND_MUTE_LIST,
    KIND_PERMISSION_SET,
    KIND_RELAY_LIST,
    ListProjector,
    ListStore,
    approved_repositories,
    blocked_relays,
    blocked_site_owners,
    merge_user_relays,
    portal_settings,
    preferred_relays,
    trusted_publishers,
    user_preferences,
)
from yunohost.nostrhost.list_specs import (
    HOST_NAMESPACE,
    is_self_service_coordinate,
    user_preferences_coordinate,
)


def _event(sk, pk, kind, d, *, p=(), r=(), content="", created_at=None, public=False):
    tags = []
    if d is not None:
        tags.append(["d", d])
    tags += [["p", value] for value in p]
    tags += [["r", value] for value in r]
    if public:
        tags.append(["public", "true"])
    event = _sign_event(sk, pk, kind, content, tags, created_at=created_at)
    return event


def _projector(tmp_path, admin_pk):
    return ListProjector(
        store=ListStore(tmp_path / "lists.json"),
        admin_pubkeys=[admin_pk],
        cursor_dir=tmp_path / "cursors",
    )


# --------------------------------------------------------------------------- #
# coordinate ownership


def test_user_preferences_coordinate_is_self_describing():
    pk = "ab" * 32
    coordinate = user_preferences_coordinate(pk)
    assert coordinate == f"{HOST_NAMESPACE}:user-preferences:{pk}"
    assert is_self_service_coordinate(coordinate, pk)
    assert not is_self_service_coordinate(coordinate, "cd" * 32)


def test_host_lists_are_not_self_service():
    for coordinate in (
        f"{HOST_NAMESPACE}:trusted-publishers",
        f"{HOST_NAMESPACE}:approved-repositories",
        f"{HOST_NAMESPACE}:portal-settings",
        "myapp.main",
    ):
        assert not is_self_service_coordinate(coordinate, "ab" * 32)


# --------------------------------------------------------------------------- #
# project + store


def test_operator_people_set_is_projected(tmp_path):
    admin_sk, admin_pk = new_key()
    _, publisher = new_key()
    projector = _projector(tmp_path, admin_pk)
    event = _event(admin_sk, admin_pk, KIND_PERMISSION_SET, f"{HOST_NAMESPACE}:trusted-publishers", p=[publisher])
    assert projector.apply(event).accepted
    store = ListStore(tmp_path / "lists.json")
    assert trusted_publishers(store) == [publisher]


def test_non_admin_cannot_write_host_list(tmp_path):
    admin_sk, admin_pk = new_key()
    attacker_sk, attacker_pk = new_key()
    _, target = new_key()
    projector = _projector(tmp_path, admin_pk)
    event = _event(attacker_sk, attacker_pk, KIND_PERMISSION_SET, f"{HOST_NAMESPACE}:trusted-publishers", p=[target])
    assert not projector.apply(event).accepted
    assert trusted_publishers(ListStore(tmp_path / "lists.json")) == []


def test_self_service_projector_writes_only_own_coordinate(tmp_path):
    admin_sk, admin_pk = new_key()
    user_sk, user_pk = new_key()
    projector = ListProjector(
        store=ListStore(tmp_path / "lists.json"),
        admin_pubkeys=[admin_pk],
        validate_self_service=is_self_service_coordinate,
        cursor_dir=tmp_path / "cursors",
    )
    own = _event(
        user_sk, user_pk, KIND_APP_DATA, user_preferences_coordinate(user_pk),
        content=json.dumps({"portal_theme": "dark"}),
    )
    assert projector.apply(own).accepted
    # A user may not write another user's coordinate.
    _, other = new_key()
    foreign = _event(
        user_sk, user_pk, KIND_APP_DATA, user_preferences_coordinate(other),
        content=json.dumps({"portal_theme": "light"}),
    )
    assert not projector.apply(foreign).accepted


def test_replaceable_newest_created_at_wins(tmp_path):
    admin_sk, admin_pk = new_key()
    _, one = new_key()
    _, two = new_key()
    projector = _projector(tmp_path, admin_pk)
    first = _event(admin_sk, admin_pk, KIND_MUTE_LIST, None, p=[one], created_at=1000)
    newer = _event(admin_sk, admin_pk, KIND_MUTE_LIST, None, p=[two], created_at=2000)
    stale = _event(admin_sk, admin_pk, KIND_MUTE_LIST, None, p=[one], created_at=500)
    projector.apply(first)
    projector.apply(stale)  # accepted-but-ignored (older)
    projector.apply(newer)
    assert blocked_site_owners(ListStore(tmp_path / "lists.json")) == [two]


# --------------------------------------------------------------------------- #
# readers + merge rules


def test_blocked_relays_are_mandatory_and_win_over_user_relays(tmp_path):
    admin_sk, admin_pk = new_key()
    projector = _projector(tmp_path, admin_pk)
    projector.apply(
        _event(admin_sk, admin_pk, 10006, None, p=["wss://blocked.example"])
    )
    store = ListStore(tmp_path / "lists.json")
    assert blocked_relays(store) == ["wss://blocked.example"]
    merged = merge_user_relays(
        ["wss://server.example", "wss://blocked.example"],
        ["wss://user.example"],
        store=store,
    )
    assert merged == ["wss://server.example", "wss://user.example"]


def test_user_preferences_mandatory_restrictions_win(tmp_path):
    admin_sk, admin_pk = new_key()
    user_sk, user_pk = new_key()
    projector = ListProjector(
        store=ListStore(tmp_path / "lists.json"),
        admin_pubkeys=[admin_pk],
        validate_self_service=is_self_service_coordinate,
        cursor_dir=tmp_path / "cursors",
    )
    projector.apply(
        _event(
            admin_sk, admin_pk, KIND_APP_DATA, f"{HOST_NAMESPACE}:portal-settings",
            content=json.dumps({"portal_theme": "system", "mandatory_restrictions": {"portal_theme": "light"}}),
        )
    )
    projector.apply(
        _event(
            user_sk, user_pk, KIND_APP_DATA, user_preferences_coordinate(user_pk),
            content=json.dumps({"portal_theme": "dark", "portal_title": "mine"}),
        )
    )
    store = ListStore(tmp_path / "lists.json")
    prefs = user_preferences(user_pk, store=store)
    assert prefs["portal_theme"] == "light"  # mandatory wins
    assert prefs["portal_title"] == "mine"  # user preference honoured
    assert prefs["mandatory"] == ["portal_theme"]


def test_approved_repositories_read(tmp_path):
    admin_sk, admin_pk = new_key()
    projector = _projector(tmp_path, admin_pk)
    projector.apply(
        _event(admin_sk, admin_pk, KIND_PERMISSION_SET, f"{HOST_NAMESPACE}:approved-repositories", r=["github.com/example/repo"])
    )
    assert approved_repositories(ListStore(tmp_path / "lists.json")) == ["github.com/example/repo"]


def test_portal_settings_document_read(tmp_path):
    admin_sk, admin_pk = new_key()
    projector = _projector(tmp_path, admin_pk)
    projector.apply(
        _event(admin_sk, admin_pk, KIND_APP_DATA, f"{HOST_NAMESPACE}:portal-settings", content=json.dumps({"portal_title": "Host"}))
    )
    assert portal_settings(ListStore(tmp_path / "lists.json")) == {"portal_title": "Host"}


# --------------------------------------------------------------------------- #
# relay list merge (preferred relays)


def test_preferred_relays_are_additive(tmp_path):
    admin_sk, admin_pk = new_key()
    user_sk, user_pk = new_key()
    projector = ListProjector(
        store=ListStore(tmp_path / "lists.json"),
        admin_pubkeys=[admin_pk],
        validate_self_service=is_self_service_coordinate,
        cursor_dir=tmp_path / "cursors",
    )
    # 10002 has no d; both server and user relay lists are accepted, each in
    # their own per-author slot.
    assert projector.apply(_event(admin_sk, admin_pk, KIND_RELAY_LIST, None, r=["wss://server"])).accepted
    assert projector.apply(_event(user_sk, user_pk, KIND_RELAY_LIST, None, r=["wss://mine"])).accepted
    store = ListStore(tmp_path / "lists.json")
    assert preferred_relays(admin_pk, store=store) == ["wss://server"]
    assert preferred_relays(user_pk, store=store) == ["wss://mine"]
    assert set(preferred_relays(store=store)) == {"wss://server", "wss://mine"}


# --------------------------------------------------------------------------- #
# compatibility renderers


def test_render_trusted_publishers_rewrites_catalogue_env(tmp_path):
    from yunohost.nostrhost.list_render import render_trusted_publishers

    env = tmp_path / "catalogue.env"
    env.write_text("NOSTRHOST_CATALOG_RELAYS=wss://r\nNOSTRHOST_CATALOG_PUBLISHERS=old\n")
    render_trusted_publishers(["ab" * 32, "cd" * 32], path=env)
    lines = env.read_text().splitlines()
    assert f"NOSTRHOST_CATALOG_PUBLISHERS={'ab' * 32},{'cd' * 32}" in lines
    assert "NOSTRHOST_CATALOG_RELAYS=wss://r" in lines  # other lines preserved


def test_render_trusted_publishers_appends_when_absent(tmp_path):
    from yunohost.nostrhost.list_render import render_trusted_publishers

    env = tmp_path / "catalogue.env"
    env.write_text("NOSTRHOST_CATALOG_RELAYS=wss://r\n")
    render_trusted_publishers(["ab" * 32], path=env)
    assert f"NOSTRHOST_CATALOG_PUBLISHERS={'ab' * 32}" in env.read_text().splitlines()


def test_render_portal_settings_preserves_apps(tmp_path):
    from yunohost.nostrhost.list_render import render_portal_settings

    portal = tmp_path / "portal"
    portal.mkdir()
    (portal / "example.com.json").write_text(json.dumps({"apps": {"app": {"public": True}}, "portal_title": "old"}))
    render_portal_settings({"portal_title": "Host", "portal_theme": "dark", "evil": "x"}, portal_dir=portal)
    data = json.loads((portal / "example.com.json").read_text())
    assert data["apps"] == {"app": {"public": True}}  # apps owned by the permission projection
    assert data["portal_title"] == "Host"
    assert data["portal_theme"] == "dark"
    assert "evil" not in data  # unknown keys are dropped


def test_render_entry_dispatches_by_coordinate(tmp_path, monkeypatch):
    from yunohost.nostrhost import list_render
    from yunohost.nostrhost.list_projection import ListEntry

    calls = []
    monkeypatch.setattr(list_render, "render_trusted_publishers", lambda entries, **kw: calls.append(("pub", entries)))
    list_render.render_entry(ListEntry(kind=30000, coordinate="nostrhost:trusted-publishers", key="k"))
    assert calls == [("pub", [])]


# --------------------------------------------------------------------------- #
# importers publish signed events without changing effective access


def test_import_trusted_publishers_publishes_signed_event(tmp_path, monkeypatch):
    admin_sk, admin_pk = new_key()
    _, publisher = new_key()
    sent = []

    class Cfg:
        operator_sk = admin_sk
        operator_pubkey = admin_pk
        control_relay = "ws://relay"

    monkeypatch.setattr("yunohost.nostr_identity._operator_config", lambda *a, **k: Cfg())
    from yunohost.nostrhost.list_projection import import_trusted_publishers

    event = import_trusted_publishers([publisher], transport=lambda relay, ev: sent.append(ev))
    assert event["kind"] == KIND_PERMISSION_SET
    assert ["d", "nostrhost:trusted-publishers"] in event["tags"]
    assert ["p", publisher] in event["tags"]
    assert sent and sent[0]["id"] == event["id"]


def test_publish_user_preferences_rejects_key_mismatch():
    signer_sk, signer_pk = new_key()
    _, other = new_key()
    from yunohost.nostrhost.list_projection import publish_user_preferences

    try:
        publish_user_preferences(other, {"portal_theme": "dark"}, signer_sk=signer_sk, transport=lambda *a: None)
    except ValueError as exc:
        assert "does not match" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected a key mismatch error")


def test_publish_user_preferences_uses_own_coordinate(monkeypatch):
    signer_sk, signer_pk = new_key()
    sent = []

    class Cfg:
        control_relay = "ws://relay"

    monkeypatch.setattr("yunohost.nostr_identity._operator_config", lambda *a, **k: Cfg())
    from yunohost.nostrhost.list_projection import publish_user_preferences

    event = publish_user_preferences(signer_pk, {"portal_theme": "dark"}, signer_sk=signer_sk, transport=lambda relay, ev: sent.append(ev))
    assert event["pubkey"] == signer_pk
    assert ["d", user_preferences_coordinate(signer_pk)] in event["tags"]
    assert sent and sent[0]["id"] == event["id"]


# --------------------------------------------------------------------------- #
# account deletion / orphaned preference


def test_user_preferences_empty_for_unlinked_pubkey(tmp_path):
    _, unknown = new_key()
    store = ListStore(tmp_path / "lists.json")
    assert user_preferences(unknown, store=store) == {}
