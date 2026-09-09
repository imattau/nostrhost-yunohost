"""Unit tests for the fork's Nostr-native identity (Phase 3).

Run with: pytest tests_nostr/  (needs nostrhost-auth, coincurve, nostr-sdk)
"""

from __future__ import annotations

import json
import os

import pytest
from coincurve import PublicKeyXOnly

from yunohost.nostr_identity import (
    IdentityError,
    _build_identity_event,
    _parse_pubkey,
    _store,
    link_identity,
    resolve_pubkey,
    resolve_username,
    revoke_identity,
)
from yunohost.nostr_identityd import handle_identity_event


def new_key():
    sk = os.urandom(32).hex()
    pk = PublicKeyXOnly.from_secret(bytes.fromhex(sk)).format().hex()
    return sk, pk


class FakeAccounts:
    def __init__(self):
        self.ensured = []

    def user_exists(self, username):
        return username in self.ensured

    def ensure_user(self, username):
        self.ensured.append(username)


class FakeTransport:
    def __init__(self):
        self.sent = []

    def __call__(self, relay, event):
        self.sent.append((relay, event))


def test_parse_pubkey_hex():
    _, pk = new_key()
    assert _parse_pubkey(pk) == pk
    with pytest.raises(IdentityError):
        _parse_pubkey("nope")


def test_parse_pubkey_npub():
    from nostrhost_auth.identity.npub import hex_to_npub

    _, pk = new_key()
    npub = hex_to_npub(pk)
    assert _parse_pubkey(npub) == pk


def test_link_identity_publishes_valid_event():
    sk, pk = new_key()
    _, subject_pk = new_key()
    transport = FakeTransport()

    link_identity(
        "matt",
        subject_pk,
        operator_sk=sk,
        control_relay="ws://127.0.0.1:4848",
        signer_type="nip46",
        label="phone",
        transport=transport,
    )

    assert transport.sent
    relay, ev = transport.sent[0]
    assert relay == "ws://127.0.0.1:4848"
    assert ev["kind"] == 31102
    assert ev["pubkey"] == pk
    assert ev["tags"][0] == ["d", subject_pk]
    assert json.loads(ev["content"]) == {"username": "matt", "signer_type": "nip46", "label": "phone", "enabled": True}

    from nostr_sdk import Event as NsEvent

    ns = NsEvent.from_json(json.dumps(ev))
    assert ns.verify()


def test_link_identity_bad_signer_type():
    _, subject_pk = new_key()
    with pytest.raises(IdentityError):
        link_identity("matt", subject_pk, operator_sk="0" * 64, signer_type="fido", transport=FakeTransport())


def test_revoke_identity_publishes():
    sk, _ = new_key()
    _, subject_pk = new_key()
    transport = FakeTransport()
    event = revoke_identity(subject_pk, operator_sk=sk, transport=transport)
    assert json.loads(event["content"])["enabled"] is False
    assert event["tags"][0] == ["d", subject_pk]


def test_resolve_empty(tmp_path):
    assert resolve_pubkey("f" * 64, db_path=tmp_path / "i.db") is None


def test_projector_materializes_and_creates_account(tmp_path):
    admin_sk, admin_pk = new_key()
    _, subject_pk = new_key()
    store = _store(tmp_path / "i.db")
    accounts = FakeAccounts()

    event = _build_identity_event(admin_sk, admin_pk, subject_pk, "matt", "nip46", None, True)
    assert handle_identity_event(event, store=store, admin_pubkeys=[admin_pk], accounts=accounts) is True

    identity = resolve_pubkey(subject_pk, db_path=tmp_path / "i.db")
    assert identity is not None
    assert identity.username == "matt"
    assert identity.signer_type == "nip46"
    assert accounts.ensured == ["matt"]


def test_projector_ignores_non_admin(tmp_path):
    _, non_admin_pk = new_key()
    admin_sk, admin_pk = new_key()
    _, subject_pk = new_key()
    store = _store(tmp_path / "i.db")
    accounts = FakeAccounts()

    event = _build_identity_event(admin_sk, non_admin_pk, subject_pk, "matt", "unknown", None, True)
    assert handle_identity_event(event, store=store, admin_pubkeys=[admin_pk], accounts=accounts) is False

    assert resolve_pubkey(subject_pk, db_path=tmp_path / "i.db") is None
    assert accounts.ensured == []


def test_projector_revoke_and_reenable(tmp_path):
    admin_sk, admin_pk = new_key()
    _, subject_pk = new_key()
    store = _store(tmp_path / "i.db")

    on = _build_identity_event(admin_sk, admin_pk, subject_pk, "matt", "passkey", None, True)
    handle_identity_event(on, store=store, admin_pubkeys=[admin_pk])
    assert resolve_pubkey(subject_pk, db_path=tmp_path / "i.db") is not None

    off = _build_identity_event(admin_sk, admin_pk, subject_pk, "matt", "passkey", None, False)
    handle_identity_event(off, store=store, admin_pubkeys=[admin_pk])
    assert resolve_pubkey(subject_pk, db_path=tmp_path / "i.db") is None

    # re-enable uses set_identity_enabled (no duplicate row)
    handle_identity_event(on, store=store, admin_pubkeys=[admin_pk])
    identity = resolve_pubkey(subject_pk, db_path=tmp_path / "i.db")
    assert identity is not None
    assert len(resolve_username("matt", db_path=tmp_path / "i.db")) == 1


def test_resolve_username_lists_identities(tmp_path):
    admin_sk, admin_pk = new_key()
    _, pk1 = new_key()
    _, pk2 = new_key()
    store = _store(tmp_path / "i.db")
    handle_identity_event(
        _build_identity_event(admin_sk, admin_pk, pk1, "matt", "nip07", None, True),
        store=store, admin_pubkeys=[admin_pk],
    )
    handle_identity_event(
        _build_identity_event(admin_sk, admin_pk, pk2, "matt", "nip46", "phone", True),
        store=store, admin_pubkeys=[admin_pk],
    )
    ids = resolve_username("matt", db_path=tmp_path / "i.db")
    assert len(ids) == 2
