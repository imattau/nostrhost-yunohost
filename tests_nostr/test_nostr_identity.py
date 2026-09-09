"""Unit tests for the fork's Nostr-native identity (Phase 3).

Run with: pytest tests_nostr/  (needs nostrhost-auth, coincurve, nostr-sdk)
"""

from __future__ import annotations

import json
import os
from pathlib import Path

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


def test_operator_config_server_key_split(tmp_path, monkeypatch):
    """A bootstrapped config carries a distinct server key; _operator_config
    reads it and derives the server pubkey. Legacy configs (no server_sk)
    fall back to the operator key."""
    sk, pk = new_key()
    server_sk, server_pk = new_key()
    cfg_path = tmp_path / "operator.toml"
    cfg_path.write_text(
        f'server_sk = "{server_sk}"\noperator_sk = "{sk}"\ncontrol_relay = "ws://127.0.0.1:4848"\nadmins = ["{pk}"]\n'
    )
    monkeypatch.setenv("NOSTRHOST_OPERATOR_CONFIG", str(cfg_path))

    from yunohost.nostr_identity import _operator_config

    cfg = _operator_config()
    assert cfg.operator_sk == sk
    assert cfg.operator_pubkey == pk
    assert cfg.server_sk == server_sk
    assert cfg.server_pubkey == server_pk
    assert cfg.server_pubkey != cfg.operator_pubkey

    legacy = tmp_path / "legacy.toml"
    legacy.write_text(f'operator_sk = "{sk}"\n')
    monkeypatch.setenv("NOSTRHOST_OPERATOR_CONFIG", str(legacy))
    cfg = _operator_config()
    assert cfg.server_sk == sk  # legacy single-key fallback
    assert cfg.server_pubkey == pk


def test_bootstrapped_state(tmp_path, monkeypatch):
    from yunohost.nostr_identity import _require_bootstrapped, is_bootstrapped

    monkeypatch.setenv("NOSTRHOST_OPERATOR_CONFIG", str(tmp_path / "nope.toml"))
    monkeypatch.delenv("NOSTRHOST_OPERATOR_SK", raising=False)
    assert is_bootstrapped() is False
    with pytest.raises(IdentityError, match="nostrhost-bootstrap"):
        _require_bootstrapped()

    monkeypatch.setenv("NOSTRHOST_OPERATOR_SK", "0" * 64)
    assert is_bootstrapped() is True
    _require_bootstrapped()  # no raise


def test_bootstrap_tool_writes_distinct_keys(tmp_path, monkeypatch):
    """nostrhost-bootstrap writes server + operator keys (distinct, root-only
    mode), refuses overwrite, and --force regenerates."""
    import runpy

    cfg_path = tmp_path / "operator.toml"
    monkeypatch.setenv("NOSTRHOST_OPERATOR_CONFIG", str(cfg_path))
    monkeypatch.delenv("NOSTRHOST_OPERATOR_SK", raising=False)
    monkeypatch.setattr("os.geteuid", lambda: 0)

    tool = str(Path(Path(__file__).resolve().parents[1] / "bin" / "nostrhost-bootstrap"))
    rc = runpy.run_path(tool)
    argv = [tool, "--server-sk", "1" * 64, "--operator-sk", "2" * 64, "--admins", "3" * 64]
    monkeypatch.setattr("sys.argv", argv)
    assert rc["main"]() == 0

    from yunohost.nostr_identity import _operator_config

    cfg = _operator_config()
    assert cfg.server_sk == "1" * 64
    assert cfg.operator_sk == "2" * 64
    assert cfg.admins == ("3" * 64,)
    assert (cfg_path.stat().st_mode & 0o777) == 0o600

    # refusing overwrite
    assert rc["main"]() == 1
    # force regenerates
    monkeypatch.setattr("sys.argv", argv + ["--force"])
    assert rc["main"]() == 0


def test_publish_to_relay_nip42_handshake(tmp_path, monkeypatch):
    """publish_to_relay answers a NIP-42 AUTH challenge with a kind-22242
    event (relay + challenge tags) and re-sends the original event."""
    import asyncio
    import threading
    import time

    import websockets

    from yunohost.nostr_identity import _sign_event, publish_to_relay

    sk, pk = new_key()
    monkeypatch.setenv("NOSTRHOST_OPERATOR_SK", sk)
    monkeypatch.setenv("NOSTRHOST_OPERATOR_CONFIG", str(tmp_path / "none.toml"))

    event = _sign_event(sk, pk, 2200, json.dumps({"tool": "system.version", "args": {}}), [])
    auth_seen = {"n": 0}

    async def handler(ws):
        authed = {"v": False}
        async for raw in ws:
            msg = json.loads(raw)
            if msg[0] == "AUTH":
                auth_seen["n"] += 1
                assert msg[1]["kind"] == 22242
                assert any(t[0] == "challenge" and t[1] == "challenge-xyz" for t in msg[1]["tags"])
                assert any(t[0] == "relay" for t in msg[1]["tags"])
                authed["v"] = True
                await ws.send(json.dumps(["OK", msg[1]["id"], True, "auth ok"]))
            elif msg[0] == "EVENT":
                if not authed["v"]:
                    await ws.send(json.dumps(["AUTH", "challenge-xyz"]))
                else:
                    await ws.send(json.dumps(["OK", event["id"], True, "accepted"]))

    ports: list[int] = []
    done = threading.Event()

    async def serve():
        async with websockets.serve(handler, "127.0.0.1", 0) as srv:
            ports.append(srv.sockets[0].getsockname()[1])
            while not done.is_set():
                await asyncio.sleep(0.1)

    def run_server():
        asyncio.run(serve())

    t = threading.Thread(target=run_server, daemon=True)
    t.start()
    while not ports:
        time.sleep(0.05)

    publish_to_relay(f"ws://127.0.0.1:{ports[0]}", event)
    done.set()
    t.join(timeout=5)
    assert auth_seen["n"] == 1
