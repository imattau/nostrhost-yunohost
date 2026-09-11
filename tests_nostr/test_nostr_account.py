"""Unit tests for the identity self-service layer (roadmap §8 /nostr-account).

Covers the portalapi helpers (``nostr_account``) and the privileged control
socket on ``nostr-identityd`` (``handle_control_request`` + ``serve_control``),
which together let a logged-in user link / revoke / rename / unlink their own
Nostr identities without the portal-api holding root keys.

Run with: pytest tests_nostr/test_nostr_account.py
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import pytest
from coincurve import PublicKeyXOnly

from yunohost.nostr_account import (
    AccountError,
    allow_identity_linking,
    identityd_request,
)
from yunohost.nostr_identity import _build_identity_event, _store
from yunohost.nostr_identityd import (
    handle_control_request,
    handle_identity_event,
    serve_control,
)


def new_key():
    sk = os.urandom(32).hex()
    pk = PublicKeyXOnly.from_secret(bytes.fromhex(sk)).format().hex()
    return sk, pk


class FakeTransport:
    def __init__(self):
        self.sent = []

    def __call__(self, relay, event):
        self.sent.append((relay, event))


@pytest.fixture
def store(tmp_path):
    return _store(tmp_path / "identity.db")


@pytest.fixture
def operator():
    return new_key()[0]  # operator secret key


def _control(request, store, operator, transport):
    return handle_control_request(
        request,
        store=store,
        operator_sk=operator,
        control_relay="ws://127.0.0.1:4848",
        transport=transport,
    )


# --------------------------------------------------------------------------- #
# allow_identity_linking


def test_linking_allowed_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("NOSTRHOST_NOTICE_CONFIG", str(tmp_path / "missing.toml"))
    assert allow_identity_linking() is True


def test_linking_disabled_by_config(tmp_path, monkeypatch):
    conf = tmp_path / "portal.toml"
    conf.write_text('allow_identity_linking = false\n')
    monkeypatch.setenv("NOSTRHOST_NOTICE_CONFIG", str(conf))
    assert allow_identity_linking() is False


def test_linking_explicitly_enabled(tmp_path, monkeypatch):
    conf = tmp_path / "portal.toml"
    conf.write_text('allow_identity_linking = true\n')
    monkeypatch.setenv("NOSTRHOST_NOTICE_CONFIG", str(conf))
    assert allow_identity_linking() is True


# --------------------------------------------------------------------------- #
# handle_control_request


def test_control_link_publishes_identity_event(store, operator):
    _, subject = new_key()
    transport = FakeTransport()
    result = _control(
        {"action": "link", "username": "matt", "pubkey": subject, "signer_type": "nip46", "label": "phone"},
        store,
        operator,
        transport,
    )
    assert result["ok"] is True
    assert result["pubkey"] == subject
    relay, event = transport.sent[0]
    assert relay == "ws://127.0.0.1:4848"
    assert event["kind"] == 31102
    assert event["tags"][0] == ["d", subject]
    assert json.loads(event["content"]) == {
        "username": "matt", "signer_type": "nip46", "label": "phone", "enabled": True,
    }


def test_control_link_rejects_bad_signer_type(store, operator):
    _, subject = new_key()
    result = _control(
        {"action": "link", "username": "matt", "pubkey": subject, "signer_type": "fido"},
        store,
        operator,
        FakeTransport(),
    )
    assert result["ok"] is False
    assert "signer_type" in result["error"]


def test_control_link_rejects_pubkey_linked_elsewhere(store, operator):
    _, subject = new_key()
    other_admin_sk, other_admin_pk = new_key()
    handle_identity_event(
        _build_identity_event(other_admin_sk, other_admin_pk, subject, "alice", "unknown", None, True),
        store=store,
        admin_pubkeys=[other_admin_pk],
    )
    result = _control(
        {"action": "link", "username": "matt", "pubkey": subject},
        store,
        operator,
        FakeTransport(),
    )
    assert result["ok"] is False
    assert "different account" in result["error"]


def test_control_requires_username(store, operator):
    _, subject = new_key()
    result = _control({"action": "link", "pubkey": subject}, store, operator, FakeTransport())
    assert result["ok"] is False
    assert "username" in result["error"]


def test_control_revoke_only_own_identity(store, operator):
    _, subject = new_key()
    admin_sk, admin_pk = new_key()
    handle_identity_event(
        _build_identity_event(admin_sk, admin_pk, subject, "alice", "unknown", None, True),
        store=store,
        admin_pubkeys=[admin_pk],
    )
    # matt cannot revoke alice's identity
    result = _control({"action": "revoke", "username": "matt", "pubkey": subject}, store, operator, FakeTransport())
    assert result["ok"] is False

    transport = FakeTransport()
    result = _control({"action": "revoke", "username": "alice", "pubkey": subject}, store, operator, transport)
    assert result["ok"] is True
    assert json.loads(transport.sent[0][1]["content"])["enabled"] is False


def test_control_rename_relinks_with_label(store, operator):
    _, subject = new_key()
    admin_sk, admin_pk = new_key()
    handle_identity_event(
        _build_identity_event(admin_sk, admin_pk, subject, "matt", "nip07", "Laptop", True),
        store=store,
        admin_pubkeys=[admin_pk],
    )
    transport = FakeTransport()
    result = _control(
        {"action": "rename", "username": "matt", "pubkey": subject, "label": "Work laptop"},
        store,
        operator,
        transport,
    )
    assert result["ok"] is True
    content = json.loads(transport.sent[0][1]["content"])
    assert content["enabled"] is True
    assert content["label"] == "Work laptop"
    assert content["signer_type"] == "nip07"


def test_control_rename_requires_label(store, operator):
    _, subject = new_key()
    admin_sk, admin_pk = new_key()
    handle_identity_event(
        _build_identity_event(admin_sk, admin_pk, subject, "matt", "nip07", "Laptop", True),
        store=store,
        admin_pubkeys=[admin_pk],
    )
    result = _control(
        {"action": "rename", "username": "matt", "pubkey": subject, "label": "  "},
        store,
        operator,
        FakeTransport(),
    )
    assert result["ok"] is False
    assert "label" in result["error"]


def test_control_unlink_revokes_all(store, operator):
    _, pk1 = new_key()
    _, pk2 = new_key()
    admin_sk, admin_pk = new_key()
    for pk in (pk1, pk2):
        handle_identity_event(
            _build_identity_event(admin_sk, admin_pk, pk, "matt", "unknown", None, True),
            store=store,
            admin_pubkeys=[admin_pk],
        )
    transport = FakeTransport()
    result = _control({"action": "unlink", "username": "matt"}, store, operator, transport)
    assert result["ok"] is True
    assert len(result["event_ids"]) == 2
    for _, event in transport.sent:
        assert json.loads(event["content"])["enabled"] is False


def test_control_unknown_action(store, operator):
    result = _control({"action": "explode", "username": "matt"}, store, operator, FakeTransport())
    assert result["ok"] is False


# --------------------------------------------------------------------------- #
# control socket + client


def test_socket_roundtrip_link(tmp_path, monkeypatch):
    """serve_control + identityd_request end-to-end: a link request over the
    UNIX socket is validated, operator-signed, and published."""
    import os as _os

    from yunohost.nostr_identityd import _portal_uid

    monkeypatch.setattr("yunohost.nostr_identityd._portal_uid", lambda: _os.getuid())

    store = _store(tmp_path / "identity.db")
    operator_sk, _ = new_key()
    _, subject = new_key()
    transport = FakeTransport()
    sock = tmp_path / "identity.sock"

    stop = threading.Event()
    thread = serve_control(
        store,
        operator_sk=operator_sk,
        control_relay="ws://127.0.0.1:4848",
        sock_path=sock,
        stop=stop,
        transport=transport,
    )
    try:
        import time

        for _ in range(50):
            if sock.exists():
                break
            time.sleep(0.02)
        result = identityd_request(
            {"action": "link", "username": "matt", "pubkey": subject, "signer_type": "passkey", "label": "phone"},
            sock_path=sock,
        )
    finally:
        stop.set()
        thread.join(timeout=5)

    assert result["ok"] is True
    assert result["pubkey"] == subject
    relay, event = transport.sent[0]
    assert event["kind"] == 31102
    assert json.loads(event["content"])["signer_type"] == "passkey"


def test_socket_forbids_unprivileged_peer(tmp_path, monkeypatch):
    """A peer that is neither root nor ynh-portal is rejected."""
    from yunohost.nostr_identityd import _portal_uid

    # Force the portal uid to None: only root (uid 0) is then allowed, and
    # the test process runs as a non-root user, so the request is refused.
    monkeypatch.setattr("yunohost.nostr_identityd._portal_uid", lambda: None)
    assert _portal_uid() is None
    store = _store(tmp_path / "identity.db")
    operator_sk, _ = new_key()
    sock = tmp_path / "identity.sock"
    stop = threading.Event()
    thread = serve_control(
        store,
        operator_sk=operator_sk,
        control_relay="ws://127.0.0.1:4848",
        sock_path=sock,
        stop=stop,
    )
    try:
        import time

        for _ in range(50):
            if sock.exists():
                break
            time.sleep(0.02)
        result = identityd_request({"action": "link", "username": "matt", "pubkey": "1" * 64}, sock_path=sock)
    finally:
        stop.set()
        thread.join(timeout=5)

    assert result["ok"] is False
    assert result["error"] == "forbidden"


def test_identityd_request_missing_socket(tmp_path):
    with pytest.raises(AccountError, match="not running"):
        identityd_request({"action": "unlink", "username": "matt"}, sock_path=tmp_path / "none.sock")