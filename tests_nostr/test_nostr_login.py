"""Unit tests for §8 passwordless Nostr portal login.

Run with: pytest tests_nostr/  (needs nostrhost-auth and nostr-sdk)
"""

from __future__ import annotations

import json
import os
import sys
import types

import pytest
from nostr_sdk import Keys

from yunohost.nostr_identity import _sign_event, _store
from yunohost.nostr_login import (
    LOGIN_ACTION,
    LoginError,
    auth_request_route,
    create_portal_session,
    handle_login,
    issue_challenge,
)
from yunohost import nostr_login

CHALLENGE_KIND = 22242
DOMAIN = "nostrhost.test"


def new_key():
    sk = os.urandom(32).hex()
    pk = Keys.parse(sk).public_key().to_hex()
    return sk, pk


def _signed_challenge_event(sk, pk, *, nonce, domain=DOMAIN, action=LOGIN_ACTION):
    return _sign_event(
        sk,
        pk,
        CHALLENGE_KIND,
        "",
        [["challenge", nonce], ["domain", domain], ["action", action]],
    )


def _link(db, username, pk, signer_type="nip07"):
    store = _store(db)
    store.add_identity(username, pk, signer_type=signer_type)
    return store


class Recorder:
    def __init__(self):
        self.sessions = []
        self.notices = []

    def record_session(self, username, **kwargs):
        self.sessions.append((username, kwargs))

    def record_notice(self, pubkey, username):
        self.notices.append((pubkey, username))


@pytest.fixture
def rec(monkeypatch):
    r = Recorder()
    monkeypatch.setattr(nostr_login, "create_portal_session", r.record_session)
    monkeypatch.setattr(nostr_login, "_publish_login_notice", r.record_notice)
    return r


@pytest.fixture
def fake_ldap_ynhuser(monkeypatch):
    """Stub yunohost.authenticators.ldap_ynhuser so create_portal_session
    can be exercised without python-ldap (which needs system build deps)."""

    class FakeAuthenticator:
        sessions: list[dict] = []

        def set_session_cookie(self, infos):
            FakeAuthenticator.sessions.append(infos)

    mod = types.ModuleType("yunohost.authenticators.ldap_ynhuser")
    mod.Authenticator = FakeAuthenticator
    mod.encrypt = lambda data: f"enc:{data}"
    mod.user_is_allowed_on_domain = lambda user, domain: True
    mod._host_domain = lambda host: host
    sys.modules["yunohost.authenticators.ldap_ynhuser"] = mod

    yield mod

    sys.modules.pop("yunohost.authenticators.ldap_ynhuser", None)


def test_issue_challenge_returns_nonce():
    nonce = issue_challenge(domain=DOMAIN)
    assert isinstance(nonce, str) and len(nonce) >= 32


def test_auth_request_returns_compatibility_headers(monkeypatch):
    class FakeAuthenticator:
        def get_session_cookie(self):
            return {
                "user": "matt",
                "email": "matt@example.test",
                "fullname": "Matt Example",
            }

    mod = types.ModuleType("yunohost.authenticators.ldap_ynhuser")
    mod.Authenticator = FakeAuthenticator
    mod._host_domain = lambda host: host
    monkeypatch.setitem(sys.modules, "yunohost.authenticators.ldap_ynhuser", mod)

    result = auth_request_route()

    assert result.status_code == 204
    # identity headers ride on the returned HTTPResponse (bottle drops headers
    # set on the global `response` when a fresh HTTPResponse is returned)
    assert result.headers["X-Remote-User"] == "matt"
    assert result.headers["X-Remote-Email"] == "matt@example.test"
    assert result.headers["X-Remote-Fullname"] == "Matt Example"


def test_auth_request_rejects_invalid_session(monkeypatch):
    class FakeAuthenticator:
        def get_session_cookie(self):
            raise RuntimeError("expired")

    mod = types.ModuleType("yunohost.authenticators.ldap_ynhuser")
    mod.Authenticator = FakeAuthenticator
    mod._host_domain = lambda host: host
    monkeypatch.setitem(sys.modules, "yunohost.authenticators.ldap_ynhuser", mod)

    with pytest.raises(Exception) as exc_info:
        auth_request_route()

    assert exc_info.value.status_code == 401


def test_handle_login_success(rec, tmp_path):
    sk, pk = new_key()
    _link(tmp_path / "i.db", "matt", pk)
    nonce = issue_challenge(domain=DOMAIN)
    event = _signed_challenge_event(sk, pk, nonce=nonce)

    res = handle_login(event, domain=DOMAIN, identity_db=tmp_path / "i.db")

    assert res == {"ok": True, "user": "matt", "pubkey": pk}
    assert rec.sessions == [("matt", {"domain": DOMAIN})]
    assert rec.notices == [(pk, "matt")]


def test_handle_login_rejects_replay(rec, tmp_path):
    sk, pk = new_key()
    _link(tmp_path / "i.db", "matt", pk)
    nonce = issue_challenge(domain=DOMAIN)
    event = _signed_challenge_event(sk, pk, nonce=nonce)

    handle_login(event, domain=DOMAIN, identity_db=tmp_path / "i.db")
    with pytest.raises(LoginError):
        handle_login(event, domain=DOMAIN, identity_db=tmp_path / "i.db")
    assert len(rec.sessions) == 1


def test_handle_login_rejects_unlinked_pubkey(rec, tmp_path):
    sk, pk = new_key()
    nonce = issue_challenge(domain=DOMAIN)
    event = _signed_challenge_event(sk, pk, nonce=nonce)

    with pytest.raises(LoginError, match="not linked"):
        handle_login(event, domain=DOMAIN, identity_db=tmp_path / "i.db")
    assert rec.sessions == []


def test_handle_login_rejects_wrong_domain(rec, tmp_path):
    sk, pk = new_key()
    _link(tmp_path / "i.db", "matt", pk)
    nonce = issue_challenge(domain="a.test")
    event = _signed_challenge_event(sk, pk, nonce=nonce, domain="a.test")

    with pytest.raises(LoginError, match="different domain"):
        handle_login(event, domain=DOMAIN, identity_db=tmp_path / "i.db")
    assert rec.sessions == []


def test_handle_login_rejects_tampered_signature(rec, tmp_path):
    sk, pk = new_key()
    _link(tmp_path / "i.db", "matt", pk)
    nonce = issue_challenge(domain=DOMAIN)
    event = _signed_challenge_event(sk, pk, nonce=nonce)
    event["content"] = "tampered"

    with pytest.raises(LoginError):
        handle_login(event, domain=DOMAIN, identity_db=tmp_path / "i.db")
    assert rec.sessions == []


def test_handle_login_rejects_missing_challenge(rec, tmp_path):
    sk, pk = new_key()
    _link(tmp_path / "i.db", "matt", pk)
    event = _sign_event(sk, pk, CHALLENGE_KIND, "", [["domain", DOMAIN], ["action", LOGIN_ACTION]])

    with pytest.raises(LoginError, match="missing challenge"):
        handle_login(event, domain=DOMAIN, identity_db=tmp_path / "i.db")


def test_handle_login_rejects_wrong_kind(rec, tmp_path):
    sk, pk = new_key()
    _link(tmp_path / "i.db", "matt", pk)
    nonce = issue_challenge(domain=DOMAIN)
    event = _sign_event(
        sk,
        pk,
        22243,
        "",
        [["challenge", nonce], ["domain", DOMAIN], ["action", LOGIN_ACTION]],
    )

    with pytest.raises(LoginError):
        handle_login(event, domain=DOMAIN, identity_db=tmp_path / "i.db")


def test_create_portal_session_success(monkeypatch, fake_ldap_ynhuser):
    monkeypatch.setattr(
        nostr_login,
        "_user_infos_for_session",
        lambda username: {"cn": "Matt", "mail": "matt@example.test"},
    )

    create_portal_session("matt", domain=DOMAIN)

    infos = fake_ldap_ynhuser.Authenticator.sessions[-1]
    assert infos["user"] == "matt"
    assert infos["email"] == "matt@example.test"
    assert infos["fullname"] == "Matt"
    assert infos["passwordless"] is True
    assert infos["pwd"].startswith("enc:")


def test_create_portal_session_denied_on_domain(fake_ldap_ynhuser):
    fake_ldap_ynhuser.user_is_allowed_on_domain = lambda user, domain: False
    with pytest.raises(LoginError, match="not allowed"):
        create_portal_session("matt", domain=DOMAIN)


def test_create_portal_session_requires_domain(fake_ldap_ynhuser):
    with pytest.raises(LoginError, match="missing Host"):
        create_portal_session("matt")


def test_notice_signer_absent_by_default(monkeypatch):
    monkeypatch.setenv("NOSTRHOST_NOTICE_CONFIG", "/nonexistent/portal.toml")
    assert nostr_login._notice_signer() is None


def test_notice_signer_reads_portal_config(tmp_path, monkeypatch):
    sk, pk = new_key()
    cfg = tmp_path / "portal.toml"
    cfg.write_text(f'notice_sk = "{sk}"\n')
    monkeypatch.setenv("NOSTRHOST_NOTICE_CONFIG", str(cfg))
    assert nostr_login._notice_signer() == (sk, pk)


def test_publish_login_notice_uses_dedicated_key(tmp_path, monkeypatch):
    import yunohost.nostr_identity as ni

    notice_sk, notice_pk = new_key()
    _, user_pk = new_key()
    cfg = tmp_path / "portal.toml"
    cfg.write_text(f'notice_sk = "{notice_sk}"\ncontrol_relay = "ws://127.0.0.1:4848"\n')
    monkeypatch.setenv("NOSTRHOST_NOTICE_CONFIG", str(cfg))

    sent = []
    monkeypatch.setattr(ni, "publish_to_relay", lambda relay, event: sent.append((relay, event)))

    nostr_login._publish_login_notice(user_pk, "matt")

    assert len(sent) == 1
    relay, event = sent[0]
    assert relay == "ws://127.0.0.1:4848"
    assert event["kind"] == 2206
    assert event["pubkey"] == notice_pk
    assert [t for t in event["tags"] if t[0] == "p"][0][1] == user_pk
    assert json.loads(event["content"])["username"] == "matt"
