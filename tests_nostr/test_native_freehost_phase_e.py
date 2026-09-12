"""Workstream 4 (Phase E): nostr-native free hostname (identity-backed Dynette).

Covers the free-hostname subscription (``dns.subscribe``): the operator
identity signs the ownership claim and the TSIG secret is provisioned into
the credential broker under ``secret:dns/dynette/<hostname>`` — replacing the
legacy TOTP ``yunohost dyndns subscribe`` dance. The Dynette provider then
resolves that broker ref (no explicit credential, no legacy key file), and
the ``domain.add`` gate accepts an identity-subscribed host without a
credential.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from coincurve import PublicKeyXOnly

from nostrhost.credentials import CredentialError, read_secret, set_secret
from nostrhost.dns.freehost import (
    CLAIM_KIND,
    FREE_HOSTNAME_ZONES,
    is_free_hostname,
    list_subscriptions,
    read_subscription,
    subscribe,
    unsubscribe,
    zone_for,
)
from nostrhost.dns.providers.dynette import DynetteProvider

SK = "01" * 32
PUBKEY = PublicKeyXOnly.from_secret(bytes.fromhex(SK)).format().hex()


def _signer(sk, pubkey, kind, content, tags):
    from yunohost.nostr_identity import _sign_event

    return _sign_event(sk, pubkey, kind, content, tags)


def _verify_claim(claim):
    serialized = json.dumps(
        [0, claim["pubkey"], claim["created_at"], claim["kind"], claim["tags"], claim["content"]],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    event_id = hashlib.sha256(serialized).hexdigest()
    return PublicKeyXOnly(bytes.fromhex(claim["pubkey"])).verify(
        bytes.fromhex(claim["sig"]), bytes.fromhex(event_id)
    )


def _sub(tmp_path, hostname="foo.nohost.me", **kw):
    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    return subscribe(state, hostname, operator=(SK, PUBKEY), signer=_signer, **kw)


# --------------------------------------------------------------------------- #
# zone gate

def test_free_hostname_zones():
    assert zone_for("foo.nohost.me") == "nohost.me"
    assert zone_for("mybox.noho.st") == "noho.st"
    assert zone_for("z.ynh.fr") == "ynh.fr"
    assert zone_for("nohost.me") is None  # the bare apex is not a hostname
    assert zone_for("foo.nohost.co") is None
    assert zone_for("example.org") is None
    assert is_free_hostname("foo.nohost.me") is True
    assert is_free_hostname("example.org") is False
    assert FREE_HOSTNAME_ZONES == ("nohost.me", "noho.st", "ynh.fr")


def test_subscribe_rejects_non_free_zone(tmp_path):
    from nostrhost.core import NostrHostError

    with pytest.raises(NostrHostError, match="not a free hostname"):
        _sub(tmp_path, hostname="example.org")


# --------------------------------------------------------------------------- #
# identity-backed subscription

def test_subscribe_signs_claim_and_provisions_secret(tmp_path):
    state = tmp_path / "state"
    out = _sub(tmp_path)
    assert out["hostname"] == "foo.nohost.me"
    assert out["zone"] == "nohost.me"
    assert out["provider"] == "dynette"
    assert out["pubkey"] == PUBKEY
    assert out["secret_ref"] == "secret:dns/dynette/foo.nohost.me"
    claim = out["claim"]
    assert claim["kind"] == CLAIM_KIND
    assert claim["pubkey"] == PUBKEY
    assert ["free-hostname", "foo.nohost.me"] in claim["tags"]
    assert _verify_claim(claim) is True  # the ownership proof is the signature
    # broker holds the TSIG secret
    assert read_secret("secret:dns/dynette/foo.nohost.me", state_dir=state)
    # subscription record persisted root-0600
    record = read_subscription(state, "foo.nohost.me")
    assert record["pubkey"] == PUBKEY
    assert record["claim"]["id"] == out["claim_id"]
    path = state / "free-hostnames" / "foo.nohost.me.json"
    assert (path.stat().st_mode & 0o777) == 0o600


def test_subscribe_keeps_secret_then_rotates(tmp_path):
    state = tmp_path / "state"
    first = _sub(tmp_path)
    first_secret = read_secret(first["secret_ref"], state_dir=state)
    again = _sub(tmp_path)
    assert read_secret(again["secret_ref"], state_dir=state) == first_secret
    assert again["rotated"] is False
    rotated = _sub(tmp_path, rotate=True)
    new_secret = read_secret(rotated["secret_ref"], state_dir=state)
    assert new_secret != first_secret
    assert rotated["rotated"] is True


def test_subscribe_honours_given_secret(tmp_path):
    state = tmp_path / "state"
    out = _sub(tmp_path, secret="given-tsig-secret")
    assert read_secret(out["secret_ref"], state_dir=state) == "given-tsig-secret"


def test_list_subscriptions(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    _sub(tmp_path, hostname="foo.nohost.me")
    _sub(tmp_path, hostname="bar.ynh.fr")
    subs = list_subscriptions(state)
    assert {s["hostname"] for s in subs} == {"foo.nohost.me", "bar.ynh.fr"}
    assert all(s["pubkey"] == PUBKEY for s in subs)
    assert all(s["claim_id"] for s in subs)


def test_unsubscribe_drops_record_and_secret(tmp_path):
    state = tmp_path / "state"
    _sub(tmp_path)
    out = unsubscribe(state, "foo.nohost.me")
    assert out["unsubscribed"] is True and out["secret_removed"] is True
    assert read_subscription(state, "foo.nohost.me") is None
    with pytest.raises(CredentialError):
        read_secret("secret:dns/dynette/foo.nohost.me", state_dir=state)
    with pytest.raises(Exception, match="no nostr free-hostname subscription"):
        unsubscribe(state, "foo.nohost.me")


# --------------------------------------------------------------------------- #
# provider resolution: identity-subscribed default broker ref

def test_provider_resolves_identity_subscription(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    _sub(tmp_path)
    provider = DynetteProvider(
        zone="foo.nohost.me",
        state_dir=state,
        push=lambda *a, **k: None,
        auth_servers=("203.0.113.53",),
    )
    assert provider._get_secret() == read_secret("secret:dns/dynette/foo.nohost.me", state_dir=state)


def test_provider_still_falls_back_to_legacy_key_file(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    key_dir = tmp_path / "dyndns"
    key_dir.mkdir()
    (key_dir / "Kfoo.nohost.me.+165+1234.key").write_text("foo.nohost.me. IN KEY 0 3 165 legacy-one legacy-two\n")
    provider = DynetteProvider(zone="foo.nohost.me", state_dir=state, key_dir=key_dir, push=lambda *a, **k: None)
    assert provider._get_secret() == "legacy-one legacy-two"


def test_provider_resolves_explicit_ref_over_subscription(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    _sub(tmp_path)
    set_secret("secret:dns/dynette/main", "explicit-secret", state_dir=state)
    provider = DynetteProvider(
        credential="secret:dns/dynette/main",
        zone="foo.nohost.me",
        state_dir=state,
        push=lambda *a, **k: None,
    )
    assert provider._get_secret() == "explicit-secret"


# --------------------------------------------------------------------------- #
# domain.add compat gate (identity-backed)

def _monkeypatch_service_and_state(monkeypatch, tmp_path):
    import nostrhost.dns.freehost as freehost
    from nostrhost.domains import operations

    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    seen: dict = {}

    class FakeService:
        state_dir = state

        def add(self, resource, **kw):
            seen["resource"] = resource
            return {"action": "domain.add", "ok": True}

    monkeypatch.setattr(operations, "DomainService", lambda: FakeService())
    monkeypatch.setattr(freehost, "_default_operator", lambda: (SK, PUBKEY))
    return seen, state


def test_dns_subscribe_op_writes_subscription(tmp_path, monkeypatch):
    from nostrhost.domains.operations import _safe_dns_subscribe

    _monkeypatch_service_and_state(monkeypatch, tmp_path)
    out = _safe_dns_subscribe(hostname="foo.nohost.me")
    assert out["hostname"] == "foo.nohost.me" and out["claim_id"]
    record = read_subscription(tmp_path / "state", "foo.nohost.me")
    assert record["pubkey"] == PUBKEY


def test_dns_subscriptions_op_lists(tmp_path, monkeypatch):
    from nostrhost.domains.operations import _safe_dns_subscribe, _safe_dns_subscriptions

    _monkeypatch_service_and_state(monkeypatch, tmp_path)
    _safe_dns_subscribe(hostname="foo.nohost.me")
    out = _safe_dns_subscriptions()
    assert [s["hostname"] for s in out["subscriptions"]] == ["foo.nohost.me"]


def test_domain_add_accepts_identity_subscription(tmp_path, monkeypatch):
    from nostrhost import credentials as credentials_module
    from nostrhost.dns.freehost import subscribe
    from nostrhost.domains.operations import _safe_domain_add

    seen, state = _monkeypatch_service_and_state(monkeypatch, tmp_path)
    subscribe(state, "foo.nohost.me", operator=(SK, PUBKEY), signer=_signer)
    monkeypatch.setattr(credentials_module, "credentials_dir", lambda state_dir=None: tmp_path / "credentials")
    out = _safe_domain_add(domain="foo.nohost.me", provider_type="dynette", apply_dns=False)
    assert out["ok"] is True
    resource = seen["resource"]
    assert resource.provider.type == "dynette"
    assert resource.provider.credential is None  # identity subscription suffices


def test_domain_add_still_requires_something_without_subscription(tmp_path, monkeypatch):
    from nostrhost import credentials as credentials_module
    from nostrhost.core import NostrHostError
    from nostrhost.domains.operations import _safe_domain_add

    _monkeypatch_service_and_state(monkeypatch, tmp_path)
    monkeypatch.setattr(credentials_module, "credentials_dir", lambda state_dir=None: tmp_path / "credentials")
    with pytest.raises(NostrHostError, match="dynette"):
        _safe_domain_add(domain="foo.nohost.me", provider_type="dynette")


# --------------------------------------------------------------------------- #
# operation registry wiring

def test_dns_subscribe_tool_spec():
    from yunohost.nostr_operations import TOOLS, tool_spec

    assert "dns.subscribe" in TOOLS
    spec = tool_spec("dns.subscribe")
    assert spec.scope == "dns.write" and spec.require_approval is True
    spec = tool_spec("dns.unsubscribe")
    assert spec.scope == "dns.write" and spec.require_approval is True
    spec = tool_spec("dns.subscriptions")
    assert spec.scope == "domains.read" and spec.require_approval is False
    assert callable(tool_spec("dns.subscribe").handler)


def test_cli_has_subscribe_commands():
    from nostrhost.cli import _TOOL_HANDLERS

    assert "dns.subscribe" in _TOOL_HANDLERS
    assert "dns.subscriptions" in _TOOL_HANDLERS
    assert "dns.unsubscribe" in _TOOL_HANDLERS
    assert all(callable(h) for h in (_TOOL_HANDLERS["dns.subscribe"], _TOOL_HANDLERS["dns.unsubscribe"]))
