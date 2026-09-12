"""Workstream 4 (Phase D): Dynette compat provider.

Covers the ``dynette`` dynamic-IP-only provider (RFC 2136 TSIG hmac-sha512
push to dyndns.yunohost.org), the *compat conditional* credential resolution
(explicit ``secret:dns/dynette/<name>`` ref, else the legacy
``/etc/yunohost/dyndns/K<host>.+165+1234.key`` key file), the registry
wiring and the ``domain.add`` gate that lets a legacy-subscribed Dynette
host be registered natively without re-entering its key.
"""

from __future__ import annotations

import pytest

from nostrhost.credentials import CredentialError, set_secret
from nostrhost.dns.models import DnsProviderResource, DnsRecord
from nostrhost.dns.providers import build_provider, provider_capabilities
from nostrhost.dns.providers.dynette import (
    DynetteProvider,
    _read_key_secret,
    find_tsig_key,
)


def _key_file(key_dir, hostname="foo.nohost.me", secret="abc123def456 abc789def012"):
    path = key_dir / f"K{hostname}.+165+1234.key"
    path.write_text(f"{hostname}. IN KEY 0 3 165 {secret}\n")
    return path


def _dynette_provider(
    tmp_path,
    *,
    secret=None,
    key_dir=None,
    resolve=None,
    push=None,
    auth_servers=("203.0.113.53",),
):
    return DynetteProvider(
        zone="foo.nohost.me",
        state_dir=tmp_path / "state",
        secret=secret,
        key_dir=key_dir,
        resolve=resolve,
        push=push,
        auth_servers=auth_servers,
    )


def _apex(ipv4="203.0.113.7", ipv6=None):
    records = [DnsRecord(zone="foo.nohost.me", name="@", type="A", value=ipv4, owner="nostrhost")]
    if ipv6:
        records.append(DnsRecord(zone="foo.nohost.me", name="@", type="AAAA", value=ipv6, owner="nostrhost"))
    return records


# --------------------------------------------------------------------------- #
# registry + capabilities

def test_dynette_capabilities():
    caps = provider_capabilities("dynette")
    assert caps.dynamic_ip is True
    assert caps.full_zone is False
    assert caps.wildcard is False
    assert caps.txt is False
    assert caps.caa is False


def test_dynette_in_provider_types():
    from nostrhost.dns.models import PROVIDER_TYPES

    assert "dynette" in PROVIDER_TYPES


def test_build_provider_wires_dynette(tmp_path):
    state = tmp_path / "state"
    provider = build_provider(DnsProviderResource(type="dynette", zone="foo.nohost.me"), state)
    assert isinstance(provider, DynetteProvider)
    assert provider.capabilities.full_zone is False


# --------------------------------------------------------------------------- #
# compat-conditional credential resolution

def test_credential_from_secret_ref(tmp_path):
    state = tmp_path / "state"
    set_secret("secret:dns/dynette/main", "my-tsig-secret", state_dir=state)
    provider = DynetteProvider(
        credential="secret:dns/dynette/main",
        zone="foo.nohost.me",
        state_dir=state,
        push=lambda *a, **k: None,
    )
    assert provider._get_secret() == "my-tsig-secret"


def test_credential_from_legacy_key_file(tmp_path):
    key_dir = tmp_path / "dyndns"
    key_dir.mkdir()
    _key_file(key_dir, secret="legacy-secret-part1 legacy-secret-part2")
    provider = _dynette_provider(tmp_path, key_dir=key_dir)
    assert provider._get_secret() == "legacy-secret-part1 legacy-secret-part2"


def test_credential_requires_key_or_ref(tmp_path):
    provider = _dynette_provider(tmp_path)
    with pytest.raises(CredentialError, match="dynette"):
        provider._get_secret()


def test_find_tsig_key_and_secret_parse(tmp_path):
    key_dir = tmp_path / "dyndns"
    key_dir.mkdir()
    path = _key_file(key_dir)
    assert find_tsig_key("foo.nohost.me", key_dir) == path
    assert find_tsig_key("other.nohost.me", key_dir) is None
    assert _read_key_secret(path) == "abc123def456 abc789def012"


# --------------------------------------------------------------------------- #
# push_records

def test_push_skips_unchanged(tmp_path):
    pushes: list[tuple] = []
    provider = _dynette_provider(
        tmp_path,
        secret="k",
        resolve=lambda host, servers: ("203.0.113.7", None),
        push=lambda *args: pushes.append(args),
    )
    result = provider.push_records(_apex(ipv4="203.0.113.7"))
    assert result[0]["action"] == "skip"
    assert pushes == []


def test_push_builds_tsig_update_on_change(tmp_path):
    pushes: list[tuple] = []
    provider = _dynette_provider(
        tmp_path,
        secret="tsig-secret",
        resolve=lambda host, servers: ("198.51.100.42", "2001:db8::1"),
        push=lambda *args: pushes.append(args),
    )
    result = provider.push_records(_apex(ipv4="203.0.113.7", ipv6="2001:db8::2"))
    zone, hostname, secret, ipv4, ipv6, ttl, servers = pushes[0]
    assert zone == "nohost.me"  # parent zone, first label stripped
    assert hostname == "foo.nohost.me"
    assert secret == "tsig-secret"
    assert ipv4 == "203.0.113.7"
    assert ipv6 == "2001:db8::2"
    assert ttl == 3600
    assert servers == ["203.0.113.53"]  # auth servers passed through as IP literals
    assert all(r["action"] == "update" for r in result)


def test_push_zone_for_other_suffix(tmp_path):
    pushes: list[tuple] = []
    provider = DynetteProvider(
        zone="mybox.ynh.fr",
        state_dir=tmp_path / "state",
        secret="k",
        resolve=lambda host, servers: (None, None),
        push=lambda *args: pushes.append(args),
        auth_servers=("203.0.113.53",),
    )
    provider.push_records([DnsRecord(zone="mybox.ynh.fr", name="@", type="A", value="203.0.113.7", owner="nostrhost")])
    assert pushes[0][0] == "ynh.fr"


def test_push_skips_without_apex(tmp_path):
    provider = _dynette_provider(tmp_path, secret="k")
    result = provider.push_records([DnsRecord(zone="foo.nohost.me", name="*", type="A", value="1.2.3.4", owner="nostrhost")])
    assert result[0]["action"] == "skip"


def test_push_requires_credential(tmp_path):
    provider = _dynette_provider(
        tmp_path,
        resolve=lambda host, servers: (None, None),
        push=lambda *a, **k: None,
    )
    with pytest.raises(CredentialError, match="dynette"):
        provider.push_records(_apex())


def test_verify_record_resolves(tmp_path):
    provider = _dynette_provider(tmp_path, secret="k")
    out = provider.verify_record(DnsRecord(zone="foo.nohost.me", name="@", type="A", value="1.2.3.4", owner="nostrhost"))
    assert "verified" in out


# --------------------------------------------------------------------------- #
# DomainService routing (dynamic push path)

def test_dynette_domain_add_and_apply_push(tmp_path):
    pushes: list[tuple] = []
    key_dir = tmp_path / "dyndns"
    key_dir.mkdir()
    _key_file(key_dir)
    from nostrhost.domains.models import DomainResource
    from nostrhost.domains.service import DomainService

    def factory(resource, state_dir):
        if resource.type == "dynette":
            return DynetteProvider(
                credential=resource.credential,
                zone=resource.zone or "",
                state_dir=state_dir,
                key_dir=key_dir,
                resolve=lambda host, servers: (None, None),
                push=lambda *args: pushes.append(args),
                auth_servers=("203.0.113.53",),
            )
        from nostrhost.dns.providers.manual import ManualProvider

        return ManualProvider(zone=resource.zone or "", state_dir=state_dir)

    service = DomainService(state_dir=tmp_path / "state", caddy=None, public_ipv4=lambda: "203.0.113.7", public_ipv6=lambda: None, provider_factory=factory)
    domain = DomainResource(
        name="foo.nohost.me",
        provider=DnsProviderResource(type="dynette", capabilities=provider_capabilities("dynette")),
    )
    result = service.add(domain, apply_dns=True, verify=False)
    assert result["mode"] == "dynamic"
    assert result["provider"] == "dynette"
    assert pushes  # push happened at add
    assert service.dynamic_domains() == ["foo.nohost.me"]
    applied = service.dns_apply("foo.nohost.me")
    assert applied["mode"] == "push"
    plan = service.dns_plan("foo.nohost.me")
    assert plan["mode"] == "dynamic" and plan["drift"]["in_sync"] is None


# --------------------------------------------------------------------------- #
# domain.add compat gate

def _monkeypatch_service_and_keydir(monkeypatch, tmp_path, key_dir=True):
    from nostrhost.dns.providers import dynette
    from nostrhost.domains import operations

    seen: dict = {}

    class FakeService:
        def add(self, resource, **kw):
            seen["resource"] = resource
            return {"action": "domain.add", "ok": True}

    monkeypatch.setattr(operations, "DomainService", lambda: FakeService())
    keydir = tmp_path / "dyndns"
    if key_dir:
        keydir.mkdir()
        _key_file(keydir)
    monkeypatch.setattr(dynette, "DEFAULT_KEY_DIR", keydir)
    return seen


def test_dynette_add_accepts_legacy_key(tmp_path, monkeypatch):
    from nostrhost.domains.operations import _safe_domain_add

    seen = _monkeypatch_service_and_keydir(monkeypatch, tmp_path, key_dir=True)
    out = _safe_domain_add(domain="foo.nohost.me", provider_type="dynette", apply_dns=False)
    assert out["ok"] is True
    resource = seen["resource"]
    assert resource.provider.type == "dynette"
    assert resource.provider.credential is None  # compat conditional: key file suffices
    assert resource.provider.capabilities.full_zone is False


def test_dynette_add_requires_key_or_credential(tmp_path, monkeypatch):
    from nostrhost.core import NostrHostError
    from nostrhost.domains.operations import _safe_domain_add

    _monkeypatch_service_and_keydir(monkeypatch, tmp_path, key_dir=False)
    with pytest.raises(NostrHostError, match="dynette"):
        _safe_domain_add(domain="foo.nohost.me", provider_type="dynette")


def test_dynette_add_validates_credential_ref(tmp_path, monkeypatch):
    from nostrhost import credentials as credentials_module
    from nostrhost.domains.operations import _safe_domain_add

    monkeypatch.setattr(credentials_module, "credentials_dir", lambda state_dir=None: tmp_path / "credentials")
    with pytest.raises(CredentialError, match="not configured"):
        _safe_domain_add(domain="foo.nohost.me", provider_type="dynette", credential="secret:dns/dynette/main")


def test_dynette_add_with_credential_ok(tmp_path, monkeypatch):
    from nostrhost import credentials as credentials_module
    from nostrhost.domains.operations import _safe_domain_add

    seen = _monkeypatch_service_and_keydir(monkeypatch, tmp_path, key_dir=False)
    monkeypatch.setattr(credentials_module, "credentials_dir", lambda state_dir=None: tmp_path / "credentials")
    set_secret("secret:dns/dynette/main", "tok", dir=tmp_path / "credentials")
    out = _safe_domain_add(domain="foo.nohost.me", provider_type="dynette", credential="secret:dns/dynette/main", apply_dns=False)
    assert out["ok"] is True
    assert seen["resource"].provider.credential == "secret:dns/dynette/main"
