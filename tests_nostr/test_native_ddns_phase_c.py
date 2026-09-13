"""Workstream 4 (Phase C): DDNS providers + IP watcher.

Covers the DuckDNS/Dynu dynamic-IP-only providers, the deSEC full-zone REST
provider, the DomainService capability branches (plan/apply/add/remove),
the DDNS IP watcher (poll -> reconcile on change, persisted state) and the
ops/CLI wiring for ``dns.watch``.
"""

from __future__ import annotations

import os

import pytest

from nostrhost.credentials import set_secret
from nostrhost.dns import ownership
from nostrhost.dns.models import DnsProviderResource, DnsRecord
from nostrhost.dns.providers import build_provider, provider_capabilities
from nostrhost.dns.providers.duckdns import DuckDnsProvider
from nostrhost.dns.providers.dynu import DynuProvider
from nostrhost.dns.providers.desec import DesecProvider
from nostrhost.dns.providers.manual import ManualProvider
from nostrhost.domains.models import DomainResource
from nostrhost.domains.service import DomainService
from nostrhost.network.ddns import DdnsWatchRunner, WatchState
from nostrhost.network.public_ip import IpWatcher
from yunohost.nostr_operations import known_tools, tool_spec


def _svc(tmp_path, *, public_ipv4="203.0.113.7", provider_factory=None):
    state = tmp_path / "state"
    return DomainService(
        state_dir=state,
        caddy=None,
        public_ipv4=lambda: public_ipv4,
        public_ipv6=lambda: None,
        provider_factory=provider_factory,
    )


def _duck_provider_factory(calls, tmp_path):
    def factory(resource, state_dir):
        if resource.type == "duckdns":
            return DuckDnsProvider(credential=resource.credential, state_dir=state_dir, request=lambda url: calls.append(url) or (200, "OK"))
        return ManualProvider(zone=resource.zone or "", state_dir=state_dir)

    return factory


def _duck_domain(name="mybox.duckdns.org"):
    return DomainResource(
        name=name,
        provider=DnsProviderResource(type="duckdns", credential="secret:dns/duckdns/main", capabilities=provider_capabilities("duckdns")),
    )


# --------------------------------------------------------------------------- #
# provider registry + capabilities

def test_provider_types_registered():
    assert set(provider_capabilities("duckdns").dict()) >= {"dynamic_ip"}
    assert provider_capabilities("duckdns").full_zone is False
    assert provider_capabilities("duckdns").wildcard is False
    assert provider_capabilities("dynu").full_zone is False
    assert provider_capabilities("dynu").txt is False
    assert provider_capabilities("desec").full_zone is True
    assert provider_capabilities("desec").dynamic_ip is True
    with pytest.raises(ValueError):
        provider_capabilities("nope")


def test_build_provider_wires_ddns(tmp_path):
    state = tmp_path / "state"
    for type_ in ("duckdns", "dynu", "desec"):
        set_secret(f"secret:dns/{type_}/main", "tok", state_dir=state)
        provider = build_provider(DnsProviderResource(type=type_, credential=f"secret:dns/{type_}/main"), state)
        assert provider.capabilities.full_zone is (type_ == "desec")


# --------------------------------------------------------------------------- #
# DuckDnsProvider

def test_duckdns_push_builds_correct_request(tmp_path):
    state = tmp_path / "state"
    set_secret("secret:dns/duckdns/main", "tok-123", state_dir=state)
    calls: list[str] = []
    provider = DuckDnsProvider(credential="secret:dns/duckdns/main", state_dir=state, request=lambda url: calls.append(url) or (200, "OK"))
    records = [
        DnsRecord(zone="mybox.duckdns.org", name="@", type="A", value="1.2.3.4", owner="nostrhost"),
        DnsRecord(zone="mybox.duckdns.org", name="@", type="AAAA", value="2001:db8::1", owner="nostrhost"),
        DnsRecord(zone="mybox.duckdns.org", name="*", type="A", value="1.2.3.4", owner="nostrhost"),
    ]
    result = provider.push_records(records)
    assert len(result) == 2  # only apex records, wildcard dropped
    url = calls[0]
    assert "domains=mybox" in url
    assert "token=tok-123" in url
    assert "ip=1.2.3.4" in url
    assert "ipv6=2001%3Adb8%3A%3A1" in url
    assert "domains=mybox&token=tok-123" in url  # subname, not the fqdn


def test_duckdns_push_rejects_ko(tmp_path):
    state = tmp_path / "state"
    set_secret("secret:dns/duckdns/main", "tok", state_dir=state)
    provider = DuckDnsProvider(credential="secret:dns/duckdns/main", state_dir=state, request=lambda url: (200, "KO"))
    with pytest.raises(RuntimeError, match="duckdns update failed"):
        provider.push_records([DnsRecord(zone="mybox.duckdns.org", name="@", type="A", value="1.2.3.4", owner="nostrhost")])


def test_duckdns_push_requires_credential(tmp_path):
    provider = DuckDnsProvider(zone="mybox.duckdns.org", state_dir=tmp_path / "state")
    with pytest.raises(Exception, match="credential"):
        provider.push_records([DnsRecord(zone="mybox.duckdns.org", name="@", type="A", value="1.2.3.4", owner="nostrhost")])


def test_duckdns_subname_strips_suffix():
    assert DuckDnsProvider.subname("mybox.duckdns.org") == "mybox"
    assert DuckDnsProvider.subname("plain.example.com") == "plain.example.com"


# --------------------------------------------------------------------------- #
# DynuProvider

def test_dynu_push_basic_auth(tmp_path):
    state = tmp_path / "state"
    set_secret("secret:dns/dynu/main", "user:secret", state_dir=state)
    calls: list[dict] = []
    provider = DynuProvider(credential="secret:dns/dynu/main", state_dir=state, request=lambda url, headers=None: calls.append({"url": url, "headers": headers}) or (200, "good 5.6.7.8"))
    result = provider.push_records([DnsRecord(zone="myhost.dynu.net", name="@", type="A", value="5.6.7.8", owner="nostrhost")])
    assert result and result[0]["hostname"] == "myhost.dynu.net"
    call = calls[0]
    assert "myip=5.6.7.8" in call["url"]
    assert "myipv6=no" in call["url"]
    assert call["headers"]["Authorization"].startswith("Basic ")
    assert "password" not in call["url"]  # never in the query string


def test_dynu_push_password_only(tmp_path):
    state = tmp_path / "state"
    set_secret("secret:dns/dynu/main", "justpassword", state_dir=state)
    calls: list[dict] = []
    provider = DynuProvider(credential="secret:dns/dynu/main", state_dir=state, request=lambda url, headers=None: calls.append({"url": url, "headers": headers}) or (200, "nochg"))
    provider.push_records([DnsRecord(zone="x.dynu.net", name="@", type="A", value="1.2.3.4", owner="nostrhost")])
    assert "password=justpassword" in calls[0]["url"]
    assert not calls[0]["headers"].get("Authorization")


def test_dynu_push_surfaces_auth_error(tmp_path):
    state = tmp_path / "state"
    set_secret("secret:dns/dynu/main", "u:pw", state_dir=state)
    provider = DynuProvider(credential="secret:dns/dynu/main", state_dir=state, request=lambda url, headers=None: (200, "badauth"))
    with pytest.raises(Exception, match="dynu rejected"):
        provider.push_records([DnsRecord(zone="x.dynu.net", name="@", type="A", value="1.2.3.4", owner="nostrhost")])


# --------------------------------------------------------------------------- #
# DesecProvider

class FakeDesecApi:
    def __init__(self, rrsets=None):
        self.rrsets = list(rrsets or [])
        self.calls: list[tuple] = []
        self.domains = {"example.com"}

    def get_domain(self, domain):
        return {"name": domain} if domain in self.domains else None

    def list_rrsets(self, domain):
        self.calls.append(("list", domain))
        return list(self.rrsets)

    def put_rrset(self, domain, subname, type_, records, ttl):
        self.calls.append(("put", subname, type_, records, ttl))
        self.rrsets = [r for r in self.rrsets if not (r["subname"] == subname and r["type"] == type_)]
        self.rrsets.append({"subname": subname, "type": type_, "ttl": ttl, "records": records})

    def delete_rrset(self, domain, subname, type_):
        self.calls.append(("delete", subname, type_))
        self.rrsets = [r for r in self.rrsets if not (r["subname"] == subname and r["type"] == type_)]


def _desec_provider(tmp_path, api=None):
    state = tmp_path / "state"
    set_secret("secret:dns/desec/main", "tok", state_dir=state)
    return DesecProvider(credential="secret:dns/desec/main", zone="example.com", state_dir=state, api=api or FakeDesecApi())


def test_desec_discovers_zone(tmp_path):
    api = FakeDesecApi()
    provider = _desec_provider(tmp_path, api=api)
    assert provider.discover_zone("example.com") == "example.com"
    with pytest.raises(RuntimeError, match="no domain"):
        provider.discover_zone("missing.com")


def test_desec_record_lifecycle_ownership_bounded(tmp_path):
    api = FakeDesecApi()
    provider = _desec_provider(tmp_path, api=api)
    provider.create_record(DnsRecord(zone="example.com", name="@", type="A", value="203.0.113.10", owner="nostrhost"))
    provider.create_record(DnsRecord(zone="example.com", name="www", type="A", value="203.0.113.11", owner="nostrhost"))
    listed = provider.list_records("example.com")
    assert {r.name for r in listed} == {"@", "www"}
    assert all(r.owner == "nostrhost" for r in listed)
    assert {r.provider_id for r in listed} == {":A", "www:A"}

    # apex TXT round-trips quoting
    provider.create_record(DnsRecord(zone="example.com", name="@", type="TXT", value="v=spf1 -all", owner="nostrhost"))
    txt = next(r for r in provider.list_records("example.com") if r.type == "TXT")
    assert txt.value == "v=spf1 -all"
    assert any(c[0] == "put" and c[3] == ['"v=spf1 -all"'] for c in api.calls)

    # foreign rrset preserved
    api.rrsets.append({"subname": "mx", "type": "MX", "ttl": 3600, "records": ["10 mail.example.com"]})
    from nostrhost.dns.reconciler import build_plan

    plan = build_plan([DnsRecord(zone="example.com", name="@", type="A", value="203.0.113.10", owner="nostrhost")], provider.list_records("example.com"))
    assert len(plan.preserved) == 1
    assert plan.preserved[0].owner.startswith("desec:")

    # delete an owned record by its rrset identity
    apex = next(r for r in listed if r.name == "@")
    provider.delete_record(apex.provider_id)
    assert ("delete", "", "A") in api.calls


# --------------------------------------------------------------------------- #
# DomainService capability branches

def test_domain_service_routes_dynamic_domains(tmp_path):
    calls: list[str] = []
    svc = _svc(tmp_path, provider_factory=_duck_provider_factory(calls, tmp_path))
    set_secret("secret:dns/duckdns/main", "tok", state_dir=tmp_path / "state")
    svc.add(_duck_domain(), apply_dns=False, verify=False)
    svc.add(DomainResource(name="w4.test"), apply_dns=False, verify=False)

    assert set(svc.dynamic_domains()) == {"mybox.duckdns.org", "w4.test"}

    plan = svc.dns_plan("mybox.duckdns.org")
    assert plan["mode"] == "dynamic" and plan["drift"]["in_sync"] is None
    assert svc.inspect("mybox.duckdns.org")["mode"] == "dynamic"
    assert svc.inspect("w4.test")["mode"] == "full_zone"

    calls.clear()
    pushed = svc.dns_apply("mybox.duckdns.org")
    assert pushed["mode"] == "push" and calls
    assert svc.dns_apply("w4.test")["mode"] == "full_zone"


def test_domain_add_pushes_dynamic_domain(tmp_path):
    calls: list[str] = []
    svc = _svc(tmp_path, provider_factory=_duck_provider_factory(calls, tmp_path))
    set_secret("secret:dns/duckdns/main", "tok", state_dir=tmp_path / "state")
    result = svc.add(_duck_domain(), verify=False)
    assert result["mode"] == "dynamic" and calls
    assert result["dns_plan"]["mode"] == "push"


def test_domain_remove_dynamic_domain_notes_external_cleanup(tmp_path):
    svc = _svc(tmp_path)
    set_secret("secret:dns/duckdns/main", "tok", state_dir=tmp_path / "state")
    svc.add(_duck_domain(), apply_dns=False, verify=False)
    result = svc.remove("mybox.duckdns.org")
    assert result["deleted"][0]["action"] == "note"
    assert svc.list_domains()["domains"] == []


def test_dns_update_dynamic_sweeps(tmp_path):
    calls: list[str] = []
    svc = _svc(tmp_path, provider_factory=_duck_provider_factory(calls, tmp_path))
    set_secret("secret:dns/duckdns/main", "tok", state_dir=tmp_path / "state")
    svc.add(_duck_domain(), apply_dns=False, verify=False)
    result = svc.dns_update_dynamic()
    assert all(item["ok"] for item in result["updated"])
    assert calls  # the duckdns push happened


def test_desec_update_replaces_stale_mirror_entry(tmp_path):
    """An IP-flip update must not leave the old fingerprint entry behind."""
    api = FakeDesecApi()
    provider = _desec_provider(tmp_path, api=api)
    provider.create_record(DnsRecord(zone="example.com", name="@", type="A", value="203.0.113.7", owner="nostrhost"))
    provider.update_record(":A", DnsRecord(zone="example.com", name="@", type="A", value="198.51.100.42", owner="nostrhost", provider_id=":A"))
    owned = ownership.owned_records(tmp_path / "state", "example.com")
    assert len(owned) == 1, "update must not leave a stale fingerprint entry"
    assert owned[0].value == "198.51.100.42"


def test_domain_remove_uses_provider_id_for_non_manual(tmp_path):
    api = FakeDesecApi()
    state = tmp_path / "state"
    set_secret("secret:dns/desec/main", "tok", state_dir=state)

    def factory(resource, state_dir):
        return DesecProvider(credential=resource.credential, zone="example.com", state_dir=state_dir, api=api)

    svc = _svc(tmp_path, provider_factory=factory)
    svc.add(DomainResource(name="example.com", provider=DnsProviderResource(type="desec", credential="secret:dns/desec/main", capabilities=provider_capabilities("desec"))), apply_dns=False, verify=False)
    # create a desec-owned record so both the fake API and the mirror agree
    DesecProvider(credential="secret:dns/desec/main", zone="example.com", state_dir=state, api=api).create_record(DnsRecord(zone="example.com", name="@", type="A", value="203.0.113.7", owner="nostrhost"))
    svc.remove("example.com")
    assert any(c[0] == "delete" and c[1] == "" and c[2] == "A" for c in api.calls)
    assert ownership.owned_records(state, "example.com") == []


# --------------------------------------------------------------------------- #
# ownership mirror hygiene (manual + reconciler dedup)

def test_manual_update_replaces_stale_mirror_entry(tmp_path):
    """A manual provider value change must not leave the old fingerprint entry."""
    from nostrhost.dns.providers.manual import ManualProvider

    state = tmp_path / "state"
    provider = ManualProvider(zone="w4.test", state_dir=state)
    provider.create_record(DnsRecord(zone="w4.test", name="@", type="A", value="203.0.113.7", owner="nostrhost"))
    provider.update_record("A w4.test = 203.0.113.7", DnsRecord(zone="w4.test", name="@", type="A", value="198.51.100.42", owner="nostrhost"))
    owned = ownership.owned_records(state, "w4.test")
    assert len(owned) == 1 and owned[0].value == "198.51.100.42"


def test_manual_create_is_idempotent_by_diff_key(tmp_path):
    from nostrhost.dns.providers.manual import ManualProvider

    state = tmp_path / "state"
    provider = ManualProvider(zone="w4.test", state_dir=state)
    provider.create_record(DnsRecord(zone="w4.test", name="@", type="A", value="203.0.113.7", owner="nostrhost"))
    provider.create_record(DnsRecord(zone="w4.test", name="@", type="A", value="198.51.100.42", owner="nostrhost"))
    owned = ownership.owned_records(state, "w4.test")
    assert len(owned) == 1 and owned[0].value == "198.51.100.42"


def test_manual_delete_by_current_fingerprint(tmp_path):
    from nostrhost.dns.providers.manual import ManualProvider

    state = tmp_path / "state"
    provider = ManualProvider(zone="w4.test", state_dir=state)
    provider.create_record(DnsRecord(zone="w4.test", name="@", type="A", value="203.0.113.7", owner="nostrhost"))
    provider.delete_record(provider.list_records("w4.test")[0].fingerprint())
    assert ownership.owned_records(state, "w4.test") == []


def test_build_plan_deletes_stale_duplicates():
    from nostrhost.dns.reconciler import build_plan

    desired = [DnsRecord(zone="w4.test", name="@", type="A", value="198.51.100.42", owner="nostrhost")]
    actual = [
        DnsRecord(zone="w4.test", name="@", type="A", value="203.0.113.7", owner="nostrhost"),
        DnsRecord(zone="w4.test", name="@", type="A", value="198.51.100.42", owner="nostrhost"),
    ]
    plan = build_plan(desired, actual)
    actions = {c.action for c in plan.changes}
    assert "update" in actions and "delete" in actions
    deleted = [c for c in plan.changes if c.action == "delete"]
    assert len(deleted) == 1 and deleted[0].record.value == "198.51.100.42"


# --------------------------------------------------------------------------- #
# DDNS IP watcher

class FakeProbe:
    def __init__(self, current):
        self.current = current

    def __call__(self, protocol):
        return self.current[0] if protocol == 4 else None


def test_watch_poll_reconciles_on_change(tmp_path):
    calls: list[str] = []
    svc = _svc(tmp_path, provider_factory=_duck_provider_factory(calls, tmp_path))
    set_secret("secret:dns/duckdns/main", "tok", state_dir=tmp_path / "state")
    svc.add(_duck_domain(), apply_dns=False, verify=False)

    current = ["203.0.113.7"]
    runner = DdnsWatchRunner(service=svc, watcher=IpWatcher(probe_factory=FakeProbe(current)), state_dir=tmp_path / "state")

    first = runner.poll_once()
    assert "4" in first["changed"]  # initial reconcile (no persisted state)

    calls.clear()
    assert not runner.poll_once()["changed"] and not calls

    current[0] = "198.51.100.9"
    calls.clear()
    changed = runner.poll_once()
    assert "4" in changed["changed"] and calls
    assert changed["updated"][0]["ok"] is True

    state = WatchState(state_dir=tmp_path / "state")
    assert state.last_ipv4 == "198.51.100.9" and state.last_update


def test_watch_restart_does_not_fire_spurious_update(tmp_path):
    svc = _svc(tmp_path)
    svc.add(DomainResource(name="w4.test"), apply_dns=False, verify=False)
    WatchState(state_dir=tmp_path / "state").save(ipv4="203.0.113.7", ipv6=None)
    runner = DdnsWatchRunner(service=svc, watcher=IpWatcher(probe_factory=FakeProbe(["203.0.113.7"])), state_dir=tmp_path / "state")
    result = runner.poll_once()
    assert not result["changed"]


def test_watch_state_roundtrip(tmp_path):
    path = tmp_path / "state"
    WatchState(state_dir=path).save(ipv4="1.2.3.4", ipv6="::1", last_update="now")
    state = WatchState(state_dir=path)
    assert state.last_ipv4 == "1.2.3.4"
    assert state.last_ipv6 == "::1"
    assert state.last_update == "now"
    assert os.stat(state.path).st_mode & 0o777 == 0o600


# --------------------------------------------------------------------------- #
# ops + CLI wiring

def test_dns_watch_op_registered():
    assert "dns.watch" in known_tools()
    spec = tool_spec("dns.watch")
    assert spec.scope == "domains.read"
    assert spec.require_approval is False


def test_dns_watch_handler(tmp_path, monkeypatch):
    from nostrhost.domains import service as service_module

    monkeypatch.setattr(service_module, "_default_state_dir", lambda: tmp_path / "state")
    from nostrhost.domains.operations import _safe_dns_watch

    out = _safe_dns_watch()
    assert out["ipv4"] is None and out["dynamic_domains"] == []
    assert out["state"].endswith("ddns-watch.json")
