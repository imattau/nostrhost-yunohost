"""Workstream 4 (Phase B): credential broker, Cloudflare provider, app
``[dns.*]`` enforce+own, and drift report-vs-reconcile.
"""

from __future__ import annotations

import json
import os

import pytest

from nostrhost.credentials import (
    CredentialError,
    credential_path,
    list_secrets,
    read_secret,
    remove_secret,
    resolve,
    set_secret,
)
from nostrhost.dns.models import DnsRecord
from nostrhost.dns.ownership import owned_records
from nostrhost.dns.providers.cloudflare import CloudflareProvider
from nostrhost.dns.reconciler import build_plan
from nostrhost.domains.models import DomainResource
from nostrhost.domains.service import DomainService
from nostrhost.package_engine import (
    DnsRecordResource,
    PackageManifest,
    plan_package,
)
from nostrhost_policy.policy.scopes import Scope
from nostrhost_native_policy import _native_policy_key
from yunohost.nostr_operations import known_tools, tool_spec


# --------------------------------------------------------------------------- #
# credential broker

def test_credential_set_read_remove(tmp_path):
    state = tmp_path / "state"
    ref = "secret:dns/cloudflare/main"
    result = set_secret(ref, "tok-123", state_dir=state)
    assert result["set"] is True
    path = credential_path(ref, state_dir=state)
    assert path.is_file()
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert read_secret(ref, state_dir=state) == "tok-123"
    assert list_secrets(state_dir=state) == [{"ref": ref}]
    assert remove_secret(ref, state_dir=state)["removed"] is True
    assert not path.is_file()


def test_credential_ref_validation():
    with pytest.raises(CredentialError):
        credential_path("secret:dns/nope/main")
    with pytest.raises(CredentialError):
        credential_path("secret:http://x")
    with pytest.raises(CredentialError):
        credential_path("naked-token")
    with pytest.raises(CredentialError):
        credential_path("secret:dns/cloudflare/../evil")


def test_credential_dir_override(tmp_path):
    store = tmp_path / "credentials"
    set_secret("secret:dns/cloudflare/main", "tok", dir=store)
    assert read_secret("secret:dns/cloudflare/main", dir=store) == "tok"
    with pytest.raises(CredentialError):
        resolve("secret:dns/cloudflare/main", dir=tmp_path / "other")


def test_credential_resolve_missing_raises(tmp_path):
    with pytest.raises(CredentialError):
        resolve("secret:dns/cloudflare/absent", state_dir=tmp_path / "state")


def test_credential_list_never_exposes_values(tmp_path):
    set_secret("secret:dns/cloudflare/a", "x", state_dir=tmp_path / "state")
    set_secret("secret:dns/cloudflare/b", "y", state_dir=tmp_path / "state")
    listing = list_secrets("cloudflare", state_dir=tmp_path / "state")
    assert len(listing) == 2
    assert all(set(item) == {"ref"} for item in listing)
    assert all("x" not in json.dumps(item) and "y" not in json.dumps(item) for item in listing)


# --------------------------------------------------------------------------- #
# cloudflare provider (fake API)

class FakeCloudflareApi:
    def __init__(self, *, zone="w4.test", records=None):
        self.zone = zone
        self.records = list(records or [])
        self._next_id = 1000
        self.calls = []

    def find_zone(self, domain):
        self.calls.append(("find_zone", domain))
        if domain != self.zone:
            raise RuntimeError(f"cloudflare: no active zone for {domain}")
        return self.zone

    def zone_id(self, zone):
        return f"zone-{zone}"

    def list_records(self, zone):
        self.calls.append(("list_records", zone))
        return list(self.records)

    def create_record(self, zone, name, type_, content, ttl):
        self.calls.append(("create", name, type_, content, ttl))
        rid = str(self._next_id)
        self._next_id += 1
        self.records.append({"id": rid, "name": name, "type": type_, "content": content, "ttl": ttl})
        return rid

    def update_record(self, zone, record_id, name, type_, content, ttl):
        self.calls.append(("update", record_id, name, content))
        for entry in self.records:
            if entry["id"] == record_id:
                entry.update({"name": name, "type": type_, "content": content, "ttl": ttl})
                return

    def delete_record(self, zone, record_id):
        self.calls.append(("delete", record_id))
        self.records = [entry for entry in self.records if entry["id"] != record_id]


def _cf_provider(tmp_path, api=None, ref="secret:dns/cloudflare/main"):
    state = tmp_path / "state"
    set_secret(ref, "tok", state_dir=state)
    return CloudflareProvider(credential=ref, zone="w4.test", state_dir=state, api=api or FakeCloudflareApi())


def test_cloudflare_discovers_zone(tmp_path):
    api = FakeCloudflareApi(zone="w4.test")
    provider = _cf_provider(tmp_path, api=api)
    assert provider.discover_zone("w4.test") == "w4.test"
    assert api.calls and api.calls[0][0] == "find_zone"


def test_cloudflare_record_lifecycle_ownership_bounded(tmp_path):
    api = FakeCloudflareApi()
    provider = _cf_provider(tmp_path, api=api)
    apex = DnsRecord(zone="w4.test", name="@", type="A", value="203.0.113.10", owner="nostrhost")
    provider.create_record(apex)
    # second run: listed via the fake API, tagged owned through the mirror
    listed = provider.list_records("w4.test")
    assert listed and listed[0].owner == "nostrhost"
    assert listed[0].provider_id is not None

    # a foreign record (not in the mirror) is preserved, never owned
    api.records.append({"id": "foreign1", "name": "mx.w4.test", "type": "MX", "content": "mail.example.com", "priority": 10, "ttl": 300})
    plan = build_plan([apex], provider.list_records("w4.test"))
    assert len(plan.preserved) == 1
    assert plan.preserved[0].owner.startswith("cf:")

    # delete the owned record by its provider id; the fake API call used the cf id
    cf_id = listed[0].provider_id
    provider.delete_record(cf_id)
    assert ("delete", cf_id) in api.calls
    assert owned_records(tmp_path / "state", "w4.test") == []


def test_cloudflare_mx_and_caa_mapping(tmp_path):
    api = FakeCloudflareApi(records=[{"id": "r1", "name": "w4.test", "type": "CAA", "content": "", "data": {"flags": 0, "tag": "issue", "value": "letsencrypt.org"}, "ttl": 300}])
    provider = _cf_provider(tmp_path, api=api)
    records = provider.list_records("w4.test")
    assert records[0].type == "CAA"
    assert records[0].value == '0 issue "letsencrypt.org"'

    entry = provider._record_to_entry(DnsRecord(zone="w4.test", name="mx", type="MX", value="10 mail.example.com"))
    assert entry["priority"] == 10 and entry["content"] == "mail.example.com"


# --------------------------------------------------------------------------- #
# app [dns.*] manifest: enforce + own

def test_manifest_dns_section_validation():
    m = PackageManifest.parse_obj({"app": {"id": "photos", "version": "0.1"}, "web": {"domain": "w4.test"}, "dns": {"spf": {"name": "@", "type": "txt", "value": "v=spf1 -all"}, "cdn": {"type": "A", "value": "203.0.113.7"}}})
    assert m.dns["cdn"].name == "@" and m.dns["cdn"].type == "A"
    assert m.dns["spf"].type == "TXT"
    with pytest.raises(Exception):
        DnsRecordResource(type="ZOMG", value="x")
    # dns records require a web.domain
    with pytest.raises(Exception):
        PackageManifest.parse_obj({"app": {"id": "x", "version": "0.1"}, "dns": {"a": {"type": "A", "value": "1.2.3.4"}}})


def test_plan_package_emits_dns_records_op():
    package = PackageManifest.parse_obj({"app": {"id": "photos", "version": "0.1"}, "web": {"domain": "w4.test", "path": "/"}, "dns": {"cdn": {"type": "A", "value": "203.0.113.7"}}})
    plan = plan_package(package)
    names = [op.name for op in plan]
    assert "dns.records.ensure" in names
    op = next(op for op in plan if op.name == "dns.records.ensure")
    assert op.args["domain"] == "w4.test" and op.args["app"] == "photos"
    assert op.reverse == "dns.records.remove"
    # removal plan carries the reverse
    from nostrhost.package_engine import plan_package_removal

    removal = plan_package_removal(package)
    assert any(op.name == "dns.records.remove" for op in removal)


def test_domain_add_folds_app_records(tmp_path):
    svc = DomainService(state_dir=tmp_path, caddy=None, public_ipv4=lambda: "203.0.113.10", public_ipv6=lambda: None)
    svc.add(DomainResource(name="w4.test"), verify=False)
    # install a native app declaring dns records on the domain
    packages = tmp_path / "packages"
    packages.mkdir()
    (packages / "photos-manifest.json").write_text(json.dumps({
        "id": "photos",
        "version": "0.1",
        "manifest": {"app": {"id": "photos", "version": "0.1"}, "web": {"domain": "w4.test", "path": "/"}, "dns": {"cdn": {"name": "cdn", "type": "A", "value": "203.0.113.7"}}},
    }))
    desired = svc._desired(svc._require("w4.test"))
    app_records = [r for r in desired if r.owner == "app:photos"]
    assert len(app_records) == 1
    assert app_records[0].fqdn() == "cdn.w4.test"


def test_app_record_removal_excludes_departing_app(tmp_path):
    svc = DomainService(state_dir=tmp_path, caddy=None, public_ipv4=lambda: "203.0.113.10", public_ipv6=lambda: None)
    svc.add(DomainResource(name="w4.test"), verify=False)
    packages = tmp_path / "packages"
    packages.mkdir()
    (packages / "photos-manifest.json").write_text(json.dumps({
        "id": "photos",
        "version": "0.1",
        "manifest": {"app": {"id": "photos", "version": "0.1"}, "web": {"domain": "w4.test", "path": "/"}, "dns": {"cdn": {"name": "cdn", "type": "A", "value": "203.0.113.7"}}},
    }))
    full = svc._desired(svc._require("w4.test"))
    assert any(r.owner == "app:photos" for r in full)
    excluded = svc._desired(svc._require("w4.test"), exclude_app="photos")
    assert not any(r.owner == "app:photos" for r in excluded)


def test_dns_records_provider_reconciles_via_service(tmp_path):
    from nostrhost.native_providers import DnsRecordsProvider

    svc = DomainService(state_dir=tmp_path, caddy=None, public_ipv4=lambda: "203.0.113.10", public_ipv6=lambda: None)
    svc.add(DomainResource(name="w4.test"), verify=False)
    packages = tmp_path / "packages"
    packages.mkdir()
    (packages / "photos-manifest.json").write_text(json.dumps({
        "id": "photos",
        "version": "0.1",
        "manifest": {"app": {"id": "photos", "version": "0.1"}, "web": {"domain": "w4.test", "path": "/"}, "dns": {"cdn": {"name": "cdn", "type": "A", "value": "203.0.113.7"}}},
    }))
    provider = DnsRecordsProvider(reconciler=lambda app_id, domain, exclude: svc.dns_reconcile_app(app_id, domain, exclude_app=exclude))
    result = provider.apply(type("Op", (), {"name": "dns.records.ensure", "args": {"app": "photos", "domain": "w4.test", "records": []}})())
    assert result["ok"] is True
    # the app-owned record is now in the zone mirror
    owned = owned_records(tmp_path, "w4.test")
    assert any(r.owner == "app:photos" and r.fqdn() == "cdn.w4.test" for r in owned)
    # removal excludes the app -> its record is gone
    result = provider.apply(type("Op", (), {"name": "dns.records.remove", "args": {"app": "photos", "domain": "w4.test", "records": []}})())
    assert result["ok"] is True
    assert not any(r.owner == "app:photos" for r in owned_records(tmp_path, "w4.test"))


def test_dns_records_provider_requires_native_domain(tmp_path):
    from nostrhost.domains.service import DomainError
    from nostrhost.native_providers import DnsRecordsProvider

    provider = DnsRecordsProvider()
    with pytest.raises(DomainError):
        provider.apply(type("Op", (), {"name": "dns.records.ensure", "args": {"app": "photos", "domain": "not-registered.test", "records": []}})())


# --------------------------------------------------------------------------- #
# drift report-vs-reconcile

def test_dns_plan_reports_drift(tmp_path):
    svc = DomainService(state_dir=tmp_path, caddy=None, public_ipv4=lambda: "203.0.113.10", public_ipv6=lambda: None)
    svc.add(DomainResource(name="w4.test"), verify=False)
    plan = svc.dns_plan("w4.test")
    assert plan["drift"]["in_sync"] is True
    assert plan["drift"]["summary"]["create"] == 0
    # force drift: the mirror now wants a different apex ip
    from nostrhost.dns import ownership

    svc._desired(svc._require("w4.test"))  # warm
    ownership.update_record_entry(tmp_path, "A w4.test = 203.0.113.10", DnsRecord(zone="w4.test", name="@", type="A", value="203.0.113.99"))
    drifted = svc.dns_plan("w4.test")
    assert drifted["drift"]["in_sync"] is False
    assert "A w4.test = 203.0.113.99" in drifted["drift"]["to_update"] or len(drifted["drift"]["to_update"]) >= 1


# --------------------------------------------------------------------------- #
# ops + scopes + policy wiring

def test_phase_b_tools_registered():
    tools = known_tools()
    for tool in ("credential.set", "credential.remove", "credential.list"):
        assert tool in tools
    assert tool_spec("credential.set").scope == "dns.credentials.write"
    assert tool_spec("credential.list").scope == "dns.credentials.read"
    assert Scope.DNS_CREDENTIALS_WRITE == "dns.credentials.write"
    assert Scope.DNS_CREDENTIALS_READ == "dns.credentials.read"


def test_credential_policy_mapping():
    assert _native_policy_key("credential.set", {}) == "dns.credentials.write"
    assert _native_policy_key("credential.remove", {}) == "dns.credentials.write"
    assert _native_policy_key("domain.add", {}) == "domains.write"


def test_credential_ops_surface(tmp_path, monkeypatch):
    from nostrhost import credentials as credentials_module
    from nostrhost.domains.operations import _safe_credential_list, _safe_credential_set

    monkeypatch.setattr(credentials_module, "credentials_dir", lambda *a, **k: tmp_path / "credentials")
    result = _safe_credential_set(provider="cloudflare", name="main", value="tok")
    assert result["set"] is True
    listing = _safe_credential_list()
    assert any(item["ref"] == "secret:dns/cloudflare/main" for item in listing["credentials"])
    with pytest.raises(Exception):
        _safe_credential_set(provider="", name="", value="x")
