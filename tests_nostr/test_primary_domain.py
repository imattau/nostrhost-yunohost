import sys
import types
from pathlib import Path

from nostrhost.domains.models import DomainResource
from nostrhost.domains.primary import apply_primary, plan_primary
from nostrhost.domains.service import DomainService, load_domain, save_domain


class FakeCaddy:
    def __init__(self):
        self.routes = []

    def ensure_portal_routes(self, domain, *, expose_native_api=False):
        self.routes.append((domain, expose_native_api))
        return [domain]


class ReadyService(DomainService):
    def inspect(self, name):
        return {"drift": {"in_sync": True}}

    def certificate_readiness(self, name):
        return {"ready": True, "expires": "2030-01-01"}


def _service(tmp_path: Path):
    service = ReadyService(state_dir=tmp_path, caddy=FakeCaddy())
    save_domain(tmp_path, DomainResource(name="old.example", primary=True))
    save_domain(tmp_path, DomainResource(name="new.example", primary=False))
    return service


def test_primary_plan_preserves_application_addresses(tmp_path):
    service = _service(tmp_path)
    plan = plan_primary("new.example", service)
    assert plan["new_admin_url"] == "https://new.example/nostrhost/admin/"
    assert "Installed application addresses" in plan["unchanged"]
    assert plan["sign_in_again"] is True
    assert plan["reversibility"] == "reversible-with-plan"
    assert set(plan["registry"]) == {"old.example", "new.example"}


def test_primary_plan_fingerprint_changes_with_registry_state(tmp_path):
    service = _service(tmp_path)
    reviewed = plan_primary("new.example", service)
    resource = load_domain(tmp_path, "new.example")
    resource.nostr.nip05 = True
    save_domain(tmp_path, resource)

    refreshed = plan_primary("new.example", service)

    assert refreshed["plan_sha256"] != reviewed["plan_sha256"]


def test_primary_apply_sets_exactly_one_flag_and_reconciles_routes(tmp_path, monkeypatch):
    service = _service(tmp_path)
    changed = []
    module = types.ModuleType("yunohost.domain")
    module.domain_main_domain = lambda new_main_domain: changed.append(new_main_domain)
    monkeypatch.setitem(sys.modules, "yunohost.domain", module)
    init_called = []
    identity = types.ModuleType("yunohost.nostr_identity")
    identity._init_headless_yunohost = lambda: init_called.append(True)
    monkeypatch.setitem(sys.modules, "yunohost.nostr_identity", identity)

    result = apply_primary("new.example", service)

    assert result["new_domain"] == "new.example"
    assert changed == ["new.example"]
    assert init_called == [True]
    assert load_domain(tmp_path, "old.example").primary is False
    assert load_domain(tmp_path, "new.example").primary is True
    assert ("new.example", True) in service.caddy.routes
    assert ("old.example", False) in service.caddy.routes
