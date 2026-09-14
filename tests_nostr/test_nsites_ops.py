"""Nsites gateway lifecycle tests (Phase 1, task 1.4).

Run with: PYTHONPATH=src python -m pytest -c /dev/null tests_nostr/test_nsites_ops.py -q
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nostrhost import caddy_admin
from nostrhost.domains.service import DomainService
from nostrhost.nsites.models import GatewayConfig
from nostrhost.nsites import operations, service


class FakeCaddy:
    def __init__(self) -> None:
        self.ensured: list[str] = []
        self.removed: list[str] = []

    def ensure_nsite_routes(self, domain: str, upstream: str) -> str:
        self.ensured.append(domain)
        return f"nostrhost-nsite:{domain}"

    def remove_nsite_routes(self, domain: str) -> None:
        self.removed.append(domain)


class FakeSystemctl:
    def __init__(self, active: bool = True) -> None:
        self.active = active
        self.calls: list[str] = []

    def __call__(self, *args: str) -> str:
        self.calls.append(" ".join(args))
        if args and args[0] == "is-active":
            return "active" if self.active else "inactive"
        if args and args[0] == "enable":
            self.active = True
        if args and args[0] == "disable":
            self.active = False
        return ""


def make_service(
    tmp_path: Path, *, caddy: FakeCaddy, systemctl: FakeSystemctl
) -> service.NsiteService:
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True)
    (state_dir / "domains-native").mkdir(parents=True)
    (state_dir / "domains-native" / "sites.example.org.json").write_text(
        "{}", encoding="utf-8"
    )

    template_dir = tmp_path / "caddy-templates"
    template_dir.mkdir()
    (template_dir / "caddy_nsite.conf").write_text(
        "{{ domain }}, *.{{ domain }} {\n\tlog\n\ttls { on_demand }\n}\n",
        encoding="utf-8",
    )
    conf_dir = tmp_path / "caddy-conf.d"
    conf_dir.mkdir()
    service.CADDY_TEMPLATE_DIR = template_dir
    service.CADDY_CONF_DIR = conf_dir

    return service.NsiteService(
        state_dir=state_dir,
        caddy=caddy,
        systemctl=systemctl,
        config_path=tmp_path / "nsite.toml",
    )


def cfg(domain: str = "sites.example.org") -> GatewayConfig:
    return GatewayConfig(domain=domain)


def test_config_to_toml_has_required_sections():
    text = cfg().to_toml()
    assert 'domain = "sites.example.org"' in text
    assert 'mode = "hosted"' in text
    assert "[relays]" in text and "[blossom]" in text and "[limits]" in text
    assert (
        'fallback_servers = ["https://blossom.primal.net", "https://blossom.band"]'
        in text
    )


def test_build_nsite_routes():
    route = caddy_admin.build_nsite_routes("sites.example.org", "127.0.0.1:8195")
    assert route["@id"] == "nostrhost-nsite:sites.example.org"
    assert route["terminal"] is True
    assert route["match"] == [{"host": ["sites.example.org", "*.sites.example.org"]}]
    assert route["handle"][0]["handler"] == "headers"
    assert route["handle"][1] == {
        "handler": "reverse_proxy",
        "upstreams": [{"dial": "127.0.0.1:8195"}],
    }
    with pytest.raises(caddy_admin.CaddyError):
        caddy_admin.build_nsite_routes("sites.example.org", "not-an-upstream")


def test_registry_has_nsite_tools():
    from yunohost.nostr_operations import TOOLS

    spec = TOOLS["nsite.gateway.status"]
    assert spec.scope == "nsites.read" and spec.require_approval is False
    for name in (
        "nsite.gateway.enable",
        "nsite.gateway.disable",
        "nsite.gateway.configure",
    ):
        spec = TOOLS[name]
        assert spec.scope == "nsites.admin"
        assert spec.require_approval is True
    assert TOOLS["nsite.gateway.enable"].input_schema() is not None


def test_gateway_enable_flow(tmp_path: Path):
    caddy, systemctl = FakeCaddy(), FakeSystemctl(active=False)
    svc = make_service(tmp_path, caddy=caddy, systemctl=systemctl)
    result = svc.enable(cfg())
    assert result["ok"] is True
    assert svc.config_path.is_file()
    assert 'domain = "sites.example.org"' in svc.config_path.read_text()
    assert caddy.ensured == ["sites.example.org"]
    assert (tmp_path / "caddy-conf.d" / "sites.example.org.conf").is_file()
    assert systemctl.active is True
    state = service.load_gateway(svc.state_dir)
    assert state["enabled"] is True
    assert state["config"]["domain"] == "sites.example.org"


def test_gateway_disable_flow(tmp_path: Path):
    caddy = FakeCaddy()
    systemctl = FakeSystemctl(active=False)
    svc = make_service(tmp_path, caddy=caddy, systemctl=systemctl)
    svc.enable(cfg())
    result = svc.disable()
    assert result["ok"] is True
    assert caddy.removed == ["sites.example.org"]
    assert not (tmp_path / "caddy-conf.d" / "sites.example.org.conf").exists()
    assert systemctl.active is False
    assert service.load_gateway(svc.state_dir)["enabled"] is False


def test_gateway_configure_requires_enabled(tmp_path: Path):
    caddy, systemctl = FakeCaddy(), FakeSystemctl()
    svc = make_service(tmp_path, caddy=caddy, systemctl=systemctl)
    with pytest.raises(service.NsiteError):
        svc.configure(cfg())
    svc.enable(cfg())
    result = svc.configure(cfg())
    assert result["ok"] is True
    assert "kill -s HUP" in " ".join(systemctl.calls)


def test_gateway_status_disabled(tmp_path: Path):
    caddy, systemctl = FakeCaddy(), FakeSystemctl(active=False)
    svc = make_service(tmp_path, caddy=caddy, systemctl=systemctl)
    status = svc.gateway_status()
    assert status["gateway"]["enabled"] is False
    assert status["gateway"]["health"] == "degraded"


def test_gateway_status_enabled_active(tmp_path: Path):
    caddy, systemctl = FakeCaddy(), FakeSystemctl(active=True)
    svc = make_service(tmp_path, caddy=caddy, systemctl=systemctl)
    svc.enable(cfg())
    status = svc.gateway_status()
    assert status["gateway"]["enabled"] is True
    assert status["gateway"]["service_active"] is True


def test_enable_rejects_unregistered_domain(tmp_path: Path):
    caddy, systemctl = FakeCaddy(), FakeSystemctl()
    svc = make_service(tmp_path, caddy=caddy, systemctl=systemctl)
    with pytest.raises(service.NsiteError, match="not a registered native domain"):
        svc.enable(cfg("notregistered.example.org"))


def test_enable_rejects_subdomain_conflict(tmp_path: Path):
    caddy, systemctl = FakeCaddy(), FakeSystemctl()
    svc = make_service(tmp_path, caddy=caddy, systemctl=systemctl)
    (svc.state_dir / "domains-native" / "example.org.json").write_text(
        "{}", encoding="utf-8"
    )
    (svc.state_dir / "domains-native" / "blog.example.org.json").write_text(
        "{}", encoding="utf-8"
    )
    with pytest.raises(service.NsiteError, match="registered subdomain"):
        svc.enable(cfg("example.org"))


def test_domain_dependents_includes_gateway(tmp_path: Path):
    svc = make_service(tmp_path, caddy=FakeCaddy(), systemctl=FakeSystemctl())
    svc.enable(cfg())
    dependents = DomainService(state_dir=svc.state_dir)._dependents("sites.example.org")
    assert "nsite-gateway" in dependents


def test_gateway_args_strict_validation():
    with pytest.raises(Exception):
        operations.GatewayArgs(domain="sites.example.org", unexpected="x")
    args = operations.GatewayArgs(domain="sites.example.org", max_blob_bytes=1048576)
    assert args.max_blob_bytes == 1048576


def test_policy_scope_and_rule():
    from nostrhost_policy.policy.scopes import Scope
    from nostrhost_policy.policy.rules import DEFAULT_POLICY

    assert Scope.NSITES_READ.value == "nsites.read"
    assert Scope.NSITES_ADMIN.value == "nsites.admin"
    assert Scope.NSITES_PUBLISH.value == "nsites.publish"
    assert DEFAULT_POLICY["nsites.publish"].require_confirmation is True
