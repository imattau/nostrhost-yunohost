"""Phase 4: custom-domain lifecycle tests (nsite.domain.attach/detach/list).

Covers the ownership proof (CNAME / TXT), uniqueness across
``state/nsites/domains``, gateway-overlap rejection, the Caddy route wiring,
the ``nsite.toml`` custom_domains rendering, and the registry wiring
(ToolSpec scope/required_scopes/schema).

Run with: PYTHONPATH=src python -m pytest -c /dev/null tests_nostr/test_nsites_domains.py -q
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nostrhost import caddy_admin
from nostrhost.nsites import service


class FakeCaddy:
    def __init__(self) -> None:
        self.ensured: list[str] = []
        self.removed: list[str] = []

    def ensure_nsite_routes(self, domain: str, upstream: str) -> str:
        self.ensured.append(domain)
        return f"nostrhost-nsite:{domain}"

    def remove_nsite_routes(self, domain: str) -> None:
        self.removed.append(domain)

    def ensure_custom_domain_route(self, fqdn: str, upstream: str) -> str:
        self.ensured.append(f"custom:{fqdn}")
        return f"nostrhost-nsite:{fqdn}"

    def remove_custom_domain_route(self, fqdn: str) -> None:
        self.removed.append(f"custom:{fqdn}")


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


PUBKEY = "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732"
GATEWAY = "sites.example.org"


def make_service(
    tmp_path: Path,
    *,
    caddy: FakeCaddy | None = None,
    systemctl: FakeSystemctl | None = None,
    verify_dns=None,
) -> service.NsiteService:
    caddy = caddy or FakeCaddy()
    systemctl = systemctl or FakeSystemctl()
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True)
    (state_dir / "domains-native").mkdir(parents=True)
    (state_dir / "domains-native" / f"{GATEWAY}.json").write_text("{}", encoding="utf-8")
    template_dir = tmp_path / "caddy-templates"
    template_dir.mkdir()
    (template_dir / "caddy_nsite.conf").write_text(
        "{{ domain }}, *.{{ domain }} {\n\tlog\n\ttls {\n\t\ton_demand\n\t}\n}\n",
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
        verify_dns=verify_dns,
    )


def fake_dns(answers: dict[tuple[str, str], list[str]]):
    def lookup(qname: str, rtype: str) -> list[str]:
        return answers.get((qname.lower(), rtype.upper()), [])
    return lookup


def boot_site(svc: service.NsiteService, *, d: str = "") -> None:
    svc.enable(service.GatewayConfig(domain=GATEWAY))
    svc.site_register(PUBKEY, kind=35128 if d else 15128, d=d)


def test_build_custom_domain_route():
    route = caddy_admin.build_custom_domain_route("blog.example.com", "127.0.0.1:8195")
    assert route["@id"] == "nostrhost-nsite:blog.example.com"
    # A custom FQDN is served as exactly that one host, never a wildcard.
    assert route["match"] == [{"host": ["blog.example.com"]}]
    assert route["handle"][1] == {
        "handler": "reverse_proxy",
        "upstreams": [{"dial": "127.0.0.1:8195"}],
    }
    assert route["terminal"] is True
    with pytest.raises(caddy_admin.CaddyError):
        caddy_admin.build_custom_domain_route("blog.example.com", "nope")


def test_verify_ownership_cname(tmp_path: Path):
    svc = make_service(tmp_path, verify_dns=fake_dns({("blog.example.com", "CNAME"): [GATEWAY]}))
    proof = service._verify_ownership("blog.example.com", PUBKEY, GATEWAY, "cname", svc._verify_dns)
    assert proof["ok"] is True and proof["verification"] == GATEWAY
    svc2 = make_service(tmp_path / "b", verify_dns=fake_dns({}))
    proof = service._verify_ownership("blog.example.com", PUBKEY, GATEWAY, "cname", svc2._verify_dns)
    assert proof["ok"] is False


def test_verify_ownership_txt(tmp_path: Path):
    token = f"nostrhost-site:{PUBKEY}"
    svc = make_service(
        tmp_path,
        verify_dns=fake_dns({("_nostrhost-site.blog.example.com", "TXT"): [f'"{token}"']}),
    )
    proof = service._verify_ownership("blog.example.com", PUBKEY, GATEWAY, "txt", svc._verify_dns)
    assert proof["ok"] is True and proof["verification"] == token
    svc2 = make_service(
        tmp_path / "b",
        verify_dns=fake_dns({("_nostrhost-site.blog.example.com", "TXT"): [f'"nostrhost-site:{PUBKEY[:-2]}xx"']}),
    )
    proof = service._verify_ownership("blog.example.com", PUBKEY, GATEWAY, "txt", svc2._verify_dns)
    assert proof["ok"] is False


def test_verify_ownership_unknown_method(tmp_path: Path):
    svc = make_service(tmp_path, verify_dns=fake_dns({}))
    proof = service._verify_ownership("blog.example.com", PUBKEY, GATEWAY, "spf", svc._verify_dns)
    assert proof["ok"] is False


def test_domain_attach_cname_flow(tmp_path: Path):
    caddy, systemctl = FakeCaddy(), FakeSystemctl()
    svc = make_service(
        tmp_path,
        caddy=caddy,
        systemctl=systemctl,
        verify_dns=fake_dns({("blog.example.com", "CNAME"): [GATEWAY]}),
    )
    boot_site(svc)
    result = svc.domain_attach("blog.example.com", PUBKEY, method="cname")
    assert result["ok"] is True and result["fqdn"] == "blog.example.com"
    # state marker
    marker = service.custom_domain_path(svc.state_dir, "blog.example.com")
    assert marker.is_file()
    record = marker.read_text(encoding="utf-8")
    assert f'"pubkey": "{PUBKEY}"' in record
    assert '"method": "cname"' in record
    # Caddy route + gateway config refresh + caddy reload
    assert "custom:blog.example.com" in caddy.ensured
    assert "reload caddy" in systemctl.calls
    assert svc.config_path.is_file()
    toml = svc.config_path.read_text()
    assert "[[custom_domains]]" in toml
    assert 'fqdn = "blog.example.com"' in toml
    assert f'pubkey = "{PUBKEY}"' in toml
    # list sees it
    assert svc.domain_list()["count"] == 1


def test_domain_attach_txt_flow(tmp_path: Path):
    token = f"nostrhost-site:{PUBKEY}"
    svc = make_service(
        tmp_path,
        verify_dns=fake_dns({("_nostrhost-site.example.com", "TXT"): [f'"{token}"']}),
    )
    boot_site(svc)
    result = svc.domain_attach("example.com", PUBKEY, method="txt")
    assert result["ok"] is True and result["method"] == "txt"
    record = service.custom_domain_path(svc.state_dir, "example.com").read_text()
    assert token in record


def test_domain_attach_rejects_failed_proof(tmp_path: Path):
    svc = make_service(tmp_path, verify_dns=fake_dns({}))
    boot_site(svc)
    with pytest.raises(service.NsiteError, match="ownership proof failed"):
        svc.domain_attach("blog.example.com", PUBKEY, method="cname")
    assert service.custom_domain_path(svc.state_dir, "blog.example.com").is_file() is False


def test_domain_attach_requires_registered_site(tmp_path: Path):
    svc = make_service(tmp_path, verify_dns=fake_dns({("blog.example.com", "CNAME"): [GATEWAY]}))
    svc.enable(service.GatewayConfig(domain=GATEWAY))
    with pytest.raises(service.NsiteError, match="not registered"):
        svc.domain_attach("blog.example.com", PUBKEY, method="cname")


def test_domain_attach_requires_gateway(tmp_path: Path):
    svc = make_service(tmp_path, verify_dns=fake_dns({("blog.example.com", "CNAME"): [GATEWAY]}))
    with pytest.raises(service.NsiteError, match="gateway is not enabled"):
        svc.domain_attach("blog.example.com", PUBKEY, method="cname")


def test_domain_attach_rejects_invalid_fqdn(tmp_path: Path):
    svc = make_service(tmp_path, verify_dns=fake_dns({}))
    boot_site(svc)
    with pytest.raises(service.NsiteError, match="invalid fqdn"):
        svc.domain_attach("under_score.example.com", PUBKEY, method="cname")
    with pytest.raises(service.NsiteError, match="invalid fqdn"):
        svc.domain_attach("../etc/passwd", PUBKEY, method="cname")


def test_domain_attach_rejects_overlap(tmp_path: Path):
    svc = make_service(tmp_path, verify_dns=fake_dns({}))
    boot_site(svc)
    for bad in (GATEWAY, f"blog.{GATEWAY}", "example.org"):
        with pytest.raises(service.NsiteError, match="overlaps|parent of the gateway"):
            svc.domain_attach(bad, PUBKEY, method="cname")


def test_domain_attach_rejects_duplicate(tmp_path: Path):
    svc = make_service(
        tmp_path,
        verify_dns=fake_dns({("blog.example.com", "CNAME"): [GATEWAY]}),
    )
    boot_site(svc)
    svc.domain_attach("blog.example.com", PUBKEY, method="cname")
    with pytest.raises(service.NsiteError, match="already attached"):
        svc.domain_attach("blog.example.com", PUBKEY, method="cname")


def test_domain_attach_requires_named_site_d(tmp_path: Path):
    svc = make_service(tmp_path, verify_dns=fake_dns({("blog.example.com", "CNAME"): [GATEWAY]}))
    boot_site(svc, d="blog")
    # a named site must be attached with its d tag; an invalid d is rejected
    with pytest.raises(service.NsiteError, match="site is not registered"):
        svc.domain_attach("blog.example.com", PUBKEY, method="cname")


def test_domain_detach_removes_route_and_marker(tmp_path: Path):
    caddy, systemctl = FakeCaddy(), FakeSystemctl()
    svc = make_service(
        tmp_path,
        caddy=caddy,
        systemctl=systemctl,
        verify_dns=fake_dns({("blog.example.com", "CNAME"): [GATEWAY]}),
    )
    boot_site(svc)
    svc.domain_attach("blog.example.com", PUBKEY, method="cname")
    result = svc.domain_detach("blog.example.com")
    assert result["ok"] is True and result["removed"] is True
    assert "custom:blog.example.com" in caddy.removed
    assert service.custom_domain_path(svc.state_dir, "blog.example.com").is_file() is False
    # the site itself is untouched
    assert service.site_path(svc.state_dir, PUBKEY).is_file() is True
    toml = svc.config_path.read_text()
    assert "[[custom_domains]]" not in toml
    assert "reload caddy" in systemctl.calls


def test_domain_detach_not_attached(tmp_path: Path):
    svc = make_service(tmp_path)
    boot_site(svc)
    with pytest.raises(service.NsiteError, match="not attached"):
        svc.domain_detach("blog.example.com")


def test_domain_list_empty(tmp_path: Path):
    svc = make_service(tmp_path)
    assert svc.domain_list() == {"domains": [], "count": 0}


def test_registry_has_domain_tools():
    from yunohost.nostr_operations import TOOLS

    for name in ("nsite.domain.attach", "nsite.domain.detach"):
        spec = TOOLS[name]
        assert spec.scope == "nsites.admin"
        assert spec.required_scopes == ("domains.write",)
        assert spec.require_approval is True
        assert spec.input_schema() is not None
    spec = TOOLS["nsite.domain.list"]
    assert spec.scope == "nsites.read"
    assert spec.require_approval is False


def test_policy_rules_for_domain_attach():
    from nostrhost_policy.policy.rules import DEFAULT_POLICY

    assert DEFAULT_POLICY["nsite.domain.write"].require_confirmation is True


def test_native_policy_key_maps_domain_attach():
    from nostrhost_native_policy import _native_policy_key

    assert _native_policy_key("nsite.domain.attach", {}) == "nsite.domain.write"
    assert _native_policy_key("nsite.domain.detach", {}) == "nsite.domain.write"
    assert _native_policy_key("nsite.mirror", {}) == "nsite.mirror"
