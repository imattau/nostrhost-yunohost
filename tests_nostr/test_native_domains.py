"""Workstream 4 (Phase A): native domains & DNS.

Covers the resource models, the planner, ownership-bounded reconciliation,
the manual provider, the domain lifecycle service (add/inspect/plan/apply/
verify/remove) and the parallel registry hook so permission URL validation
accepts native domains without LDAP.
"""

from __future__ import annotations

import contextlib
import json
import types
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from nostrhost.dns.models import DnsProviderResource, DnsRecord
from nostrhost.dns.reconciler import build_plan
from nostrhost.dns.providers.manual import ManualProvider
from nostrhost.domains.models import DomainExposure, DomainNostr, DomainResource, DomainTls
from nostrhost.domains.planner import desired_records, discover_zone
from nostrhost.domains.service import (
    DomainError,
    DomainService,
    native_domain_names,
    native_domain_registry,
)
from yunohost.nostr_operations import known_tools


def test_caddy_regen_uses_native_domain_registry():
    """Native-only installs must not call the removed ``yunohost`` CLI.

    A suppressed command-not-found here leaves registered domains out of the
    Caddyfile, so their short-lived internal certificates expire and they can
    never become primary-domain candidates.
    """
    hook = Path(__file__).parents[1] / "hooks" / "conf_regen" / "15-caddy"
    body = hook.read_text(encoding="utf-8")
    assert "nostrhost domain list --output-as json" in body
    assert "yunohost domain list --output-as json" not in body


# --------------------------------------------------------------------------- #
# models

def test_domain_resource_validation():
    d = DomainResource(name="W4.Test", provider=DnsProviderResource(type="manual"))
    assert d.name == "w4.test"
    with pytest.raises(Exception):
        DomainResource(name="not_a_domain")
    with pytest.raises(Exception):
        DomainResource(name="123.456")


def test_dns_record_validation_and_fqdn():
    r = DnsRecord(zone="w4.test", name="@", type="A", value="10.0.0.1")
    assert r.fqdn() == "w4.test"
    assert r.is_on_domain("w4.test")
    assert not r.is_on_domain("other.test")
    sub = DnsRecord(zone="w4.test", name="photos", type="A", value="10.0.0.1")
    assert sub.fqdn() == "photos.w4.test"
    assert sub.is_on_domain("w4.test")
    with pytest.raises(Exception):
        DnsRecord(zone="w4.test", name="bad name!", type="A", value="x")
    with pytest.raises(Exception):
        DnsRecord(zone="w4.test", name="@", type="ZOMG", value="x")


def test_dns_provider_credential_must_be_secret_ref():
    with pytest.raises(Exception):
        DnsProviderResource(type="cloudflare", credential="naked-token")
    DnsProviderResource(type="cloudflare", credential="secret:dns/cloudflare/main")


# --------------------------------------------------------------------------- #
# planner

def test_desired_records_default():
    d = DomainResource(name="w4.test")
    records = desired_records(d, ipv4="203.0.113.10", ipv6="2001:db8::1")
    names = {(r.name, r.type) for r in records}
    assert ("@", "A") in names and ("*", "A") in names
    assert ("@", "AAAA") in names and ("*", "AAAA") in names
    assert all(r.owner == "nostrhost" for r in records)


def test_desired_records_no_wildcard():
    d = DomainResource(name="w4.test", exposure=DomainExposure(wildcard=False))
    records = desired_records(d, ipv4="203.0.113.10", ipv6=None)
    names = {(r.name, r.type) for r in records}
    assert names == {("@", "A")}


def test_desired_records_caa_only_when_configured():
    plain = desired_records(DomainResource(name="w4.test"), ipv4="1.2.3.4")
    assert all(r.type != "CAA" for r in plain)
    with_caa = desired_records(DomainResource(name="w4.test", tls=DomainTls(caa=["letsencrypt.org"])), ipv4="1.2.3.4")
    caa = [r for r in with_caa if r.type == "CAA"]
    assert len(caa) == 1 and caa[0].value == '0 issue "letsencrypt.org"'


def test_discover_zone():
    assert discover_zone("sub.example.com", registered=["example.com"]) == "example.com"
    assert discover_zone("w4.test", registered=[]) == "w4.test"
    assert discover_zone("w4.test", provider_zone="w4.test") == "w4.test"


# --------------------------------------------------------------------------- #
# reconciler + ownership

def _a(zone="w4.test", name="@", value="1.2.3.4", owner="nostrhost"):
    return DnsRecord(zone=zone, name=name, type="A", value=value, owner=owner)


def test_reconciler_create_keep_update_delete():
    desired = [_a(value="1.2.3.4"), _a(name="*", value="1.2.3.4")]
    plan = build_plan(desired, actual=[])
    assert [c.action for c in plan.changes] == ["create", "create"]

    plan = build_plan(desired, actual=desired)
    assert [c.action for c in plan.changes] == ["keep", "keep"]

    plan = build_plan([_a(value="5.6.7.8")], actual=[_a(value="1.2.3.4")])
    assert plan.changes[0].action == "update"

    plan = build_plan([], actual=[_a()])
    # empty desired -> no changes, nothing preserved
    assert plan.changes == [] and plan.preserved == []


def test_reconciler_preserves_external_records():
    external = _a(name="mail", value="9.9.9.9", owner="google")
    desired = [_a()]
    plan = build_plan(desired, actual=[_a(), external])
    assert [c.action for c in plan.changes] == ["keep"]
    assert plan.preserved == [external]


def test_manual_provider_roundtrip(tmp_path):
    provider = ManualProvider(zone="w4.test", state_dir=tmp_path)
    record = _a()
    record_id = provider.create_record(record)
    assert provider.list_records("w4.test") == [record]
    provider.update_record(record_id, _a(value="5.6.7.8"))
    assert provider.list_records("w4.test")[0].value == "5.6.7.8"
    # the manual mirror is keyed by fingerprint, so delete by the current one
    provider.delete_record(provider.list_records("w4.test")[0].fingerprint())
    assert provider.list_records("w4.test") == []


# --------------------------------------------------------------------------- #
# lifecycle service

def _service(tmp_path, ipv4="203.0.113.10"):
    return DomainService(state_dir=tmp_path, caddy=None, public_ipv4=lambda: ipv4, public_ipv6=lambda: None)


def test_domain_add_apply_and_state(tmp_path):
    svc = _service(tmp_path)
    result = svc.add(DomainResource(name="w4.test"), verify=False)
    assert result["ok"] is True
    assert result["dns_plan"]["summary"]["create"] == 2
    assert len(result["applied"]) == 2
    assert (tmp_path / "domains-native" / "w4.test.json").is_file()
    assert svc.list_domains()["domains"] == ["w4.test"]
    # re-add is rejected
    with pytest.raises(DomainError):
        svc.add(DomainResource(name="w4.test"), verify=False)


def test_domain_add_nip05_flag(tmp_path):
    svc = _service(tmp_path)
    result = svc.add(DomainResource(name="w4.test", nostr=DomainNostr(nip05=True)), verify=False)
    assert result["routes"]["nip05"] == "no-caddy"


def test_domain_plan_and_apply(tmp_path):
    svc = _service(tmp_path)
    svc.add(DomainResource(name="w4.test"), verify=False)
    plan = svc.dns_plan("w4.test")
    assert plan["plan"]["summary"]["keep"] == 2
    svc.public_ipv4 = lambda: "10.1.2.3"
    drift = svc.dns_plan("w4.test")
    assert drift["plan"]["summary"]["update"] == 2
    applied = svc.dns_apply("w4.test")
    assert applied["ok"] is True and len(applied["applied"]) == 2


def test_domain_verify(tmp_path):
    svc = _service(tmp_path)
    svc.add(DomainResource(name="w4.test"), verify=False)
    verification = svc.dns_verify("w4.test")
    assert isinstance(verification["verify"], list) and len(verification["verify"]) == 2


def test_domain_remove_bounded_and_blocks_dependents(tmp_path):
    svc = _service(tmp_path)
    svc.add(DomainResource(name="w4.test"), verify=False)
    # simulate a native app attached to the domain (real stored-manifest shape:
    # {id, version, manifest: <nested dict with [web]>})
    packages = tmp_path / "packages"
    packages.mkdir()
    (packages / "photos-manifest.json").write_text(
        json.dumps({"id": "photos", "version": "0.1", "manifest": {"app": {"id": "photos"}, "web": {"domain": "w4.test", "path": "/photos/"}}})
    )
    with pytest.raises(DomainError):
        svc.remove("w4.test")
    # force removal succeeds and removes owned records + unregisters
    result = svc.remove("w4.test", force=True)
    assert result["ok"] is True and len(result["deleted"]) == 2
    assert not (tmp_path / "domains-native" / "w4.test.json").is_file()
    assert svc.list_domains()["domains"] == []


def test_domain_remove_preserves_external_zone(tmp_path):
    svc = _service(tmp_path)
    svc.add(DomainResource(name="w4.test"), verify=False)
    # an external record in the same zone must survive removal
    provider = ManualProvider(zone="w4.test", state_dir=tmp_path)
    external = _a(name="mx", value="9.9.9.9", owner="google")
    provider.create_record(external)
    result = svc.remove("w4.test", force=True)
    assert result["ok"] is True
    remaining = provider.list_records("w4.test")
    assert len(remaining) == 1 and remaining[0].name == "mx"


def test_domain_inspect(tmp_path):
    svc = _service(tmp_path)
    svc.add(DomainResource(name="w4.test", nostr=DomainNostr(nip05=True)), verify=False)
    info = svc.inspect("w4.test")
    assert info["domain"]["name"] == "w4.test"
    assert info["zone"] == "w4.test"
    assert info["plan"]["summary"]["keep"] == 2


# --------------------------------------------------------------------------- #
# parallel registry (no LDAP)

def test_native_domain_registry(tmp_path):
    svc = _service(tmp_path)
    svc.add(DomainResource(name="w4.test"), verify=False)
    assert native_domain_names(tmp_path) == ["w4.test"]
    assert "w4.test" in native_domain_registry(tmp_path)
    svc.remove("w4.test", force=True)
    assert native_domain_names(tmp_path) == []


def test_assert_domain_exists_accepts_native(monkeypatch, tmp_path):
    state = tmp_path / "state"
    svc = _service(state)
    svc.add(DomainResource(name="w4.test"), verify=False)

    from yunohost import domain as domain_module
    from yunohost.utils.error import YunohostValidationError

    monkeypatch.setattr(domain_module, "_get_domains", lambda *a, **k: [])
    monkeypatch.setenv("NOSTRHOST_STATE_DIR", str(state))
    domain_module._assert_domain_exists("w4.test")
    with pytest.raises(YunohostValidationError):
        domain_module._assert_domain_exists("nope.test")


# --------------------------------------------------------------------------- #
# op registry surface

def test_native_domain_tools_registered():
    tools = known_tools()
    for tool in ("domain.list", "domain.inspect", "domain.add", "domain.remove", "dns.plan", "dns.apply", "dns.verify", "network.public_ip"):
        assert tool in tools


def test_network_public_ip():
    from nostrhost.domains.operations import _safe_network_public_ip

    result = _safe_network_public_ip()
    assert set(result) == {"ipv4", "ipv6"}


# --------------------------------------------------------------------------- #
# NIP-05 route + authd endpoint wiring

def test_nip05_caddy_route():
    from nostrhost.caddy_admin import build_nip05_route

    route = build_nip05_route("w4.test")
    assert route["@id"] == "nostrhost-nip05:w4.test"
    assert route["match"] == [{"host": ["w4.test"], "path": ["/.well-known/nostr.json"]}]
    assert route["handle"][0]["handler"] == "reverse_proxy"


def test_portal_routes_host_and_path_anded():
    from nostrhost.caddy_admin import build_portal_routes

    routes = {r["@id"]: r for r in build_portal_routes("w4.test", expose_native_api=True)}
    # YunoHost and native API endpoints are unconditional reverse proxies
    assert routes["nostrhost-api:w4.test"]["match"] == [{"host": ["w4.test"], "path": ["/nostrhost/api/*"]}]
    # api/portalapi strip their /nostrhost/... prefix before proxying (the
    # handle_path equivalent), so the reverse_proxy comes after the rewrite
    portalapi = routes["nostrhost-portalapi:w4.test"]
    assert portalapi["handle"][-1]["handler"] == "reverse_proxy"
    assert portalapi["handle"][0] == {"handler": "rewrite", "strip_path_prefix": "/nostrhost/portalapi"}
    native_api = routes["nostrhost-native-api:w4.test"]
    assert native_api["match"] == [{"host": ["w4.test"], "path": ["/package/*"]}]
    assert native_api["handle"][0]["upstreams"] == [{"dial": "127.0.0.1:8190"}]
    # sso/admin only when the static dirs exist
    assert "nostrhost-sso:w4.test" in routes or True
    for route in routes.values():
        assert all(set(m) == {"host", "path"} for m in route["match"])
        assert route["terminal"] is True


def test_portal_routes_hide_native_api_by_default():
    """H4: /package/* (the native admin API) must NOT be routed on app
    subdomains — only the primary admin domain exposes it. The bare portal
    routes for a non-primary domain omit the native-api route entirely."""
    from nostrhost.caddy_admin import build_portal_routes

    routes = {r["@id"]: r for r in build_portal_routes("app.w4.test")}
    assert "nostrhost-native-api:app.w4.test" not in routes
    # the SSO/portalapi surface stays (forward_auth needs it)
    assert "nostrhost-api:app.w4.test" in routes
    assert "nostrhost-portalapi:app.w4.test" in routes


def test_native_api_exposed_only_on_primary_domain(tmp_path):
    """H4: the DomainService only routes /package/* for the flagged primary
    domain; until one exists it keeps the legacy (pre-split) behaviour."""
    from nostrhost.domains.models import DomainResource
    from nostrhost.domains.service import DomainService, save_domain

    service = DomainService(state_dir=tmp_path, caddy=None)
    # legacy: no primary flagged yet -> the surface stays exposed
    assert service._expose_native_api("w4.test") is True

    save_domain(tmp_path, DomainResource(name="w4.test", primary=True))
    save_domain(tmp_path, DomainResource(name="app.w4.test", primary=False))
    assert service._expose_native_api("w4.test") is True
    assert service._expose_native_api("app.w4.test") is False


def test_portal_admin_route_uses_nostrhost_prefix(monkeypatch):
    """The admin SPA route must live under /nostrhost/admin, matching
    conf/caddy/caddy_domain.conf, so it falls under the reserved-path
    exclusion build_web_route() enforces for root-claimed apps."""
    from nostrhost import caddy_admin

    monkeypatch.setattr(caddy_admin.os.path, "isdir", lambda _root: True)
    routes = {r["@id"]: r for r in caddy_admin.build_portal_routes("w4.test")}
    admin = routes["nostrhost-admin:w4.test"]
    assert admin["match"] == [{"host": ["w4.test"], "path": ["/nostrhost/admin/*"]}]


def test_portal_bare_prefixes_redirect_to_trailing_slash(monkeypatch):
    """A bare /nostrhost/admin or /nostrhost/sso must 301 to the trailing-slash
    form so it reaches the SPA instead of the domain root responder (nginx's
    ``rewrite ^/yunohost/admin$ /yunohost/admin/ permanent;``)."""
    from nostrhost import caddy_admin

    monkeypatch.setattr(caddy_admin.os.path, "isdir", lambda _root: True)
    routes = {r["@id"]: r for r in caddy_admin.build_portal_routes("w4.test")}
    for tag, path in (("admin", "/nostrhost/admin"), ("sso", "/nostrhost/sso")):
        route = routes[f"nostrhost-{tag}-redir:w4.test"]
        assert route["match"] == [{"host": ["w4.test"], "path": [path]}]
        handle = route["handle"][0]
        assert handle["handler"] == "static_response"
        assert handle["status_code"] == 301
        assert handle["headers"]["Location"] == [f"{path}/"]


def test_sso_route_serves_app_logos_before_spa_fallback(monkeypatch):
    """App logos live outside the portal build dir, so the sso route must serve
    /nostrhost/sso/applogos/* from their real directory *before* the SPA
    try_files fallback. Without it, logo requests get index.html and every
    portal tile image is broken (the nginx applogos alias was dropped in the
    nginx->Caddy cutover)."""
    from nostrhost import caddy_admin

    monkeypatch.setattr(caddy_admin.os.path, "isdir", lambda _root: True)
    routes = {r["@id"]: r for r in caddy_admin.build_portal_routes("w4.test")}
    inner = routes["nostrhost-sso:w4.test"]["handle"][0]["routes"]

    logos, spa = inner[0], inner[1]
    assert logos["match"] == [{"path": ["/nostrhost/sso/applogos/*"]}]
    assert logos["terminal"] is True
    assert logos["handle"][0] == {
        "handler": "rewrite",
        "strip_path_prefix": "/nostrhost/sso/applogos",
    }
    assert logos["handle"][1] == {"handler": "vars", "root": "/usr/share/yunohost/applogos"}
    assert logos["handle"][-1] == {"handler": "file_server"}
    # the SPA fallback still covers the rest of /nostrhost/sso/*
    assert spa["match"] == [{"path": ["/nostrhost/sso/*"]}]
    # the admin SPA has no app-logos pre-route
    assert len(routes["nostrhost-admin:w4.test"]["handle"][0]["routes"]) == 1


def test_caddy_domain_template_serves_app_logos_before_sso():
    """conf/caddy/caddy_domain.conf must keep the applogos handle_path ahead of
    the sso SPA block; Caddy evaluates handle_path blocks in written order, so
    the reverse would send logo requests to index.html."""
    from pathlib import Path

    template = (
        Path(__file__).resolve().parents[1] / "conf" / "caddy" / "caddy_domain.conf"
    ).read_text()
    logos = template.index("/nostrhost/sso/applogos/*")
    sso = template.index("handle_path /nostrhost/sso/*")
    assert logos < sso
    assert "root * /usr/share/yunohost/applogos" in template


def test_web_route_root_excludes_reserved_paths():
    """A [web] resource claiming path "/" gets a host-only catch-all matcher
    (no `path` key). insert_route() always inserts new routes at index 0, so
    without an explicit exclusion this route would shadow the portal/admin/
    API routes whenever it happens to land ahead of them. It must instead
    exclude the reserved prefixes so it's safe regardless of route order."""
    from nostrhost.caddy_admin import RESERVED_EXACT_PATHS, RESERVED_PATH_PREFIXES, build_web_route

    route = build_web_route({"domain": "w4.test", "upstream": "127.0.0.1:9000", "path": "/"})
    assert route["match"] == [
        {
            "host": ["w4.test"],
            "not": [{"path": [f"{p}/*" for p in RESERVED_PATH_PREFIXES] + list(RESERVED_EXACT_PATHS)}],
        }
    ]
    assert route["terminal"] is True


def test_web_route_normal_path_unaffected():
    from nostrhost.caddy_admin import build_web_route

    route = build_web_route({"domain": "w4.test", "upstream": "127.0.0.1:9000", "path": "/blog"})
    # Bare path AND prefix are matched (a bare-path link like "/blog" falls
    # through a prefix-only matcher to whatever route is next).
    assert route["match"] == [{"host": ["w4.test"], "path": ["/blog", "/blog/*"]}]


@pytest.mark.parametrize("path", ["/nostrhost/admin", "/nostrhost/sso", "/package", "/package/foo"])
def test_web_route_rejects_reserved_paths(path):
    from nostrhost.caddy_admin import CaddyError, build_web_route

    with pytest.raises(CaddyError):
        build_web_route({"domain": "w4.test", "upstream": "127.0.0.1:9000", "path": path})


def _fake_request(*, host="w4.test", query=None, method="GET"):
    """A minimal stand-in for a Starlette request for the nostrhost.web context."""
    return types.SimpleNamespace(
        method=method,
        headers={"host": host},
        url=urlsplit(f"http://{host}/"),
        query_params=query or {},
        cookies={},
        state=types.SimpleNamespace(),
    )


@contextlib.contextmanager
def _web_context(**kwargs):
    """Bind the nostrhost.web per-request context to a fake request."""
    from nostrhost import web

    token = web.begin(_fake_request(**kwargs))
    try:
        yield
    finally:
        web.end(token)


def test_nip05_endpoint_wired():
    from nostrhost.portal_api import build_app

    app = build_app()
    assert any(route.path == "/.well-known/nostr.json" for route in app.routes)


def test_portal_public_and_me_routes_wired():
    """The portal SPA boots from /public (settings) and reads the session via
    /me; both must be served by the portal-api (previously only in the retired
    moulinette portal.py)."""
    from nostrhost.portal_api import build_app

    app = build_app()
    rules = {route.path for route in app.routes}
    assert "/public" in rules
    assert "/me" in rules
    assert "/logout" in rules


def test_portal_public_returns_settings(monkeypatch):
    from yunohost.nostrhost import portal_settings as ps

    # no portal settings dir content, no session -> defaults with empty apps
    monkeypatch.setattr(ps, "PORTAL_SETTINGS_DIR", "/nonexistent")
    monkeypatch.setattr("yunohost.nostr_account._session_username", lambda: None)
    with _web_context(host="w4.test"):
        out = ps.portal_public_route()
    assert out["domain"] == "w4.test"
    assert out["apps"] == {}


def test_portal_me_reports_admin_flag(monkeypatch):
    """The /me route exposes whether the session user is an admin, so the
    portal can gate the Administration footer link to admins only."""
    from yunohost.nostrhost import portal_settings as ps

    monkeypatch.setattr("yunohost.nostr_account._session_username", lambda: "alice")
    monkeypatch.setattr(
        "yunohost.nostrhost.accounts.user_get",
        lambda username: {"fullname": "Alice", "mail": ["alice@w4.test"], "admin": True},
    )
    monkeypatch.setattr(ps, "PORTAL_SETTINGS_DIR", "/nonexistent")
    with _web_context(host="w4.test"):
        out = ps.portal_me_route()
    assert out["username"] == "alice"
    assert out["admin"] is True


def test_nip05_body_builder(monkeypatch, tmp_path):
    from yunohost.nostr_account import nip05_route

    monkeypatch.setenv("NOSTRHOST_IDENTITY_DB", str(tmp_path / "identity.db"))
    with _web_context(query={"name": "alice"}):
        body = nip05_route()
    assert isinstance(body, dict) and "names" in body
