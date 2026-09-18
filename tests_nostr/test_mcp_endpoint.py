"""Tests for the MCP endpoint setup helpers (src/nostrhost/mcp_endpoint.py)."""

from __future__ import annotations

import pytest

import yunohost.nostrhost.caddy_admin as caddy_admin_module
from yunohost.nostrhost import mcp_endpoint


class FakeCaddyAdminClient:
    """Captures calls instead of hitting Caddy's admin API."""

    instances: list["FakeCaddyAdminClient"] = []

    def __init__(self, base_url=None):
        self.base_url = base_url
        self.ensured_sites: list[str] = []
        self.ensured_routes: list[dict] = []
        self.deleted_routes: list[str] = []
        FakeCaddyAdminClient.instances.append(self)

    def ensure_domain_site(self, domain):
        self.ensured_sites.append(domain)
        return f"nostrhost-domain:{domain}"

    def ensure_route(self, route):
        self.ensured_routes.append(route)
        return route["@id"]

    def delete_route(self, route_id):
        self.deleted_routes.append(route_id)


@pytest.fixture(autouse=True)
def _reset_fake_instances():
    FakeCaddyAdminClient.instances = []
    yield
    FakeCaddyAdminClient.instances = []


def test_read_endpoint_config_returns_none_when_missing(tmp_path):
    assert mcp_endpoint.read_endpoint_config(str(tmp_path / "nope.toml")) is None


def test_write_then_read_roundtrip(tmp_path):
    path = str(tmp_path / "mcp.toml")
    mcp_endpoint.write_endpoint_config("mcp.example.com", 8930, path=path)
    assert mcp_endpoint.read_endpoint_config(path) == {"domain": "mcp.example.com", "port": 8930}


def test_read_endpoint_config_ignores_malformed_file(tmp_path):
    path = tmp_path / "mcp.toml"
    path.write_text("not = [valid toml")
    assert mcp_endpoint.read_endpoint_config(str(path)) is None


def test_read_endpoint_config_ignores_missing_domain(tmp_path):
    path = tmp_path / "mcp.toml"
    path.write_text('port = 8930\n')
    assert mcp_endpoint.read_endpoint_config(str(path)) is None


def test_configure_route_ensures_site_then_route_then_persists(monkeypatch, tmp_path):
    monkeypatch.setattr(mcp_endpoint, "CONFIG_PATH", str(tmp_path / "mcp.toml"))
    monkeypatch.setattr(mcp_endpoint, "MCP_ENV_PATH", str(tmp_path / "nope.env"))
    monkeypatch.setattr(caddy_admin_module, "CaddyAdminClient", FakeCaddyAdminClient)

    route_id = mcp_endpoint.configure_route("mcp.example.com", port=9999)

    assert route_id == "nostrhost-web:mcp"
    client = FakeCaddyAdminClient.instances[0]
    assert client.ensured_sites == ["mcp.example.com"]
    assert client.ensured_routes[0]["@id"] == "nostrhost-web:mcp"
    assert client.ensured_routes[0]["match"][0]["host"] == ["mcp.example.com"]
    assert mcp_endpoint.read_endpoint_config() == {"domain": "mcp.example.com", "port": 9999}


def test_configure_route_is_idempotent_on_reconfigure(monkeypatch, tmp_path):
    monkeypatch.setattr(mcp_endpoint, "CONFIG_PATH", str(tmp_path / "mcp.toml"))
    monkeypatch.setattr(mcp_endpoint, "MCP_ENV_PATH", str(tmp_path / "nope.env"))
    monkeypatch.setattr(caddy_admin_module, "CaddyAdminClient", FakeCaddyAdminClient)

    mcp_endpoint.configure_route("mcp.example.com", port=8930)
    mcp_endpoint.configure_route("mcp.example.com", port=9999)

    assert mcp_endpoint.read_endpoint_config() == {"domain": "mcp.example.com", "port": 9999}


def test_remove_route_deletes_the_mcp_route_and_config(monkeypatch, tmp_path):
    config_path = str(tmp_path / "mcp.toml")
    monkeypatch.setattr(mcp_endpoint, "CONFIG_PATH", config_path)
    monkeypatch.setattr(mcp_endpoint, "MCP_ENV_PATH", str(tmp_path / "nope.env"))
    monkeypatch.setattr(caddy_admin_module, "CaddyAdminClient", FakeCaddyAdminClient)

    mcp_endpoint.configure_route("mcp.example.com", port=8930)
    mcp_endpoint.remove_route("mcp.example.com")

    assert FakeCaddyAdminClient.instances[-1].deleted_routes == ["nostrhost-web:mcp"]
    assert mcp_endpoint.read_endpoint_config() is None


def test_remove_route_leaves_config_when_domain_does_not_match(monkeypatch, tmp_path):
    monkeypatch.setattr(mcp_endpoint, "CONFIG_PATH", str(tmp_path / "mcp.toml"))
    monkeypatch.setattr(mcp_endpoint, "MCP_ENV_PATH", str(tmp_path / "nope.env"))
    monkeypatch.setattr(caddy_admin_module, "CaddyAdminClient", FakeCaddyAdminClient)

    mcp_endpoint.configure_route("mcp.example.com", port=8930)
    mcp_endpoint.remove_route("other.example.com")

    assert mcp_endpoint.read_endpoint_config() == {"domain": "mcp.example.com", "port": 8930}


def test_export_ca_bundle_none_when_no_internal_ca(tmp_path):
    bundle = mcp_endpoint.export_ca_bundle(
        domain="mcp.example.test",
        caddy_root=str(tmp_path / "root.crt"),
        system_bundle=str(tmp_path / "system.crt"),
    )
    assert bundle is None


def test_export_ca_bundle_combines_system_and_caddy_root(tmp_path):
    caddy_root = tmp_path / "root.crt"
    caddy_root.write_bytes(b"-----BEGIN CERTIFICATE-----\nCADDY\n-----END CERTIFICATE-----\n")
    system_bundle = tmp_path / "system.crt"
    system_bundle.write_bytes(b"-----BEGIN CERTIFICATE-----\nSYSTEM\n-----END CERTIFICATE-----\n")

    bundle = mcp_endpoint.export_ca_bundle(
        domain="mcp.example.test", caddy_root=str(caddy_root), system_bundle=str(system_bundle)
    )

    assert bundle == system_bundle.read_bytes() + caddy_root.read_bytes()


def test_export_ca_bundle_works_without_a_system_bundle(tmp_path):
    caddy_root = tmp_path / "root.crt"
    caddy_root.write_bytes(b"CADDY-ROOT\n")

    bundle = mcp_endpoint.export_ca_bundle(
        domain="mcp.example.test", caddy_root=str(caddy_root), system_bundle=str(tmp_path / "nope.crt")
    )

    assert bundle == b"CADDY-ROOT\n"


def test_export_ca_bundle_none_for_public_acme_domain(tmp_path):
    """A public ACME domain needs no client-side trust even when the node
    keeps an internal CA for its lab/test domains (regression: the bundle
    was previously exported whenever Caddy's internal root existed on disk,
    so every public-cert endpoint wrongly reported self-signed)."""
    caddy_root = tmp_path / "root.crt"
    caddy_root.write_bytes(b"CADDY-ROOT\n")

    bundle = mcp_endpoint.export_ca_bundle(
        domain="mcp.example.com", caddy_root=str(caddy_root), system_bundle=str(tmp_path / "system.crt")
    )

    assert bundle is None


def test_export_ca_bundle_none_without_a_configured_domain(tmp_path):
    caddy_root = tmp_path / "root.crt"
    caddy_root.write_bytes(b"CADDY-ROOT\n")

    bundle = mcp_endpoint.export_ca_bundle(
        caddy_root=str(caddy_root), system_bundle=str(tmp_path / "system.crt")
    )

    assert bundle is None


def test_ensure_adapter_host_appends_domain_and_restarts(monkeypatch, tmp_path):
    env_path = tmp_path / "mcp.env"
    env_path.write_text("NOSTRHOST_AGENT_SK=abc\nNOSTRHOST_MCP_ALLOWED_HOSTS=mcp.nostrhost.test\n")
    monkeypatch.setattr(mcp_endpoint, "MCP_ENV_PATH", str(env_path))
    restarts = []
    monkeypatch.setattr(mcp_endpoint.subprocess, "run", lambda args, **kwargs: restarts.append(args))

    restarted = mcp_endpoint._ensure_adapter_host("nmcp.example.com")

    assert restarted is True
    assert env_path.read_text() == (
        "NOSTRHOST_AGENT_SK=abc\nNOSTRHOST_MCP_ALLOWED_HOSTS=mcp.nostrhost.test nmcp.example.com\n"
    )
    assert restarts == [["systemctl", "restart", mcp_endpoint.MCP_SERVICE]]


def test_ensure_adapter_host_noop_when_domain_already_allowed(monkeypatch, tmp_path):
    env_path = tmp_path / "mcp.env"
    env_path.write_text("NOSTRHOST_MCP_ALLOWED_HOSTS=mcp.nostrhost.test nmcp.example.com\n")
    monkeypatch.setattr(mcp_endpoint, "MCP_ENV_PATH", str(env_path))
    restarts = []
    monkeypatch.setattr(mcp_endpoint.subprocess, "run", lambda args, **kwargs: restarts.append(args))

    restarted = mcp_endpoint._ensure_adapter_host("nmcp.example.com")

    assert restarted is False
    assert env_path.read_text() == "NOSTRHOST_MCP_ALLOWED_HOSTS=mcp.nostrhost.test nmcp.example.com\n"
    assert restarts == []


def test_ensure_adapter_host_creates_var_when_missing(monkeypatch, tmp_path):
    env_path = tmp_path / "mcp.env"
    env_path.write_text("NOSTRHOST_AGENT_SK=abc\n")
    monkeypatch.setattr(mcp_endpoint, "MCP_ENV_PATH", str(env_path))
    restarts = []
    monkeypatch.setattr(mcp_endpoint.subprocess, "run", lambda args, **kwargs: restarts.append(args))

    restarted = mcp_endpoint._ensure_adapter_host("nmcp.example.com")

    assert restarted is True
    assert env_path.read_text() == "NOSTRHOST_AGENT_SK=abc\nNOSTRHOST_MCP_ALLOWED_HOSTS=nmcp.example.com\n"
    assert len(restarts) == 1


def test_ensure_adapter_host_noop_without_env_file(monkeypatch, tmp_path):
    monkeypatch.setattr(mcp_endpoint, "MCP_ENV_PATH", str(tmp_path / "nope.env"))
    restarts = []
    monkeypatch.setattr(mcp_endpoint.subprocess, "run", lambda args, **kwargs: restarts.append(args))

    assert mcp_endpoint._ensure_adapter_host("nmcp.example.com") is False
    assert restarts == []
