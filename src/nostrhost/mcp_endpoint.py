"""MCP endpoint setup: the Caddy route + CA-trust half of bringing up
``nostrhost-mcp`` behind a reverse proxy (docs/MCP-SETUP-RUNBOOK.md §§3-4).

Turns the runbook's hand-edited Caddy vhost + manual CA-bundle steps into
one CLI command each, reusing the same admin-API route mechanism (and the
same TLS story) every other native `[web]` resource already uses — no new
Caddy config file, no separate TLS handling. The endpoint's chosen
domain/port is persisted so the Admin UI (and other CLI calls) can read it
back without the operator re-typing it.
"""

from __future__ import annotations

import os
import tomllib
from typing import Any

import tomli_w

CONFIG_PATH = os.environ.get("NOSTRHOST_MCP_CONFIG", "/etc/nostrhost/mcp.toml")
DEFAULT_PORT = 8930

# Only present when this node's TLS comes from Caddy's own internal CA
# (`tls internal` — a lab/test domain, per the runbook's `mcp.nostrhost.test`)
# rather than a public ACME certificate, which needs no client-side trust
# change at all.
CADDY_INTERNAL_ROOT = os.environ.get(
    "NOSTRHOST_CADDY_INTERNAL_ROOT", "/var/lib/caddy/pki/authorities/local/root.crt"
)
SYSTEM_CA_BUNDLE = os.environ.get("NOSTRHOST_SYSTEM_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt")


def read_endpoint_config(path: str | None = None) -> dict[str, Any] | None:
    """The persisted {domain, port}, or None if no endpoint is configured yet."""
    path = path or CONFIG_PATH
    if not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as fh:
            config = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        return None
    domain = config.get("domain")
    if not isinstance(domain, str) or not domain:
        return None
    port = config.get("port")
    return {"domain": domain, "port": int(port) if isinstance(port, int) else DEFAULT_PORT}


def write_endpoint_config(domain: str, port: int, *, path: str | None = None) -> None:
    path = path or CONFIG_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        tomli_w.dump({"domain": domain, "port": port}, fh)
    os.chmod(path, 0o644)  # not secret: a hostname + port, readable like relay.toml


def configure_route(domain: str, *, port: int = DEFAULT_PORT, caddy_admin_url: str | None = None) -> str:
    """Ensure the domain's Caddy site exists and routes to the local MCP
    adapter, then persist the choice. Idempotent — safe to re-run after
    changing the port.

    The domain itself must already be able to resolve/issue a certificate
    the way any other NostrHost domain does; this only adds the MCP app's
    route on top of it (the same shape a native ``[web]`` resource's route
    takes), it does not run DNS/domain registration.
    """
    from .caddy_admin import CaddyAdminClient, build_web_route

    client = CaddyAdminClient(caddy_admin_url) if caddy_admin_url else CaddyAdminClient()
    client.ensure_domain_site(domain)
    route_id = client.ensure_route(build_web_route({"app": "mcp", "domain": domain, "upstream": f"127.0.0.1:{port}"}))
    write_endpoint_config(domain, port)
    return route_id


def remove_route(domain: str, *, caddy_admin_url: str | None = None) -> None:
    from .caddy_admin import CaddyAdminClient

    client = CaddyAdminClient(caddy_admin_url) if caddy_admin_url else CaddyAdminClient()
    client.delete_route("nostrhost-web:mcp")
    current = read_endpoint_config()
    if current and current["domain"] == domain and os.path.exists(CONFIG_PATH):
        os.remove(CONFIG_PATH)


def export_ca_bundle(
    *, caddy_root: str = CADDY_INTERNAL_ROOT, system_bundle: str = SYSTEM_CA_BUNDLE
) -> bytes | None:
    """The combined CA bundle (system CAs + Caddy's internal root), or None
    when this node isn't using Caddy's internal CA — a public ACME
    certificate needs no extra client trust at all, so there is nothing to
    export."""
    if not os.path.exists(caddy_root):
        return None
    with open(caddy_root, "rb") as fh:
        caddy_pem = fh.read()
    system_pem = b""
    if os.path.exists(system_bundle):
        with open(system_bundle, "rb") as fh:
            system_pem = fh.read()
    if system_pem and not system_pem.endswith(b"\n"):
        system_pem += b"\n"
    return system_pem + caddy_pem
