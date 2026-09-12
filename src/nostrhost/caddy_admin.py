"""Caddy admin-API client and native web-route builder (roadmap §7.2 / P4).

The CaddyProvider must reconcile routes without clobbering Caddy's ACME or
runtime state, so this client talks to Caddy's admin API (default
``127.0.0.1:2019``) with granular, ``@id``-tagged mutations instead of a
whole-config ``POST /load``:

- a route carries a stable ``@id`` (``nostrhost-web:<app>``);
- ``ensure_route`` inserts it at the front of the HTTP server's route array
  with ``PUT .../routes/0`` (precise host+path matchers make that safe even in
  front of the Caddyfile-generated routes) and is a no-op when an identical
  route already exists, so reconciliation is idempotent;
- ``delete_route`` removes it via ``DELETE /id/<id>`` (404 is a no-op), so the
  operation is reversible.

Caddy's admin API semantics (see docs/api): POST to an array appends, PUT to
an array *index* inserts, PATCH replaces, and ``@id`` objects are addressable
through ``/id/<id>``.
"""

from __future__ import annotations

import logging
import urllib.parse
from typing import Any

import requests

logger = logging.getLogger("nostr-caddy")

DEFAULT_ADMIN = "http://127.0.0.1:2019"
DEFAULT_SERVER = "srv0"
AUTHD_ADDR = "127.0.0.1:6788"
AUTHD_PATH = "/nostr/auth-request"
IDENTITY_HEADERS = (
    "X-Remote-User",
    "X-Remote-Email",
    "X-Remote-Fullname",
    "X-Nostr-Pubkey",
    "X-Nostr-Npub",
)


class CaddyError(RuntimeError):
    """The Caddy admin API call failed (unreachable, rejected, …)."""


def _forward_auth_handler() -> dict[str, Any]:
    """Replicate the Caddyfile ``forward_auth`` adapter output.

    ``forward_auth`` is not a handler module: the adapter expands it to a
    ``reverse_proxy`` whose 2xx ``handle_response`` deletes any client-supplied
    identity header, then re-sets it from the authd's response only when
    non-empty. The ``vars`` handler is the adapter's empty placeholder.
    """
    header_routes: list[dict[str, Any]] = [{"handle": [{"handler": "vars"}]}]
    for header in IDENTITY_HEADERS:
        placeholder = f"{{http.reverse_proxy.header.{header}}}"
        header_routes.append({"handle": [{"handler": "headers", "request": {"delete": [header]}}]})
        header_routes.append(
            {
                "handle": [{"handler": "headers", "request": {"set": {header: [placeholder]}}}],
                "match": [{"not": [{"vars": {placeholder: [""]}}]}],
            }
        )
    return {
        "handler": "reverse_proxy",
        "headers": {
            "request": {
                "set": {
                    "X-Forwarded-Method": ["{http.request.method}"],
                    "X-Forwarded-Uri": ["{http.request.uri}"],
                }
            }
        },
        "rewrite": {"method": "GET", "uri": AUTHD_PATH},
        "upstreams": [{"dial": AUTHD_ADDR}],
        "handle_response": [{"match": {"status_code": [2]}, "routes": header_routes}],
    }


def _route_id(desired: dict[str, Any]) -> str:
    app = desired.get("app")
    if app:
        return f"nostrhost-web:{app}"
    return f"nostrhost-web:{desired.get('domain') or 'app'}"


def build_domain_site(domain: str) -> dict[str, Any]:
    """A minimal, precise Caddy site for a domain (domain_add/create).

    Matches only the domain's root path, so it never shadows app routes on the
    same host. ACME for the domain is handled by Caddy's global ``acme_ca`` /
    automatic HTTPS (the "ACME policy"); ``certd`` exports the resulting cert.
    """
    return {
        "@id": f"nostrhost-domain:{domain}",
        "match": [{"host": [domain]}, {"path": ["/"]}],
        "handle": [{"handler": "static_response", "status_code": 200, "body": f"nostrhost domain {domain}"}],
        "terminal": True,
    }


def build_nip05_route(domain: str, upstream: str = "127.0.0.1:6788") -> dict[str, Any]:
    """Route ``domain/.well-known/nostr.json`` to the authd (portal-api),
    which resolves the queried username against the identity store (W4)."""
    return {
        "@id": f"nostrhost-nip05:{domain}",
        "match": [{"host": [domain]}, {"path": ["/.well-known/nostr.json"]}],
        "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": upstream}]}],
        "terminal": True,
    }


def build_web_route(desired: dict[str, Any]) -> dict[str, Any]:
    """Build a Caddy route JSON object for a native ``[web]`` resource.

    ``desired`` is the operation args for ``web.route.ensure``: the
    ``package_engine.WebResource`` fields (``domain``, ``upstream``, ``auth``,
    ``https``, ``path``, ``file_root``) plus ``app``.

    - ``file_root`` set  -> ``file_server`` (static app)
    - otherwise          -> ``reverse_proxy`` to ``upstream``
    - ``auth = "nostrhost"`` -> a ``forward_auth`` handler is prepended so the
      authd decision gates the route and identity headers reach the app.
    """
    domain = desired.get("domain")
    path = (desired.get("path") or "/").rstrip("/")

    route: dict[str, Any] = {"@id": _route_id(desired), "terminal": True}

    match: list[dict[str, Any]] = []
    # host + path are ANDed in a SINGLE matcher object (multiple objects in
    # Caddy's match array are OR'd, which would let an app route shadow the
    # whole domain). The app route must only match its own path prefix.
    matcher: dict[str, Any] = {}
    if domain:
        matcher["host"] = [domain]
    if path:
        matcher["path"] = [f"{path}/*"]
    if matcher:
        match.append(matcher)
    if match:
        route["match"] = match

    handle: list[dict[str, Any]] = []
    if desired.get("auth") == "nostrhost":
        # forward_auth first: its X-Forwarded-Uri reflects the original path
        # (with the app prefix) so the authd can match the app's permission.
        handle.append(_forward_auth_handler())
    if path:
        # Then strip the app prefix for the backend, like Caddyfile handle_path.
        handle.append({"handler": "rewrite", "strip_path_prefix": path})

    file_root = desired.get("file_root")
    if file_root:
        handle.append({"handler": "file_server", "root": file_root})
    else:
        upstream = desired.get("upstream")
        if not isinstance(upstream, str) or not upstream:
            raise CaddyError("web resource needs upstream host:port or file_root")
        host, _, port = upstream.rpartition(":")
        if not host or not port.isdigit():
            raise CaddyError(f"invalid web upstream {upstream!r} (expected host:port)")
        handle.append({"handler": "reverse_proxy", "upstreams": [{"dial": upstream}]})

    route["handle"] = handle
    return route


def _route_signature(route: dict[str, Any]) -> tuple[Any, ...]:
    """Canonical identity for idempotent comparison (ignore ``@id``)."""
    return (route.get("match"), route.get("handle"))


class CaddyAdminClient:
    """Granular, ``@id``-tagged mutations against Caddy's admin API."""

    def __init__(
        self,
        base_url: str = DEFAULT_ADMIN,
        server: str = DEFAULT_SERVER,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.server = server
        self.timeout = timeout
        self.routes_path = f"/config/apps/http/servers/{server}/routes"

    def _request(self, method: str, path: str, body: Any = None) -> requests.Response:
        try:
            response = requests.request(
                method,
                self.base_url + path,
                json=body if body is not None else None,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise CaddyError(f"caddy admin {method} {path} failed: {exc}") from exc
        if response.status_code >= 500:
            raise CaddyError(
                f"caddy admin {method} {path} -> {response.status_code}: {response.text[:200]}"
            )
        return response

    def get_config(self) -> dict[str, Any]:
        response = self._request("GET", "/config/")
        response.raise_for_status()
        return response.json()

    def get_route(self, route_id: str) -> dict[str, Any] | None:
        response = self._request("GET", f"/id/{urllib.parse.quote(route_id, safe='')}")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()

    def insert_route(self, route: dict[str, Any]) -> None:
        # PUT to an array index inserts; index 0 puts the app route in front of
        # the Caddyfile-generated routes (its precise matchers make that safe).
        response = self._request("PUT", f"{self.routes_path}/0", route)
        response.raise_for_status()

    def ensure_route(self, route: dict[str, Any]) -> str:
        route_id = route["@id"]
        existing = self.get_route(route_id)
        if existing is not None and _route_signature(existing) == _route_signature(route):
            logger.debug("route %s already in sync", route_id)
            return route_id
        if existing is not None:
            self.delete_route(route_id)
        self.insert_route(route)
        logger.info("ensured caddy route %s", route_id)
        return route_id

    def delete_route(self, route_id: str) -> None:
        response = self._request("DELETE", f"/id/{urllib.parse.quote(route_id, safe='')}")
        if response.status_code == 404:
            logger.debug("route %s already absent", route_id)
            return
        response.raise_for_status()
        logger.info("removed caddy route %s", route_id)

    def ensure_domain_site(self, domain: str) -> str:
        """Create (or reconcile) Caddy's site for ``domain`` (domain_add)."""
        return self.ensure_route(build_domain_site(domain))

    def remove_domain_site(self, domain: str) -> None:
        """Remove Caddy's site for ``domain`` (domain_remove)."""
        self.delete_route(f"nostrhost-domain:{domain}")

    def ensure_nip05_route(self, domain: str) -> str:
        """Create (or reconcile) the NIP-05 route for ``domain`` (W4)."""
        return self.ensure_route(build_nip05_route(domain))

    def remove_nip05_route(self, domain: str) -> None:
        """Remove the NIP-05 route for ``domain`` (W4)."""
        self.delete_route(f"nostrhost-nip05:{domain}")