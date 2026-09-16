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
import os
import urllib.parse
from typing import Any

import httpx2

logger = logging.getLogger("nostr-caddy")

DEFAULT_ADMIN = "http://127.0.0.1:2019"
DEFAULT_SERVER = "srv0"
AUTHD_ADDR = "127.0.0.1:6788"
AUTHD_PATH = "/nostr/auth-request"

# App logos live outside the portal SPA build dir. The catalog daemon writes
# them here (app_catalog.APPS_CATALOG_LOGOS) and permission.py stores custom
# per-permission logos alongside; app.py/permissions.py advertise them at
# /nostrhost/sso/applogos/<hash>.png (upstream nginx aliased this path to the
# directory, and the nginx->Caddy cutover dropped that alias).
APPS_CATALOG_LOGOS = "/usr/share/yunohost/applogos"
APP_LOGOS_PREFIX = "/nostrhost/sso/applogos"

# Prefixes/paths build_portal_routes() reserves for NostrHost's own admin,
# SSO, and API surface (plus the NIP-05 well-known route). No [web] resource
# may claim these, and a root-path ("/") resource's catch-all matcher must
# exclude them explicitly — see build_web_route().
RESERVED_PATH_PREFIXES = ("/nostrhost", "/package")
RESERVED_EXACT_PATHS = ("/.well-known/nostr.json",)
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


def _is_reserved_path(path: str) -> bool:
    """Whether `path` (normalized, leading slash, no trailing slash) falls
    under a path YunoHost's own admin/SSO/API surface owns."""
    if path in RESERVED_EXACT_PATHS:
        return True
    return any(path == prefix or path.startswith(f"{prefix}/") for prefix in RESERVED_PATH_PREFIXES)


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

    host + path live in a SINGLE matcher object: separate objects would be
    OR'd, letting the root route hijack every request with path ``/`` on any
    host (the same trap ``build_web_route`` documents).
    """
    return {
        "@id": f"nostrhost-domain:{domain}",
        "match": [{"host": [domain], "path": ["/"]}],
        "handle": [{"handler": "static_response", "status_code": 200, "body": f"nostrhost domain {domain}"}],
        "terminal": True,
    }


def build_nip05_route(domain: str, upstream: str = "127.0.0.1:6788") -> dict[str, Any]:
    """Route ``domain/.well-known/nostr.json`` to the authd (portal-api),
    which resolves the queried username against the identity store (W4)."""
    return {
        "@id": f"nostrhost-nip05:{domain}",
        "match": [{"host": [domain], "path": ["/.well-known/nostr.json"]}],
        "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": upstream}]}],
        "terminal": True,
    }


def _spa_redirect_route(domain: str, tag: str, path: str) -> dict[str, Any]:
    """301 the bare prefix to the trailing-slash form, so ``/nostrhost/admin``
    reaches the SPA instead of falling through to the domain root responder.

    Mirrors upstream nginx's ``rewrite ^/yunohost/admin$ /yunohost/admin/
    permanent;`` (a bare ``location /yunohost/admin/`` would 404/fall through
    for the no-slash form, and client-side routing needs the canonical path).
    """
    return {
        "@id": f"nostrhost-{tag}-redir:{domain}",
        "match": [{"host": [domain], "path": [path]}],
        "handle": [
            {
                "handler": "static_response",
                "status_code": 301,
                "headers": {"Location": [f"{path}/"]},
            }
        ],
        "terminal": True,
    }


def _applogos_route_handle() -> dict[str, Any]:
    """Ordered inner route serving app logos from their real directory.

    Upstream nginx aliased ``/yunohost/sso/applogos/`` to
    ``/usr/share/yunohost/applogos/``; the nginx->Caddy cutover kept the
    advertised ``logo`` URLs (``/nostrhost/sso/applogos/<hash>.png``) but
    dropped the alias, so logo requests fall through to the SPA
    ``try_files`` and the browser receives index.html instead of a PNG
    (every tile image is broken). This route is prepended *inside* the SSO
    subroute (and marked terminal) so it is matched before the ``/*`` SPA
    fallback regardless of the outer route array order.
    """
    return {
        "handle": [
            {"handler": "rewrite", "strip_path_prefix": APP_LOGOS_PREFIX},
            {"handler": "vars", "root": APPS_CATALOG_LOGOS},
            {
                "handler": "headers",
                "response": {"set": {"Cache-Control": ["max-age=2629746, public"]}},
            },
            {"handler": "file_server"},
        ],
        "match": [{"path": [f"{APP_LOGOS_PREFIX}/*"]}],
        "terminal": True,
    }


def _spa_route_handle(
    root: str,
    prefix: str,
    *,
    pre_routes: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Caddy JSON for a SPA route that serves real files and falls back to
    index.html for client-side routes.

    Mirrors what the Caddyfile ``handle_path <prefix>/* { root * <root>;
    try_files {path} {path}/ /index.html; file_server }`` block adapts to:
    strip the path prefix, resolve the file (``{http.matchers.file.relative}``)
    or fall back to ``/index.html``, then serve from ``root``. An unconditional
    ``rewrite /index.html`` would return the HTML shell for asset requests too
    (the browser then fails to load the SPA's JS/CSS and renders a blank page).

    ``pre_routes`` are inner routes evaluated before the SPA fallback (e.g.
    the app-logos file server), so a nested path never hits ``index.html``.
    """
    inner_routes: list[dict[str, Any]] = list(pre_routes or [])
    inner_routes.append(
        {
            "handle": [
                {
                    "handler": "subroute",
                    "routes": [
                        {"handle": [{"handler": "rewrite", "strip_path_prefix": prefix}]},
                        {"handle": [{"handler": "vars", "root": root}]},
                        {
                            "handle": [{"handler": "rewrite", "uri": "{http.matchers.file.relative}"}],
                            "match": [
                                {
                                    "file": {
                                        "try_files": [
                                            "{http.request.uri.path}",
                                            "{http.request.uri.path}/",
                                            "/index.html",
                                        ]
                                    }
                                }
                            ],
                        },
                        {"handle": [{"handler": "file_server"}]},
                    ],
                }
            ],
            "match": [{"path": [f"{prefix}/*"]}],
        }
    )
    return [{"handler": "subroute", "routes": inner_routes}]


def build_portal_routes(domain: str, *, expose_native_api: bool = False) -> list[dict[str, Any]]:
    """The per-domain portal/SSO surface an auth-required app needs.

    The authd ``forward_auth`` 302s unauthenticated requests to
    ``/nostrhost/sso/``; without routes serving the portal (and the API /
    portal-api / admin paths a browser needs), the redirect lands on a 404
    and an auth app's health check fails even though its backend is up.
    Mirrors the per-domain Caddyfile handlers the testbed writes by hand.

    ``expose_native_api`` controls whether the native control-plane API
    (``/package/*`` → 8190) is routed on this domain. H4: it must ONLY be
    exposed on the primary admin domain — never on app subdomains — so a
    subdomain app XSS cannot reach the admin API surface at all.
    """
    routes: list[dict[str, Any]] = [
        {
            "@id": f"nostrhost-api:{domain}",
            "match": [{"host": [domain], "path": ["/nostrhost/api/*"]}],
            # handle_path-equivalent: strip the prefix so the backend sees
            # /... instead of /nostrhost/api/... (nginx trailing-slash proxy_pass).
            "handle": [
                {"handler": "rewrite", "strip_path_prefix": "/nostrhost/api"},
                {"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:6787"}]},
            ],
            "terminal": True,
        },
        {
            "@id": f"nostrhost-portalapi:{domain}",
            "match": [{"host": [domain], "path": ["/nostrhost/portalapi/*"]}],
            "handle": [
                {"handler": "rewrite", "strip_path_prefix": "/nostrhost/portalapi"},
                {"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:6788"}]},
            ],
            "terminal": True,
        },
    ]
    if expose_native_api:
        routes.append(
            {
                "@id": f"nostrhost-native-api:{domain}",
                "match": [{"host": [domain], "path": ["/package/*"]}],
                "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:8190"}]}],
                "terminal": True,
            }
        )
    for root, tag, prefix in (
        ("/usr/share/nostrhost/portal", "sso", "/nostrhost/sso"),
        ("/usr/share/nostrhost/admin", "admin", "/nostrhost/admin"),
    ):
        if os.path.isdir(root):
            routes.append(_spa_redirect_route(domain, tag, prefix))
            routes.append(
                {
                    "@id": f"nostrhost-{tag}:{domain}",
                    "match": [{"host": [domain], "path": [f"{prefix}/*"]}],
                    "handle": _spa_route_handle(
                        root,
                        prefix,
                        pre_routes=[_applogos_route_handle()] if tag == "sso" else None,
                    ),
                    "terminal": True,
                }
            )
    return routes


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

    if path and _is_reserved_path(path):
        raise CaddyError(
            f"path {path!r} is reserved for YunoHost's own admin/SSO/API routes "
            f"({', '.join(RESERVED_PATH_PREFIXES)}, {RESERVED_EXACT_PATHS[0]})"
        )

    route: dict[str, Any] = {"@id": _route_id(desired), "terminal": True}

    match: list[dict[str, Any]] = []
    # host + path are ANDed in a SINGLE matcher object (multiple objects in
    # Caddy's match array are OR'd, which would let an app route shadow the
    # whole domain). The app route must only match its own path prefix.
    matcher: dict[str, Any] = {}
    if domain:
        matcher["host"] = [domain]
    if path:
        # Match the bare path too, not just everything under it - portal
        # tiles and permission URLs link to the bare path (e.g. "/ditto",
        # no trailing slash), which otherwise falls through this route
        # entirely and hits whatever the next matching route is (typically
        # a default/placeholder handler), even though the app is installed
        # and reachable at "/ditto/...".
        matcher["path"] = [path, f"{path}/*"]
    else:
        # Root claim: no `path` matcher means this route matches EVERY path
        # on the host. Caddy's route array is order-dependent (first
        # terminal match wins) and insert_route() always inserts new routes
        # at index 0, so a root app installed after the portal/admin/API
        # routes would otherwise land ahead of them and swallow
        # /nostrhost/*, /package/*, and the NIP-05 well-known route. Excluding
        # them here makes the root app safe regardless of insertion order.
        #
        # This must also exclude every OTHER installed app's own claimed
        # path on this domain - without it, a root app installed (or
        # reconciled) after a sibling subpath app shadows that sibling
        # entirely, since the root route is terminal and has no path
        # restriction beyond the reserved prefixes.
        exclude_paths = [f"{prefix}/*" for prefix in RESERVED_PATH_PREFIXES] + list(RESERVED_EXACT_PATHS)
        this_app = desired.get("app")
        try:
            from .cli import _iter_installed_manifests

            for other_id, other_manifest in _iter_installed_manifests():
                if other_id == this_app:
                    continue
                other_web = other_manifest.get("web")
                if not isinstance(other_web, dict) or other_web.get("domain") != domain:
                    continue
                other_path = str(other_web.get("path") or "").rstrip("/")
                if other_path:
                    exclude_paths.extend([other_path, f"{other_path}/*"])
        except Exception:  # noqa: BLE001 - a broken sibling manifest must not block this app's own route
            pass
        matcher["not"] = [{"path": exclude_paths}]
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


def build_nsite_routes(domain: str, upstream: str) -> dict[str, Any]:
    """Caddy route JSON for the nsite gateway origin (D2).

    The gateway domain serves only the gateway: an apex + wildcard host
    matcher proxying to the loopback gateway. ``@id nostrhost-nsite:<domain>``
    makes enable/disable an idempotent admin-API mutation like every other
    route. The gateway origin must never match NostrHost's own admin/portal
    routes — those live on other domains; the per-domain snippet for this
    domain is ``caddy_nsite.conf`` (not the standard one).
    """
    host, _, port = upstream.rpartition(":")
    if not host or not port.isdigit():
        raise CaddyError(f"invalid nsite upstream {upstream!r} (expected host:port)")
    return {
        "@id": f"nostrhost-nsite:{domain}",
        "match": [{"host": [domain, f"*.{domain}"]}],
        "handle": [
            {
                "handler": "headers",
                "response": {
                    "set": {
                        "X-Content-Type-Options": ["nosniff"],
                        "Referrer-Policy": ["strict-origin-when-cross-origin"],
                        "Cross-Origin-Opener-Policy": ["same-origin"],
                    },
                    "delete": ["Server"],
                },
            },
            {"handler": "reverse_proxy", "upstreams": [{"dial": upstream}]},
        ],
        "terminal": True,
    }


def build_custom_domain_route(fqdn: str, upstream: str) -> dict[str, Any]:
    """Caddy route JSON for one attached custom FQDN (Phase 4).

    Unlike the gateway origin (which serves every ``*.domain`` label), an
    attached FQDN is served as exactly that one host — the operator's CNAME
    only reaches this host for that name, so a wildcard matcher would claim
    subdomains that resolve elsewhere. On-demand TLS for the FQDN is allowed
    by the gateway's ``tls-ask`` once the mapping is in ``nsite.toml``.
    """
    host, _, port = upstream.rpartition(":")
    if not host or not port.isdigit():
        raise CaddyError(f"invalid nsite upstream {upstream!r} (expected host:port)")
    return {
        "@id": f"nostrhost-nsite:{fqdn}",
        "match": [{"host": [fqdn]}],
        "handle": [
            {
                "handler": "headers",
                "response": {
                    "set": {
                        "X-Content-Type-Options": ["nosniff"],
                        "Referrer-Policy": ["strict-origin-when-cross-origin"],
                        "Cross-Origin-Opener-Policy": ["same-origin"],
                    },
                    "delete": ["Server"],
                },
            },
            {"handler": "reverse_proxy", "upstreams": [{"dial": upstream}]},
        ],
        "terminal": True,
    }


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

    def _request(self, method: str, path: str, body: Any = None) -> httpx2.Response:
        try:
            response = httpx2.request(
                method,
                self.base_url + path,
                json=body if body is not None else None,
                timeout=self.timeout,
                follow_redirects=True,
            )
        except httpx2.RequestError as exc:
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

    def ensure_nsite_routes(self, domain: str, upstream: str) -> str:
        """Idempotently ensure the gateway origin route for ``domain``."""
        return self.ensure_route(build_nsite_routes(domain, upstream))

    def remove_nsite_routes(self, domain: str) -> None:
        """Remove the gateway origin route for ``domain`` (idempotent)."""
        self.delete_route(f"nostrhost-nsite:{domain}")

    def ensure_custom_domain_route(self, fqdn: str, upstream: str) -> str:
        """Idempotently ensure the route proxying attached ``fqdn`` (Phase 4)."""
        return self.ensure_route(build_custom_domain_route(fqdn, upstream))

    def remove_custom_domain_route(self, fqdn: str) -> None:
        """Remove the route for attached ``fqdn`` (Phase 4, idempotent)."""
        self.delete_route(f"nostrhost-nsite:{fqdn}")

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

    def ensure_portal_routes(self, domain: str, *, expose_native_api: bool = False) -> list[str]:
        """Create (or reconcile) the per-domain portal/SSO routes (W4)."""
        desired = build_portal_routes(domain, expose_native_api=expose_native_api)
        results = [self.ensure_route(route) for route in desired]
        if not expose_native_api:
            self.delete_route(f"nostrhost-native-api:{domain}")
        return results

    def remove_portal_routes(self, domain: str) -> None:
        """Remove the per-domain portal/SSO routes (W4)."""
        for tag in ("api", "portalapi", "native-api", "sso", "admin"):
            self.delete_route(f"nostrhost-{tag}:{domain}")
