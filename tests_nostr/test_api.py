"""Stage 5: native HTTP API tests (FastAPI + NIP-98).

Endpoints are exercised over the ASGI interface with monkeypatched handlers
(no real services/relay/keys).  The NIP-98 authorizer is tested both with a
real SDK-signed event (via the fork's ``_sign_event``) and with an
injected fake for the operation routes.
"""

from __future__ import annotations

import asyncio
import base64
import json
import secrets
import types

import httpx2
import pytest

from nostrhost import api as api_module
from nostrhost.api import ApiError, build_app
from nostrhost.core import NostrHostError


# --------------------------------------------------------------------------- #
# ASGI test harness (keeps the historical (status, headers, body) tuple so the
# assertions below stay unchanged)

def wsgi_request(app, method, path, body=None, headers=None, raw_body=None):
    if raw_body is not None:
        content = raw_body
    else:
        content = json.dumps(body).encode() if body is not None else b""
    request_headers = dict(headers or {})
    if body is not None or raw_body is not None:
        request_headers.setdefault("Content-Type", "application/json")

    async def call():
        transport = httpx2.ASGITransport(app=app)
        async with httpx2.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.request(method, path, content=content, headers=request_headers)

    response = asyncio.run(call())
    # Title-case header names so existing assertions like headers["Content-Type"] hold.
    response_headers = {key.title(): value for key, value in response.headers.items()}
    return str(response.status_code), response_headers, response.content


# --------------------------------------------------------------------------- #
# portal-session test helpers (H4)

def _fake_session_infos(username, session_id="test-session-id"):
    """A fabricated admin-cookie payload (id/host/user/pwd), matching what
    Authenticator().get_admin_cookie() returns in production."""
    return {"id": session_id, "host": "test", "user": username, "pwd": "x", "email": "", "fullname": ""}


def _session_headers(monkeypatch, infos, secret="test-secret"):
    """Pin the session secret and return the matching CSRF request header."""
    from yunohost.authenticators import ldap_ynhuser

    monkeypatch.setattr(ldap_ynhuser, "SESSION_SECRET", lambda: secret)
    return {"X-Nostrhost-CSRF": ldap_ynhuser.session_csrf_token(infos, secret=secret)}


# --------------------------------------------------------------------------- #
# healthz + public

def test_simple_get_forwards_all_have_dispatch_handlers():
    """Every simple GET forward must resolve in the dispatch map.

    ``_run_tool`` indexes ``_TOOL_HANDLERS`` directly, so a forward whose tool
    was added to the catalogue/registry but never wired into ``_TOOL_HANDLERS``
    raised KeyError -> a generic 500 (e.g. /package/nsite/domain/list).
    """
    forwards = {tool for _path, tool, _map in api_module._SIMPLE_GET_FORWARDS}
    missing = sorted(forwards - set(api_module._TOOL_HANDLERS))
    assert missing == []


def test_api_records_problems_for_unhandled_errors(tmp_path, monkeypatch):
    """A server-side exception becomes a 500 to the client and a structured
    problem record (with traceback) the introspection tools can read."""
    from nostrhost import problems

    problems.configure(str(tmp_path / "problems.log"))

    def boom(**_kwargs):
        raise RuntimeError("kaboom")

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "system.version", boom)
    app = build_app(authorizer=lambda _rule: "admin")
    status, headers, body = wsgi_request(app, "GET", "/package/system/version")
    assert status == "500"
    assert headers["X-Nostrhost-Request-Id"]
    assert json.loads(body)["code"] == "internal_error"
    entry = json.loads((tmp_path / "problems.log").read_text().splitlines()[-1])
    assert entry["status"] == 500
    assert entry["code"] == "internal_error"
    assert entry["kind"] == "unhandled"
    assert entry["source"] == "api"
    assert entry["path"] == "/package/system/version"
    assert "kaboom" in entry["traceback"]


def test_api_records_problems_for_auth_denials(tmp_path, monkeypatch):
    from nostrhost import problems

    problems.configure(str(tmp_path / "problems.log"))

    def deny(_rule: str = "") -> str:
        raise ApiError(403, "forbidden", "nope")

    app = build_app(authorizer=deny)
    status, headers, _ = wsgi_request(app, "GET", "/package/system/version")
    assert status == "403"
    assert headers["X-Nostrhost-Request-Id"]
    entry = json.loads((tmp_path / "problems.log").read_text().splitlines()[-1])
    assert entry["status"] == 403
    assert entry["code"] == "forbidden"
    assert entry["kind"] == "auth"
    assert entry["source"] == "api"


def test_healthz_is_public():
    app = build_app()
    status, _, body = wsgi_request(app, "GET", "/package/healthz")
    assert status == "200"
    assert json.loads(body)["ok"] is True


def test_healthz_is_public_but_other_routes_authorize():
    """_ApiRoute skips the authorizer for the public routes and maps a denial
    on any other route to the JSON error envelope."""

    def deny_authorizer(_rule: str = "") -> str:
        raise ApiError(401, "authentication_required", "nope")

    app = build_app(authorizer=deny_authorizer)
    status, _, body = wsgi_request(app, "GET", "/package/healthz")
    assert status == "200"
    assert json.loads(body)["ok"] is True

    status, _, body = wsgi_request(app, "GET", "/package/system/version")
    assert status == "401"
    assert json.loads(body)["code"] == "authentication_required"


# --------------------------------------------------------------------------- #
# auth

def _signed_header(
    sk_hex: str,
    pubkey_hex: str,
    method: str = "GET",
    path: str = "/",
    body_bytes: bytes = b"",
) -> str:
    """A correct NIP-98 (kind-27235) Authorization header bound to exactly
    one request: u=method=payload tags matching the request URL/method/body
    as the API reconstructs it (the ASGI harness below serves as
    http://test)."""
    import hashlib

    from yunohost.nostr_identity import _sign_event

    url = f"http://test{path}"
    tags = [["u", url], ["method", method]]
    if body_bytes:
        tags.append(["payload", hashlib.sha256(body_bytes).hexdigest()])
    event = _sign_event(sk_hex, pubkey_hex, 27235, "", tags)
    return "Nostr " + base64.b64encode(json.dumps(event).encode()).decode()


def test_missing_auth_header_401():
    app = build_app()
    status, _, body = wsgi_request(app, "GET", "/package/system/version")
    assert status == "401"
    assert json.loads(body)["code"] == "authentication_required"


def test_app_management_combines_catalogue_and_installations(monkeypatch):
    def fake_run_tool(name, args):
        if name == "catalog.list":
            return {"entries": [{"declaration": {"AppID": "available", "Version": "2", "Name": "Available"}}]}
        if name == "app.list":
            return {"apps": {"orphan": {"version": "1", "name": {"en": "Orphan"}}}}
        raise AssertionError(name)

    monkeypatch.setattr(api_module, "_run_tool", fake_run_tool)
    app = build_app(authorizer=lambda _rule: "admin")
    status, _, body = wsgi_request(app, "GET", "/package/app/management")
    assert status == "200"
    rows = {row["id"]: row for row in json.loads(body)["apps"]}
    assert rows["available"]["status"] == "available"
    assert rows["orphan"]["status"] == "installed-unlisted"


def test_app_management_attaches_catalogue_logos(monkeypatch):
    def fake_run_tool(name, args):
        if name == "catalog.list":
            return {"entries": [{"declaration": {"AppID": "wordpress", "Version": "2", "Name": "WordPress"}}]}
        if name == "app.list":
            return {"apps": {"wordpress__2": {"version": "2", "name": {"en": "WordPress"}}}}
        raise AssertionError(name)

    monkeypatch.setattr(api_module, "app_catalog_logo_urls", lambda: {"wordpress": "/nostrhost/sso/applogos/abc.png"})
    monkeypatch.setattr(api_module, "_run_tool", fake_run_tool)
    app = build_app(authorizer=lambda _rule: "admin")
    status, _, body = wsgi_request(app, "GET", "/package/app/management")
    assert status == "200"
    rows = {row["id"]: row for row in json.loads(body)["apps"]}
    # both the catalogue entry and the multi-instance install share the logo
    assert rows["wordpress"]["logo"] == "/nostrhost/sso/applogos/abc.png"
    assert rows["wordpress__2"]["logo"] == "/nostrhost/sso/applogos/abc.png"


def test_catalog_list_attaches_catalogue_logos(monkeypatch):
    monkeypatch.setattr(api_module, "app_catalog_logo_urls", lambda: {"wordpress": "/nostrhost/sso/applogos/abc.png"})
    monkeypatch.setattr(api_module, "_run_tool", lambda name, args: [
        {"declaration": {"AppID": "wordpress"}, "event_id": "e1"},
        {"declaration": {"AppID": "nativeonly"}, "event_id": "e2"},
    ])
    app = build_app(authorizer=lambda _rule: "admin")
    status, _, body = wsgi_request(app, "GET", "/package/catalog/list")
    assert status == "200"
    entries = {entry["declaration"]["AppID"]: entry for entry in json.loads(body)["entries"]}
    assert entries["wordpress"]["logo"] == "/nostrhost/sso/applogos/abc.png"
    assert "logo" not in entries["nativeonly"]


def test_native_settings_plan_and_apply_are_bound_to_reviewed_digest(monkeypatch, tmp_path):
    manifest = {
        "app": {"id": "example", "version": "1.0.0"},
        "settings": {"fields": {"mode": {"type": "enum", "choices": ["safe", "fast"], "default": "safe"}}, "values": {"mode": "safe"}},
        "config": {"main": {"destination": "/etc/example.conf", "template_content": "mode={{ settings.mode }}\n"}},
        "service": {"name": "example", "exec": "/usr/bin/example"},
    }
    from nostrhost import native_providers

    monkeypatch.setattr(native_providers, "installed_package_manifest", lambda app_id, state_dir=None: manifest if app_id == "example" else None)
    app = build_app(authorizer=lambda _rule: "admin")
    values = {"mode": "fast"}
    status, _, body = wsgi_request(app, "POST", "/package/app/example/settings/plan", {"values": values})
    assert status == "200"
    plan = json.loads(body)
    lifecycle_calls = []
    monkeypatch.setattr(api_module, "_run_lifecycle", lambda tool, args, state: lifecycle_calls.append((tool, args, state)) or {"ok": True, "request_id": "r" * 64})

    status, _, stale = wsgi_request(app, "POST", "/package/app/example/settings/apply", {"values": values, "plan_sha256": "0" * 64})
    assert status == "409"
    assert json.loads(stale)["code"] == "plan_changed"
    assert lifecycle_calls == []

    status, _, result = wsgi_request(app, "POST", "/package/app/example/settings/apply", {"values": values, "plan_sha256": plan["plan_sha256"]})
    assert status == "200"
    assert json.loads(result)["operation"]["request_id"] == "r" * 64
    assert lifecycle_calls[0][0] == "package.reconcile"
    assert "settings_diff" not in lifecycle_calls[0][1]["plan"]


def test_catalogue_lifecycle_apply_revalidates_plan_and_uses_signed_chain(monkeypatch):
    plan = {
        "schema": 1,
        "package": {"id": "example", "version": "1.2.0"},
        "manifest_sha256": "m" * 64,
        "plan_sha256": "p" * 64,
        "operations": [],
    }
    monkeypatch.setattr(api_module, "catalogue_lifecycle_plan", lambda app_id, action: plan)
    calls = []
    monkeypatch.setattr(api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64})
    app = build_app(authorizer=lambda _rule: "admin")

    status, _, stale = wsgi_request(app, "POST", "/package/app/example/install/apply", {"plan_sha256": "x" * 64})
    assert status == "409"
    assert json.loads(stale)["code"] == "plan_changed"
    assert calls == []

    status, _, result = wsgi_request(app, "POST", "/package/app/example/install/apply", {"plan_sha256": plan["plan_sha256"]})
    assert status == "200"
    assert json.loads(result)["action"] == "install"
    assert calls[0][0] == "package.reconcile"


def test_malformed_auth_header_401():
    app = build_app()
    status, _, body = wsgi_request(app, "GET", "/package/system/version", headers={"Authorization": "Nostr !!!not-base64!!!"})
    assert status == "401"


def test_invalid_signature_401():
    app = build_app()
    bad = "Nostr " + base64.b64encode(b'{"kind":1,"content":"x"}').decode()
    status, _, body = wsgi_request(app, "GET", "/package/system/version", headers={"Authorization": bad})
    assert status == "401"
    assert json.loads(body)["code"] == "invalid_nip98"


def test_nip98_rejects_non_27235_event(monkeypatch):
    """Regression for the critical admin-auth bypass: a validly signed event
    that is NOT a kind-27235 NIP-98 request (e.g. a public kind-1 note, a
    relay-auth challenge) must never authenticate an API request."""
    from yunohost.nostr_identity import _sign_event
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    # Correct signature, wrong kind — signed for the exact request otherwise.
    event = _sign_event(sk, pubkey, 1, "hello world", [["u", "http://test/package/system/version"], ["method", "GET"]])
    header = "Nostr " + base64.b64encode(json.dumps(event).encode()).decode()
    monkeypatch.setattr(api_module, "resolve_pubkey", lambda p: _fake_identity(p))
    app = build_app(admin_pubkeys=(pubkey,))
    status, _, body = wsgi_request(app, "GET", "/package/system/version", headers={"Authorization": header})
    assert status == "401"
    assert json.loads(body)["code"] == "invalid_nip98"


def test_nip98_rejects_stale_event(monkeypatch):
    """A correctly-kind, correctly-signed but old NIP-98 event must be refused
    (no indefinite replay of a captured credential)."""
    import time

    from nostr_sdk import EventBuilder, Keys, Kind, Tag, Timestamp
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    stale = int(time.time()) - 3600
    event = (
        EventBuilder(Kind(27235), "")
        .tags([Tag.parse(t) for t in [["u", "http://test/package/system/version"], ["method", "GET"]]])
        .custom_created_at(Timestamp.from_secs(stale))
        .finalize(Keys.parse(sk))
    )
    raw = {
        "id": event.id().to_hex(),
        "pubkey": pubkey,
        "created_at": stale,
        "kind": 27235,
        "tags": [["u", "http://test/package/system/version"], ["method", "GET"]],
        "content": "",
        "sig": event.signature(),
    }
    header = "Nostr " + base64.b64encode(json.dumps(raw).encode()).decode()
    monkeypatch.setattr(api_module, "resolve_pubkey", lambda p: _fake_identity(p))
    app = build_app(admin_pubkeys=(pubkey,))
    status, _, body = wsgi_request(app, "GET", "/package/system/version", headers={"Authorization": header})
    assert status == "401"


def test_nip98_rejects_wrong_url_and_method(monkeypatch):
    from yunohost.nostr_identity import _sign_event
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    monkeypatch.setattr(api_module, "resolve_pubkey", lambda p: _fake_identity(p))
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "system.version", lambda **k: {"version": "1"})
    app = build_app(admin_pubkeys=(pubkey,))

    # Signed for a different URL than the one requested.
    wrong_url = _sign_event(sk, pubkey, 27235, "", [["u", "http://test:80/package/other"], ["method", "GET"]])
    status, _, _ = wsgi_request(
        app, "GET", "/package/system/version",
        headers={"Authorization": "Nostr " + base64.b64encode(json.dumps(wrong_url).encode()).decode()},
    )
    assert status == "401"

    # Signed with the wrong method.
    wrong_method = _sign_event(sk, pubkey, 27235, "", [["u", "http://test:80/package/system/version"], ["method", "POST"]])
    status, _, _ = wsgi_request(
        app, "GET", "/package/system/version",
        headers={"Authorization": "Nostr " + base64.b64encode(json.dumps(wrong_method).encode()).decode()},
    )
    assert status == "401"


def test_nip98_replay_rejected(monkeypatch):
    """The same valid NIP-98 event must be accepted once and rejected on replay."""
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    monkeypatch.setattr(api_module, "resolve_pubkey", lambda p: _fake_identity(p))
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "system.version", lambda **k: {"version": "1"})
    app = build_app(admin_pubkeys=(pubkey,))
    header = _signed_header(sk, pubkey, "GET", "/package/system/version")

    status, _, body = wsgi_request(app, "GET", "/package/system/version", headers={"Authorization": header})
    assert status == "200"

    status, _, body = wsgi_request(app, "GET", "/package/system/version", headers={"Authorization": header})
    assert status == "401"
    assert json.loads(body)["code"] == "invalid_nip98"


def test_nip98_post_payload_bound(monkeypatch):
    """A POST NIP-98 event must carry a payload tag matching the body, and the
    body must be readable by the route after the authorizer consumed it."""
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    calls = []
    monkeypatch.setattr(api_module, "resolve_pubkey", lambda p: _fake_identity(p))
    monkeypatch.setattr(api_module, "_run_lifecycle", lambda tool, args, state: calls.append(args) or {"ok": True, "request_id": "r" * 64})
    app = build_app(admin_pubkeys=(pubkey,))
    body = {"plan_sha256": "0" * 64}
    status, _, resp = wsgi_request(
        app, "POST", "/package/nsite/publish", body,
        headers={"Authorization": _signed_header(sk, pubkey, "POST", "/package/nsite/publish", json.dumps(body).encode())},
    )
    assert status == "200"
    # The body reached the handler intact (the route normalises missing keys
    # to None; the real check is that the sha256 payload bound to `body` was
    # accepted and the parsed body made it through after the authorizer read it).
    assert calls and calls[0]["plan_sha256"] == body["plan_sha256"]


def test_valid_signed_event_but_not_linked_403():
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    app = build_app(admin_pubkeys=(pubkey,))
    status, _, body = wsgi_request(
        app, "GET", "/package/system/version", headers={"Authorization": _signed_header(sk, pubkey, "GET", "/package/system/version")}
    )
    # resolve_pubkey (real) returns None for an unlinked key -> 403
    assert status == "403"
    assert json.loads(body)["code"] == "identity_not_linked"


def _fake_identity(pubkey_hex: str, username: str = "admin"):
    return types.SimpleNamespace(
        pubkey=pubkey_hex,
        username=username,
        ynh_username=username,
        signer_type="nip07",
        label=username,
        enabled=True,
        created_at=0,
        last_used=0,
    )


def test_authorized_nip98_admin_ok(monkeypatch):
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    monkeypatch.setattr(api_module, "resolve_pubkey", lambda p: _fake_identity(p))
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "system.version", lambda **k: {"version": "1"})

    app = build_app(admin_pubkeys=(pubkey,))
    status, _, body = wsgi_request(
        app, "GET", "/package/system/version", headers={"Authorization": _signed_header(sk, pubkey, "GET", "/package/system/version")}
    )
    assert status == "200"
    assert json.loads(body)["version"] == "1"


def test_non_admin_pubkey_403(monkeypatch):
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    monkeypatch.setattr(api_module, "resolve_pubkey", lambda p: object())
    app = build_app(admin_pubkeys=())  # operator/admin set empty
    status, _, body = wsgi_request(
        app, "GET", "/package/system/version", headers={"Authorization": _signed_header(sk, pubkey, "GET", "/package/system/version")}
    )
    assert status == "403"


def test_session_endpoint_public_and_unauthenticated(monkeypatch):
    """/session is public (no NIP-98 header needed) and reports the session
    state so the admin SPA can decide to show the console or redirect."""
    monkeypatch.setattr(api_module, "_session_username", lambda: None)
    app = build_app()
    status, _, body = wsgi_request(app, "GET", "/package/session")
    assert status == "200"
    out = json.loads(body)
    assert out["authenticated"] is False
    assert out["admin"] is False


def test_session_endpoint_admin(monkeypatch):
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    infos = _fake_session_infos("admin")
    _session_headers(monkeypatch, infos)
    monkeypatch.setattr(api_module, "_session_infos", lambda: infos)
    monkeypatch.setattr(api_module, "resolve_username", lambda username: [_fake_identity(pubkey)])
    app = build_app(admin_pubkeys=(pubkey,))
    status, _, body = wsgi_request(app, "GET", "/package/session")
    assert status == "200"
    out = json.loads(body)
    assert out["authenticated"] is True
    assert out["username"] == "admin"
    assert out["pubkey"] == pubkey
    assert out["admin"] is True
    # H4: the probe hands the console the per-session CSRF token.
    assert out["csrf_token"]


def test_session_endpoint_non_admin(monkeypatch):
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    infos = _fake_session_infos("alice")
    _session_headers(monkeypatch, infos)
    monkeypatch.setattr(api_module, "_session_infos", lambda: infos)
    monkeypatch.setattr(api_module, "resolve_username", lambda username: [_fake_identity(pubkey)])
    app = build_app(admin_pubkeys=())  # not an admin
    status, _, body = wsgi_request(app, "GET", "/package/session")
    assert status == "200"
    out = json.loads(body)
    assert out["authenticated"] is True
    assert out["admin"] is False


def test_session_auth_admin_ok(monkeypatch):
    """A valid admin session (host-only admin cookie + CSRF token) authorizes
    the API without any NIP-98 header — the unified single sign-in path."""
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    infos = _fake_session_infos("admin")
    headers = _session_headers(monkeypatch, infos)
    monkeypatch.setattr(api_module, "_session_infos", lambda: infos)
    monkeypatch.setattr(api_module, "resolve_username", lambda username: [_fake_identity(pubkey)])
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "system.version", lambda **k: {"version": "1"})
    app = build_app(admin_pubkeys=(pubkey,))
    status, _, body = wsgi_request(app, "GET", "/package/system/version", headers=headers)
    assert status == "200"
    assert json.loads(body)["version"] == "1"


def test_session_auth_requires_csrf_token(monkeypatch):
    """H4: a cookie-session request WITHOUT the per-request CSRF token is
    rejected even when the session is a valid admin — the whole point is that
    a subdomain XSS riding the SSO cookie cannot drive the admin API."""
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    infos = _fake_session_infos("admin")
    monkeypatch.setattr(api_module, "_session_infos", lambda: infos)
    monkeypatch.setattr(api_module, "resolve_username", lambda username: [_fake_identity(pubkey)])
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "system.version", lambda **k: {"version": "1"})
    app = build_app(admin_pubkeys=(pubkey,))
    status, _, body = wsgi_request(app, "GET", "/package/system/version")
    assert status == "403"
    assert json.loads(body)["code"] == "csrf_required"


def test_session_auth_rejects_wrong_csrf_token(monkeypatch):
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    infos = _fake_session_infos("admin")
    _session_headers(monkeypatch, infos)
    monkeypatch.setattr(api_module, "_session_infos", lambda: infos)
    monkeypatch.setattr(api_module, "resolve_username", lambda username: [_fake_identity(pubkey)])
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "system.version", lambda **k: {"version": "1"})
    app = build_app(admin_pubkeys=(pubkey,))
    status, _, body = wsgi_request(app, "GET", "/package/system/version", headers={"X-Nostrhost-CSRF": "forged"})
    assert status == "403"
    assert json.loads(body)["code"] == "csrf_required"


def test_session_auth_non_admin_403(monkeypatch):
    """A valid portal session that is not an admin is refused by the API."""
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    infos = _fake_session_infos("alice")
    headers = _session_headers(monkeypatch, infos)
    monkeypatch.setattr(api_module, "_session_infos", lambda: infos)
    monkeypatch.setattr(api_module, "resolve_username", lambda username: [_fake_identity(pubkey)])
    app = build_app(admin_pubkeys=())
    status, _, body = wsgi_request(app, "GET", "/package/system/version", headers=headers)
    assert status == "403"
    assert json.loads(body)["code"] == "not_authorized"


def test_session_endpoint_admin_via_account_flag(monkeypatch):
    """Option A: a linked identity of an account whose admin flag / admins-
    group membership marks it admin is reported as an admin even when the
    pubkey is absent from the static operator set (the 'added to the admins
    group but no privileges' regression)."""
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    infos = _fake_session_infos("lostcause")
    _session_headers(monkeypatch, infos)
    monkeypatch.setattr(api_module, "_session_infos", lambda: infos)
    monkeypatch.setattr(
        api_module,
        "resolve_username",
        lambda username: [_fake_identity(pubkey, username="lostcause")],
    )
    monkeypatch.setattr(
        api_module,
        "resolve_pubkey",
        lambda p: _fake_identity(p, username="lostcause"),
    )
    monkeypatch.setattr(
        api_module, "_native_user_is_admin", lambda username: username == "lostcause"
    )
    app = build_app(admin_pubkeys=())  # not in the static set
    status, _, body = wsgi_request(app, "GET", "/package/session")
    assert status == "200"
    out = json.loads(body)
    assert out["authenticated"] is True
    assert out["admin"] is True
    assert out["pubkey"] == pubkey


def test_session_auth_admin_via_account_flag_ok(monkeypatch):
    """The same account-admin session authorizes a real admin route."""
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    infos = _fake_session_infos("lostcause")
    headers = _session_headers(monkeypatch, infos)
    monkeypatch.setattr(api_module, "_session_infos", lambda: infos)
    monkeypatch.setattr(
        api_module,
        "resolve_username",
        lambda username: [_fake_identity(pubkey, username="lostcause")],
    )
    monkeypatch.setattr(
        api_module,
        "resolve_pubkey",
        lambda p: _fake_identity(p, username="lostcause"),
    )
    monkeypatch.setattr(
        api_module, "_native_user_is_admin", lambda username: username == "lostcause"
    )
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "system.version", lambda **k: {"version": "1"})
    app = build_app(admin_pubkeys=())
    status, _, body = wsgi_request(app, "GET", "/package/system/version", headers=headers)
    assert status == "200"
    assert json.loads(body)["version"] == "1"


def test_nip98_auth_admin_via_account_flag_ok(monkeypatch):
    """NIP-98 path: a signed request by an account-admin linked key is admin."""
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    monkeypatch.setattr(
        api_module,
        "resolve_pubkey",
        lambda p: _fake_identity(p, username="lostcause"),
    )
    monkeypatch.setattr(
        api_module, "_native_user_is_admin", lambda username: username == "lostcause"
    )
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "system.version", lambda **k: {"version": "1"})
    app = build_app(admin_pubkeys=())
    headers = {"Authorization": _signed_header(sk, pubkey, "GET", "/package/system/version")}
    status, _, body = wsgi_request(app, "GET", "/package/system/version", headers=headers)
    assert status == "200"
    assert json.loads(body)["version"] == "1"


# --------------------------------------------------------------------------- #
# scope-aware nsite routes (D8 portal "My site": non-admin linked identities
# authorized per kind-31100 granted scopes, like the signed operation chain)

def test_scoped_nsite_publish_requires_publish_scope(monkeypatch):
    """A non-admin linked identity needs nsites.publish for the publish route."""
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    lifecycle = []
    monkeypatch.setattr(api_module, "resolve_pubkey", lambda p: _fake_identity(p))
    monkeypatch.setattr(api_module, "_granted_scopes", lambda p: {"nsites.read"})
    monkeypatch.setattr(api_module, "_run_lifecycle", lambda tool, args, state: lifecycle.append((tool, args)) or {"ok": True})
    app = build_app(admin_pubkeys=())
    status, _, body = wsgi_request(
        app, "POST", "/package/nsite/publish", {"event": {"id": "x"}, "plan_sha256": "0" * 64},
        headers={"Authorization": _signed_header(sk, pubkey, "POST", "/package/nsite/publish", json.dumps({"event": {"id": "x"}, "plan_sha256": "0" * 64}).encode())},
    )
    assert status == "403"
    assert json.loads(body)["code"] == "not_authorized"
    assert lifecycle == []


def test_scoped_nsite_publish_granted_non_admin_ok(monkeypatch):
    """nsites.publish grant lets a non-admin linked identity publish."""
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    lifecycle = []
    monkeypatch.setattr(api_module, "resolve_pubkey", lambda p: _fake_identity(p))
    monkeypatch.setattr(api_module, "_granted_scopes", lambda p: {"nsites.read", "nsites.publish"})
    monkeypatch.setattr(api_module, "_run_lifecycle", lambda tool, args, state: lifecycle.append((tool, args)) or {"ok": True, "request_id": "r" * 64})
    app = build_app(admin_pubkeys=())
    status, _, body = wsgi_request(
        app, "POST", "/package/nsite/publish", {"event": {"id": "x"}, "plan_sha256": "0" * 64},
        headers={"Authorization": _signed_header(sk, pubkey, "POST", "/package/nsite/publish", json.dumps({"event": {"id": "x"}, "plan_sha256": "0" * 64}).encode())},
    )
    assert status == "200"
    assert json.loads(body)["ok"] is True
    assert lifecycle and lifecycle[0][0] == "nsite.publish"


def test_scoped_nsite_read_grants_read_but_not_admin_routes(monkeypatch):
    """nsites.read lets a non-admin use read routes but not admin ones."""
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    lifecycle = []
    monkeypatch.setattr(api_module, "resolve_pubkey", lambda p: _fake_identity(p))
    monkeypatch.setattr(api_module, "_granted_scopes", lambda p: {"nsites.read"})
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "nsite.list", lambda **k: {"sites": []})
    monkeypatch.setattr(api_module, "_run_lifecycle", lambda tool, args, state: lifecycle.append((tool, args)) or {"ok": True})
    app = build_app(admin_pubkeys=())

    status, _, body = wsgi_request(app, "GET", "/package/nsite/list", headers={"Authorization": _signed_header(sk, pubkey, "GET", "/package/nsite/list")})
    assert status == "200"
    assert json.loads(body)["sites"] == []

    status, _, body = wsgi_request(app, "POST", "/package/nsite/gateway/enable", {"domain": "sites.example.org"}, headers={"Authorization": _signed_header(sk, pubkey, "POST", "/package/nsite/gateway/enable", json.dumps({"domain": "sites.example.org"}).encode())})
    assert status == "403"
    assert json.loads(body)["code"] == "not_authorized"
    assert lifecycle == []


def test_scoped_nsite_admin_bypasses_scope_check(monkeypatch):
    """An admin can publish without any kind-31100 grant."""
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    lifecycle = []
    monkeypatch.setattr(api_module, "resolve_pubkey", lambda p: _fake_identity(p))
    monkeypatch.setattr(api_module, "_granted_scopes", lambda p: set())
    monkeypatch.setattr(api_module, "_run_lifecycle", lambda tool, args, state: lifecycle.append((tool, args)) or {"ok": True, "request_id": "r" * 64})
    app = build_app(admin_pubkeys=(pubkey,))
    status, _, body = wsgi_request(
        app, "POST", "/package/nsite/publish", {"event": {"id": "x"}, "plan_sha256": "0" * 64},
        headers={"Authorization": _signed_header(sk, pubkey, "POST", "/package/nsite/publish", json.dumps({"event": {"id": "x"}, "plan_sha256": "0" * 64}).encode())},
    )
    assert status == "200"
    assert lifecycle and lifecycle[0][0] == "nsite.publish"


def test_scoped_nsite_session_linked_non_admin_ok(monkeypatch):
    """A portal session whose linked identity holds nsites.publish is allowed."""
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    lifecycle = []
    infos = _fake_session_infos("alice")
    headers = _session_headers(monkeypatch, infos)
    monkeypatch.setattr(api_module, "_session_infos", lambda: infos)
    monkeypatch.setattr(api_module, "resolve_username", lambda username: [_fake_identity(pubkey)])
    monkeypatch.setattr(api_module, "_granted_scopes", lambda p: {"nsites.publish"})
    monkeypatch.setattr(api_module, "_run_lifecycle", lambda tool, args, state: lifecycle.append((tool, args)) or {"ok": True, "request_id": "r" * 64})
    app = build_app(admin_pubkeys=())
    status, _, body = wsgi_request(
        app, "POST", "/package/nsite/publish", {"event": {"id": "x"}, "plan_sha256": "0" * 64},
        headers=headers,
    )
    assert status == "200"
    assert lifecycle and lifecycle[0][0] == "nsite.publish"


def test_scoped_nsite_session_without_identity_403(monkeypatch):
    """A portal session with no linked nostr identity cannot use nsite routes."""
    infos = _fake_session_infos("alice")
    headers = _session_headers(monkeypatch, infos)
    monkeypatch.setattr(api_module, "_session_infos", lambda: infos)
    monkeypatch.setattr(api_module, "resolve_username", lambda username: [])
    app = build_app(admin_pubkeys=())
    status, _, body = wsgi_request(app, "GET", "/package/nsite/list", headers=headers)
    assert status == "403"
    assert json.loads(body)["code"] == "not_authorized"


def test_scoped_nsite_publish_plan_requires_read_scope(monkeypatch):
    """The plan route mirrors the operation chain: it needs nsites.read."""
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    plan_calls = []
    monkeypatch.setattr(api_module, "resolve_pubkey", lambda p: _fake_identity(p))
    monkeypatch.setattr(api_module, "_granted_scopes", lambda p: {"nsites.publish"})
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "nsite.publish.plan", lambda **k: plan_calls.append(k) or {"plan_sha256": "0" * 64})
    app = build_app(admin_pubkeys=())
    body = {"pubkey": pubkey, "kind": 15128, "items": [{"path": "/index.html", "sha256": "0" * 64}]}
    status, _, body_resp = wsgi_request(
        app, "POST", "/package/nsite/publish/plan",
        body,
        headers={"Authorization": _signed_header(sk, pubkey, "POST", "/package/nsite/publish/plan", json.dumps(body).encode())},
    )
    assert status == "403"
    assert json.loads(body_resp)["code"] == "not_authorized"
    assert plan_calls == []


# --------------------------------------------------------------------------- #
# operation routes (fake authorizer + monkeypatched handlers)

@pytest.fixture()
def app():
    return build_app(authorizer=lambda _rule: "admin-pubkey")


def test_get_system_version(app, monkeypatch):
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "system.version", lambda **k: {"os": "debian", "version": "12"})
    status, _, body = wsgi_request(app, "GET", "/package/system/version")
    assert status == "200"
    assert json.loads(body)["version"] == "12"


def test_get_system_updates(app, monkeypatch):
    monkeypatch.setitem(
        api_module._TOOL_HANDLERS,
        "updates.check",
        lambda **k: {"system": [], "apps": [], "pending_migrations": []},
    )
    status, _, body = wsgi_request(app, "GET", "/package/system/updates")
    assert status == "200"
    assert json.loads(body) == {"system": [], "apps": [], "pending_migrations": []}


def test_post_system_updates_refresh_defaults_to_apps(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"target": kwargs["target"]}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "updates.refresh", fake)
    status, _, body = wsgi_request(app, "POST", "/package/system/updates/refresh", {})
    assert status == "200"
    assert captured == {"target": "apps"}


def test_post_system_updates_refresh_target(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"target": kwargs["target"]}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "updates.refresh", fake)
    status, _, body = wsgi_request(app, "POST", "/package/system/updates/refresh", {"target": "system"})
    assert status == "200"
    assert captured == {"target": "system"}


def test_post_system_updates_apply_uses_signed_chain(app, monkeypatch):
    """system.upgrade is high-risk/requires approval: it must go through
    _run_lifecycle (signed chain + owner co-signature), never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    status, _, body = wsgi_request(app, "POST", "/package/system/updates/apply", {"target": "system"})
    assert status == "200"
    assert json.loads(body)["request_id"] == "r" * 64
    assert calls == [("system.upgrade", {"target": "system"})]


def test_post_system_updates_apply_defaults_to_system(app, monkeypatch):
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True}
    )
    status, _, body = wsgi_request(app, "POST", "/package/system/updates/apply", {})
    assert status == "200"
    assert calls == [("system.upgrade", {"target": "system"})]


def test_get_system_migrations_query_flags(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"migrations": [], "state": {}}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "system.migrations", fake)
    status, _, body = wsgi_request(app, "GET", "/package/system/migrations?pending=true&done=false")
    assert status == "200"
    assert captured == {"pending": True, "done": False}


def test_get_system_migrations_defaults(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"migrations": [], "state": {}}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "system.migrations", fake)
    status, _, body = wsgi_request(app, "GET", "/package/system/migrations")
    assert status == "200"
    assert captured == {"pending": False, "done": False}


def test_post_system_migrate_uses_signed_chain(app, monkeypatch):
    """system.migrate is high-risk/irreversible: it must go through
    _run_lifecycle (signed chain + owner co-signature), never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    body = {"targets": ["0032_firewall_config"], "accept_disclaimer": True}
    status, _, resp = wsgi_request(app, "POST", "/package/system/migrate", body)
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("system.migrate", body)]


def test_get_domain_list(app, monkeypatch):
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "domain.list", lambda **k: {"domains": []})
    status, _, body = wsgi_request(app, "GET", "/package/domain/list")
    assert status == "200"
    assert json.loads(body) == {"domains": []}


def test_get_domain_inspect(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"domain": kwargs["domain"]}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "domain.inspect", fake)
    status, _, body = wsgi_request(app, "GET", "/package/domain/example.com/inspect")
    assert status == "200"
    assert captured == {"domain": "example.com"}


def test_post_domain_add_uses_signed_chain(app, monkeypatch):
    """domain.add is high-risk (registers a domain + DNS + Caddy routes): it
    must go through _run_lifecycle (signed chain + owner co-signature),
    never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    body = {"domain": "example.com", "provider_type": "manual"}
    status, _, resp = wsgi_request(app, "POST", "/package/domain/add", body)
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [
        (
            "domain.add",
            {
                "domain": "example.com",
                "provider_type": "manual",
                "provider_zone": None,
                "credential": None,
                "primary": False,
                "ipv4": True,
                "ipv6": True,
                "wildcard": True,
                "nip05": False,
                "tls_caa": None,
                "apply_dns": True,
                "verify": True,
            },
        )
    ]


def test_post_domain_remove_uses_signed_chain(app, monkeypatch):
    """domain.remove is high-risk: it must go through _run_lifecycle, never
    _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    status, _, resp = wsgi_request(app, "POST", "/package/domain/remove", {"domain": "example.com", "force": True})
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("domain.remove", {"domain": "example.com", "force": True})]


def test_get_dns_plan(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"plan": []}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "dns.plan", fake)
    status, _, body = wsgi_request(app, "GET", "/package/dns/plan/example.com")
    assert status == "200"
    assert captured == {"domain": "example.com"}


def test_post_dns_apply_uses_signed_chain(app, monkeypatch):
    """dns.apply is high-risk (mutates DNS through the provider): it must go
    through _run_lifecycle, never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    status, _, resp = wsgi_request(app, "POST", "/package/dns/apply", {"domain": "example.com"})
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("dns.apply", {"domain": "example.com"})]


def test_get_dns_verify(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"verified": True}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "dns.verify", fake)
    status, _, body = wsgi_request(app, "GET", "/package/dns/verify/example.com")
    assert status == "200"
    assert captured == {"domain": "example.com"}


def test_get_dns_watch(app, monkeypatch):
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "dns.watch", lambda **k: {"watchers": []})
    status, _, body = wsgi_request(app, "GET", "/package/dns/watch")
    assert status == "200"
    assert json.loads(body) == {"watchers": []}


def test_post_dns_subscribe_uses_signed_chain(app, monkeypatch):
    """dns.subscribe claims a free hostname and provisions a broker secret:
    high-risk, must go through _run_lifecycle, never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    status, _, resp = wsgi_request(app, "POST", "/package/dns/subscribe", {"hostname": "myhost"})
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("dns.subscribe", {"hostname": "myhost", "secret": None, "rotate": False})]


def test_get_dns_subscriptions(app, monkeypatch):
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "dns.subscriptions", lambda **k: {"subscriptions": []})
    status, _, body = wsgi_request(app, "GET", "/package/dns/subscriptions")
    assert status == "200"
    assert json.loads(body) == {"subscriptions": []}


def test_post_dns_unsubscribe_uses_signed_chain(app, monkeypatch):
    """dns.unsubscribe drops a broker secret: high-risk, must go through
    _run_lifecycle, never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    status, _, resp = wsgi_request(app, "POST", "/package/dns/unsubscribe", {"hostname": "myhost"})
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("dns.unsubscribe", {"hostname": "myhost"})]


def test_get_network_public_ip(app, monkeypatch):
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "network.public_ip", lambda **k: {"ipv4": "203.0.113.1"})
    status, _, body = wsgi_request(app, "GET", "/package/network/public-ip")
    assert status == "200"
    assert json.loads(body) == {"ipv4": "203.0.113.1"}


def test_get_credential_list(app, monkeypatch):
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "credential.list", lambda **k: {"credentials": []})
    status, _, body = wsgi_request(app, "GET", "/package/credential/list")
    assert status == "200"
    assert json.loads(body) == {"credentials": []}


def test_post_credential_set_uses_signed_chain(app, monkeypatch):
    """credential.set stores a DNS provider token: high-risk, must go
    through _run_lifecycle, never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    body = {"provider": "cloudflare", "name": "primary", "value": "secret-token"}
    status, _, resp = wsgi_request(app, "POST", "/package/credential/set", body)
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("credential.set", body)]


def test_post_credential_remove_uses_signed_chain(app, monkeypatch):
    """credential.remove deletes a DNS provider token: high-risk, must go
    through _run_lifecycle, never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    status, _, resp = wsgi_request(app, "POST", "/package/credential/remove", {"provider": "cloudflare", "name": "primary"})
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("credential.remove", {"provider": "cloudflare", "name": "primary"})]


def test_get_backup_list(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"snapshots": []}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "backup.list", fake)
    status, _, body = wsgi_request(app, "GET", "/package/backup/list?tag=nostrhost&host=box")
    assert status == "200"
    assert captured == {"tag": "nostrhost", "host": "box"}
    assert json.loads(body) == {"snapshots": []}


def test_get_backup_list_defaults(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"snapshots": []}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "backup.list", fake)
    status, _, body = wsgi_request(app, "GET", "/package/backup/list")
    assert status == "200"
    assert captured == {"tag": "", "host": ""}


def test_get_backup_policy(app, monkeypatch):
    captured = {}
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "backup.policy.read", lambda **kw: captured.update(kw) or {"retention": {}})
    status, _, body = wsgi_request(app, "GET", "/package/backup/policy")
    assert status == "200"
    assert captured == {}
    assert json.loads(body) == {"retention": {}}


def test_get_backup_info(app, monkeypatch):
    captured = {}
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "backup.info", lambda **kw: captured.update(kw) or {"id": "abc"})
    status, _, body = wsgi_request(app, "GET", "/package/backup/abc123")
    assert status == "200"
    assert captured == {"snapshot": "abc123"}
    assert json.loads(body) == {"id": "abc"}


def test_post_backup_create_uses_signed_chain(app, monkeypatch):
    """backup.create is medium-risk: it must go through _run_lifecycle
    (signed chain + admin confirmation), never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    body = {"tag": "manual", "paths": ["/etc"], "host": "box"}
    status, _, resp = wsgi_request(app, "POST", "/package/backup/create", body)
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("backup.create", {"tag": "manual", "paths": ["/etc"], "host": "box"})]


def test_post_backup_restore_uses_signed_chain(app, monkeypatch):
    """backup.restore is high-risk: it must go through _run_lifecycle,
    never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    body = {"snapshot": "abc123", "target": "/tmp/restore", "include": ["/etc"]}
    status, _, resp = wsgi_request(app, "POST", "/package/backup/restore", body)
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [
        (
            "backup.restore",
            {"snapshot": "abc123", "target": "/tmp/restore", "include": ["/etc"]},
        )
    ]


def test_post_backup_delete_uses_signed_chain(app, monkeypatch):
    """backup.delete is high-risk/irreversible: it must go through
    _run_lifecycle, never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    status, _, resp = wsgi_request(app, "POST", "/package/backup/delete", {"snapshot": "abc123", "prune": False})
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("backup.delete", {"snapshot": "abc123", "apply_retention": False, "prune": False})]


def test_post_backup_policy_set_uses_signed_chain(app, monkeypatch):
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    body = {"retention": {"keep_last": 3}, "schedule_enabled": True, "schedule_calendar": "weekly"}
    status, _, resp = wsgi_request(app, "POST", "/package/backup/policy", body)
    assert status == "200"
    assert calls == [
        ("backup.policy.set", {"retention": {"keep_last": 3}, "schedule_enabled": True, "schedule_calendar": "weekly"})
    ]


def test_get_state_status(app, monkeypatch):
    captured = {}
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "state.status", lambda **kw: captured.update(kw) or {"revision": "abc"})
    status, _, body = wsgi_request(app, "GET", "/package/state/status")
    assert status == "200"
    assert captured == {}
    assert json.loads(body) == {"revision": "abc"}


def test_post_state_rollback_apply_uses_signed_chain(app, monkeypatch):
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    plan = {"steps": [{"path": "x"}]}
    status, _, resp = wsgi_request(app, "POST", "/package/state/rollback/apply", {"plan": plan})
    assert status == "200"
    assert calls == [("rollback.apply", {"plan": plan})]


def test_post_diagnosis_run(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"reports": []}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "diagnosis.run", fake)
    body = {"categories": ["dnsrecords"], "force": True, "full": True}
    status, _, resp = wsgi_request(app, "POST", "/package/diagnosis/run", body)
    assert status == "200"
    assert captured == {"categories": ["dnsrecords"], "force": True, "full": True}
    assert json.loads(resp) == {"reports": []}


def test_post_diagnosis_run_defaults(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"reports": []}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "diagnosis.run", fake)
    status, _, resp = wsgi_request(app, "POST", "/package/diagnosis/run", {})
    assert status == "200"
    assert captured == {"categories": [], "force": False, "full": False}


def test_get_diagnosis_ignored(app, monkeypatch):
    monkeypatch.setitem(
        api_module._TOOL_HANDLERS, "diagnosis.ignored", lambda **k: {"ignore_filters": {}}
    )
    status, _, body = wsgi_request(app, "GET", "/package/diagnosis/ignored")
    assert status == "200"
    assert json.loads(body) == {"ignore_filters": {}}


def test_post_diagnosis_ignore_uses_signed_chain(app, monkeypatch):
    """diagnosis.ignore mutates admin config: it must go through
    _run_lifecycle (signed chain + owner co-signature), never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    body = {"filter": ["dnsrecords", "domain=yolo.test"]}
    status, _, resp = wsgi_request(app, "POST", "/package/diagnosis/ignore", body)
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("diagnosis.ignore", {"filter": ["dnsrecords", "domain=yolo.test"]})]


def test_post_diagnosis_unignore_uses_signed_chain(app, monkeypatch):
    """diagnosis.unignore must go through _run_lifecycle, never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    body = {"filter": ["dnsrecords", "domain=yolo.test"]}
    status, _, resp = wsgi_request(app, "POST", "/package/diagnosis/unignore", body)
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("diagnosis.unignore", {"filter": ["dnsrecords", "domain=yolo.test"]})]


def test_get_firewall_list(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"tcp": [22, 80, 443]}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "firewall.list", fake)
    status, _, body = wsgi_request(app, "GET", "/package/firewall/list")
    assert status == "200"
    assert captured == {"protocol": "tcp", "forwarded": False}
    assert json.loads(body) == {"tcp": [22, 80, 443]}


def test_get_firewall_list_udp_forwarded(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"udp": []}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "firewall.list", fake)
    status, _, body = wsgi_request(app, "GET", "/package/firewall/list?protocol=udp&forwarded=true")
    assert status == "200"
    assert captured == {"protocol": "udp", "forwarded": True}


def test_post_firewall_open_uses_signed_chain(app, monkeypatch):
    """firewall.open is high-risk: it must go through _run_lifecycle, never
    _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    body = {"port": "8080", "protocol": "tcp", "comment": "custom app", "upnp": True}
    status, _, resp = wsgi_request(app, "POST", "/package/firewall/open", body)
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [
        ("firewall.open", {"port": "8080", "protocol": "tcp", "comment": "custom app", "upnp": True})
    ]


def test_post_firewall_open_defaults_comment(app, monkeypatch):
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True}
    )
    status, _, resp = wsgi_request(app, "POST", "/package/firewall/open", {"port": "8080", "protocol": "tcp"})
    assert status == "200"
    assert calls == [
        (
            "firewall.open",
            {"port": "8080", "protocol": "tcp", "comment": "opened via native operation", "upnp": False},
        )
    ]


def test_post_firewall_close_uses_signed_chain(app, monkeypatch):
    """firewall.close is high-risk: it must go through _run_lifecycle, never
    _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    body = {"port": "8080", "protocol": "tcp", "upnp_only": True}
    status, _, resp = wsgi_request(app, "POST", "/package/firewall/close", body)
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("firewall.close", {"port": "8080", "protocol": "tcp", "upnp_only": True})]


def test_post_firewall_reload_uses_signed_chain(app, monkeypatch):
    """firewall.reload is high-risk: it must go through _run_lifecycle,
    never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    status, _, resp = wsgi_request(app, "POST", "/package/firewall/reload", {"skip_upnp": True})
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("firewall.reload", {"skip_upnp": True})]


def test_post_service_restart_uses_signed_chain(app, monkeypatch):
    """service.restart is a write with real consequences: it must go through
    the signed operation chain (policy + approval), not a direct tool call."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    status, _, body = wsgi_request(app, "POST", "/package/service/restart", {"name": "caddy"})
    assert status == "200"
    assert calls == [("service.restart", {"name": "caddy"})]


def test_get_service_status_names_query(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"services": []}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "service.status", fake)
    status, _, body = wsgi_request(app, "GET", "/package/service/status?names=caddy,nginx")
    assert status == "200"
    assert captured["names"] == ["caddy", "nginx"]


def test_get_service_status_no_query(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"caddy": {"status": "running"}}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "service.status", fake)
    status, _, body = wsgi_request(app, "GET", "/package/service/status")
    assert status == "200"
    assert captured == {}
    assert json.loads(body)["caddy"]["status"] == "running"


def test_post_service_control_uses_signed_chain(app, monkeypatch):
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    status, _, body = wsgi_request(app, "POST", "/package/service/control", {"name": "caddy", "action": "restart"})
    assert status == "200"
    assert calls == [("service.control", {"name": "caddy", "action": "restart"})]


def test_post_app_remove_uses_signed_chain(app, monkeypatch):
    """app.remove is data-loss-capable: it must go through the signed
    operation chain, not a direct tool call."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    status, _, body = wsgi_request(app, "POST", "/package/app/remove", {"app": "immich", "purge": True})
    assert status == "200"
    assert calls == [("app.remove", {"app": "immich", "purge": True})]


def test_user_list(app, monkeypatch):
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "user.list", lambda **k: {"users": {"alice": {}}})
    status, _, body = wsgi_request(app, "GET", "/package/user/list")
    assert status == "200"
    assert json.loads(body) == {"users": {"alice": {}}}


def test_user_create_uses_signed_chain(app, monkeypatch):
    """user.create is require_approval=True in the registry: it must go
    through _run_lifecycle (signed chain + owner co-signature), never
    _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    status, _, body = wsgi_request(
        app,
        "POST",
        "/package/user/create",
        {
            "username": "alice",
            "domain": "example.com",
            "password": "hunter2",
            "fullname": "Alice Example",
        },
    )
    assert status == "200"
    assert json.loads(body)["request_id"] == "r" * 64
    assert calls == [
        (
            "user.create",
            {
                "username": "alice",
                "domain": "example.com",
                "password": "hunter2",
                "fullname": "Alice Example",
                "mailbox_quota": "0",
                "admin": False,
            },
        )
    ]


def test_user_update_uses_signed_chain(app, monkeypatch):
    """user.update is require_approval=True in the registry: it must go
    through _run_lifecycle, never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    status, _, body = wsgi_request(app, "POST", "/package/user/update", {"username": "alice", "fullname": "Alice B"})
    assert status == "200"
    assert json.loads(body)["request_id"] == "r" * 64
    tool, args = calls[0]
    assert tool == "user.update"
    assert args["username"] == "alice"
    assert args["fullname"] == "Alice B"
    assert args["mail"] is None


def test_user_delete_uses_signed_chain(app, monkeypatch):
    """user.delete is high-risk/irreversible: it must go through
    _run_lifecycle, never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    status, _, body = wsgi_request(app, "POST", "/package/user/delete", {"username": "alice", "purge": True})
    assert status == "200"
    assert json.loads(body)["request_id"] == "r" * 64
    assert calls == [("user.delete", {"username": "alice", "purge": True, "force": False})]


def test_get_user_group_list(app, monkeypatch):
    monkeypatch.setitem(
        api_module._TOOL_HANDLERS, "user.group.list", lambda **k: {"admins": {"members": []}}
    )
    status, _, body = wsgi_request(app, "GET", "/package/user/group/list")
    assert status == "200"
    assert json.loads(body) == {"admins": {"members": []}}


def test_post_user_group_create_uses_signed_chain(app, monkeypatch):
    """user.group.create is medium-risk: it must go through _run_lifecycle,
    never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    status, _, resp = wsgi_request(app, "POST", "/package/user/group/create", {"groupname": "editors"})
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("user.group.create", {"groupname": "editors", "gid": None})]


def test_post_user_group_update_uses_signed_chain(app, monkeypatch):
    """user.group.update is medium-risk: it must go through _run_lifecycle,
    never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    body = {"groupname": "editors", "add": ["alice"], "remove": ["bob"]}
    status, _, resp = wsgi_request(app, "POST", "/package/user/group/update", body)
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("user.group.update", {"groupname": "editors", "add": ["alice"], "remove": ["bob"]})]


def test_post_user_group_delete_uses_signed_chain(app, monkeypatch):
    """user.group.delete is high-risk/irreversible: it must go through
    _run_lifecycle, never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    status, _, resp = wsgi_request(app, "POST", "/package/user/group/delete", {"groupname": "editors"})
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("user.group.delete", {"groupname": "editors", "force": False})]


def test_get_user_permission_list(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"permissions": {}}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "user.permission.list", fake)
    status, _, body = wsgi_request(app, "GET", "/package/user/permission/list?full=true")
    assert status == "200"
    assert captured == {"full": True}
    assert json.loads(body) == {"permissions": {}}


def test_get_user_permission_info(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"label": "Nextcloud"}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "user.permission.info", fake)
    status, _, body = wsgi_request(app, "GET", "/package/user/permission/info/nextcloud.main")
    assert status == "200"
    assert captured == {"permission": "nextcloud.main"}
    assert json.loads(body) == {"label": "Nextcloud"}


def test_post_user_permission_add_uses_signed_chain(app, monkeypatch):
    """user.permission.add is medium-risk: it must go through
    _run_lifecycle, never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    body = {"permission": "nextcloud.main", "names": ["editors"]}
    status, _, resp = wsgi_request(app, "POST", "/package/user/permission/add", body)
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("user.permission.add", {"permission": "nextcloud.main", "names": ["editors"]})]


def test_post_user_permission_remove_uses_signed_chain(app, monkeypatch):
    """user.permission.remove is medium-risk: it must go through
    _run_lifecycle, never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    body = {"permission": "nextcloud.main", "names": ["editors"]}
    status, _, resp = wsgi_request(app, "POST", "/package/user/permission/remove", body)
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("user.permission.remove", {"permission": "nextcloud.main", "names": ["editors"]})]


def test_post_user_permission_update_uses_signed_chain(app, monkeypatch):
    """user.permission.update is medium-risk: it must go through
    _run_lifecycle, never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    body = {"permission": "nextcloud.main", "label": "Cloud", "show_tile": True}
    status, _, resp = wsgi_request(app, "POST", "/package/user/permission/update", body)
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [
        ("user.permission.update", {"permission": "nextcloud.main", "label": "Cloud", "show_tile": True})
    ]


def test_catalog_list(app, monkeypatch):
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "catalog.list", lambda **k: {"entries": []})
    status, _, body = wsgi_request(app, "GET", "/package/catalog/list")
    assert status == "200"
    assert json.loads(body) == {"entries": []}


def test_catalog_get(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"declaration": {"AppID": kwargs["app_id"]}, "event_id": "abc"}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "catalog.get", fake)
    status, _, body = wsgi_request(app, "GET", "/package/catalog/get/immich")
    assert status == "200"
    assert captured == {"app_id": "immich"}


def test_identity_list_username(app, monkeypatch):
    captured = {}

    def fake(username):
        captured["username"] = username
        return []

    monkeypatch.setattr(api_module, "list_identities_for_username", fake)
    status, _, body = wsgi_request(app, "GET", "/package/identity/list?username=alice")
    assert status == "200"
    assert captured["username"] == "alice"


def test_identity_link(app, monkeypatch):
    calls = []

    def fake(tool, args, state):
        calls.append((tool, args))
        return {"ok": True, "request_id": "r" * 64}

    monkeypatch.setattr(api_module, "_run_lifecycle", fake)
    status, _, body = wsgi_request(app, "POST", "/package/identity/link", {"username": "alice", "pubkey_or_npub": "npub1test", "signer_type": "nip07"})
    assert status == "200"
    assert calls[0][0] == "identity.link"
    assert calls[0][1]["username"] == "alice"
    assert calls[0][1]["pubkey_or_npub"] == "npub1test"
    assert calls[0][1]["signer_type"] == "nip07"


def test_catalog_list_wraps_bare_list(app, monkeypatch):
    """The catalogue CLI emits a bare list; the API wraps it under 'entries'
    so the admin client's CatalogueList type (entries: [...]) holds."""
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "catalog.list", lambda **k: [{"declaration": {"AppID": "x"}}])
    status, _, body = wsgi_request(app, "GET", "/package/catalog/list")
    assert status == "200"
    out = json.loads(body)
    assert isinstance(out, dict) and "entries" in out
    assert out["entries"] == [{"declaration": {"AppID": "x"}}]


def test_catalog_list_passthrough_dict(app, monkeypatch):
    """When catalog.list already returns a dict, it passes through unchanged."""
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "catalog.list", lambda **k: {"entries": []})
    status, _, body = wsgi_request(app, "GET", "/package/catalog/list")
    assert json.loads(body) == {"entries": []}


def test_agent_status_route(app, monkeypatch):
    monkeypatch.setattr(api_module, "_agent_status", lambda: {"installed": True, "configured": True, "service_enabled": True, "service_active": False})
    status, _, body = wsgi_request(app, "GET", "/package/agent/status")
    assert status == "200"
    out = json.loads(body)
    assert out["installed"] is True
    assert out["configured"] is True


def test_agent_service_routes(app, monkeypatch):
    calls = []

    def fake(tool, args, state):
        calls.append((tool, args))
        return {"ok": True, "result": {"action": tool.split(".")[1]}, "request_id": "r" * 64}

    monkeypatch.setattr(api_module, "_run_lifecycle", fake)
    status, _, body = wsgi_request(app, "POST", "/package/agent/enable", {})
    assert status == "200"
    assert json.loads(body)["result"]["action"] == "enable"
    assert calls == [("agent.enable", {})]


def test_identity_dict_uses_username(monkeypatch):
    """_identity_dict must read the Identity dataclass's 'username' field
    (the old code read 'ynh_username', which no longer exists on the dataclass
    and crashed identity screens)."""
    from types import SimpleNamespace

    ident = SimpleNamespace(pubkey="ab" * 32, username="alice", signer_type="nip07", label="Laptop", enabled=True, created_at=0, last_used=0)
    out = api_module._identity_dict(ident)
    assert out["username"] == "alice"
    assert out["pubkey"] == "ab" * 32


def test_json_safe_serializes_datetimes():
    """Tool results carrying datetimes (service.status's last_state_change)
    must serialise to ISO strings instead of 500ing the response."""
    import datetime

    out = api_module._json_safe(
        {"last_state_change": datetime.datetime(2026, 1, 2, 3, 4, 5), "tags": {"a", "b"}}
    )
    assert out["last_state_change"] == "2026-01-02T03:04:05"
    assert out["tags"] == ["a", "b"]


def test_capability_grant(app, monkeypatch):
    calls = []

    def fake(tool, args, state):
        calls.append((tool, args))
        return {"ok": True, "request_id": "r" * 64}

    monkeypatch.setattr(api_module, "_run_lifecycle", fake)
    status, _, body = wsgi_request(app, "POST", "/package/capability/grant", {"pubkey": "abcd", "scopes": ["apps.read"], "type": "agent"})
    assert status == "200"
    assert calls[0][0] == "capability.grant"
    assert calls[0][1]["scopes"] == ["apps.read"]


def test_capability_list(app, monkeypatch):
    def fake(**kwargs):
        return [{"pubkey": "ab" * 32, "type": "agent", "scopes": ["apps.read"], "granted_at": 1000, "event_id": "e" * 64}]

    monkeypatch.setattr(api_module, "list_capabilities", fake)
    monkeypatch.setattr(api_module, "_config_admin_sk", lambda: None)
    monkeypatch.setattr(api_module, "_config_control_relay", lambda: None)
    status, _, body = wsgi_request(app, "GET", "/package/capability/list")
    assert status == "200"
    grants = json.loads(body)["grants"]
    assert grants == [{"pubkey": "ab" * 32, "type": "agent", "scopes": ["apps.read"], "granted_at": 1000, "event_id": "e" * 64}]


def test_post_system_reboot_uses_signed_chain(app, monkeypatch):
    """system.reboot is high-risk: it must go through _run_lifecycle, never
    _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    status, _, resp = wsgi_request(app, "POST", "/package/system/reboot", {})
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("system.reboot", {})]


def test_post_system_shutdown_uses_signed_chain(app, monkeypatch):
    """system.shutdown is high-risk: it must go through _run_lifecycle,
    never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    status, _, resp = wsgi_request(app, "POST", "/package/system/shutdown", {})
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("system.shutdown", {})]


def test_get_settings_list(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"settings": {"ssowat.panel_overlay.enabled": True}}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "settings.list", fake)
    status, _, body = wsgi_request(app, "GET", "/package/settings/list?full=true")
    assert status == "200"
    assert captured == {"full": True}
    assert json.loads(body) == {"settings": {"ssowat.panel_overlay.enabled": True}}


def test_get_settings_get(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"key": "ssowat.panel_overlay.enabled", "value": True}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "settings.get", fake)
    status, _, body = wsgi_request(app, "GET", "/package/settings/get/ssowat.panel_overlay.enabled")
    assert status == "200"
    assert captured == {"key": "ssowat.panel_overlay.enabled"}
    assert json.loads(body) == {"key": "ssowat.panel_overlay.enabled", "value": True}


def test_post_settings_set_uses_signed_chain(app, monkeypatch):
    """settings.set is medium-risk: it must go through _run_lifecycle, never
    _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    body = {"key": "ssowat.panel_overlay.enabled", "value": False}
    status, _, resp = wsgi_request(app, "POST", "/package/settings/set", body)
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("settings.set", {"key": "ssowat.panel_overlay.enabled", "value": False})]


def test_post_settings_reset_uses_signed_chain(app, monkeypatch):
    """settings.reset is medium-risk: it must go through _run_lifecycle,
    never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    status, _, resp = wsgi_request(app, "POST", "/package/settings/reset", {"key": "ssowat.panel_overlay.enabled"})
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("settings.reset", {"key": "ssowat.panel_overlay.enabled"})]


def test_post_settings_reset_all_uses_signed_chain(app, monkeypatch):
    """settings.reset_all is high-risk: it must go through _run_lifecycle,
    never _run_tool."""
    calls = []
    monkeypatch.setattr(
        api_module, "_run_lifecycle", lambda tool, args, state: calls.append((tool, args)) or {"ok": True, "request_id": "r" * 64}
    )
    status, _, resp = wsgi_request(app, "POST", "/package/settings/reset_all", {})
    assert status == "200"
    assert json.loads(resp)["request_id"] == "r" * 64
    assert calls == [("settings.reset_all", {})]


def test_agent_init(app, monkeypatch):
    calls = []

    def fake(tool, args, state):
        calls.append((tool, args))
        return {"ok": True, "result": {"configured": True, "agent_pubkey": "abcd"}, "request_id": "r" * 64}

    monkeypatch.setattr(api_module, "_run_lifecycle", fake)
    status, _, body = wsgi_request(app, "POST", "/package/agent/init")
    assert status == "200"
    assert json.loads(body)["result"]["agent_pubkey"] == "abcd"
    assert calls == [("agent.init", {})]


def test_agent_disable(app, monkeypatch):
    calls = []

    def fake(tool, args, state):
        calls.append((tool, args))
        return {"ok": True, "result": {"action": "disable"}, "request_id": "r" * 64}

    monkeypatch.setattr(api_module, "_run_lifecycle", fake)
    status, _, body = wsgi_request(app, "POST", "/package/agent/disable")
    assert status == "200"
    assert json.loads(body)["result"]["action"] == "disable"
    assert calls == [("agent.disable", {})]


def test_agent_init_error_maps_to_400(app, monkeypatch):
    def boom(tool, args, state):
        raise NostrHostError("nostrhost-agent is not installed")

    monkeypatch.setattr(api_module, "_run_lifecycle", boom)
    status, _, body = wsgi_request(app, "POST", "/package/agent/init")
    assert status == "400"
    assert json.loads(body)["code"] == "operation_failed"


def test_handler_error_maps_to_400(app, monkeypatch):
    def boom(tool, args, state):
        raise ApiError(400, "operation_failed", "boom")

    monkeypatch.setattr(api_module, "_run_lifecycle", boom)
    status, _, body = wsgi_request(app, "POST", "/package/service/restart", {"name": "caddy"})
    assert status == "400"
    assert json.loads(body)["code"] == "operation_failed"


def test_invalid_json_body_400(app):
    status, _, _ = wsgi_request(app, "POST", "/package/service/restart", raw_body=b"{not json")
    assert status == "400"


def test_internal_error_does_not_leak_exception(app, monkeypatch):
    """M18: an unexpected exception must not echo its message (paths, config
    snippets, provider errors) back to the caller."""

    def boom(tool, args, state):
        raise RuntimeError("/etc/nostrhost/operator.toml secret=abc123")

    monkeypatch.setattr(api_module, "_run_lifecycle", boom)
    status, _, body = wsgi_request(app, "POST", "/package/service/restart", {"name": "caddy"})
    assert status == "500"
    out = json.loads(body)
    assert out["code"] == "internal_error"
    assert "operator.toml" not in json.dumps(out)
    assert "abc123" not in json.dumps(out)


def test_unknown_route_404(app):
    status, _, _ = wsgi_request(app, "GET", "/package/nope")
    assert status == "404"


def test_mcp_endpoint_info_reports_unconfigured(app, monkeypatch):
    monkeypatch.setattr(api_module, "read_endpoint_config", lambda: None)
    status, _, body = wsgi_request(app, "GET", "/package/mcp/endpoint")
    assert status == "200"
    assert json.loads(body) == {"configured": False}


def test_mcp_endpoint_info_reports_configured(app, monkeypatch):
    monkeypatch.setattr(api_module, "read_endpoint_config", lambda: {"domain": "mcp.example.com", "port": 8930})
    status, _, body = wsgi_request(app, "GET", "/package/mcp/endpoint")
    assert status == "200"
    assert json.loads(body) == {"configured": True, "domain": "mcp.example.com", "port": 8930}


def test_mcp_endpoint_configure_sets_route_and_returns_endpoint(app, monkeypatch):
    configured = {}

    def configure(domain):
        configured.update({"domain": domain, "port": 8930})

    monkeypatch.setattr(api_module, "configure_route", configure)
    monkeypatch.setattr(api_module, "read_endpoint_config", lambda: configured or None)

    status, _, body = wsgi_request(app, "POST", "/package/mcp/endpoint", {"domain": " MCP.Example.COM. "})

    assert status == "200"
    assert configured == {"domain": "mcp.example.com", "port": 8930}
    assert json.loads(body) == {"configured": True, "domain": "mcp.example.com", "port": 8930}


@pytest.mark.parametrize("domain", [None, "", "   ", 123, ["mcp.example.com"]])
def test_mcp_endpoint_configure_rejects_invalid_domain(app, monkeypatch, domain):
    monkeypatch.setattr(api_module, "configure_route", lambda _domain: pytest.fail("must not configure"))

    status, _, body = wsgi_request(app, "POST", "/package/mcp/endpoint", {"domain": domain})

    assert status == "400"
    assert json.loads(body)["code"] == "invalid_body"


def test_mcp_ca_bundle_unavailable_when_no_internal_ca(app, monkeypatch):
    monkeypatch.setattr(api_module, "export_ca_bundle", lambda **kwargs: None)
    status, _, body = wsgi_request(app, "GET", "/package/mcp/ca-bundle")
    assert status == "200"
    assert json.loads(body) == {"available": False}


def test_mcp_ca_bundle_returns_pem_when_available(app, monkeypatch):
    monkeypatch.setattr(
        api_module, "export_ca_bundle", lambda **kwargs: b"-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n"
    )
    status, _, body = wsgi_request(app, "GET", "/package/mcp/ca-bundle")
    assert status == "200"
    data = json.loads(body)
    assert data["available"] is True
    assert data["pem"] == "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n"


def test_mcp_ca_bundle_passes_configured_domain(app, monkeypatch):
    """The CA-bundle decision must be based on the configured endpoint domain:
    a public ACME domain yields available False even when the node keeps an
    internal CA for its lab/test domains."""
    captured = {}

    def fake_export(domain, **kwargs):
        captured["domain"] = domain
        return None

    monkeypatch.setattr(api_module, "export_ca_bundle", fake_export)
    monkeypatch.setattr(api_module, "read_endpoint_config", lambda: {"domain": "nmcp.example.com", "port": 8930})

    status, _, body = wsgi_request(app, "GET", "/package/mcp/ca-bundle")

    assert status == "200"
    assert captured["domain"] == "nmcp.example.com"
    assert json.loads(body) == {"available": False}


# --------------------------------------------------------------------------- #
# package authoring: fetch a manifest straight from its repository

def test_package_fetch_manifest(app, monkeypatch):
    captured = {}

    def fake(repository, revision="", package_path=""):
        captured.update({"repository": repository, "revision": revision, "package_path": package_path})
        return {"package": {"app": {"id": "example-app", "version": "0.1.0"}}, "valid": True, "diagnostics": [], "commit": "a" * 40}

    import nostrhost.package_authoring as package_authoring_module

    monkeypatch.setattr(package_authoring_module, "fetch_manifest_from_repository", fake)
    status, _, body = wsgi_request(
        app, "POST", "/package/authoring/fetch_manifest",
        {"repository": "https://example.invalid/app.git", "revision": "main"},
    )
    assert status == "200"
    assert captured["repository"] == "https://example.invalid/app.git"
    assert captured["revision"] == "main"
    data = json.loads(body)
    assert data["valid"] is True
    assert data["package"]["app"]["id"] == "example-app"


def test_package_fetch_manifest_requires_repository(app):
    status, _, body = wsgi_request(app, "POST", "/package/authoring/fetch_manifest", {})
    assert status == "400"


# --------------------------------------------------------------------------- #
# operations (kind-2200..2204 approval chain)

def test_package_operations_list(app, monkeypatch):
    captured = {}

    def fake(*, limit, control_relay):
        captured.update({"limit": limit, "control_relay": control_relay})
        return [{"request_id": "a" * 64, "state": "REQUESTED"}]

    monkeypatch.setattr(api_module, "list_operations", fake)
    monkeypatch.setattr(api_module, "_config_control_relay", lambda: None)
    status, _, body = wsgi_request(app, "GET", "/package/operations?limit=5")
    assert status == "200"
    assert captured["limit"] == 5
    assert json.loads(body)["entries"][0]["state"] == "REQUESTED"


def test_package_operations_get_found(app, monkeypatch):
    monkeypatch.setattr(api_module, "get_operation", lambda rid, **kw: {"request_id": rid, "state": "APPROVED"})
    status, _, body = wsgi_request(app, "GET", "/package/operations/" + "a" * 64)
    assert status == "200"
    assert json.loads(body)["state"] == "APPROVED"


def test_package_operations_get_missing_404(app, monkeypatch):
    monkeypatch.setattr(api_module, "get_operation", lambda rid, **kw: None)
    status, _, body = wsgi_request(app, "GET", "/package/operations/" + "a" * 64)
    assert status == "404"
    assert json.loads(body)["code"] == "not_found"


def test_package_operations_approval_template(app, monkeypatch):
    captured = {}

    def fake(admin_pubkey, request_id, note):
        captured.update({"admin_pubkey": admin_pubkey, "request_id": request_id, "note": note})
        return {"kind": 2201, "pubkey": admin_pubkey}

    monkeypatch.setattr(api_module, "build_approval_template", fake)
    status, _, body = wsgi_request(app, "GET", "/package/operations/" + "a" * 64 + "/approval-template?note=looks+fine")
    assert status == "200"
    assert captured["admin_pubkey"] == "admin-pubkey"
    assert captured["note"] == "looks fine"


def test_package_operations_rejection_template(app, monkeypatch):
    captured = {}

    def fake(admin_pubkey, request_id, reason):
        captured.update({"admin_pubkey": admin_pubkey, "request_id": request_id, "reason": reason})
        return {"kind": 2202, "pubkey": admin_pubkey}

    monkeypatch.setattr(api_module, "build_rejection_template", fake)
    status, _, body = wsgi_request(app, "GET", "/package/operations/" + "a" * 64 + "/rejection-template")
    assert status == "200"
    assert captured["reason"] is None


def test_package_operations_approve_falls_back_to_admin_key(app, monkeypatch):
    captured = {}

    def fake(request_id, **kwargs):
        captured.update({"request_id": request_id, **kwargs})
        return {"id": "event-id"}

    monkeypatch.setattr(api_module, "approve_operation", fake)
    monkeypatch.setattr(api_module, "_config_admin_sk", lambda: None)
    monkeypatch.setattr(api_module, "_config_control_relay", lambda: None)
    status, _, body = wsgi_request(app, "POST", "/package/operations/" + "a" * 64 + "/approve", {"note": "ok"})
    assert status == "200"
    data = json.loads(body)
    assert data["ok"] is True
    assert data["status"] == "submitted"
    assert data["event_id"] == "event-id"
    assert captured["note"] == "ok"


def test_package_operations_approve_with_bunker_event(app, monkeypatch):
    signed = {"id": "e" * 64, "pubkey": "admin-pubkey", "kind": 2201, "tags": [], "content": "", "sig": "s" * 128}
    published = {}

    monkeypatch.setattr(api_module, "validate_signed_approval", lambda event, rid: event)
    monkeypatch.setattr(api_module, "publish_to_relay", lambda relay, event: published.update({"relay": relay, "event": event}))
    monkeypatch.setattr(api_module, "_config_control_relay", lambda: "ws://relay.test")
    status, _, body = wsgi_request(app, "POST", "/package/operations/" + "a" * 64 + "/approve", {"event": signed})
    assert status == "200"
    data = json.loads(body)
    assert data["status"] == "submitted"
    assert data["event_id"] == signed["id"]
    assert published["relay"] == "ws://relay.test"


def test_package_operations_approve_rejects_event_from_another_pubkey(app, monkeypatch):
    signed = {"id": "e" * 64, "pubkey": "someone-else", "kind": 2201, "tags": [], "content": "", "sig": "s" * 128}
    status, _, body = wsgi_request(app, "POST", "/package/operations/" + "a" * 64 + "/approve", {"event": signed})
    assert status == "403"
    assert json.loads(body)["code"] == "not_authorized"


def test_package_operations_approve_rejects_non_dict_event(app):
    status, _, body = wsgi_request(app, "POST", "/package/operations/" + "a" * 64 + "/approve", {"event": "not-a-dict"})
    assert status == "400"
    assert json.loads(body)["code"] == "invalid_body"


def test_package_operations_reject_falls_back_to_admin_key(app, monkeypatch):
    captured = {}

    def fake(request_id, **kwargs):
        captured.update({"request_id": request_id, **kwargs})
        return {"id": "event-id"}

    monkeypatch.setattr(api_module, "reject_operation", fake)
    monkeypatch.setattr(api_module, "_config_admin_sk", lambda: None)
    monkeypatch.setattr(api_module, "_config_control_relay", lambda: None)
    status, _, body = wsgi_request(app, "POST", "/package/operations/" + "a" * 64 + "/reject", {"reason": "no"})
    assert status == "200"
    assert json.loads(body)["status"] == "submitted"
    assert captured["reason"] == "no"


def test_package_operations_reject_with_bunker_event(app, monkeypatch):
    signed = {"id": "e" * 64, "pubkey": "admin-pubkey", "kind": 2202, "tags": [], "content": "", "sig": "s" * 128}

    monkeypatch.setattr(api_module, "validate_signed_rejection", lambda event, rid: event)
    monkeypatch.setattr(api_module, "publish_to_relay", lambda relay, event: None)
    monkeypatch.setattr(api_module, "_config_control_relay", lambda: None)
    status, _, body = wsgi_request(app, "POST", "/package/operations/" + "a" * 64 + "/reject", {"event": signed})
    assert status == "200"
    data = json.loads(body)
    assert data["status"] == "submitted"
    assert data["event_id"] == signed["id"]


def test_notify_signers_reports_registered_targets(app, monkeypatch):
    from yunohost.nostr_signerd import SignerTarget

    monkeypatch.setattr(
        "yunohost.nostr_signerd.load_targets",
        lambda: [SignerTarget(signer_pubkey="admin-pubkey", relays=("wss://r.example",), secret=None, label="phone")],
    )
    status, _, body = wsgi_request(app, "GET", "/package/notify/signers")
    assert status == "200"
    data = json.loads(body)
    assert data["remote"] is True
    assert data["this_admin"] is True
    assert data["targets"][0]["signer_pubkey"] == "admin-pubkey"
    assert data["targets"][0]["paired"] is False


def test_notify_signers_without_targets(app, monkeypatch):
    monkeypatch.setattr("yunohost.nostr_signerd.load_targets", lambda: [])
    status, _, body = wsgi_request(app, "GET", "/package/notify/signers")
    assert status == "200"
    assert json.loads(body) == {"remote": False, "this_admin": False, "targets": []}


def test_contribution_settings_returns_unwrapped_result(monkeypatch):
    """The admin client contract is the settings object, not the signed-chain
    envelope, so a successful lifecycle write must be unwrapped."""
    settings = {
        "enabled": True,
        "auto_submit": False,
        "dataset_repo": "imattau/nostrhost-contributions",
        "token_configured": True,
    }
    monkeypatch.setattr(
        api_module,
        "_run_lifecycle",
        lambda tool, args, state: {"ok": True, "result": settings, "request_id": "r" * 64, "state": "succeeded"},
    )
    app = build_app(authorizer=lambda _rule: "admin")
    status, _, body = wsgi_request(
        app,
        "POST",
        "/package/agent/contribution/settings",
        {"dataset_repo": "imattau/nostrhost-contributions", "auto_submit": False},
    )
    assert status == "200"
    assert json.loads(body) == settings


def test_contribution_share_returns_unwrapped_result(monkeypatch):
    result = {
        "uploaded": True,
        "repo": "imattau/nostrhost-contributions",
        "path": "contributions.jsonl",
        "base_revision": "main",
        "pull_request_url": "https://github.com/imattau/nostrhost-contributions/pull/1",
        "message": "opened a pull request",
    }
    monkeypatch.setattr(
        api_module,
        "_run_lifecycle",
        lambda tool, args, state: {"ok": True, "result": result, "request_id": "r" * 64, "state": "succeeded"},
    )
    app = build_app(authorizer=lambda _rule: "admin")
    status, _, body = wsgi_request(app, "POST", "/package/agent/contribution/share", {"cycle_id": "c1"})
    assert status == "200"
    assert json.loads(body) == result


def test_contribution_settings_keeps_envelope_on_failure(monkeypatch):
    """A rejected or parked operation must still surface ok:false to the client."""
    envelope = {"ok": False, "request_id": "r" * 64, "state": "rejected", "reason": "policy"}
    monkeypatch.setattr(api_module, "_run_lifecycle", lambda tool, args, state: envelope)
    app = build_app(authorizer=lambda _rule: "admin")
    status, _, body = wsgi_request(app, "POST", "/package/agent/contribution/settings", {"dataset_repo": "x/y"})
    assert status == "200"
    assert json.loads(body) == envelope


# --------------------------------------------------------------------------- #
# remote-signer registration (cross-session approvals)

_HEX_ADMIN = "ab" * 32
_HEX_OTHER = "cd" * 32


def _admin_app(admin=_HEX_ADMIN):
    return build_app(authorizer=lambda _rule: admin)


def _bunker_uri(signer=_HEX_ADMIN) -> str:
    return f"bunker://{signer}?relay=wss%3A%2F%2Frelay.example&secret=s3cret"


def test_notify_signers_register_own_bunker(monkeypatch):
    from yunohost.nostr_signerd import SignerTarget

    registered = []

    def fake_add(uri, *, label=None, path=None):
        registered.append((uri, label))
        return []

    monkeypatch.setattr("yunohost.nostr_signerd.add_target_from_bunker_uri", fake_add)
    monkeypatch.setattr(
        "yunohost.nostr_signerd.load_targets",
        lambda: [SignerTarget(signer_pubkey=_HEX_ADMIN, relays=("wss://relay.example",), secret="s3cret", label="phone")],
    )
    status, _, body = wsgi_request(_admin_app(), "POST", "/package/notify/signers", {"bunker_uri": _bunker_uri(), "label": "phone"})
    assert status == "200"
    data = json.loads(body)
    assert registered == [(_bunker_uri(), "phone")]
    assert data["this_admin"] is True
    assert data["targets"][0]["paired"] is True


def test_notify_signers_register_rejects_another_identity():
    status, _, body = wsgi_request(_admin_app(), "POST", "/package/notify/signers", {"bunker_uri": _bunker_uri(_HEX_OTHER)})
    assert status == "403"
    assert json.loads(body)["code"] == "not_authorized"


def test_notify_signers_register_rejects_bad_uri():
    status, _, body = wsgi_request(_admin_app(), "POST", "/package/notify/signers", {"bunker_uri": "npub1notabunker"})
    assert status == "400"


def test_notify_signers_remove_own_target(monkeypatch):
    monkeypatch.setattr("yunohost.nostr_signerd.remove_target", lambda pubkey, path=None: True)
    monkeypatch.setattr("yunohost.nostr_signerd.load_targets", lambda: [])
    status, _, body = wsgi_request(_admin_app(), "DELETE", f"/package/notify/signers/{_HEX_ADMIN}")
    assert status == "200"
    assert json.loads(body)["removed"] is True


def test_notify_signers_remove_rejects_another_identity():
    status, _, _ = wsgi_request(_admin_app(), "DELETE", f"/package/notify/signers/{_HEX_OTHER}")
    assert status == "403"


def test_notify_signers_remove_missing_is_404(monkeypatch):
    monkeypatch.setattr("yunohost.nostr_signerd.remove_target", lambda pubkey, path=None: False)
    status, _, _ = wsgi_request(_admin_app(), "DELETE", f"/package/notify/signers/{_HEX_ADMIN}")
    assert status == "404"


def test_notify_signers_pair_start_and_status(monkeypatch):
    from yunohost.nostr_signer_pairing import PairingRegistry

    saved = []
    registry = PairingRegistry(
        client_sk="11" * 32,
        pair_fn=lambda **k: {"signer_pubkey": _HEX_ADMIN, "relays": ["wss://signer.example"]},
        save_target=lambda *a, **k: saved.append((a, k)),
        start_thread=False,
    )
    monkeypatch.setattr(api_module, "_signer_pairing_registry", lambda: registry)
    app = _admin_app()

    status, _, body = wsgi_request(app, "POST", "/package/notify/signers/pair", {"relays": ["wss://relay.example"]})
    assert status == "200"
    data = json.loads(body)
    assert data["status"] == "pending"
    assert data["uri"].startswith("nostrconnect://")
    pairing_id = data["pairing_id"]

    status, _, body = wsgi_request(app, "GET", f"/package/notify/signers/pair/{pairing_id}")
    assert json.loads(body)["status"] == "pending"

    registry._run(registry.get(pairing_id), None)
    assert saved and saved[0][0][0] == _HEX_ADMIN

    from yunohost.nostr_signerd import SignerTarget

    monkeypatch.setattr(
        "yunohost.nostr_signerd.load_targets",
        lambda: [SignerTarget(signer_pubkey=_HEX_ADMIN, relays=("wss://signer.example",))],
    )
    status, _, body = wsgi_request(app, "GET", f"/package/notify/signers/pair/{pairing_id}")
    data = json.loads(body)
    assert data["status"] == "paired"
    assert data["this_admin"] is True


def test_notify_signers_pair_status_is_admin_scoped(monkeypatch):
    from yunohost.nostr_signer_pairing import PairingRegistry

    registry = PairingRegistry(
        client_sk="11" * 32,
        pair_fn=lambda **k: {"signer_pubkey": _HEX_ADMIN, "relays": ["wss://r"]},
        save_target=lambda *a, **k: None,
        start_thread=False,
    )
    monkeypatch.setattr(api_module, "_signer_pairing_registry", lambda: registry)
    pending = registry.start(admin_pubkey=_HEX_ADMIN, relays=["wss://r"])

    status, _, _ = wsgi_request(_admin_app(_HEX_OTHER), "GET", f"/package/notify/signers/pair/{pending.pairing_id}")
    assert status == "404"
    status, _, _ = wsgi_request(_admin_app(), "GET", "/package/notify/signers/pair/" + "0" * 32)
    assert status == "404"
