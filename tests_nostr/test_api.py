"""Stage 5: native HTTP API tests (Bottle + NIP-98).

Endpoints are exercised over the WSGI interface with monkeypatched handlers
(no real services/relay/keys).  The NIP-98 authorizer is tested both with a
real SDK-signed event (via the fork's ``_sign_event``) and with an
injected fake for the operation routes.
"""

from __future__ import annotations

import base64
import io
import json
import secrets
import types

import pytest

from nostrhost import api as api_module
from nostrhost.api import ApiError, build_app


# --------------------------------------------------------------------------- #
# WSGI test harness

def wsgi_request(app, method, path, body=None, headers=None, raw_body=None):
    if raw_body is not None:
        body_bytes = raw_body
    else:
        body_bytes = json.dumps(body).encode() if body is not None else b""
    path_info, _, query_string = path.partition("?")
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path_info,
        "QUERY_STRING": query_string,
        "SERVER_NAME": "test",
        "SERVER_PORT": "80",
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": "http",
        "wsgi.input": io.BytesIO(body_bytes),
        "wsgi.errors": io.StringIO(),
        "wsgi.multithread": False,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
        "CONTENT_LENGTH": str(len(body_bytes)),
        "CONTENT_TYPE": "application/json" if body is not None or raw_body is not None else "",
    }
    for key, value in (headers or {}).items():
        environ[f"HTTP_{key.upper().replace('-', '_')}"] = value
    status_holder: list[str] = []
    response_headers: dict[str, str] = {}

    def start_response(status, resp_headers, exc_info=None):
        status_holder.append(status)
        response_headers.update(resp_headers)

    chunks = app(environ, start_response)
    status = status_holder[0].split(" ", 1)[0]
    return status, response_headers, b"".join(chunks)


# --------------------------------------------------------------------------- #
# healthz + public

def test_healthz_is_public():
    app = build_app()
    status, _, body = wsgi_request(app, "GET", "/package/healthz")
    assert status == "200"
    assert json.loads(body)["ok"] is True


def test_healthz_public_when_bottle_route_is_dict():
    """bottle 0.12's Route is a dict subclass: the auth plugin must read the
    rule from the dict, not via `.rule`, or /healthz 500s on real Debian."""

    def deny_authorizer() -> str:
        raise ApiError(401, "authentication_required", "nope")

    plugin = api_module._AuthErrorsPlugin(authorizer=deny_authorizer)
    plugin.app = None
    wrapped = plugin.apply(lambda: "ok", {"rule": "/package/healthz", "method": "GET"})
    assert wrapped() == "ok"
    # non-healthz dict route runs the authorizer and maps its ApiError to a
    # JSON 401 response (the wrapper converts errors, it does not re-raise)
    wrapped_auth = plugin.apply(lambda: "ok", {"rule": "/package/system/version", "method": "GET"})
    assert "authentication_required" in str(wrapped_auth())


# --------------------------------------------------------------------------- #
# auth

def _signed_header(sk_hex: str, pubkey_hex: str) -> str:
    from yunohost.nostr_identity import _sign_event

    event = _sign_event(sk_hex, pubkey_hex, 27235, "", [["u", "https://nostrhost.local/"], ["method", "GET"]])
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
    app = build_app(authorizer=lambda: "admin")
    status, _, body = wsgi_request(app, "GET", "/package/app/management")
    assert status == "200"
    rows = {row["id"]: row for row in json.loads(body)["apps"]}
    assert rows["available"]["status"] == "available"
    assert rows["orphan"]["status"] == "installed-unlisted"


def test_native_settings_plan_and_apply_are_bound_to_reviewed_digest(monkeypatch, tmp_path):
    manifest = {
        "app": {"id": "example", "version": "1.0.0"},
        "settings": {"fields": {"mode": {"type": "enum", "choices": ["safe", "fast"], "default": "safe"}}, "values": {"mode": "safe"}},
        "config": {"main": {"destination": "/etc/example.conf", "template_content": "mode={{ settings.mode }}\n"}},
        "service": {"name": "example", "exec": "/usr/bin/example"},
    }
    from nostrhost import native_providers

    monkeypatch.setattr(native_providers, "installed_package_manifest", lambda app_id, state_dir=None: manifest if app_id == "example" else None)
    app = build_app(authorizer=lambda: "admin")
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
    app = build_app(authorizer=lambda: "admin")

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
    assert json.loads(body)["code"] == "invalid_signature"


def test_valid_signed_event_but_not_linked_403():
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    app = build_app(admin_pubkeys=(pubkey,))
    status, _, body = wsgi_request(
        app, "GET", "/package/system/version", headers={"Authorization": _signed_header(sk, pubkey)}
    )
    # resolve_pubkey (real) returns None for an unlinked key -> 403
    assert status == "403"
    assert json.loads(body)["code"] == "identity_not_linked"


def _fake_identity(pubkey_hex: str):
    return types.SimpleNamespace(
        pubkey=pubkey_hex,
        ynh_username="admin",
        signer_type="nip07",
        label="admin",
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
        app, "GET", "/package/system/version", headers={"Authorization": _signed_header(sk, pubkey)}
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
        app, "GET", "/package/system/version", headers={"Authorization": _signed_header(sk, pubkey)}
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
    monkeypatch.setattr(api_module, "_session_username", lambda: "admin")
    monkeypatch.setattr(api_module, "resolve_username", lambda username: [_fake_identity(pubkey)])
    app = build_app(admin_pubkeys=(pubkey,))
    status, _, body = wsgi_request(app, "GET", "/package/session")
    assert status == "200"
    out = json.loads(body)
    assert out["authenticated"] is True
    assert out["username"] == "admin"
    assert out["pubkey"] == pubkey
    assert out["admin"] is True


def test_session_endpoint_non_admin(monkeypatch):
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    monkeypatch.setattr(api_module, "_session_username", lambda: "alice")
    monkeypatch.setattr(api_module, "resolve_username", lambda username: [_fake_identity(pubkey)])
    app = build_app(admin_pubkeys=())  # not an admin
    status, _, body = wsgi_request(app, "GET", "/package/session")
    assert status == "200"
    out = json.loads(body)
    assert out["authenticated"] is True
    assert out["admin"] is False


def test_session_auth_admin_ok(monkeypatch):
    """A valid portal session whose linked identity is an admin authorizes the
    API without any NIP-98 header — the unified single sign-in path."""
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    monkeypatch.setattr(api_module, "_session_username", lambda: "admin")
    monkeypatch.setattr(api_module, "resolve_username", lambda username: [_fake_identity(pubkey)])
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "system.version", lambda **k: {"version": "1"})
    app = build_app(admin_pubkeys=(pubkey,))
    status, _, body = wsgi_request(app, "GET", "/package/system/version")
    assert status == "200"
    assert json.loads(body)["version"] == "1"


def test_session_auth_non_admin_403(monkeypatch):
    """A valid portal session that is not an admin is refused by the API."""
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    monkeypatch.setattr(api_module, "_session_username", lambda: "alice")
    monkeypatch.setattr(api_module, "resolve_username", lambda username: [_fake_identity(pubkey)])
    app = build_app(admin_pubkeys=())
    status, _, body = wsgi_request(app, "GET", "/package/system/version")
    assert status == "403"
    assert json.loads(body)["code"] == "not_authorized"


# --------------------------------------------------------------------------- #
# operation routes (fake authorizer + monkeypatched handlers)

@pytest.fixture()
def app():
    return build_app(authorizer=lambda: "admin-pubkey")


def test_get_system_version(app, monkeypatch):
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "system.version", lambda **k: {"os": "debian", "version": "12"})
    status, _, body = wsgi_request(app, "GET", "/package/system/version")
    assert status == "200"
    assert json.loads(body)["version"] == "12"


def test_post_service_restart(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"service": kwargs["name"]}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "service.restart", fake)
    status, _, body = wsgi_request(app, "POST", "/package/service/restart", {"name": "caddy"})
    assert status == "200"
    assert captured["name"] == "caddy"


def test_get_service_status_names_query(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"services": []}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "service.status", fake)
    status, _, body = wsgi_request(app, "GET", "/package/service/status?names=caddy,nginx")
    assert status == "200"
    assert captured["names"] == ["caddy", "nginx"]


def test_post_app_remove_purge(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"app": kwargs["app"]}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "app.remove", fake)
    status, _, body = wsgi_request(app, "POST", "/package/app/remove", {"app": "immich", "purge": True})
    assert status == "200"
    assert captured == {"app": "immich", "purge": True}


def test_user_list(app, monkeypatch):
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "user.list", lambda **k: {"users": {"alice": {}}})
    status, _, body = wsgi_request(app, "GET", "/package/user/list")
    assert status == "200"
    assert json.loads(body) == {"users": {"alice": {}}}


def test_user_create(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"username": kwargs["username"], "domain": kwargs["domain"], "admin": kwargs["admin"]}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "user.create", fake)
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
    assert captured == {
        "username": "alice",
        "domain": "example.com",
        "password": "hunter2",
        "fullname": "Alice Example",
        "mailbox_quota": "0",
        "admin": False,
    }


def test_user_update(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"username": kwargs["username"]}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "user.update", fake)
    status, _, body = wsgi_request(app, "POST", "/package/user/update", {"username": "alice", "fullname": "Alice B"})
    assert status == "200"
    assert captured["username"] == "alice"
    assert captured["fullname"] == "Alice B"
    assert captured["mail"] is None


def test_user_delete(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"username": kwargs["username"], "purge": kwargs["purge"]}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "user.delete", fake)
    status, _, body = wsgi_request(app, "POST", "/package/user/delete", {"username": "alice", "purge": True})
    assert status == "200"
    assert captured == {"username": "alice", "purge": True, "force": False}


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
    captured = {}

    def fake(username, pubkey_or_npub, **kwargs):
        captured.update({"username": username, "pubkey_or_npub": pubkey_or_npub, **kwargs})
        return {"kind": 31102}

    monkeypatch.setattr(api_module, "link_identity", fake)
    monkeypatch.setattr(api_module, "_config_operator_sk", lambda: None)
    monkeypatch.setattr(api_module, "_config_control_relay", lambda: None)
    status, _, body = wsgi_request(app, "POST", "/package/identity/link", {"username": "alice", "pubkey_or_npub": "npub1test", "signer_type": "nip07"})
    assert status == "200"
    assert captured["username"] == "alice"
    assert captured["signer_type"] == "nip07"


def test_capability_grant(app, monkeypatch):
    captured = {}

    def fake(pubkey, scopes, **kwargs):
        captured.update({"pubkey": pubkey, "scopes": scopes, **kwargs})
        return {"kind": 31100}

    monkeypatch.setattr(api_module, "grant_capability", fake)
    monkeypatch.setattr(api_module, "_config_admin_sk", lambda: None)
    monkeypatch.setattr(api_module, "_config_control_relay", lambda: None)
    status, _, body = wsgi_request(app, "POST", "/package/capability/grant", {"pubkey": "abcd", "scopes": ["apps.read"], "type": "agent"})
    assert status == "200"
    assert captured["scopes"] == ["apps.read"]


def test_handler_error_maps_to_400(app, monkeypatch):
    def boom(**kwargs):
        raise ApiError(400, "operation_failed", "boom")

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "service.restart", boom)
    status, _, body = wsgi_request(app, "POST", "/package/service/restart", {"name": "caddy"})
    assert status == "400"
    assert json.loads(body)["code"] == "operation_failed"


def test_invalid_json_body_400(app):
    status, _, _ = wsgi_request(app, "POST", "/package/service/restart", raw_body=b"{not json")
    assert status == "400"


def test_unknown_route_404(app):
    status, _, _ = wsgi_request(app, "GET", "/package/nope")
    assert status == "404"
