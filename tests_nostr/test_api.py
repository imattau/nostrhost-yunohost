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
    status, _, body = wsgi_request(app, "GET", "/healthz")
    assert status == "200"
    assert json.loads(body)["ok"] is True


def test_healthz_public_when_bottle_route_is_dict():
    """bottle 0.12's Route is a dict subclass: the auth plugin must read the
    rule from the dict, not via `.rule`, or /healthz 500s on real Debian."""

    def deny_authorizer() -> str:
        raise ApiError(401, "authentication_required", "nope")

    plugin = api_module._AuthErrorsPlugin(authorizer=deny_authorizer)
    plugin.app = None
    wrapped = plugin.apply(lambda: "ok", {"rule": "/healthz", "method": "GET"})
    assert wrapped() == "ok"
    # non-healthz dict route runs the authorizer and maps its ApiError to a
    # JSON 401 response (the wrapper converts errors, it does not re-raise)
    wrapped_auth = plugin.apply(lambda: "ok", {"rule": "/system/version", "method": "GET"})
    assert "authentication_required" in str(wrapped_auth())


# --------------------------------------------------------------------------- #
# auth

def _signed_header(sk_hex: str, pubkey_hex: str) -> str:
    from yunohost.nostr_identity import _sign_event

    event = _sign_event(sk_hex, pubkey_hex, 27235, "", [["u", "https://nostrhost.local/"], ["method", "GET"]])
    return "Nostr " + base64.b64encode(json.dumps(event).encode()).decode()


def test_missing_auth_header_401():
    app = build_app()
    status, _, body = wsgi_request(app, "GET", "/system/version")
    assert status == "401"
    assert json.loads(body)["code"] == "authentication_required"


def test_malformed_auth_header_401():
    app = build_app()
    status, _, body = wsgi_request(app, "GET", "/system/version", headers={"Authorization": "Nostr !!!not-base64!!!"})
    assert status == "401"


def test_invalid_signature_401():
    app = build_app()
    bad = "Nostr " + base64.b64encode(b'{"kind":1,"content":"x"}').decode()
    status, _, body = wsgi_request(app, "GET", "/system/version", headers={"Authorization": bad})
    assert status == "401"
    assert json.loads(body)["code"] == "invalid_signature"


def test_valid_signed_event_but_not_linked_403():
    from yunohost.nostr_operations import _derive_pubkey

    sk = secrets.token_hex(32)
    pubkey = _derive_pubkey(sk)
    app = build_app(admin_pubkeys=(pubkey,))
    status, _, body = wsgi_request(
        app, "GET", "/system/version", headers={"Authorization": _signed_header(sk, pubkey)}
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
        app, "GET", "/system/version", headers={"Authorization": _signed_header(sk, pubkey)}
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
        app, "GET", "/system/version", headers={"Authorization": _signed_header(sk, pubkey)}
    )
    assert status == "403"


# --------------------------------------------------------------------------- #
# operation routes (fake authorizer + monkeypatched handlers)

@pytest.fixture()
def app():
    return build_app(authorizer=lambda: "admin-pubkey")


def test_get_system_version(app, monkeypatch):
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "system.version", lambda **k: {"os": "debian", "version": "12"})
    status, _, body = wsgi_request(app, "GET", "/system/version")
    assert status == "200"
    assert json.loads(body)["version"] == "12"


def test_post_service_restart(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"service": kwargs["name"]}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "service.restart", fake)
    status, _, body = wsgi_request(app, "POST", "/service/restart", {"name": "caddy"})
    assert status == "200"
    assert captured["name"] == "caddy"


def test_get_service_status_names_query(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"services": []}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "service.status", fake)
    status, _, body = wsgi_request(app, "GET", "/service/status?names=caddy,nginx")
    assert status == "200"
    assert captured["names"] == ["caddy", "nginx"]


def test_post_app_remove_purge(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"app": kwargs["app"]}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "app.remove", fake)
    status, _, body = wsgi_request(app, "POST", "/app/remove", {"app": "immich", "purge": True})
    assert status == "200"
    assert captured == {"app": "immich", "purge": True}


def test_identity_list_username(app, monkeypatch):
    captured = {}

    def fake(username):
        captured["username"] = username
        return []

    monkeypatch.setattr(api_module, "list_identities_for_username", fake)
    status, _, body = wsgi_request(app, "GET", "/identity/list?username=alice")
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
    status, _, body = wsgi_request(app, "POST", "/identity/link", {"username": "alice", "pubkey_or_npub": "npub1test", "signer_type": "nip07"})
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
    status, _, body = wsgi_request(app, "POST", "/capability/grant", {"pubkey": "abcd", "scopes": ["apps.read"], "type": "agent"})
    assert status == "200"
    assert captured["scopes"] == ["apps.read"]


def test_handler_error_maps_to_400(app, monkeypatch):
    def boom(**kwargs):
        raise ApiError(400, "operation_failed", "boom")

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "service.restart", boom)
    status, _, body = wsgi_request(app, "POST", "/service/restart", {"name": "caddy"})
    assert status == "400"
    assert json.loads(body)["code"] == "operation_failed"


def test_invalid_json_body_400(app):
    status, _, _ = wsgi_request(app, "POST", "/service/restart", raw_body=b"{not json")
    assert status == "400"


def test_unknown_route_404(app):
    status, _, _ = wsgi_request(app, "GET", "/nope")
    assert status == "404"
