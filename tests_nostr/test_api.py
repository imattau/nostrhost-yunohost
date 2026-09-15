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
from nostrhost.core import NostrHostError


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


def test_get_service_status_no_query(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"caddy": {"status": "running"}}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "service.status", fake)
    status, _, body = wsgi_request(app, "GET", "/service/status")
    assert status == "200"
    assert captured == {}
    assert json.loads(body)["caddy"]["status"] == "running"


def test_post_service_control(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"service": kwargs["name"], "action": kwargs["action"], "status": "running"}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "service.control", fake)
    status, _, body = wsgi_request(app, "POST", "/service/control", {"name": "caddy", "action": "restart"})
    assert status == "200"
    assert captured == {"name": "caddy", "action": "restart"}
    assert json.loads(body)["status"] == "running"


def test_get_catalog_list(app, monkeypatch):
    monkeypatch.setitem(api_module._TOOL_HANDLERS, "catalog.list", lambda **k: {"apps": [{"id": "immich"}]})
    status, _, body = wsgi_request(app, "GET", "/catalog/list")
    assert status == "200"
    assert json.loads(body)["apps"] == [{"id": "immich"}]


def test_get_catalog_get(app, monkeypatch):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"id": kwargs["app_id"], "trusted": True}

    monkeypatch.setitem(api_module._TOOL_HANDLERS, "catalog.get", fake)
    status, _, body = wsgi_request(app, "GET", "/catalog/get/immich")
    assert status == "200"
    assert captured["app_id"] == "immich"
    assert json.loads(body)["trusted"] is True


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


def test_agent_status(app, monkeypatch):
    monkeypatch.setattr(api_module, "_agent_status", lambda: {"installed": False, "configured": False, "service_enabled": False, "service_active": False})
    status, _, body = wsgi_request(app, "GET", "/agent/status")
    assert status == "200"
    assert json.loads(body)["installed"] is False


def test_agent_init(app, monkeypatch):
    monkeypatch.setattr(api_module, "_agent_init", lambda: {"configured": True, "agent_pubkey": "abcd"})
    status, _, body = wsgi_request(app, "POST", "/agent/init")
    assert status == "200"
    assert json.loads(body)["agent_pubkey"] == "abcd"


def test_agent_enable(app, monkeypatch):
    captured = {}

    def fake(action):
        captured["action"] = action
        return {"service": "nostrhost-agent.service", "action": action}

    monkeypatch.setattr(api_module, "_agent_service", fake)
    status, _, body = wsgi_request(app, "POST", "/agent/enable")
    assert status == "200"
    assert captured["action"] == "enable"


def test_agent_disable(app, monkeypatch):
    captured = {}

    def fake(action):
        captured["action"] = action
        return {"service": "nostrhost-agent.service", "action": action}

    monkeypatch.setattr(api_module, "_agent_service", fake)
    status, _, body = wsgi_request(app, "POST", "/agent/disable")
    assert status == "200"
    assert captured["action"] == "disable"


def test_agent_init_error_maps_to_400(app, monkeypatch):
    def boom():
        raise NostrHostError("nostrhost-agent is not installed")

    monkeypatch.setattr(api_module, "_agent_init", boom)
    status, _, body = wsgi_request(app, "POST", "/agent/init")
    assert status == "400"
    assert json.loads(body)["code"] == "operation_failed"


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
    assert captured["reason"] == "no"


def test_package_operations_reject_with_bunker_event(app, monkeypatch):
    signed = {"id": "e" * 64, "pubkey": "admin-pubkey", "kind": 2202, "tags": [], "content": "", "sig": "s" * 128}

    monkeypatch.setattr(api_module, "validate_signed_rejection", lambda event, rid: event)
    monkeypatch.setattr(api_module, "publish_to_relay", lambda relay, event: None)
    monkeypatch.setattr(api_module, "_config_control_relay", lambda: None)
    status, _, body = wsgi_request(app, "POST", "/package/operations/" + "a" * 64 + "/reject", {"event": signed})
    assert status == "200"
    assert json.loads(body)["event_id"] == signed["id"]
