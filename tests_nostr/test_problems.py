"""Structured problem-log tests: the nostrhost.problems module and the api /
portal-api error boundaries that write to it."""

from __future__ import annotations

import json
import time

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.responses import PlainTextResponse

from nostrhost import problems


def _request(path="/package/x", *, method="GET", host="example.test", rid=None):
    headers = [(b"host", host.encode())]
    if rid:
        headers.append((b"x-nostrhost-request-id", rid.encode()))
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": headers,
        "client": ("1.2.3.4", 1234),
        "server": ("test", 80),
    }
    return Request(scope)


def test_finalize_records_server_error_with_traceback(tmp_path):
    log = tmp_path / "problems.log"
    problems.configure(str(log))
    response = PlainTextResponse("internal server error", status_code=500)
    try:
        raise ValueError("kaboom")
    except ValueError as exc:
        out = problems.finalize(
            response, _request(), started=time.perf_counter(), exc=exc, kind="unhandled", source="portal"
        )
    rid = out.headers["X-Nostrhost-Request-Id"]
    entry = json.loads(log.read_text().splitlines()[-1])
    assert entry["status"] == 500
    assert entry["code"] == "internal_error"
    assert entry["kind"] == "unhandled"
    assert entry["source"] == "portal"
    assert entry["exc_type"] == "ValueError"
    assert "ValueError: kaboom" in entry["traceback"]
    assert entry["request_id"] == rid
    assert entry["path"] == "/package/x"
    assert entry["actor"] == "anonymous"


def test_finalize_skips_success_but_attaches_request_id(tmp_path):
    log = tmp_path / "problems.log"
    problems.configure(str(log))
    out = problems.finalize(JSONResponse({"ok": True}), _request(), started=time.perf_counter())
    assert out.headers["X-Nostrhost-Request-Id"]
    assert not log.exists() or log.read_text() == ""


def test_finalize_uses_explicit_error_code_and_message(tmp_path):
    log = tmp_path / "problems.log"
    problems.configure(str(log))

    class FakeApiError(Exception):
        def __init__(self):
            super().__init__("nope")
            self.code = "not_found"
            self.message = "no such thing"

    out = problems.finalize(
        JSONResponse({"error": "no such thing", "code": "not_found"}, status_code=404),
        _request(),
        started=time.perf_counter(),
        exc=FakeApiError(),
        kind="api_error",
    )
    assert out.status_code == 404
    entry = json.loads(log.read_text().splitlines()[-1])
    assert entry["code"] == "not_found"
    assert entry["message"] == "no such thing"
    assert entry["kind"] == "api_error"
    assert "traceback" not in entry


def test_request_id_honours_client_header(tmp_path):
    problems.configure(str(tmp_path / "p.log"))
    assert problems.request_id(_request(rid="abc123")) == "abc123"


def test_record_redacts_secrets(tmp_path):
    log = tmp_path / "problems.log"
    problems.configure(str(log))
    problems.record(_request(), status=500, code="internal_error", message="password=topsecret leaked")
    entry = json.loads(log.read_text().splitlines()[-1])
    assert "topsecret" not in entry["message"]
    assert "[REDACTED]" in entry["message"]


# --------------------------------------------------------------------------- #
# client-side SPA error reporting (POST /nostrhost/portalapi/report)

def _portal_request(app, payload):
    import asyncio

    import httpx2

    async def call():
        transport = httpx2.ASGITransport(app=app)
        async with httpx2.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post("/report", json=payload)

    return asyncio.run(call())


def test_client_error_report_records_kind_client(tmp_path, monkeypatch):
    from nostrhost.portal_api import build_app as portal_build_app

    problems.configure(str(tmp_path / "problems.log"))
    response = _portal_request(
        portal_build_app(),
        {"events": [{"message": "Cannot read properties of undefined (reading 'x')", "stack": "TypeError: boom\n  at render", "route": "/dashboard", "app": "admin"}]},
    )
    assert response.status_code == 200
    entry = json.loads((tmp_path / "problems.log").read_text().splitlines()[-1])
    assert entry["status"] is None
    assert entry["code"] == "client_error"
    assert entry["kind"] == "client"
    assert entry["source"] == "portal"
    assert "admin SPA error at /dashboard" in entry["message"]
    assert "Cannot read properties" in entry["message"]
    assert entry["method"] == "POST"
    assert entry["request_id"]


def test_client_error_report_accepts_single_event(tmp_path, monkeypatch):
    from nostrhost.portal_api import build_app as portal_build_app

    problems.configure(str(tmp_path / "problems.log"))
    response = _portal_request(portal_build_app(), {"message": "boom", "app": "portal"})
    assert response.status_code == 200
    entry = json.loads((tmp_path / "problems.log").read_text().splitlines()[-1])
    assert entry["kind"] == "client"
    assert "portal SPA error" in entry["message"]


def test_client_error_report_rejects_empty_and_malformed(tmp_path, monkeypatch):
    from nostrhost.portal_api import build_app as portal_build_app

    problems.configure(str(tmp_path / "problems.log"))
    app = portal_build_app()
    assert _portal_request(app, {"events": []}).status_code == 400
    assert _portal_request(app, {}).status_code == 400
    assert _portal_request(app, {"events": [{"app": "admin"}]}).status_code == 200
    assert all(json.loads(line)["code"] != "client_error" for line in (tmp_path / "problems.log").read_text().splitlines())


def test_client_error_report_rejects_oversized_body(tmp_path, monkeypatch):
    from nostrhost.portal_api import build_app as portal_build_app

    problems.configure(str(tmp_path / "problems.log"))
    response = _portal_request(
        portal_build_app(),
        {"events": [{"message": "x" * 20_000, "app": "portal"}]},
    )
    assert response.status_code == 413
    assert all(json.loads(line)["code"] != "client_error" for line in (tmp_path / "problems.log").read_text().splitlines())


def test_update_route_returns_real_json_400_for_short_fullname(monkeypatch):
    """The portal reads error.value.data.path/.error: the 400 must ride on the
    Response itself (sync routes run in a threadpool, so the web.response.status
    override would be lost)."""
    from nostrhost.portal_api import build_app as portal_build_app

    import yunohost.nostr_account as nostr_account
    import yunohost.nostrhost.accounts as accounts

    monkeypatch.setattr(nostr_account, "_session_username", lambda: "alice")
    monkeypatch.setattr(accounts, "user_get", lambda _u: {"username": "alice"})
    monkeypatch.setattr(accounts, "users", lambda: {})
    monkeypatch.setattr(accounts, "save_users", lambda _u: None)

    import asyncio

    import httpx2

    app = portal_build_app()

    async def call():
        transport = httpx2.ASGITransport(app=app)
        async with httpx2.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.put("/update", json={"fullname": "x"})

    response = asyncio.run(call())
    assert response.status_code == 400
    assert response.json() == {"path": "fullname", "error": "Full name must be at least 2 characters."}
