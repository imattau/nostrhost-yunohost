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
