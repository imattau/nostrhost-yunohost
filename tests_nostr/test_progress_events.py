"""Kind-2205 execution.progress + SSE subscription tests (§10).

Covers the progress event builder/authoring, the executor emitting progress
during execution, SSE framing, and the API's /events SSE endpoint.
"""

from __future__ import annotations

import io
import json
import os

from coincurve import PublicKeyXOnly
from typer.testing import CliRunner

from nostrhost import api as api_module
from nostrhost import cli as cli_module
from nostrhost import events as events_module
from nostrhost.api import build_app
from yunohost.nostr_mcp_adapter import NostrMCPAdapter
from yunohost.nostr_operations import (
    KIND_EXECUTION_PROGRESS,
    build_capability,
    build_execution_progress,
    build_operation_request,
    build_approval,
    execution_progress,
)
from yunohost.nostr_operationsd import OperationEngine


# --------------------------------------------------------------------------- #
# helpers (mirror tests_nostr/test_nostr_operationsd.py)

def new_key():
    sk = os.urandom(32).hex()
    pk = PublicKeyXOnly.from_secret(bytes.fromhex(sk)).format().hex()
    return sk, pk


class FakeBackend:
    def __init__(self):
        self.calls = []
        self.results = {"system.version": {"versions": {"yunohost": "12"}}}

    def execute(self, tool, args):
        self.calls.append((tool, args))
        if tool == "service.restart":
            raise RuntimeError("restart failed")
        return self.results.get(tool, {"ok": tool})


class Harness:
    def __init__(self):
        self.server_sk, self.server_pk = new_key()
        self.admin_sk, self.admin_pk = new_key()
        self.agent_sk, self.agent_pk = new_key()
        self.published = []
        self.backend = FakeBackend()
        self.engine = OperationEngine(
            publish=self.published.append,
            server_sk=self.server_sk,
            admins=[self.admin_pk],
            backend=self.backend,
        )

    def grant(self, scopes):
        self.engine.handle_event(build_capability(self.admin_sk, self.admin_pk, self.agent_pk, "agent", scopes))

    def request(self, tool, args=None):
        ev = build_operation_request(self.agent_sk, self.agent_pk, tool, args or {})
        assert self.engine.handle_event(ev)
        return ev

    def approve(self, request_id):
        assert self.engine.handle_event(build_approval(self.admin_sk, self.admin_pk, request_id))


def _e_tag(event):
    for tag in event.get("tags") or []:
        if tag and tag[0] == "e" and len(tag) > 1:
            return tag[1]
    return None


def _content(event):
    return json.loads(event["content"])


# --------------------------------------------------------------------------- #
# builder + authoring

def test_build_execution_progress_fields():
    event = build_execution_progress(
        "a" * 64, "b" * 64, "c" * 64, stage="database", progress=0.55, message="seeding"
    )
    assert event["kind"] == KIND_EXECUTION_PROGRESS
    assert _e_tag(event) == "c" * 64
    assert _content(event) == {"operation": "c" * 64, "stage": "database", "progress": 0.55, "message": "seeding"}


def test_build_execution_progress_clamps_and_omits():
    event = build_execution_progress("a" * 64, "b" * 64, "c" * 64, stage="done", progress=1.7)
    assert _content(event)["progress"] == 1.0
    event = build_execution_progress("a" * 64, "b" * 64, "c" * 64, stage="done")
    assert "progress" not in _content(event)


def test_execution_progress_publishes_with_injected_transport():
    captured = []

    def transport(_relay, event):
        captured.append(event)

    event = execution_progress("c" * 64, "executing", progress=0.4, server_sk="a" * 64, transport=transport)
    assert event["kind"] == KIND_EXECUTION_PROGRESS
    assert captured == [event]


# --------------------------------------------------------------------------- #
# executor emits progress during execution

def test_executor_emits_progress_before_during_after():
    h = Harness()
    h.grant(["server.read"])
    request = h.request("system.version")  # read op auto-executes (ungated)

    progress = h.published and [e for e in h.published if e["kind"] == KIND_EXECUTION_PROGRESS]
    assert len(progress) == 3
    assert [_content(p)["progress"] for p in progress] == [0.0, 0.5, 1.0]
    for event in progress:
        assert _e_tag(event) == request["id"]
        assert _content(event)["operation"] == request["id"]

    kinds = [e["kind"] for e in h.published]
    assert kinds.index(2203) < kinds.index(2205) < kinds.index(2204)


def test_executor_progress_on_error_path():
    h = Harness()
    h.grant(["services.restart"])
    request = h.request("service.restart", {"name": "caddy"})
    h.approve(request["id"])
    # on failure the 1.0 "finished" progress is not reached
    assert len([e for e in h.published if e["kind"] == KIND_EXECUTION_PROGRESS]) == 2
    results = [e for e in h.published if e["kind"] == 2204]
    assert _content(results[0])["ok"] is False


# --------------------------------------------------------------------------- #
# SSE framing + API endpoint

def test_sse_format_and_ping():
    event = build_execution_progress("a" * 64, "b" * 64, "c" * 64, stage="executing", progress=0.5)
    frame = events_module.sse_format(event)
    assert frame.startswith("data: {") and frame.endswith("\n\n")
    body = json.loads(frame[6:].strip())
    assert json.loads(body["content"])["stage"] == "executing"
    assert events_module.sse_ping() == ": ping\n\n"


def wsgi_request(app, method, path):
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "SERVER_NAME": "test",
        "SERVER_PORT": "80",
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": "http",
        "wsgi.input": io.BytesIO(b""),
        "wsgi.errors": io.StringIO(),
        "wsgi.multithread": False,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
        "CONTENT_LENGTH": "0",
        "CONTENT_TYPE": "",
    }
    status_holder = []
    response_headers = {}

    def start_response(status, headers, exc_info=None):
        status_holder.append(status)
        response_headers.update(headers)

    chunks = app(environ, start_response)
    return status_holder[0].split(" ", 1)[0], response_headers, b"".join(chunks)


def test_api_events_sse_endpoint():
    events = [
        build_execution_progress("a" * 64, "b" * 64, "c" * 64, stage="executing", progress=0.5),
        {"kind": 2204, "id": "r", "content": json.dumps({"ok": True})},
    ]
    app = build_app(authorizer=lambda: "admin", event_stream=lambda request_id: iter(events))
    status, headers, body = wsgi_request(app, "GET", "/events/" + "c" * 64)
    assert status == "200"
    assert headers["Content-Type"] == "text/event-stream"
    text = body.decode()
    assert ": ping" in text
    assert text.count("data: ") == 2  # the two streamed events
    assert "executing" in text
    assert "ok" in text


def test_api_events_requires_auth():
    def deny():
        raise api_module.ApiError(401, "authentication_required", "no header")

    app = build_app(authorizer=deny)
    status, _, _ = wsgi_request(app, "GET", "/events/" + "x" * 64)
    assert status == "401"


# --------------------------------------------------------------------------- #
# CLI op follow / op status (subscriber)

def _sample_events():
    return [
        {"kind": 2203, "id": "r", "tags": [["e", "c" * 64]]},
        build_execution_progress("a" * 64, "b" * 64, "c" * 64, stage="database", progress=0.55, message="seeding"),
        {"kind": 2204, "id": "r", "tags": [["e", "c" * 64]], "content": json.dumps({"ok": True, "result": {}})},
    ]


def test_cli_op_follow_streams_events(monkeypatch):
    monkeypatch.setattr(cli_module, "_stream_events", lambda rid, relay, timeout: iter(_sample_events()))
    app = cli_module.build_app()
    result = CliRunner().invoke(app, ["op", "follow", "c" * 64])
    assert result.exit_code == 0
    assert "started" in result.stdout
    assert "database" in result.stdout and "55%" in result.stdout
    assert "done: ok" in result.stdout


def test_cli_op_follow_json(monkeypatch):
    monkeypatch.setattr(cli_module, "_stream_events", lambda rid, relay, timeout: iter(_sample_events()))
    app = cli_module.build_app()
    result = CliRunner().invoke(app, ["op", "follow", "c" * 64, "--output-as", "json"])
    assert result.exit_code == 0
    lines = [json.loads(line) for line in result.stdout.strip().splitlines()]
    assert [e["kind"] for e in lines] == [2203, KIND_EXECUTION_PROGRESS, 2204]


def test_cli_op_status_no_events(monkeypatch):
    monkeypatch.setattr(cli_module, "_stream_events", lambda rid, relay, timeout: iter(()))
    app = cli_module.build_app()
    result = CliRunner().invoke(app, ["op", "status", "c" * 64])
    assert result.exit_code == 0
    assert "no chain events" in result.stdout


def test_cli_op_group_in_help():
    app = cli_module.build_app()
    result = CliRunner().invoke(app, ["--help"])
    assert "op" in result.stdout


# --------------------------------------------------------------------------- #
# MCP adapter progress + streaming

def test_mcp_adapter_ingests_progress_and_result():
    adapter = NostrMCPAdapter(
        requester_sk="a" * 64,
        requester_pubkey="b" * 64,
        control_relay="ws://relay",
        transport=lambda _relay, _event: None,
    )
    progress = build_execution_progress("a" * 64, "b" * 64, "c" * 64, stage="database", progress=0.5)
    assert adapter.ingest_event(progress) is True
    assert adapter.latest_progress("c" * 64)["stage"] == "database"
    result = {"kind": 2204, "tags": [["e", "c" * 64]], "content": json.dumps({"ok": True, "result": {}})}
    assert adapter.ingest_event(result) is True
    assert adapter.result("c" * 64)["ok"] is True
    assert adapter.latest_progress("c" * 64)["stage"] == "database"


def test_mcp_adapter_events_delegates_to_stream(monkeypatch):
    sentinel = iter([{"kind": 2204}])
    captured = {}

    def fake_stream(request_id, **kwargs):
        captured.update({"request_id": request_id, **kwargs})
        return sentinel

    monkeypatch.setattr(events_module, "stream_operation_events", fake_stream)
    adapter = NostrMCPAdapter(
        requester_sk="a" * 64,
        requester_pubkey="b" * 64,
        control_relay="ws://relay",
        transport=lambda _relay, _event: None,
    )
    assert adapter.events("c" * 64, timeout=12) is sentinel
    assert captured["request_id"] == "c" * 64
    assert captured["relay_url"] == "ws://relay"
    assert captured["timeout"] == 12
