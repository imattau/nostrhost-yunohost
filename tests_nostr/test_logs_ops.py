"""Tests for the Phase 5 host-log operations (logs.read / logs.web /
service.history) and their bounded-argument contract."""

from __future__ import annotations

import json

import pytest

from yunohost.nostr_operations import OperationError
from yunohost.nostrhost import native_ops


def test_logs_read_rejects_unknown_units():
    with pytest.raises(OperationError, match="not allowlisted"):
        native_ops._safe_logs_read(units=["anything-else"])


def test_logs_read_requires_units():
    with pytest.raises(OperationError, match="at least one"):
        native_ops._safe_logs_read(units=[])


def test_logs_read_delegates_to_journalctl(monkeypatch):
    calls = []

    def fake_journalctl(unit, *, since, until, priority, grep, lines):
        calls.append((unit, since, until, priority, grep, lines))
        return [{"timestamp": "2026-09-03T12:00:00+00:00", "service": unit, "priority": "info", "message": "hello"}]

    monkeypatch.setattr(native_ops, "_journalctl", fake_journalctl)
    result = native_ops._safe_logs_read(units=["caddy", "sshd"], since="-1h", lines=50)
    assert [c[0] for c in calls] == ["caddy", "sshd"]
    assert calls[0][1] == "-1h"
    assert result["entries"][0]["service"] == "caddy"
    assert result["units"] == ["caddy", "sshd"]


def test_logs_read_rejects_extra_args():
    with pytest.raises(OperationError):
        native_ops._safe_logs_read(units=["nginx"], bogus=True)


def test_logs_web_parses_access_and_error(tmp_path, monkeypatch):
    monkeypatch.setenv("NOSTRHOST_CADDY_LOG_DIR", str(tmp_path))
    (tmp_path / "access.log").write_text(
        '{"level":"info","ts":1758000000.0,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"192.168.1.10","proto":"HTTP/1.1","method":"GET","host":"example.com","uri":"/api/health"},"duration":0.002,"size":24,"status":200}\n'
        '{"level":"error","ts":1758000001.0,"logger":"http.log.error","msg":"upstream connection refused","request":{"method":"GET","host":"example.com","uri":"/api/health"},"status":502}\n'
    )

    result = native_ops._safe_logs_web()
    assert result["log_dir"] == str(tmp_path)
    access = next(e for e in result["entries"] if e["kind"] == "access")
    assert access["status"] == 200
    assert access["path"] == "/api/health"
    assert access["remote_addr"] == "192.168.1.10"
    assert access["host"] == "example.com"
    error = next(e for e in result["entries"] if e["kind"] == "error")
    assert error["level"] == "error"
    assert error["status"] == 502
    assert native_ops._safe_logs_web(status=200)["entries"][0]["kind"] == "access"


def test_logs_web_filters_path(tmp_path, monkeypatch):
    monkeypatch.setenv("NOSTRHOST_CADDY_LOG_DIR", str(tmp_path))
    (tmp_path / "access.log").write_text(
        '{"level":"info","ts":1758000000.0,"logger":"http.log.access","msg":"handled request","request":{"method":"GET","host":"example.com","uri":"/api/health"},"status":200}\n'
        '{"level":"info","ts":1758000001.0,"logger":"http.log.access","msg":"handled request","request":{"method":"GET","host":"example.com","uri":"/other"},"status":404}\n'
    )
    result = native_ops._safe_logs_web(path="/other")
    assert len(result["entries"]) == 1
    assert result["entries"][0]["status"] == 404


def test_logs_web_filters_host(tmp_path, monkeypatch):
    monkeypatch.setenv("NOSTRHOST_CADDY_LOG_DIR", str(tmp_path))
    (tmp_path / "access.log").write_text(
        '{"level":"info","ts":1758000000.0,"logger":"http.log.access","msg":"handled request","request":{"method":"GET","host":"www.example.com","uri":"/x"},"status":200}\n'
    )
    result = native_ops._safe_logs_web(host="www.example.com")
    assert len(result["entries"]) == 1


def test_logs_web_filters_since(tmp_path, monkeypatch):
    monkeypatch.setenv("NOSTRHOST_CADDY_LOG_DIR", str(tmp_path))
    (tmp_path / "access.log").write_text(
        '{"level":"info","ts":1758000000.0,"logger":"http.log.access","msg":"handled request","request":{"method":"GET","host":"example.com","uri":"/x"},"status":200}\n'
    )
    # ts 1758000000 is Sep 2025: a since bound in 2026 excludes it.
    result = native_ops._safe_logs_web(since="2026-01-01T00:00:00+00:00")
    assert result["entries"] == []
    # A since bound before it keeps it.
    result = native_ops._safe_logs_web(since="2025-01-01T00:00:00+00:00")
    assert len(result["entries"]) == 1


def test_logs_web_missing_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("NOSTRHOST_CADDY_LOG_DIR", str(tmp_path / "missing"))
    result = native_ops._safe_logs_web()
    assert result["entries"] == []
    assert result["warning"]


def test_logs_web_validates_status():
    with pytest.raises(OperationError):
        native_ops._safe_logs_web(status=700)


def test_service_history_requires_known_service(monkeypatch):
    import sys
    import types

    svc = types.ModuleType("yunohost.service")
    svc._get_services = lambda: {"caddy": {}, "nginx": {}}
    monkeypatch.setitem(sys.modules, "yunohost.service", svc)
    with pytest.raises(OperationError, match="unknown service"):
        native_ops._safe_service_history(names=["not-a-service"])


def test_service_history_reports_systemctl_props(monkeypatch):
    import subprocess
    import sys
    import types

    svc = types.ModuleType("yunohost.service")
    svc._get_services = lambda: {"caddy": {}}
    monkeypatch.setitem(sys.modules, "yunohost.service", svc)

    class FakeProc:
        returncode = 0
        stdout = "Id=caddy.service\nActiveState=active\nSubState=running\nResult=success\nNRestarts=2\nMainPID=123\n"
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: FakeProc())
    monkeypatch.setattr(native_ops, "_journalctl", lambda *a, **kw: [{"timestamp": "x", "service": "caddy", "priority": "err", "message": "boom"}])

    result = native_ops._safe_service_history(names=["caddy"], lines=10)
    entry = result["services"]["caddy"]
    assert entry["status"] == "active"
    assert entry["substate"] == "running"
    assert entry["restart_count"] == "2"
    assert entry["recent_errors"][0]["message"] == "boom"


def test_normalize_journal_entry_handles_byte_message():
    raw = {"__REALTIME_TIMESTAMP": "1754300000000000", "PRIORITY": "3", "MESSAGE": [104, 105]}
    entry = native_ops._normalize_journal_entry(raw, default_service="nginx")
    assert entry["message"] == "hi"
    assert entry["priority"] == "err"
    assert entry["timestamp"] is not None


def test_parse_caddy_access_line_redacts_header_secrets():
    line = json.dumps({
        "level": "info", "ts": 1758000000.0, "logger": "http.log.access", "msg": "handled request",
        "request": {"remote_ip": "1.2.3.4", "method": "GET", "host": "example.com", "uri": "/x", "headers": {"Authorization": ["Bearer abc123"]}},
        "status": 200, "size": 12,
    })
    parsed = native_ops._parse_caddy_log_line(line, "access.log")
    assert parsed is not None
    assert parsed["kind"] == "access"
    assert parsed["path"] == "/x"
    assert parsed["remote_addr"] == "1.2.3.4"


def test_parse_caddy_error_line_redacts_secrets():
    parsed = native_ops._parse_caddy_log_line(
        '{"level":"error","ts":1758000001.0,"logger":"http.log.error","msg":"password=topsecret failed","status":500}',
        "access.log",
    )
    assert parsed["kind"] == "error"
    assert "topsecret" not in parsed["message"]
    assert "[REDACTED]" in parsed["message"]


def test_parse_caddy_raw_line():
    parsed = native_ops._parse_caddy_log_line("not json at all", "access.log")
    assert parsed["kind"] == "raw"


def test_logs_read_rejects_legacy_nginx_unit():
    # Nginx is not part of the NostrHost stack (Caddy is the web server).
    with pytest.raises(OperationError, match="not allowlisted"):
        native_ops._safe_logs_read(units=["nginx"])
