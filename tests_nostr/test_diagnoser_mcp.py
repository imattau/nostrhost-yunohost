"""Tests for the MCP diagnosis category (src/diagnosers/60-mcp.py).

The diagnoser's checks are plain functions/generator methods that never
touch the ``Diagnoser`` base class's ``__init__`` (which pulls in the full
moulinette i18n stack, out of scope for the lightweight tests_nostr suite —
see tests_nostr/conftest.py). Tests call the module's helpers directly and
the check generators as unbound functions, matching how ``run()`` uses them.
"""

from __future__ import annotations

import importlib
import subprocess

import pytest

mcp = importlib.import_module("yunohost.diagnosers.60-mcp")


def _completed(stdout: str):
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")


def test_systemd_active_reports_state(monkeypatch):
    monkeypatch.setattr(mcp.shutil, "which", lambda name: "/usr/bin/systemctl")
    monkeypatch.setattr(mcp.subprocess, "run", lambda *a, **kw: _completed("active\n"))
    assert mcp._systemd_active("nostr-operationsd") == "active"


def test_systemd_active_none_when_systemctl_missing(monkeypatch):
    monkeypatch.setattr(mcp.shutil, "which", lambda name: None)
    assert mcp._systemd_active("nostr-operationsd") is None


def test_systemd_active_none_on_timeout(monkeypatch):
    monkeypatch.setattr(mcp.shutil, "which", lambda name: "/usr/bin/systemctl")

    def boom(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="systemctl", timeout=5)

    monkeypatch.setattr(mcp.subprocess, "run", boom)
    assert mcp._systemd_active("nostr-operationsd") is None


def test_unit_installed_true_when_listed(monkeypatch):
    monkeypatch.setattr(mcp.shutil, "which", lambda name: "/usr/bin/systemctl")
    monkeypatch.setattr(
        mcp.subprocess,
        "run",
        lambda *a, **kw: _completed("UNIT FILE                STATE\nnostrhost-catalog.service enabled\n"),
    )
    assert mcp._unit_installed("nostrhost-catalog") is True


def test_unit_installed_false_when_absent(monkeypatch):
    monkeypatch.setattr(mcp.shutil, "which", lambda name: "/usr/bin/systemctl")
    monkeypatch.setattr(mcp.subprocess, "run", lambda *a, **kw: _completed("0 unit files listed.\n"))
    assert mcp._unit_installed("nostrhost-catalog") is False


def test_relay_allowed_kinds_parses_toml(tmp_path):
    config = tmp_path / "relay.toml"
    config.write_text("allowed_kinds = [2200, 2201, 32267]\n")
    assert mcp._relay_allowed_kinds(str(config)) == [2200, 2201, 32267]


def test_relay_allowed_kinds_none_when_missing(tmp_path):
    assert mcp._relay_allowed_kinds(str(tmp_path / "nope.toml")) is None


def test_relay_allowed_kinds_none_when_key_absent(tmp_path):
    config = tmp_path / "relay.toml"
    config.write_text('control_relay = "ws://127.0.0.1:4848"\n')
    assert mcp._relay_allowed_kinds(str(config)) is None


def test_check_operationsd_success(monkeypatch):
    monkeypatch.setattr(mcp, "_systemd_active", lambda unit: "active")
    items = list(mcp.MyDiagnoser._check_operationsd(None))
    assert items == [dict(meta={"service": "nostr-operationsd"}, status="SUCCESS", summary="diagnosis_mcp_operationsd_up")]


def test_check_operationsd_reports_error_when_down(monkeypatch):
    monkeypatch.setattr(mcp, "_systemd_active", lambda unit: "inactive")
    items = list(mcp.MyDiagnoser._check_operationsd(None))
    assert items[0]["status"] == "ERROR"
    assert items[0]["summary"] == "diagnosis_mcp_operationsd_down"
    assert items[0]["details"] == ["diagnosis_mcp_operationsd_down_details"]


def test_check_operationsd_warns_when_undeterminable(monkeypatch):
    monkeypatch.setattr(mcp, "_systemd_active", lambda unit: None)
    items = list(mcp.MyDiagnoser._check_operationsd(None))
    assert items[0]["status"] == "WARNING"
    assert items[0]["summary"] == "diagnosis_mcp_service_unknown"


def test_check_catalog_informational_when_not_installed(monkeypatch):
    monkeypatch.setattr(mcp, "_unit_installed", lambda unit: False)
    monkeypatch.setattr(mcp, "_relay_allowed_kinds", lambda path: None)
    items = list(mcp.MyDiagnoser._check_catalog(None))
    assert items == [dict(meta={"service": "nostrhost-catalog"}, status="INFO", summary="diagnosis_mcp_catalog_not_installed")]


def test_check_catalog_reports_running_and_allowed_kind(monkeypatch):
    monkeypatch.setattr(mcp, "_unit_installed", lambda unit: True)
    monkeypatch.setattr(mcp, "_systemd_active", lambda unit: "active")
    monkeypatch.setattr(mcp, "_relay_allowed_kinds", lambda path: [mcp.CATALOG_DECLARATION_KIND])
    items = list(mcp.MyDiagnoser._check_catalog(None))
    assert items[0] == dict(meta={"service": "nostrhost-catalog"}, status="SUCCESS", summary="diagnosis_mcp_catalog_up")
    assert items[1] == dict(status="SUCCESS", summary="diagnosis_mcp_catalog_kind_allowed")


def test_check_catalog_warns_when_kind_not_allowed(monkeypatch):
    monkeypatch.setattr(mcp, "_unit_installed", lambda unit: True)
    monkeypatch.setattr(mcp, "_systemd_active", lambda unit: "active")
    monkeypatch.setattr(mcp, "_relay_allowed_kinds", lambda path: [2200])
    items = list(mcp.MyDiagnoser._check_catalog(None))
    assert items[1]["status"] == "WARNING"
    assert items[1]["summary"] == "diagnosis_mcp_catalog_kind_not_allowed"
    assert items[1]["details"] == ["diagnosis_mcp_catalog_kind_not_allowed_details"]


def test_check_catalog_skips_kind_check_when_relay_config_unreadable(monkeypatch):
    monkeypatch.setattr(mcp, "_unit_installed", lambda unit: True)
    monkeypatch.setattr(mcp, "_systemd_active", lambda unit: "active")
    monkeypatch.setattr(mcp, "_relay_allowed_kinds", lambda path: None)
    items = list(mcp.MyDiagnoser._check_catalog(None))
    assert len(items) == 1  # only the service-status item, no kind verdict


def test_run_combines_both_checks(monkeypatch):
    monkeypatch.setattr(mcp, "_systemd_active", lambda unit: "active")
    monkeypatch.setattr(mcp, "_unit_installed", lambda unit: False)
    monkeypatch.setattr(mcp, "_relay_allowed_kinds", lambda path: None)
    # bypass Diagnoser.__init__ (pulls in the full moulinette i18n stack,
    # out of scope here) — run() only calls the two check methods below.
    diagnoser = object.__new__(mcp.MyDiagnoser)
    items = list(mcp.MyDiagnoser.run(diagnoser))
    summaries = [item["summary"] for item in items]
    assert summaries == ["diagnosis_mcp_operationsd_up", "diagnosis_mcp_catalog_not_installed"]
