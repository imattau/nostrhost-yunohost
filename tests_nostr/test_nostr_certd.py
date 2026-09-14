"""Regression tests for the timer-backed Caddy certificate exporter."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import types

import yaml

# The lightweight tests_nostr environment intentionally omits PyOpenSSL.  The
# main/managed-service tests below do not parse certificates, so provide only
# the import surface needed to load the module.
if importlib.util.find_spec("OpenSSL") is None:
    openssl = types.ModuleType("OpenSSL")
    openssl.crypto = types.SimpleNamespace()
    sys.modules["OpenSSL"] = openssl

from yunohost import nostr_certd


def test_main_returns_success_when_certificate_changes(monkeypatch):
    monkeypatch.setattr(nostr_certd, "_caddy_domains", lambda: {"example.test"})
    monkeypatch.setattr(
        nostr_certd, "export_domain", lambda domain, dry_run=False: True
    )

    assert nostr_certd.main(["--once"]) == 0


def test_main_returns_success_when_nothing_changes(monkeypatch):
    monkeypatch.setattr(nostr_certd, "_caddy_domains", lambda: {"example.test"})
    monkeypatch.setattr(
        nostr_certd, "export_domain", lambda domain, dry_run=False: False
    )

    assert nostr_certd.main(["--once"]) == 0


def test_managed_service_uses_timer_as_health_signal():
    services_path = Path(__file__).resolve().parents[1] / "conf/yunohost/services.yml"
    services = yaml.safe_load(services_path.read_text())
    certd = services["nostrhost-certd"]

    assert certd["actual_systemd_service"] == "nostrhost-certd"
    assert certd["test_status"] == "systemctl is-active --quiet nostrhost-certd.timer"
