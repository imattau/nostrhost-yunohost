"""The Meltdown diagnosis reads the kernel's mitigation-status interface.

Covers the modernization from the vendored spectre-meltdown-checker shell
script to /sys/devices/system/cpu/vulnerabilities/meltdown.
"""

from __future__ import annotations

import importlib

import pytest


def _diagnoser():
    # The module filename is not a valid identifier, so load it the way the
    # diagnosis framework does; bypass __init__ (this test only calls the
    # sysfs-reading method).
    module = importlib.import_module("yunohost.diagnosers.00-basesystem")
    return object.__new__(module.MyDiagnoser), module


def test_meltdown_absent_interface_is_not_vulnerable(monkeypatch):
    instance, module = _diagnoser()
    monkeypatch.setattr(module, "MELTDOWN_STATUS_PATH", "/nonexistent/meltdown")
    assert instance.is_vulnerable_to_meltdown() is False


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("Vulnerable", True),
        ("Vulnerable: PTI disabled", True),
        ("Mitigation: PTI", False),
        ("Mitigation: Full generic retpoline", False),
        ("Not affected", False),
        ("Unknown: Dependent on hypervisor status", False),
    ],
)
def test_meltdown_reads_kernel_status(monkeypatch, tmp_path, status, expected):
    instance, module = _diagnoser()
    status_file = tmp_path / "meltdown"
    status_file.write_text(status + "\n")
    monkeypatch.setattr(module, "MELTDOWN_STATUS_PATH", str(status_file))
    assert instance.is_vulnerable_to_meltdown() is expected
