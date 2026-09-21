"""Local Blossom server (Phase 5, D4) lifecycle tests.

Run with: PYTHONPATH=src python -m pytest -c /dev/null tests_nostr/test_nsites_blossom.py -q
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nostrhost.nsites import operations, service
from nostrhost.nsites.models import GatewayBlossomLocal, GatewayConfig


class FakeCaddy:
    def ensure_nsite_routes(self, domain: str, upstream: str) -> str:
        return f"nostrhost-nsite:{domain}"

    def remove_nsite_routes(self, domain: str) -> None:
        pass


class FakeSystemctl:
    def __init__(self, active: bool = True) -> None:
        self.active = active
        self.calls: list[str] = []

    def __call__(self, *args: str) -> str:
        self.calls.append(" ".join(args))
        if args and args[0] == "is-active":
            return "active" if self.active else "inactive"
        if args and args[0] == "enable":
            self.active = True
        if args and args[0] == "disable":
            self.active = False
        return ""


def make_service(tmp_path: Path) -> service.NsiteService:
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True)
    (state_dir / "domains-native").mkdir(parents=True)
    (state_dir / "domains-native" / "sites.example.org.json").write_text(
        "{}", encoding="utf-8"
    )
    template_dir = tmp_path / "caddy-templates"
    template_dir.mkdir()
    (template_dir / "caddy_nsite.conf").write_text(
        "{{ domain }}, *.{{ domain }} {\n\tlog\n\ttls {\n\t\ton_demand\n\t}\n}\n",
        encoding="utf-8",
    )
    conf_dir = tmp_path / "caddy-conf.d"
    conf_dir.mkdir()
    service.CADDY_TEMPLATE_DIR = template_dir
    service.CADDY_CONF_DIR = conf_dir
    return service.NsiteService(
        state_dir=state_dir,
        caddy=FakeCaddy(),
        systemctl=FakeSystemctl(),
        config_path=tmp_path / "nsite.toml",
    )


def local(**kw) -> GatewayBlossomLocal:
    return GatewayBlossomLocal(**kw)


def test_config_to_toml_renders_local_section():
    text = GatewayConfig(domain="sites.example.org").to_toml()
    assert "[blossom.local]" in text
    assert 'listen = "127.0.0.1:8197"' in text
    assert "enabled = false" in text


def test_blossom_enable_flow(tmp_path: Path):
    svc = make_service(tmp_path)
    svc.enable(GatewayConfig(domain="sites.example.org"))
    result = svc.blossom_enable(local())
    assert result["ok"] is True
    assert "reloaded" in result
    toml = svc.config_path.read_text()
    assert "[blossom.local]" in toml
    assert "enabled = true" in toml
    assert 'listen = "127.0.0.1:8197"' in toml
    state = service.load_gateway(svc.state_dir)
    assert state["config"]["blossom"]["local"]["enabled"] is True


def test_blossom_enable_requires_gateway(tmp_path: Path):
    svc = make_service(tmp_path)
    with pytest.raises(service.NsiteError, match="gateway is not enabled"):
        svc.blossom_enable(local())


def test_blossom_configure_updates_contract(tmp_path: Path):
    svc = make_service(tmp_path)
    svc.enable(GatewayConfig(domain="sites.example.org"))
    svc.blossom_enable(local())
    result = svc.blossom_configure(local(quota_bytes=5 << 20, retention_days=7, max_blob_bytes=1 << 20))
    assert result["ok"] is True
    toml = svc.config_path.read_text()
    assert "quota_bytes = 5242880" in toml
    assert "retention_days = 7" in toml
    assert "max_blob_bytes = 1048576" in toml


def test_blossom_disable_flow(tmp_path: Path):
    svc = make_service(tmp_path)
    svc.enable(GatewayConfig(domain="sites.example.org"))
    svc.blossom_enable(local())
    result = svc.blossom_disable()
    assert result["ok"] is True
    toml = svc.config_path.read_text()
    assert "enabled = false" in toml
    state = service.load_gateway(svc.state_dir)
    assert state["config"]["blossom"]["local"]["enabled"] is False


def test_blossom_enable_rejects_non_loopback_listen(tmp_path: Path):
    svc = make_service(tmp_path)
    svc.enable(GatewayConfig(domain="sites.example.org"))
    with pytest.raises(service.NsiteError, match="loopback"):
        svc.blossom_enable(local(listen="0.0.0.0:8197"))


def test_blossom_enable_rejects_missing_data_dir(tmp_path: Path):
    svc = make_service(tmp_path)
    svc.enable(GatewayConfig(domain="sites.example.org"))
    with pytest.raises(service.NsiteError, match="data_dir"):
        svc.blossom_enable(local(data_dir=""))


def test_blossom_enable_rejects_oversize_blob(tmp_path: Path):
    svc = make_service(tmp_path)
    svc.enable(GatewayConfig(domain="sites.example.org"))
    with pytest.raises(service.NsiteError, match="128 MiB"):
        svc.blossom_enable(local(max_blob_bytes=service.MAX_ALLOWED_BLOB_BYTES + 1))


def test_blossom_enable_rejects_bad_pubkey(tmp_path: Path):
    svc = make_service(tmp_path)
    svc.enable(GatewayConfig(domain="sites.example.org"))
    with pytest.raises(service.NsiteError, match="allow_pubkeys"):
        svc.blossom_enable(local(allow_pubkeys=["nope"]))


def test_blossom_status_disabled(tmp_path: Path):
    svc = make_service(tmp_path)
    svc.enable(GatewayConfig(domain="sites.example.org"))
    status = svc.blossom_status()
    assert status["blossom"]["enabled"] is False
    assert status["blossom"]["health"] == "degraded"
    assert status["blossom"]["used_bytes"] is None


def test_blossom_status_enabled_reachable(tmp_path: Path, monkeypatch):
    import json as _json
    from contextlib import contextmanager

    svc = make_service(tmp_path)
    svc.enable(GatewayConfig(domain="sites.example.org"))
    svc.blossom_enable(local())

    @contextmanager
    def fake_urlopen(url, timeout=2.0):
        class FakeResp:
            status = 200

            def read(self):
                return _json.dumps(
                    {"used_bytes": 4096, "blobs": 2, "quota_bytes": 1073741824}
                ).encode()

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        yield FakeResp()

    monkeypatch.setattr(service.urllib.request, "urlopen", fake_urlopen)
    status = svc.blossom_status()
    b = status["blossom"]
    assert b["enabled"] is True
    assert b["health"] == "ok"
    assert b["used_bytes"] == 4096
    assert b["blobs"] == 2


def test_registry_has_blossom_tools():
    from yunohost.nostr_operations import TOOLS

    spec = TOOLS["nsite.blossom.status"]
    assert spec.scope == "nsites.read" and spec.require_approval is False
    for name in ("nsite.blossom.enable", "nsite.blossom.configure", "nsite.blossom.disable"):
        spec = TOOLS[name]
        assert spec.scope == "nsites.admin"
        assert spec.require_approval is True
        assert spec.input_schema() is not None


def test_blossom_args_strict_validation():
    with pytest.raises(Exception):
        operations.BlossomLocalArgs(listen="127.0.0.1:8197", unexpected="x")
    args = operations.BlossomLocalArgs(quota_bytes=1 << 20, retention_days=5)
    assert args.quota_bytes == 1 << 20
    assert args.retention_days == 5


def test_blossom_safe_handler_wraps_errors():
    from nostrhost.core import NostrHostError

    with pytest.raises(NostrHostError, match="gateway is not enabled"):
        operations._safe_blossom_enable(
            listen="127.0.0.1:8197",
            data_dir="/var/lib/nostrhost-nsite/blossom",
            quota_bytes=1 << 20,
            max_blob_bytes=33554432,
            retention_days=30,
            allow_pubkeys=[],
        )
