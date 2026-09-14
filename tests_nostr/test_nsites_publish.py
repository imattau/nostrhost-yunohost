"""Nsites Phase 3a tests: site registry, publish plan/verify/broadcast/record.

Run with: PYTHONPATH=src:../../libs/nostrhost-policy/src:../../libs/nostrhost-auth/src \
  python -m pytest -c /dev/null tests_nostr/test_nsites_publish.py -q
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nostrhost.nsites import operations, service
from nostrhost.nsites.manifest import aggregate_hash
from nostrhost.nsites.models import GatewayConfig

CORPUS_DIR = Path(__file__).resolve().parents[3] / "tools" / "tests" / "nsites" / "corpus"

# The corpus generator's test key; valid corpus events are signed by it.
TEST_PUBKEY = "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732"
HOST_PUBKEY = (
    pytest.importorskip("nostr_sdk").Keys.parse("deadbeef" * 8).public_key().to_hex()
)


class FakeCaddy:
    def __init__(self) -> None:
        self.ensured: list[str] = []

    def ensure_nsite_routes(self, domain: str, upstream: str) -> str:
        self.ensured.append(domain)
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


def corpus_event(name: str) -> dict:
    data = json.loads((CORPUS_DIR / name).read_text(encoding="utf-8"))
    assert data["expect"]["valid"]
    return data["event"]


def raw_corpus_event(name: str) -> dict:
    data = json.loads((CORPUS_DIR / name).read_text(encoding="utf-8"))
    return data["event"]


def root_event() -> dict:
    return corpus_event("valid-root.json")


def named_event() -> dict:
    return corpus_event("valid-named.json")


def snapshot_event() -> dict:
    return corpus_event("valid-snapshot.json")


def event_paths(event: dict) -> list[dict[str, str]]:
    return [
        {"path": t[1], "sha256": t[2]}
        for t in event.get("tags", [])
        if isinstance(t, list) and len(t) >= 3 and t[0] == "path"
    ]


def event_servers(event: dict) -> list[str]:
    return [t[1] for t in event.get("tags", []) if isinstance(t, list) and t and t[0] == "server"]


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
    svc = service.NsiteService(
        state_dir=state_dir,
        caddy=FakeCaddy(),
        systemctl=FakeSystemctl(),
        config_path=tmp_path / "nsite.toml",
    )
    svc.enable(GatewayConfig(domain="sites.example.org"))
    return svc


def ok_broadcast(relays: list[str] | None = None):
    """Monkeypatched ``_broadcast`` that records calls and succeeds."""

    def fake(event: dict, relay_list: list[str], timeout: float = 10.0) -> dict:
        return {
            "results": [{"relay": r, "ok": True} for r in relay_list],
            "ok_count": len(relay_list),
            "failed_count": 0,
            "succeeded": True,
        }

    return fake


def register_root(svc: service.NsiteService) -> None:
    svc.site_register(TEST_PUBKEY, kind=15128, d="", title="root site")


def assert_not_recorded(svc: service.NsiteService, pubkey: str = TEST_PUBKEY, d: str = "") -> None:
    """A rejected publish must leave the allowlist record unmodified (no
    ``last_event_id``), i.e. nothing was recorded by publish itself."""
    path = service.site_path(svc.state_dir, pubkey, d)
    assert path.exists(), "the site must be registered before publish"
    record = json.loads(path.read_text(encoding="utf-8"))
    assert not record.get("last_event_id")


# ---------------------------------------------------------------------------
# Site registry
# ---------------------------------------------------------------------------


def test_register_list_inspect_unregister(tmp_path: Path):
    svc = make_service(tmp_path)
    register_root(svc)
    listing = svc.site_list()
    assert listing["count"] == 1
    assert listing["sites"][0]["pubkey"] == TEST_PUBKEY
    assert listing["sites"][0]["kind"] == 15128

    inspect = svc.site_inspect(TEST_PUBKEY)
    assert inspect["site"]["pubkey"] == TEST_PUBKEY
    assert inspect["site"]["d"] == ""

    # registration re-renders the allowlist into the gateway config
    assert "[[sites]]" in svc.config_path.read_text(encoding="utf-8")

    svc.site_unregister(TEST_PUBKEY)
    assert svc.site_list()["count"] == 0
    with pytest.raises(service.NsiteError):
        svc.site_inspect(TEST_PUBKEY)


def test_register_named_and_unregister_missing(tmp_path: Path):
    svc = make_service(tmp_path)
    svc.site_register(TEST_PUBKEY, kind=35128, d="blog", title="blog")
    assert svc.site_inspect(TEST_PUBKEY, d="blog")["site"]["d"] == "blog"
    with pytest.raises(service.NsiteError, match="invalid named-site d tag"):
        svc.site_register(TEST_PUBKEY, kind=35128, d="bad d tag")
    with pytest.raises(service.NsiteError):
        svc.site_unregister(TEST_PUBKEY, d="nonexistent")


def test_register_rejects_bad_kind_and_root_d(tmp_path: Path):
    svc = make_service(tmp_path)
    with pytest.raises(service.NsiteError, match="site kind"):
        svc.site_register(TEST_PUBKEY, kind=9999)
    with pytest.raises(service.NsiteError, match="root sites take no d"):
        svc.site_register(TEST_PUBKEY, kind=15128, d="blog")


# ---------------------------------------------------------------------------
# Publish: happy path and every rejection before broadcast/record
# ---------------------------------------------------------------------------


def test_publish_happy_path(tmp_path: Path, monkeypatch):
    svc = make_service(tmp_path)
    register_root(svc)
    event = root_event()
    plan = svc.publish_plan(
        TEST_PUBKEY, kind=15128, d="", items=event_paths(event), servers=event_servers(event)
    )["plan"]

    # the plan digest binds exactly the event's signed content
    from nostrhost.nsites.service import plan_digest

    assert plan["plan_sha256"] == plan_digest(
        kind=15128,
        d="",
        paths=[(p["path"], p["sha256"]) for p in event_paths(event)],
        servers=event_servers(event),
    )

    monkeypatch.setattr(service, "_broadcast", ok_broadcast())
    result = svc.publish(event, plan_sha256=plan["plan_sha256"])
    assert result["ok"] is True
    assert result["event_id"] == event["id"]
    assert result["label"].startswith("npub1")
    assert result["site_url"].endswith("sites.example.org")
    assert result["plan_matched"] is True

    record = svc.site_inspect(TEST_PUBKEY)["site"]
    assert record["last_event_id"] == event["id"]
    assert record["aggregate_hash"] == aggregate_hash(
        [(p["path"], p["sha256"]) for p in event_paths(event)]
    )


def test_publish_digest_mismatch_rejected_without_broadcast(tmp_path: Path, monkeypatch):
    svc = make_service(tmp_path)
    register_root(svc)
    event = root_event()

    def explode(*args, **kwargs):  # pragma: no cover - must never be reached
        raise AssertionError("broadcast must not run after a rejected publish")

    monkeypatch.setattr(service, "_broadcast", explode)
    with pytest.raises(service.NsiteError, match="plan digest mismatch"):
        svc.publish(event, plan_sha256="0" * 64)
    assert_not_recorded(svc)


def test_publish_bad_signature_rejected_without_broadcast(tmp_path: Path, monkeypatch):
    svc = make_service(tmp_path)
    register_root(svc)
    event = root_event()
    plan = svc.publish_plan(
        TEST_PUBKEY, kind=15128, d="", items=event_paths(event), servers=event_servers(event)
    )["plan"]
    forged = dict(event)
    forged["sig"] = "0" * 128

    def explode(*args, **kwargs):  # pragma: no cover - must never be reached
        raise AssertionError("broadcast must not run after a rejected publish")

    monkeypatch.setattr(service, "_broadcast", explode)
    with pytest.raises(service.NsiteError, match="bad_signature"):
        svc.publish(forged, plan_sha256=plan["plan_sha256"])
    assert_not_recorded(svc)


def test_publish_host_key_signer_rejected(tmp_path: Path, monkeypatch):
    svc = make_service(tmp_path)
    register_root(svc)
    event = raw_corpus_event("invalid-forbidden-signer.json")
    assert event["pubkey"] == HOST_PUBKEY

    def explode(*args, **kwargs):  # pragma: no cover - must never be reached
        raise AssertionError("broadcast must not run for a host-key signer")

    monkeypatch.setattr(service, "_broadcast", explode)
    monkeypatch.setattr(
        "nostrhost.nsites.signer_guard.forbidden_signer_pubkeys",
        lambda: frozenset({HOST_PUBKEY}),
    )
    with pytest.raises(service.NsiteError, match="forbidden_signer"):
        svc.publish(event, plan_sha256="0" * 64)
    assert not service.site_path(svc.state_dir, HOST_PUBKEY).exists()


def test_publish_unregistered_pubkey_rejected_in_hosted_mode(tmp_path: Path, monkeypatch):
    svc = make_service(tmp_path)  # gateway enabled, nothing registered
    event = root_event()
    plan = svc.publish_plan(
        TEST_PUBKEY, kind=15128, d="", items=event_paths(event), servers=event_servers(event)
    )["plan"]

    def explode(*args, **kwargs):  # pragma: no cover - must never be reached
        raise AssertionError("broadcast must not run for an unregistered pubkey")

    monkeypatch.setattr(service, "_broadcast", explode)
    with pytest.raises(service.NsiteError, match="not registered in hosted mode"):
        svc.publish(event, plan_sha256=plan["plan_sha256"])
    assert not service.site_path(svc.state_dir, TEST_PUBKEY).exists()


def test_publish_requires_enabled_gateway(tmp_path: Path, monkeypatch):
    svc = make_service(tmp_path)
    svc.disable()
    event = root_event()
    with pytest.raises(service.NsiteError, match="gateway is not enabled"):
        svc.publish(event, plan_sha256="0" * 64)


def test_publish_no_relay_reached_fails_and_does_not_record(tmp_path: Path, monkeypatch):
    svc = make_service(tmp_path)
    register_root(svc)
    event = root_event()
    plan = svc.publish_plan(
        TEST_PUBKEY, kind=15128, d="", items=event_paths(event), servers=event_servers(event)
    )["plan"]

    monkeypatch.setattr(
        service,
        "_broadcast",
        lambda event, relay_list, timeout=10.0: {
            "results": [{"relay": r, "ok": False, "error": "unreachable"} for r in relay_list],
            "ok_count": 0,
            "failed_count": len(relay_list),
            "succeeded": False,
        },
    )
    with pytest.raises(service.NsiteError, match="reached no relay"):
        svc.publish(event, plan_sha256=plan["plan_sha256"])
    assert_not_recorded(svc)


def test_publish_named_site(tmp_path: Path, monkeypatch):
    svc = make_service(tmp_path)
    svc.site_register(TEST_PUBKEY, kind=35128, d="blog", title="blog")
    event = named_event()
    plan = svc.publish_plan(
        TEST_PUBKEY, kind=35128, d="blog", items=event_paths(event), servers=event_servers(event)
    )["plan"]
    monkeypatch.setattr(service, "_broadcast", ok_broadcast())
    result = svc.publish(event, plan_sha256=plan["plan_sha256"])
    assert result["ok"] is True
    record = svc.site_inspect(TEST_PUBKEY, d="blog")["site"]
    assert record["last_event_id"] == event["id"]
    assert record["d"] == "blog"


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------


def test_snapshot_records_on_referenced_site(tmp_path: Path, monkeypatch):
    svc = make_service(tmp_path)
    svc.site_register(TEST_PUBKEY, kind=35128, d="blog", title="blog")
    event = snapshot_event()
    monkeypatch.setattr(service, "_broadcast", ok_broadcast())
    snap_aggregate = aggregate_hash(
        [(t[1], t[2]) for t in event["tags"] if t[0] == "path"]
    )
    result = svc.snapshot(event, plan_sha256=snap_aggregate)
    assert result["ok"] is True
    record = svc.site_inspect(TEST_PUBKEY, d="blog")["site"]
    assert event["id"] in record.get("snapshots", [])


def test_snapshot_rejects_non_snapshot(tmp_path: Path, monkeypatch):
    svc = make_service(tmp_path)
    register_root(svc)
    event = root_event()

    def explode(*args, **kwargs):  # pragma: no cover - must never be reached
        raise AssertionError("broadcast must not run")

    monkeypatch.setattr(service, "_broadcast", explode)
    with pytest.raises(service.NsiteError):
        svc.snapshot(event)


# ---------------------------------------------------------------------------
# Validate / plan / resolve / reachability
# ---------------------------------------------------------------------------


def test_validate_manifest_reports_verdict(tmp_path: Path):
    svc = make_service(tmp_path)
    verdict = svc.validate_manifest(root_event())
    assert verdict["valid"] is True
    assert verdict["site_type"] == "root"
    assert verdict["aggregate_hash"]
    bad = svc.validate_manifest({"kind": 15128, "tags": [], "pubkey": TEST_PUBKEY})
    assert bad["valid"] is False


def test_plan_rejects_bad_items(tmp_path: Path):
    svc = make_service(tmp_path)
    with pytest.raises(service.NsiteError, match="at least one path/blob"):
        svc.publish_plan(TEST_PUBKEY, kind=15128, d="", items=[])
    with pytest.raises(service.NsiteError, match="start with '/'"):
        svc.publish_plan(TEST_PUBKEY, kind=15128, d="", items=[{"path": "index.html", "sha256": "0" * 64}])
    with pytest.raises(service.NsiteError, match="invalid blob hash"):
        svc.publish_plan(TEST_PUBKEY, kind=15128, d="", items=[{"path": "/index.html", "sha256": "zz"}])
    with pytest.raises(service.NsiteError, match="refusing non-TLS"):
        svc.publish_plan(
            TEST_PUBKEY, kind=15128, d="", items=event_paths(root_event()),
            servers=["http://insecure.example.com"],
        )


def test_plan_digest_binds_servers(tmp_path: Path):
    svc = make_service(tmp_path)
    base = svc.publish_plan(
        TEST_PUBKEY, kind=15128, d="", items=event_paths(root_event()),
        servers=["https://blossom.example.com"],
    )["plan"]
    changed = svc.publish_plan(
        TEST_PUBKEY, kind=15128, d="", items=event_paths(root_event()),
        servers=["https://blossom.example.com", "https://other.example.com"],
    )["plan"]
    assert base["plan_sha256"] != changed["plan_sha256"]


def test_resolve_fetches_newest_valid_manifest(tmp_path: Path, monkeypatch):
    svc = make_service(tmp_path)
    event = root_event()
    monkeypatch.setattr(service, "_query_relay_events", lambda *a, **k: [event])
    result = svc.resolve(pubkey=TEST_PUBKEY)
    assert result["found"] is True
    assert result["manifest"]["event_id"] == event["id"]
    assert result["manifest"]["kind"] == 15128


def test_resolve_label_root(tmp_path: Path, monkeypatch):
    svc = make_service(tmp_path)
    event = root_event()
    monkeypatch.setattr(service, "_query_relay_events", lambda *a, **k: [event])
    from nostr_sdk import PublicKey

    npub = PublicKey.parse(TEST_PUBKEY).to_bech32()
    result = svc.resolve(label=npub)
    assert result["found"] is True


def test_resolve_rejects_bad_label(tmp_path: Path):
    svc = make_service(tmp_path)
    with pytest.raises(service.NsiteError, match="cannot decode"):
        svc.resolve(label="!!not-a-label!!")


def test_reachability_probes_relays_and_servers(tmp_path: Path, monkeypatch):
    svc = make_service(tmp_path)
    monkeypatch.setattr(service, "_query_relay_events", lambda *a, **k: [])
    monkeypatch.setattr(
        service, "_http_probe",
        lambda url, timeout=5.0: {"url": url, "ok": True, "status": 200},
    )
    result = svc.reachability(relays=["wss://relay.test"], servers=["https://blossom.test"])
    assert result["relays"][0]["ok"] is True
    assert result["servers"][0]["ok"] is True


# ---------------------------------------------------------------------------
# Registry wiring + signer guard
# ---------------------------------------------------------------------------


def test_registry_wiring():
    from yunohost.nostr_operations import TOOLS

    read_only = ("nsite.list", "nsite.inspect", "nsite.resolve", "nsite.validate_manifest",
                 "nsite.reachability", "nsite.publish.plan")
    for name in read_only:
        spec = TOOLS[name]
        assert spec.scope == "nsites.read"
        assert spec.require_approval is False
        if name != "nsite.list":
            assert spec.input_schema() is not None

    for name in ("nsite.register", "nsite.unregister"):
        spec = TOOLS[name]
        assert spec.scope == "nsites.admin"
        assert spec.require_approval is True

    for name in ("nsite.publish", "nsite.snapshot"):
        spec = TOOLS[name]
        assert spec.scope == "nsites.publish"
        assert spec.require_approval is True
        assert spec.input_schema() is not None


def test_operations_strict_models():
    with pytest.raises(Exception):
        operations.SiteArgs(pubkey=TEST_PUBKEY, unexpected="x")
    with pytest.raises(Exception):
        operations.PublishArgs(event={}, plan_sha256="0" * 64, extra="x")
    args = operations.PublishArgs(event={"kind": 1}, plan_sha256="0" * 64)
    assert args.plan_sha256 == "0" * 64


def test_signer_guard_from_operator_config(tmp_path: Path):
    from nostrhost.nsites.signer_guard import forbidden_signer_pubkeys

    cfg = tmp_path / "operator.toml"
    cfg.write_text(f'server_sk = "{"aa" * 32}"\noperator_sk = "{"bb" * 32}"\npublisher_sk = "{"cc" * 32}"\n', encoding="utf-8")
    forbidden = forbidden_signer_pubkeys(operator_config=cfg, force_refresh=True)
    from nostr_sdk import Keys

    assert Keys.parse("aa" * 32).public_key().to_hex() in forbidden
    assert Keys.parse("bb" * 32).public_key().to_hex() in forbidden
    assert Keys.parse("cc" * 32).public_key().to_hex() in forbidden
    assert TEST_PUBKEY not in forbidden


def test_signer_guard_missing_config_is_empty(tmp_path: Path):
    from nostrhost.nsites.signer_guard import forbidden_signer_pubkeys

    missing = tmp_path / "does-not-exist.toml"
    assert forbidden_signer_pubkeys(operator_config=missing, force_refresh=True) == frozenset()
