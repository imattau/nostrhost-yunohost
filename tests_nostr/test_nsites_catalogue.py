"""Phase 5 tests: catalogue linkage (app tag), copy plans (a/A), open gateway mode.

Covers the optional ``app`` tag (kind-32267 address) validation and
persistence, the ``catalogue_nsite_links`` index that annotates the normal
nostrhost catalogue (custom-catalog logic — nsites are never a separate
catalogue), ``publish_plan(copy_of=…)`` producing ``a`` (parent) / ``A``
(origin) tags from a source site, and open gateway mode (any decodable label;
requires the operator's ACME DNS-01 token in operator.toml; wildcard DNS-01
snippet rendered with the provider).

Run with: PYTHONPATH=src:../../libs/nostrhost-policy/src:../../libs/nostrhost-auth/src \
  python -m pytest -c /dev/null tests_nostr/test_nsites_catalogue.py -q
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from nostrhost.nsites import service
from nostrhost.nsites.manifest import aggregate_hash, named_label, validate_manifest
from nostrhost.nsites.models import GatewayConfig

pytest.importorskip("nostr_sdk")

GATEWAY = "sites.example.org"


class FakeCaddy:
    def __init__(self) -> None:
        self.ensured: list[str] = []
        self.removed: list[str] = []

    def ensure_nsite_routes(self, domain: str, upstream: str) -> str:
        self.ensured.append(domain)
        return f"nostrhost-nsite:{domain}"

    def remove_nsite_routes(self, domain: str) -> None:
        self.removed.append(domain)


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
    (state_dir / "domains-native" / f"{GATEWAY}.json").write_text("{}", encoding="utf-8")
    template_dir = tmp_path / "caddy-templates"
    template_dir.mkdir()
    (template_dir / "caddy_nsite.conf").write_text(
        "{{ domain }}, *.{{ domain }} {\n\tlog\n\ttls {\n\t\ton_demand\n\t}\n}\n",
        encoding="utf-8",
    )
    (template_dir / "caddy_nsite_open.conf").write_text(
        "{{ domain }}, *.{{ domain }} {\n\tlog\n\ttls {\n\t\tdns {{ provider }} {$ACME_DNS_API_TOKEN}\n\t}\n}\n",
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


def ok_broadcast(relays: list[str] | None = None):
    def fake(event: dict, relay_list: list[str], timeout: float = 10.0) -> dict:
        return {
            "results": [{"relay": r, "ok": True} for r in relay_list],
            "ok_count": len(relay_list),
            "failed_count": 0,
            "succeeded": True,
        }

    return fake


# -- signing helper (matches nostr_identity._sign_event) ---------------------


def sign_event(sk: str, kind: int, tags: list[list[str]], content: str = "") -> dict:
    from nostr_sdk import EventBuilder, Keys, Kind, Tag, Timestamp

    keys = Keys.parse(sk)
    event = (
        EventBuilder(Kind(kind), content)
        .tags([Tag.parse(t) for t in tags])
        .custom_created_at(Timestamp.from_secs(int(time.time())))
        .finalize(keys)
    )
    return {
        "id": event.id().to_hex(),
        "pubkey": keys.public_key().to_hex(),
        "created_at": int(time.time()),
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": event.signature(),
    }


def new_keys() -> tuple[str, str]:
    from nostr_sdk import Keys

    keys = Keys.generate()
    return keys.secret_key().to_hex(), keys.public_key().to_hex()


def root_manifest(sk: str, pubkey: str, *, d: str = "", app: str = "", servers: list[str] | None = None) -> dict:
    kind = 35128 if d else 15128
    paths = [("/index.html", "a" * 64)]
    tags: list[list[str]] = []
    if d:
        tags.append(["d", d])
    for path, blob in sorted(paths):
        tags.append(["path", path, blob])
    for server in servers or []:
        tags.append(["server", server])
    if app:
        tags.append(["app", app, "wss://relay.example.org"])
    tags.append(["x", aggregate_hash(paths), "aggregate"])
    return sign_event(sk, kind, tags)


def operator_config(tmp_path: Path, *, provider: str = "cloudflare") -> Path:
    path = tmp_path / "operator.toml"
    path.write_text(
        f'acme_dns_provider = "{provider}"\nacme_dns_api_token = "secret-token"\n',
        encoding="utf-8",
    )
    return path


# ---------------------------------------------------------------------------
# app tag (kind-32267 linkage to the normal nostrhost catalogue)
# ---------------------------------------------------------------------------


def test_manifest_app_tag_valid():
    sk, pubkey = new_keys()
    event = root_manifest(sk, pubkey, app=f"32267:{pubkey}:site")
    verdict = validate_manifest(event)
    assert verdict.valid, verdict.errors
    assert verdict.app == f"32267:{pubkey}:site"


def test_manifest_app_tag_malformed():
    sk, pubkey = new_keys()
    paths = [("/index.html", "a" * 64)]
    tags = [
        ["path", "/index.html", "a" * 64],
        ["app", "32267:nope:site", "wss://relay.example.org"],
        ["app", "32267:not-an-address", "wss://relay.example.org"],
        ["x", aggregate_hash(paths), "aggregate"],
    ]
    verdict = validate_manifest(sign_event(sk, 15128, tags))
    assert not verdict.valid
    assert "multiple_app" in verdict.errors
    assert "bad_app_shape" in verdict.errors

    tags = [
        ["path", "/index.html", "a" * 64],
        ["app", f"32267:{pubkey}:site", "not-a-relay"],
        ["x", aggregate_hash(paths), "aggregate"],
    ]
    verdict = validate_manifest(sign_event(sk, 15128, tags))
    assert not verdict.valid
    assert "bad_app_relay" in verdict.errors


def test_publish_records_app_and_surfaces_in_list(tmp_path: Path, monkeypatch):
    sk, pubkey = new_keys()
    svc = make_service(tmp_path)
    svc.enable(GatewayConfig(domain=GATEWAY))
    svc.site_register(pubkey, kind=15128)
    monkeypatch.setattr(service, "_broadcast", ok_broadcast())
    plan = svc.publish_plan(pubkey, kind=15128, d="", items=[{"path": "/index.html", "sha256": "a" * 64}])
    event = root_manifest(sk, pubkey, app=f"32267:{pubkey}:mysite", servers=plan["plan"]["servers"])
    result = svc.publish(event, plan_sha256=plan["plan"]["plan_sha256"])
    assert result["ok"] is True

    record = svc.site_inspect(pubkey)["site"]
    assert record["app"] == f"32267:{pubkey}:mysite"
    listing = svc.site_list()
    assert any(s["app"] == f"32267:{pubkey}:mysite" for s in listing["sites"])


def test_publish_plan_carries_app_tag(tmp_path: Path):
    _, pubkey = new_keys()
    svc = make_service(tmp_path)
    svc.enable(GatewayConfig(domain=GATEWAY))
    plan = svc.publish_plan(
        pubkey,
        kind=15128,
        d="",
        items=[{"path": "/index.html", "sha256": "a" * 64}],
        app=f"32267:{pubkey}:main",
    )["plan"]
    tags = plan["unsigned_event"]["tags"]
    assert ["app", f"32267:{pubkey}:main"] in tags
    # The app tag is not part of the plan digest (it carries no
    # content-integrity meaning), so a plan with and without it digests equal.
    assert plan["plan_sha256"] == plan_digest_from(plan)

    # A signed event carrying the planned app tag validates and publishes.
    sk, signer = new_keys()
    app_event = sign_event(
        signer,
        15128,
        [t for t in plan["unsigned_event"]["tags"]],
    )
    verdict = validate_manifest(app_event)
    assert verdict.valid, verdict.errors
    assert verdict.app == f"32267:{pubkey}:main"


def test_publish_plan_rejects_bad_app_address(tmp_path: Path):
    _, pubkey = new_keys()
    svc = make_service(tmp_path)
    svc.enable(GatewayConfig(domain=GATEWAY))
    with pytest.raises(service.NsiteError, match="invalid app address"):
        svc.publish_plan(
            pubkey,
            kind=15128,
            d="",
            items=[{"path": "/index.html", "sha256": "a" * 64}],
            app="not-an-address",
        )
    with pytest.raises(service.NsiteError, match="invalid app address"):
        svc.publish_plan(
            pubkey,
            kind=15128,
            d="",
            items=[{"path": "/index.html", "sha256": "a" * 64}],
            app=f"32267:{pubkey[:8]}",
        )


def test_catalogue_nsite_links(tmp_path: Path):
    _, pubkey = new_keys()
    svc = make_service(tmp_path)
    svc.enable(GatewayConfig(domain=GATEWAY))
    svc.site_register(pubkey, kind=35128, d="blog")
    path = service.site_path(svc.state_dir, pubkey, "blog")
    record = json.loads(path.read_text(encoding="utf-8"))
    record["app"] = f"32267:{pubkey}:blog"
    record["kind"] = 35128
    record["d"] = "blog"
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    links = svc.catalogue_nsite_links()
    assert links == {
        f"32267:{pubkey}:blog": {
            "url": f"https://{named_label(pubkey, 'blog')}.{GATEWAY}/",
            "label": named_label(pubkey, "blog"),
        }
    }

    # root sites map by their npub label
    _, root_pubkey = new_keys()
    svc.site_register(root_pubkey, kind=15128)
    root_path = service.site_path(svc.state_dir, root_pubkey)
    root_record = json.loads(root_path.read_text(encoding="utf-8"))
    root_record["app"] = f"32267:{root_pubkey}:main"
    root_path.write_text(json.dumps(root_record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    links = svc.catalogue_nsite_links()
    from nostr_sdk import PublicKey

    npub = PublicKey.parse(root_pubkey).to_bech32()
    assert links[f"32267:{root_pubkey}:main"]["label"] == npub
    assert links[f"32267:{root_pubkey}:main"]["url"] == f"https://{npub}.{GATEWAY}/"


# ---------------------------------------------------------------------------
# copy plans (a parent / A origin)
# ---------------------------------------------------------------------------


def test_copy_plan_from_registered_source(tmp_path: Path, monkeypatch):
    sk, src_pubkey = new_keys()
    svc = make_service(tmp_path)
    svc.enable(GatewayConfig(domain=GATEWAY))
    svc.site_register(src_pubkey, kind=15128)
    monkeypatch.setattr(service, "_broadcast", ok_broadcast())
    src_plan = svc.publish_plan(
        src_pubkey, kind=15128, d="", items=[{"path": "/index.html", "sha256": "a" * 64}]
    )
    src_event = root_manifest(sk, src_pubkey, servers=src_plan["plan"]["servers"])
    svc.publish(src_event, plan_sha256=src_plan["plan"]["plan_sha256"])

    target_sk, target_pubkey = new_keys()
    svc.site_register(target_pubkey, kind=15128)
    plan = svc.publish_plan(
        target_pubkey, kind=15128, copy_of=f"15128:{src_pubkey}:"
    )["plan"]
    assert plan["kind"] == 15128
    assert plan["d"] == ""
    assert plan["items"] == [{"path": "/index.html", "sha256": "a" * 64}]
    tags = plan["unsigned_event"]["tags"]
    assert ["a", f"15128:{src_pubkey}:"] in tags
    assert ["A", f"15128:{src_pubkey}:"] in tags
    assert plan["plan_sha256"] == plan_digest_from(plan)

    # A signed copy validates (a/A present, aggregate correct) and publishes
    # under the copier's pubkey.
    copy_event = sign_event(
        target_sk,
        15128,
        [t for t in plan["unsigned_event"]["tags"]],
    )
    verdict = validate_manifest(copy_event)
    assert verdict.valid, verdict.errors
    assert verdict.pubkey == target_pubkey
    result = svc.publish(copy_event, plan_sha256=plan["plan_sha256"])
    assert result["ok"] is True
    assert svc.site_inspect(target_pubkey)["site"]["last_event_id"] == copy_event["id"]


def plan_digest_from(plan: dict) -> str:
    from nostrhost.nsites.service import plan_digest

    return plan_digest(
        kind=plan["kind"],
        d=plan["d"],
        paths=[(p["path"], p["sha256"]) for p in plan["items"]],
        servers=plan["servers"],
        relays=plan["relays"],
    )


def test_copy_plan_named_defaults_d(tmp_path: Path, monkeypatch):
    sk, src_pubkey = new_keys()
    svc = make_service(tmp_path)
    svc.enable(GatewayConfig(domain=GATEWAY))
    svc.site_register(src_pubkey, kind=35128, d="blog")
    monkeypatch.setattr(service, "_broadcast", ok_broadcast())
    src_plan = svc.publish_plan(
        src_pubkey, kind=35128, d="blog", items=[{"path": "/index.html", "sha256": "a" * 64}]
    )
    src_event = root_manifest(sk, src_pubkey, d="blog", servers=src_plan["plan"]["servers"])
    svc.publish(src_event, plan_sha256=src_plan["plan"]["plan_sha256"])

    _, target_pubkey = new_keys()
    plan = svc.publish_plan(
        target_pubkey, kind=35128, copy_of=f"35128:{src_pubkey}:blog"
    )["plan"]
    assert plan["kind"] == 35128
    assert plan["d"] == "blog"
    tags = plan["unsigned_event"]["tags"]
    assert ["a", f"35128:{src_pubkey}:blog"] in tags
    assert ["A", f"35128:{src_pubkey}:blog"] in tags

    # an explicit target d forks the copy into a new name
    plan2 = svc.publish_plan(
        target_pubkey, kind=35128, d="copy", copy_of=f"35128:{src_pubkey}:blog"
    )["plan"]
    assert plan2["d"] == "copy"
    assert ["a", f"35128:{src_pubkey}:blog"] in plan2["unsigned_event"]["tags"]


def test_copy_plan_invalid_source(tmp_path: Path):
    _, target_pubkey = new_keys()
    svc = make_service(tmp_path)
    svc.enable(GatewayConfig(domain=GATEWAY))
    with pytest.raises(service.NsiteError, match="invalid copy source"):
        svc.publish_plan(target_pubkey, kind=15128, copy_of="banana")
    with pytest.raises(service.NsiteError, match="invalid copy source"):
        svc.publish_plan(target_pubkey, kind=15128, copy_of="32267:deadbeef:main")


def test_copy_plan_unresolvable_source(tmp_path: Path):
    _, target_pubkey = new_keys()
    _, other = new_keys()
    svc = make_service(tmp_path)
    svc.enable(GatewayConfig(domain=GATEWAY))
    with pytest.raises(service.NsiteError, match="not registered locally"):
        svc.publish_plan(
            target_pubkey, kind=15128, copy_of=f"15128:{other}:"
        )


# ---------------------------------------------------------------------------
# open gateway mode (wildcard DNS-01, operator token required)
# ---------------------------------------------------------------------------


def test_open_mode_enable_requires_token(tmp_path: Path):
    svc = make_service(tmp_path)
    with pytest.raises(service.NsiteError, match="acme_dns"):
        svc.enable(GatewayConfig(domain=GATEWAY, mode="open"))


def test_open_mode_enable_with_token(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("NOSTRHOST_OPERATOR_CONFIG", str(operator_config(tmp_path)))
    svc = make_service(tmp_path)
    result = svc.enable(GatewayConfig(domain=GATEWAY, mode="open"))
    assert result["mode"] == "open"
    assert svc.gateway_status()["gateway"]["mode"] == "open"
    conf = (tmp_path / "caddy-conf.d" / f"{GATEWAY}.conf").read_text(encoding="utf-8")
    assert "dns cloudflare {$ACME_DNS_API_TOKEN}" in conf
    toml = svc.config_path.read_text(encoding="utf-8")
    assert 'mode = "open"' in toml


def test_open_mode_configure_switch(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("NOSTRHOST_OPERATOR_CONFIG", str(operator_config(tmp_path)))
    svc = make_service(tmp_path)
    svc.enable(GatewayConfig(domain=GATEWAY))
    assert svc.gateway_status()["gateway"]["mode"] == "hosted"
    svc.configure(GatewayConfig(domain=GATEWAY, mode="open"))
    assert svc.gateway_status()["gateway"]["mode"] == "open"
    conf = (tmp_path / "caddy-conf.d" / f"{GATEWAY}.conf").read_text(encoding="utf-8")
    assert "dns cloudflare {$ACME_DNS_API_TOKEN}" in conf


def test_open_mode_local_domain_internal_ca(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("NOSTRHOST_OPERATOR_CONFIG", str(operator_config(tmp_path)))
    svc = make_service(tmp_path)
    local = "sites.example.test"
    (tmp_path / "state" / "domains-native" / f"{local}.json").write_text("{}", encoding="utf-8")
    svc.enable(GatewayConfig(domain=local, mode="open"))
    conf = (tmp_path / "caddy-conf.d" / f"{local}.conf").read_text(encoding="utf-8")
    assert "tls internal" in conf
    assert "dns cloudflare" not in conf


def test_open_mode_publish_without_registration(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("NOSTRHOST_OPERATOR_CONFIG", str(operator_config(tmp_path)))
    sk, pubkey = new_keys()
    svc = make_service(tmp_path)
    svc.enable(GatewayConfig(domain=GATEWAY, mode="open"))
    monkeypatch.setattr(service, "_broadcast", ok_broadcast())
    plan = svc.publish_plan(
        pubkey, kind=15128, d="", items=[{"path": "/index.html", "sha256": "a" * 64}]
    )
    result = svc.publish(
        root_manifest(sk, pubkey, servers=plan["plan"]["servers"]),
        plan_sha256=plan["plan"]["plan_sha256"],
    )
    assert result["ok"] is True
    assert result["label"].startswith("npub1")


def test_hosted_mode_still_requires_registration(tmp_path: Path, monkeypatch):
    _, pubkey = new_keys()
    svc = make_service(tmp_path)
    svc.enable(GatewayConfig(domain=GATEWAY))
    monkeypatch.setattr(service, "_broadcast", ok_broadcast())
    plan = svc.publish_plan(
        pubkey, kind=15128, d="", items=[{"path": "/index.html", "sha256": "a" * 64}]
    )
    with pytest.raises(service.NsiteError, match="not registered"):
        svc.publish(
            root_manifest(*new_keys(), servers=plan["plan"]["servers"]),
            plan_sha256=plan["plan"]["plan_sha256"],
        )
