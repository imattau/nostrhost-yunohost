"""Curated nsite collections (kind 30004) operation tests.

Covers the plan/publish/validate/resolve/discover service surface plus the
registry wiring. Collections are external-relay events: no local state is
written, ``nsite.collection.publish`` broadcasts with per-relay results and
rejects a stale/mismatched plan digest or a host-key signer before any
broadcast (same shape as ``nsite.publish``).

Run with: PYTHONPATH=src:../../libs/nostrhost-policy/src:../../libs/nostrhost-auth/src \
  python -m pytest -c /dev/null tests_nostr/test_nsites_collections_ops.py -q
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from nostrhost.nsites import operations, service
from nostrhost.nsites.collections import COLLECTION_KIND, collection_plan_digest
from nostrhost.nsites.service import NsiteError

pytest.importorskip("nostr_sdk")

TEST_SK = "3f4f6b8d" * 8  # corpus test identity (matches gen_collection_corpus.py)
TEST_PUBKEY = "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732"
HOST_SK = "deadbeef" * 8
SITE_PUBKEY = "266815e0c9210dfa324c6cba3573b14bee49da4209a9456f9484e5106cd408a5"
CURATOR_SK = TEST_SK  # the curator signs what its own plan built
CURATOR_PUBKEY = TEST_PUBKEY


def new_keys() -> tuple[str, str]:
    from nostr_sdk import Keys

    keys = Keys.generate()
    return keys.secret_key().to_hex(), keys.public_key().to_hex()


def sign_event(sk: str, kind: int, tags: list[list[str]], content: str = "", created_at: int | None = None) -> dict:
    from nostr_sdk import EventBuilder, Keys, Kind, Tag, Timestamp

    keys = Keys.parse(sk)
    stamp = Timestamp.from_secs(created_at if created_at is not None else int(time.time()))
    event = (
        EventBuilder(Kind(kind), content)
        .tags([Tag.parse(t) for t in tags])
        .custom_created_at(stamp)
        .finalize(keys)
    )
    return {
        "id": event.id().to_hex(),
        "pubkey": keys.public_key().to_hex(),
        "created_at": stamp.as_secs(),
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": event.signature(),
    }


def make_service(tmp_path: Path) -> service.NsiteService:
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    return service.NsiteService(state_dir=state_dir, config_path=tmp_path / "nsite.toml")


def ok_broadcast(monkeypatch, fail: bool = False):
    """Monkeypatch ``_broadcast``: records calls; succeeds unless ``fail``."""
    calls: list[dict] = []

    def fake(event: dict, relay_list: list[str], timeout: float = 10.0) -> dict:
        calls.append({"event": event, "relays": relay_list})
        if fail:
            return {
                "results": [{"relay": r, "ok": False, "error": "rejected"} for r in relay_list],
                "ok_count": 0,
                "failed_count": len(relay_list),
                "succeeded": False,
            }
        return {
            "results": [{"relay": r, "ok": True} for r in relay_list],
            "ok_count": len(relay_list),
            "failed_count": 0,
            "succeeded": True,
        }

    monkeypatch.setattr(service, "_broadcast", fake)
    return calls


def entries() -> list[dict[str, str]]:
    return [
        {"kind": "live-root", "ref": f"15128:{SITE_PUBKEY}:", "relay": "wss://nos.lol"},
        {"kind": "pinned", "ref": "5c8ed07b8c33b5d1e2d1c1dcec4d1d1a1e1f1a1b1c1d1e1f2021222324252627"},
    ]


def build_plan(svc: service.NsiteService, pubkey: str, **kw) -> dict:
    return svc.collection_publish_plan(
        pubkey,
        d=kw.pop("d", "indie-web"),
        title=kw.pop("title", "Small independent sites"),
        description=kw.pop("description", "Personal sites."),
        image=kw.pop("image", "https://cdn.example/a.webp"),
        entries=kw.pop("entries", entries()),
        relays=kw.pop("relays", ["wss://nos.lol"]),
        **kw,
    )["plan"]


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------


def test_plan_builds_unsigned_event_and_digest(tmp_path: Path):
    svc = make_service(tmp_path)
    plan = build_plan(svc, CURATOR_PUBKEY)
    ev = plan["unsigned_event"]
    assert ev["kind"] == COLLECTION_KIND
    assert ev["created_at"] == 0
    tags = {t[0]: t for t in ev["tags"]}
    assert tags["d"][1] == "indie-web"
    assert tags["t"][1] == "nsite"
    assert tags["title"][1] == "Small independent sites"
    assert tags["a"][1] == f"15128:{SITE_PUBKEY}:"
    assert tags["e"][1] == "5c8ed07b8c33b5d1e2d1c1dcec4d1d1a1e1f1a1b1c1d1e1f2021222324252627"
    # The digest matches the shared helper over the same ordered inputs.
    assert plan["plan_sha256"] == collection_plan_digest(
        pubkey=CURATOR_PUBKEY,
        d="indie-web",
        title="Small independent sites",
        description="Personal sites.",
        image="https://cdn.example/a.webp",
        entries=[
            ["a", f"15128:{SITE_PUBKEY}:", "wss://nos.lol"],
            ["e", "5c8ed07b8c33b5d1e2d1c1dcec4d1d1a1e1f1a1b1c1d1e1f2021222324252627"],
        ],
        relays=["wss://nos.lol"],
    )


def test_plan_rejects_bad_d_and_duplicate(tmp_path: Path):
    svc = make_service(tmp_path)
    with pytest.raises(NsiteError, match="invalid collection d"):
        build_plan(svc, CURATOR_PUBKEY, d="has space")
    dup = entries() + [dict(entries()[0])]
    with pytest.raises(NsiteError, match="duplicate entry"):
        build_plan(svc, CURATOR_PUBKEY, entries=dup)
    with pytest.raises(NsiteError, match="invalid entry kind"):
        build_plan(svc, CURATOR_PUBKEY, entries=[{"kind": "nope", "ref": "x"}])


# ---------------------------------------------------------------------------
# Validate
# ---------------------------------------------------------------------------


def test_validate_unsigned_and_signed(tmp_path: Path):
    svc = make_service(tmp_path)
    plan = build_plan(svc, CURATOR_PUBKEY)
    # unsigned event is invalid (no id/signature yet)
    v = svc.collection_validate(plan["unsigned_event"])
    assert not v["valid"]
    assert "bad_id" in v["errors"]
    # a properly signed event validates
    signed = sign_event(CURATOR_SK, COLLECTION_KIND, plan["unsigned_event"]["tags"])
    v = svc.collection_validate(signed)
    assert v["valid"], v["errors"]
    assert v["coordinate"] == f"{COLLECTION_KIND}:{signed['pubkey']}:indie-web"
    assert len(v["entries"]) == 2


# ---------------------------------------------------------------------------
# Publish
# ---------------------------------------------------------------------------


def test_publish_happy_path_records_broadcast(tmp_path: Path, monkeypatch):
    svc = make_service(tmp_path)
    calls = ok_broadcast(monkeypatch)
    plan = build_plan(svc, CURATOR_PUBKEY)
    signed = sign_event(CURATOR_SK, COLLECTION_KIND, plan["unsigned_event"]["tags"])
    result = svc.collection_publish(signed, plan_sha256=plan["plan_sha256"], relays=plan["relays"])
    assert result["ok"]
    assert result["coordinate"] == f"{COLLECTION_KIND}:{signed['pubkey']}:indie-web"
    assert result["entries"] == 2
    assert calls and calls[0]["relays"] == ["wss://nos.lol"]
    # no local state written (collections are external-relay authority)
    assert not list((svc.state_dir / "nsites" / "sites").glob("*"))


def test_publish_rejects_digest_mismatch(tmp_path: Path, monkeypatch):
    svc = make_service(tmp_path)
    calls = ok_broadcast(monkeypatch)
    plan = build_plan(svc, CURATOR_PUBKEY)
    signed = sign_event(CURATOR_SK, COLLECTION_KIND, plan["unsigned_event"]["tags"])
    with pytest.raises(NsiteError, match="plan digest mismatch"):
        svc.collection_publish(signed, plan_sha256="0" * 64, relays=plan["relays"])
    assert calls == []  # nothing was broadcast


def test_publish_requires_plan(tmp_path: Path, monkeypatch):
    svc = make_service(tmp_path)
    calls = ok_broadcast(monkeypatch)
    plan = build_plan(svc, CURATOR_PUBKEY)
    signed = sign_event(CURATOR_SK, COLLECTION_KIND, plan["unsigned_event"]["tags"])
    with pytest.raises(NsiteError, match="plan_sha256"):
        svc.collection_publish(signed, plan_sha256="", relays=plan["relays"])
    assert calls == []


def test_publish_rejects_host_key_signer(tmp_path: Path, monkeypatch):
    svc = make_service(tmp_path)
    calls = ok_broadcast(monkeypatch)
    # A host-key-signed collection is rejected by the signer guard before any
    # broadcast (the plan digest is still bound, but the guard fires first).
    ev = json.loads(
        (Path(__file__).resolve().parents[3] / "tools" / "tests" / "nsites" / "collection-corpus" / "invalid-forbidden-signer.json")
        .read_text(encoding="utf-8")
    )["event"]
    monkeypatch.setattr(
        "nostrhost.nsites.signer_guard.forbidden_signer_pubkeys",
        lambda: frozenset({ev["pubkey"]}),
    )
    digest = collection_plan_digest(
        pubkey=ev["pubkey"], d=ev["tags"][0][1], title="", description="", image="",
        entries=[], relays=["wss://nos.lol"],
    )
    with pytest.raises(NsiteError, match="forbidden_signer"):
        svc.collection_publish(ev, plan_sha256=digest, relays=["wss://nos.lol"])
    assert calls == []


def test_publish_fails_when_no_relay_accepts(tmp_path: Path, monkeypatch):
    svc = make_service(tmp_path)
    ok_broadcast(monkeypatch, fail=True)
    plan = build_plan(svc, CURATOR_PUBKEY)
    signed = sign_event(CURATOR_SK, COLLECTION_KIND, plan["unsigned_event"]["tags"])
    with pytest.raises(NsiteError, match="reached no relay"):
        svc.collection_publish(signed, plan_sha256=plan["plan_sha256"], relays=plan["relays"])


# ---------------------------------------------------------------------------
# Resolve
# ---------------------------------------------------------------------------


def test_resolve_returns_newest_collection_and_entries(tmp_path: Path, monkeypatch):
    import nostrhost.connectivity as connectivity

    svc = make_service(tmp_path)
    old = sign_event(
        TEST_SK, COLLECTION_KIND,
        [["d", "indie-web"], ["title", "old"], ["t", "nsite"], ["a", f"15128:{SITE_PUBKEY}:"]],
        created_at=100,
    )
    new = sign_event(
        TEST_SK, COLLECTION_KIND,
        [["d", "indie-web"], ["title", "new"], ["t", "nsite"], ["e", "5c8ed07b8c33b5d1e2d1c1dcec4d1d1a1e1f1a1b1c1d1e1f2021222324252627"]],
        created_at=200,
    )
    monkeypatch.setattr(service, "_query_relay_events", lambda *a, **k: [old, new])
    monkeypatch.setattr(service, "_validate_relay_url", lambda *a, **k: None)
    # entry resolution: both live and pinned entries resolve to a fake "site"
    monkeypatch.setattr(
        svc, "resolve",
        lambda **kw: {"found": True, "manifest": {"event_id": "e" * 64, "label": "x", "pubkey": SITE_PUBKEY, "kind": 5128, "d": "", "aggregate_hash": "a" * 64, "paths": []}},
    )
    monkeypatch.setattr(
        connectivity,
        "effective",
        lambda: {"relays": {"catalogue": ["wss://x"], "nsite_lookup": ["wss://y"]}},
    )
    result = svc.collection_resolve(f"{COLLECTION_KIND}:{new['pubkey']}:indie-web")
    assert result["found"]
    assert result["title"] == "new"  # newest wins
    assert result["entries"][0]["kind"] == "pinned"
    assert result["entries"][0]["available"]
    assert result["coordinate"] == f"{COLLECTION_KIND}:{new['pubkey']}:indie-web"


def test_resolve_missing_coordinate(tmp_path: Path, monkeypatch):
    import nostrhost.connectivity as connectivity

    svc = make_service(tmp_path)
    monkeypatch.setattr(service, "_query_relay_events", lambda *a, **k: [])
    monkeypatch.setattr(
        connectivity,
        "effective",
        lambda: {"relays": {"catalogue": ["wss://x"], "nsite_lookup": ["wss://y"]}},
    )
    result = svc.collection_resolve(f"{COLLECTION_KIND}:{SITE_PUBKEY}:nope")
    assert not result["found"]
    with pytest.raises(NsiteError, match="invalid collection coordinate"):
        svc.collection_resolve("not-a-coordinate")


# ---------------------------------------------------------------------------
# Discover
# ---------------------------------------------------------------------------


def test_discover_validates_and_deduplicates(tmp_path: Path, monkeypatch):
    import nostrhost.connectivity as connectivity

    svc = make_service(tmp_path)
    a = sign_event(
        TEST_SK, COLLECTION_KIND,
        [["d", "indie-web"], ["title", "A"], ["t", "nsite"], ["a", f"15128:{SITE_PUBKEY}:"]],
        created_at=100,
    )
    a2 = sign_event(
        TEST_SK, COLLECTION_KIND,
        [["d", "indie-web"], ["title", "A2"], ["t", "nsite"], ["a", f"15128:{SITE_PUBKEY}:"]],
        created_at=200,
    )
    junk = sign_event(CURATOR_SK, 30023, [["d", "x"], ["title", "article"], ["t", "nsite"]])
    not_nsite = sign_event(CURATOR_SK, COLLECTION_KIND, [["d", "x"], ["title", "t"]])  # no t=nsite
    monkeypatch.setattr(service, "_query_relay_events", lambda *a, **k: [a, a2, junk, not_nsite])
    monkeypatch.setattr(service, "_validate_relay_url", lambda *a, **k: None)
    monkeypatch.setattr(service, "_operator_blocklist", lambda: frozenset())
    monkeypatch.setattr(
        connectivity,
        "effective",
        lambda: {"relays": {"catalogue": ["wss://x"], "nsite_lookup": ["wss://y"]}},
    )
    result = svc.collection_discover()
    assert result["count"] == 1
    assert result["collections"][0]["title"] == "A2"  # newest wins
    assert result["collections"][0]["entries"] == 1


def test_discover_applies_blocklist(tmp_path: Path, monkeypatch):
    import nostrhost.connectivity as connectivity

    svc = make_service(tmp_path)
    ev = sign_event(
        TEST_SK, COLLECTION_KIND,
        [["d", "indie-web"], ["title", "A"], ["t", "nsite"], ["a", f"15128:{SITE_PUBKEY}:"]],
    )
    monkeypatch.setattr(service, "_query_relay_events", lambda *a, **k: [ev])
    monkeypatch.setattr(service, "_validate_relay_url", lambda *a, **k: None)
    monkeypatch.setattr(service, "_operator_blocklist", lambda: {ev["pubkey"]})
    monkeypatch.setattr(
        connectivity,
        "effective",
        lambda: {"relays": {"catalogue": ["wss://x"], "nsite_lookup": ["wss://y"]}},
    )
    result = svc.collection_discover()
    assert result["count"] == 0


# ---------------------------------------------------------------------------
# Registry wiring
# ---------------------------------------------------------------------------


def test_registry_has_collection_tools():
    from yunohost.nostr_operations import TOOLS, validate_operation_registry

    validate_operation_registry()
    for tool in (
        "nsite.collection.validate",
        "nsite.collection.get",
        "nsite.collection.discover",
        "nsite.collection.publish.plan",
        "nsite.collection.publish",
    ):
        assert tool in TOOLS
    spec = TOOLS["nsite.collection.publish"]
    assert spec.scope == "nsites.publish"
    assert spec.require_approval is True
    assert TOOLS["nsite.collection.get"].scope == "nsites.read"


def test_operations_wrappers_reject_extra_args():
    with pytest.raises(Exception):
        operations._safe_nsite_collection_discover(refresh=False, bogus=1)
    with pytest.raises(Exception):
        operations._safe_nsite_collection_get(coordinate="x", bogus=1)