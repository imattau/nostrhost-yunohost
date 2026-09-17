"""Nsites discovery tests: bounded relay scan for kind-15128/35128 manifests.

``nsite.discover`` is an on-demand read (``nsites.read``, no approval): it
scans the operator-trusted catalogue + nsite-lookup relay sets, validates every
candidate with the full NIP-5A checks, keeps the newest valid manifest per site
(pubkey + d) and returns bounded metadata only — never manifest ``content`` and
no state written.

Run with: PYTHONPATH=src:../../libs/nostrhost-policy/src:../../libs/nostrhost-auth/src \
  python -m pytest -c /dev/null tests_nostr/test_nsites_discover.py -q
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from nostrhost.core import NostrHostError
from nostrhost.nsites import service
from nostrhost.nsites.operations import _safe_nsite_discover
from nostrhost.nsites.service import NsiteError

pytest.importorskip("nostr_sdk")

CORPUS_DIR = Path(__file__).resolve().parents[3] / "tools" / "tests" / "nsites" / "corpus"

TEST_PUBKEY = "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732"


def corpus_event(name: str) -> dict:
    data = json.loads((CORPUS_DIR / name).read_text(encoding="utf-8"))
    return data["event"]


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


def new_keys() -> tuple[str, str]:
    from nostr_sdk import Keys

    keys = Keys.generate()
    return keys.secret_key().to_hex(), keys.public_key().to_hex()


def make_service(tmp_path: Path) -> service.NsiteService:
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    return service.NsiteService(state_dir=state_dir, config_path=tmp_path / "nsite.toml")


def install_scan(monkeypatch, events, *, catalogue, lookup):
    """Point nsite.discover at fake relays and fake query results."""
    import nostrhost.connectivity as connectivity

    monkeypatch.setattr(service, "_query_relay_events", lambda *a, **k: list(events))
    monkeypatch.setattr(service, "_validate_relay_url", lambda relay, allow_private=False: None)
    monkeypatch.setattr(
        connectivity,
        "effective",
        lambda: {
            "relays": {"catalogue": list(catalogue), "nsite_lookup": list(lookup)},
            "blossom_servers": [],
            "sources": {},
        },
    )


def test_discover_returns_validated_metadata(tmp_path: Path, monkeypatch):
    root = corpus_event("valid-root.json")
    install_scan(
        monkeypatch,
        [root, corpus_event("invalid-bad-signature.json"), corpus_event("valid-snapshot.json")],
        catalogue=["wss://cat.example"],
        lookup=["wss://lookup.example"],
    )
    result = make_service(tmp_path).discover()
    assert result["relays_queried"] == ["wss://cat.example", "wss://lookup.example"]
    assert result["count"] == 1
    assert result["truncated"] is False
    site = result["sites"][0]
    assert site["pubkey"] == TEST_PUBKEY
    assert site["kind"] == 15128
    assert site["d"] == ""
    assert site["label"].startswith("npub1")
    assert site["title"] == "Conformance Root Site"
    assert site["servers"] == ["https://blossom.example.com"]
    assert site["event_id"] == root["id"]
    assert site["paths_count"] == 2
    assert site["app"] == ""
    assert site["registered"] is False


def test_discover_dedupes_newest_per_site(tmp_path: Path, monkeypatch):
    sk, _pubkey = new_keys()
    old = sign_event(sk, 15128, [["path", "/index.html", "a" * 64]], created_at=1000)
    new = sign_event(sk, 15128, [["path", "/index.html", "b" * 64]], created_at=2000)
    install_scan(monkeypatch, [old, new], catalogue=["wss://cat.example"], lookup=[])
    result = make_service(tmp_path).discover()
    assert result["count"] == 1
    assert result["sites"][0]["event_id"] == new["id"]
    assert result["sites"][0]["paths_count"] == 1


def test_discover_marks_registered_sites(tmp_path: Path, monkeypatch):
    root = corpus_event("valid-root.json")
    other_sk, other_pubkey = new_keys()
    other = sign_event(other_sk, 35128, [["d", "blog"], ["path", "/index.html", "a" * 64]])
    sites_dir = tmp_path / "state" / "nsites" / "sites"
    sites_dir.mkdir(parents=True)
    (sites_dir / f"{TEST_PUBKEY}.json").write_text(
        json.dumps({"pubkey": TEST_PUBKEY, "d": "", "kind": 15128}) + "\n",
        encoding="utf-8",
    )
    install_scan(monkeypatch, [root, other], catalogue=["wss://cat.example"], lookup=[])
    result = make_service(tmp_path).discover()
    assert len(result["sites"]) == 2
    assert any(site["pubkey"] == TEST_PUBKEY and site["registered"] is True for site in result["sites"])
    assert any(site["pubkey"] == other_pubkey and site["registered"] is False for site in result["sites"])


def test_discover_unions_catalogue_and_lookup_relays(tmp_path: Path, monkeypatch):
    install_scan(
        monkeypatch,
        [],
        catalogue=["wss://a.example", "wss://b.example"],
        lookup=["wss://b.example", "wss://c.example"],
    )
    result = make_service(tmp_path).discover()
    assert result["relays_queried"] == ["wss://a.example", "wss://b.example", "wss://c.example"]


def test_discover_filters_non_public_relays(tmp_path: Path, monkeypatch):
    install_scan(
        monkeypatch,
        [],
        catalogue=["wss://cat.example", "ws://127.0.0.1:4848"],
        lookup=[],
    )

    def reject(url: str, allow_private: bool = False) -> None:
        if url == "ws://127.0.0.1:4848":
            raise NsiteError("private relay")
        return None

    monkeypatch.setattr(service, "_validate_relay_url", reject)
    result = make_service(tmp_path).discover()
    assert result["relays_queried"] == ["wss://cat.example"]


def test_discover_bounds_relay_count(tmp_path: Path, monkeypatch):
    relays = [f"wss://r{i}.example" for i in range(10)]
    install_scan(monkeypatch, [], catalogue=relays, lookup=[])
    queries: list[str] = []
    monkeypatch.setattr(service, "_query_relay_events", lambda relay, *a, **k: queries.append(relay) or [])
    result = make_service(tmp_path).discover()
    assert len(result["relays_queried"]) == 6
    assert len(queries) == 6


def test_discover_empty_scan(tmp_path: Path, monkeypatch):
    install_scan(monkeypatch, [], catalogue=["wss://cat.example"], lookup=[])
    result = make_service(tmp_path).discover()
    assert result["sites"] == []
    assert result["count"] == 0
    assert result["truncated"] is False


def test_discover_truncates_to_bounded_list(tmp_path: Path, monkeypatch):
    sk, _ = new_keys()
    first = sign_event(sk, 15128, [["path", "/index.html", "a" * 64]], created_at=1000)
    second = sign_event(sk, 35128, [["d", "blog"], ["path", "/index.html", "a" * 64]], created_at=2000)
    install_scan(monkeypatch, [first, second], catalogue=["wss://cat.example"], lookup=[])
    monkeypatch.setattr(service, "DISCOVER_MAX_SITES", 1)
    result = make_service(tmp_path).discover()
    assert result["truncated"] is True
    assert result["count"] == 1


def test_discover_never_leaks_content_or_raw_tags(tmp_path: Path, monkeypatch):
    sk, _ = new_keys()
    secret = "super-secret-content"
    oversized_title = "t" * 200
    event = sign_event(
        sk,
        15128,
        [["path", "/index.html", "a" * 64], ["title", oversized_title], ["server", "https://blossom.example"]],
        content=secret,
    )
    install_scan(monkeypatch, [event], catalogue=["wss://cat.example"], lookup=[])
    result = make_service(tmp_path).discover()
    assert secret not in json.dumps(result)
    assert len(result["sites"][0]["title"]) == 120
    assert "content" not in result["sites"][0]


def test_discover_handler_rejects_extra_args():
    with pytest.raises(NostrHostError, match="extra args"):
        _safe_nsite_discover(limit=5)