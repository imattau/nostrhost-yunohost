"""Curated nsite collection validator tests over the shared collection corpus.

The corpus lives in the parent repo at
``tools/tests/nsites/collection-corpus``. CI checks the parent repo out with
submodules, so the relative path exists there; when the fork is developed
standalone the whole module is skipped.

Run with: PYTHONPATH=src python -m pytest -c /dev/null tests_nostr/test_nsites_collections.py -q
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nostrhost.nsites import collections

CORPUS_DIR = (
    Path(__file__).resolve().parents[3] / "tools" / "tests" / "nsites" / "collection-corpus"
)

# The corpus generator's "host key" (deadbeef*8) is the forbidden signer in
# the invalid-forbidden-signer case; it is also harmless to pass for every
# other case.
HOST_PUBKEY = (
    pytest.importorskip("nostr_sdk").Keys.parse("deadbeef" * 8).public_key().to_hex()
)


def _corpus_files() -> list[Path]:
    if not CORPUS_DIR.is_dir():
        return []
    return sorted(CORPUS_DIR.glob("*.json"))


pytestmark = pytest.mark.skipif(
    not CORPUS_DIR.is_dir(),
    reason="collection corpus not present (parent repo checkout required)",
)


@pytest.fixture(scope="module", params=_corpus_files(), ids=lambda p: p.stem)
def corpus_case(request: pytest.FixtureRequest):
    return json.loads(request.param.read_text())


def test_corpus_verdicts(corpus_case: dict):
    event = corpus_case["event"]
    expect = corpus_case["expect"]
    v = collections.validate_collection(
        event,
        forbidden_pubkeys={HOST_PUBKEY},
        max_entries=expect.get("max_entries", collections.MAX_ENTRIES),
    )
    if expect["valid"]:
        assert v.valid, v.errors
        assert v.errors == []
    else:
        assert not v.valid
        assert sorted(v.errors) == sorted(
            expect["errors"]
        ), f"expected {sorted(expect['errors'])} got {sorted(v.errors)}"
    if "coordinate" in expect:
        assert v.coordinate == expect["coordinate"]
    if "entries" in expect:
        assert len(v.entries) == expect["entries"]
    if expect["valid"]:
        assert v.pubkey == event["pubkey"]
        assert v.event_id == event["id"]
        assert v.d == expect.get("d")


def test_valid_entries_parse(corpus_case: dict):
    expect = corpus_case["expect"]
    if not expect["valid"]:
        return
    v = collections.validate_collection(corpus_case["event"], forbidden_pubkeys={HOST_PUBKEY})
    for entry in v.entries:
        assert entry.kind in ("live-root", "live-named", "pinned")
        if entry.kind in ("live-root", "live-named"):
            assert collections.is_valid_site_coordinate(entry.ref)
        else:
            assert collections.is_sha256_hex(entry.ref)
        assert entry.relay == "" or entry.relay.startswith(("wss://", "ws://"))


def test_plan_digest_matches_reference():
    # Same inputs as the Admin's collection.ts must produce the same digest:
    # sha256 over JSON([pubkey, d, title, description, image, orderedEntries, sortedRelays]).
    entries = [["a", f"15128:{'a' * 64}:", "wss://relay.example"], ["e", "b" * 64]]
    digest = collections.collection_plan_digest(
        pubkey="c" * 64,
        d="indie-web",
        title="Small independent sites",
        description="Personal sites.",
        image="https://cdn.example/a.webp",
        entries=entries,
        relays=["wss://nos.lol", "wss://relay.example"],
    )
    assert len(digest) == 64
    # Relay order must not matter.
    same = collections.collection_plan_digest(
        pubkey="c" * 64,
        d="indie-web",
        title="Small independent sites",
        description="Personal sites.",
        image="https://cdn.example/a.webp",
        entries=entries,
        relays=["wss://relay.example", "wss://nos.lol"],
    )
    assert same == digest
    # Entry order matters (display order).
    swapped = collections.collection_plan_digest(
        pubkey="c" * 64,
        d="indie-web",
        title="Small independent sites",
        description="Personal sites.",
        image="https://cdn.example/a.webp",
        entries=list(reversed(entries)),
        relays=["wss://nos.lol", "wss://relay.example"],
    )
    assert swapped != digest


def test_plan_digest_parity_with_non_ascii_metadata():
    # The digest JSON must be canonical UTF-8 (ensure_ascii=False): a non-ASCII
    # title/description would otherwise be escaped as \uXXXX by the fork and
    # diverge from the Admin's JSON.stringify (which emits raw UTF-8). Expected
    # value is the Admin's own output for these exact inputs.
    digest = collections.collection_plan_digest(
        pubkey="b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732",
        d="indie-web",
        title="Café ☕ 独立",
        description="Émoticônes 😀 et accents.",
        image="https://cdn.example/a.webp",
        entries=[
            ["a", "15128:266815e0c9210dfa324c6cba3573b14bee49da4209a9456f9484e5106cd408a5:", "wss://nos.lol"],
            ["e", "5c8ed07b8c33b5d1e2d1c1dcec4d1d1a1e1f1a1b1c1d1e1f2021222324252627"],
        ],
        relays=["wss://nos.lol"],
    )
    assert digest == "6cbde45e5b8629bfc9b9e6c6a007e5436bea8c7925b6442af4435fc52f24df66"


def test_coordinate_helpers():
    assert collections.coordinate(30004, "c" * 64, "blog") == f"30004:{'c' * 64}:blog"
    assert collections.is_valid_coordinate(f"30004:{'c' * 64}:blog")
    assert not collections.is_valid_coordinate("30004:nothex:")
    assert collections.is_valid_site_coordinate(f"15128:{'a' * 64}:")
    assert collections.is_valid_site_coordinate(f"35128:{'a' * 64}:blog")
    assert not collections.is_valid_site_coordinate("15128:nothex:")
    assert not collections.is_valid_coordinate(f"15128:{'a' * 64}:")
    assert collections.is_valid_d("blog")
    assert not collections.is_valid_d("has space")