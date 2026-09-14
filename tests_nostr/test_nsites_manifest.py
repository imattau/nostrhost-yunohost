"""NIP-5A manifest validator tests over the shared conformance corpus.

The corpus lives in the parent repo at ``tools/tests/nsites/corpus``. CI checks
the parent repo out with submodules, so the relative path exists there; when
the fork is developed standalone the whole module is skipped.

Run with: PYTHONPATH=src python -m pytest -c /dev/null tests_nostr/test_nsites_manifest.py -q
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nostrhost.nsites import manifest

CORPUS_DIR = (
    Path(__file__).resolve().parents[3] / "tools" / "tests" / "nsites" / "corpus"
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
    reason="nsites corpus not present (parent repo checkout required)",
)


@pytest.fixture(scope="module", params=_corpus_files(), ids=lambda p: p.stem)
def corpus_case(request: pytest.FixtureRequest):
    return json.loads(request.param.read_text())


def test_corpus_verdicts(corpus_case: dict):
    event = corpus_case["event"]
    expect = corpus_case["expect"]
    v = manifest.validate_manifest(
        event,
        forbidden_pubkeys={HOST_PUBKEY},
        max_paths=expect.get("max_paths", 5000),
    )
    if expect["valid"]:
        assert v.valid, v.errors
        assert v.errors == []
    else:
        assert not v.valid
        assert sorted(v.errors) == sorted(
            expect["errors"]
        ), f"expected {sorted(expect['errors'])} got {sorted(v.errors)}"
    if "site_type" in expect:
        assert v.site_type == expect["site_type"]
    if "aggregate_hash" in expect:
        assert v.aggregate_hash == expect["aggregate_hash"]
        assert v.aggregate_hash == manifest.aggregate_hash(v.paths)
    if "label" in expect:
        assert v.label == expect["label"]
    if expect["valid"]:
        assert v.pubkey == event["pubkey"]
        assert v.event_id == event["id"]


def test_valid_labels_decode(corpus_case: dict):
    expect = corpus_case["expect"]
    if not expect.get("valid") or "label" not in expect:
        return
    event = corpus_case["event"]
    site_type = expect.get("site_type")
    label = expect["label"]
    decoded = manifest.decode_label(label)
    if site_type == "root":
        assert decoded == ("root", event["pubkey"], None)
    elif site_type == "named":
        assert decoded == ("named", event["pubkey"], expect["d"])
    elif site_type == "snapshot":
        assert decoded == ("snapshot", event["id"], None)


def test_aggregate_hash_matches_reference(corpus_case: dict):
    expect = corpus_case["expect"]
    if "aggregate_hash" not in expect:
        return
    paths = [
        (t[1], t[2])
        for t in corpus_case["event"]["tags"]
        if t and t[0] == "path" and len(t) >= 3
    ]
    assert manifest.aggregate_hash(paths) == expect["aggregate_hash"]


def test_aggregate_hash_order_independence():
    paths = [("/index.html", "a" * 64), ("/about.html", "b" * 64)]
    assert manifest.aggregate_hash(list(reversed(paths))) == manifest.aggregate_hash(
        paths
    )


def test_named_label_bounds():
    # pubkeyB36 is exactly 50 chars; d fills the remaining 1-13 of the 63
    # char DNS label limit.
    pubkey = "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732"
    assert len(manifest.b36_encode_32(pubkey)) == 50
    assert len(manifest.named_label(pubkey, "a")) == 51
    assert len(manifest.named_label(pubkey, "a" * 13)) == 63
    assert manifest.is_valid_d("a" * 13)
    assert not manifest.is_valid_d("a" * 14)
    assert not manifest.is_valid_d("blog-")
    assert not manifest.is_valid_d("Blog")


def test_b36_roundtrip():
    values = [
        "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ]
    for hexv in values:
        assert manifest.b36_decode_50(manifest.b36_encode_32(hexv)) == hexv


def test_decode_label_garbage():
    assert manifest.decode_label("") == (None, None, None)
    assert manifest.decode_label("not-a-label") == (None, None, None)
    assert manifest.decode_label("npub1tampered") == (None, None, None)
    assert manifest.decode_label("v" + "0" * 49) == (
        None,
        None,
        None,
    )  # 49 chars, not 50
    assert manifest.decode_label("b" * 50 + "-") == (
        None,
        None,
        None,
    )  # d ends with '-'


def test_forbidden_signer_guard():
    event = {
        "kind": manifest.KIND_ROOT,
        "content": "",
        "created_at": 1750000000,
        "tags": [["path", "/index.html", "a" * 64]],
        "pubkey": HOST_PUBKEY,
    }
    # Build a valid event signed by the host key, then assert the guard fires.
    from nostr_sdk import EventBuilder, Kind, Keys, Tag, Timestamp

    built = (
        EventBuilder(Kind(manifest.KIND_ROOT), "")
        .tags([Tag.parse(t) for t in event["tags"]])
        .custom_created_at(Timestamp.from_secs(1750000000))
        .finalize(Keys.parse("deadbeef" * 8))
    )
    event = json.loads(built.as_json())
    v = manifest.validate_manifest(event, forbidden_pubkeys={HOST_PUBKEY})
    assert not v.valid
    assert v.errors == ["forbidden_signer"]
    # Without the guard the same event is valid.
    assert manifest.validate_manifest(event).valid


def test_canonical_site_url():
    label = manifest.named_label(
        "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732", "blog"
    )
    assert (
        manifest.canonical_site_url(label, "sites.example.org")
        == f"{label}.sites.example.org"
    )
