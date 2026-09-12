"""Interop / known-answer tests locking the nostr-sdk migration to the
NIP-01 canonical serialization.

The fork previously signed and verified events with coincurve over a
hand-rolled sha256 of ``[0, pubkey, created_at, kind, tags, content]``
serialized with ``json.dumps(separators=(",", ":"), ensure_ascii=False)``.
nostr-sdk computes the same id internally, so the event id is the
deterministic interop anchor: it is what the local control relay and the Go
control plane validate. These tests pin that byte-for-byte equality and the
public-key derivation (the previous coincurve from_secret/from_valid_secret
paths are no longer a dependency, but their outputs are frozen here).

Run with: pytest tests_nostr/test_nostr_sdk_interop.py
"""

from __future__ import annotations

import hashlib
import json

from nostr_sdk import EventBuilder, Keys, Kind, Tag, Timestamp

from yunohost.nostr_identity import _pubkey, _sign_event

FIXED_SK = "3f4f6b8d" * 8
FIXED_PUBKEY = "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732"
FIXED_KIND = 2721
FIXED_TAGS = [["e", "a" * 64], ["p", "b" * 64], ["t", "interop"]]
FIXED_CONTENT = '{"tool":"user.create","args":{"username":"alice"}}'
FIXED_CREATED_AT = 1750000000
# sha256([0, FIXED_PUBKEY, FIXED_CREATED_AT, FIXED_KIND, FIXED_TAGS, FIXED_CONTENT])
# in the canonical NIP-01 form. Hand-rolled serialization and nostr-sdk
# must agree on this value byte-for-byte (the old coincurve code, the relay,
# and the Go control plane all derive/validate the same id).
KNOWN_ID = "f4d30d31265c9853aaad771ccd7c2620404e78eb3c56761f977940e452cecb37"


def _canonical(pubkey: str, created_at: int, kind: int, tags: list[list[str]], content: str) -> str:
    serialized = json.dumps([0, pubkey, created_at, kind, tags, content], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def test_pubkey_derivation_matches_the_frozen_coincurve_value():
    # PublicKeyXOnly.from_secret(bytes.fromhex(FIXED_SK)).format().hex()
    # produced this value before the migration; Keys.parse must reproduce it.
    assert _pubkey(FIXED_SK) == FIXED_PUBKEY


def test_sdk_id_matches_the_known_answer_id():
    event = EventBuilder(Kind(FIXED_KIND), FIXED_CONTENT).tags(
        [Tag.parse(t) for t in FIXED_TAGS]
    ).custom_created_at(Timestamp.from_secs(FIXED_CREATED_AT)).finalize(Keys.parse(FIXED_SK))
    assert event.id().to_hex() == KNOWN_ID
    assert event.verify()


def test_sign_event_id_matches_canonical_serialization():
    event = _sign_event(FIXED_SK, FIXED_PUBKEY, FIXED_KIND, FIXED_CONTENT, FIXED_TAGS)
    assert event["pubkey"] == FIXED_PUBKEY
    assert event["kind"] == FIXED_KIND
    assert event["tags"] == FIXED_TAGS
    assert event["content"] == FIXED_CONTENT
    assert event["id"] == _canonical(FIXED_PUBKEY, event["created_at"], FIXED_KIND, FIXED_TAGS, FIXED_CONTENT)
    assert len(event["sig"]) == 128


def test_sign_event_output_verifies():
    event = _sign_event(FIXED_SK, FIXED_PUBKEY, FIXED_KIND, FIXED_CONTENT, FIXED_TAGS)
    parsed = EventBuilder(Kind(event["kind"]), event["content"]).tags(
        [Tag.parse(t) for t in event["tags"]]
    ).custom_created_at(Timestamp.from_secs(event["created_at"])).finalize(Keys.parse(FIXED_SK))
    assert parsed.id().to_hex() == event["id"]


def test_sign_event_non_ascii_content_id_compat():
    # rust-nostr serializes unicode unescaped, matching the previous
    # json.dumps(..., ensure_ascii=False) canonical form.
    content = "héllo — wörld ✓ 中文"
    event = _sign_event(FIXED_SK, FIXED_PUBKEY, FIXED_KIND, content, [])
    assert event["id"] == _canonical(FIXED_PUBKEY, event["created_at"], FIXED_KIND, [], content)
