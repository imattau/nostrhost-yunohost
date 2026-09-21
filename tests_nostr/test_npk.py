"""Tests for the npack integration module (hybrid staged store)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nostrhost.npk import NPK_NATIVE_MANIFEST, load_embedded_manifest, parse_coordinate, resolve, verify_embedded_matches


def test_parse_coordinate_splits_publisher_name_version():
    assert parse_coordinate("npub1abc/hello") == ("npub1abc", "hello", None)
    assert parse_coordinate("npub1abc/hello@1.2.3") == ("npub1abc", "hello", "1.2.3")
    publisher, name, _ = parse_coordinate("ab" * 32 + "/world@2.0.0")
    assert publisher == "ab" * 32
    assert name == "world"
    with pytest.raises(Exception):
        parse_coordinate("not-a-coordinate")
    with pytest.raises(Exception):
        parse_coordinate("bad-publisher/name")


def _resolved():
    return {
        "publisher": "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
        "name": "npkapp",
        "version": "1.0.0",
        "sha256": "6ebd0370f6451e2b690e606c86d15c73f382670f834063fb4baf5c1da61d70ec",
        "os": "linux",
        "arch": "x86_64",
        "format": "npk",
        "artifact_urls": ["https://blossom.example/6ebd0370"],
        "dependencies": [],
        "conflicts": [],
        "runtime_requires": [],
        "provides": [],
        "release_event_id": "e" * 64,
        "artifact_event_id": "a" * 64,
        "verification": {
            "release_signature_valid": True,
            "artifact_event_signature_valid": True,
            "release_event_is_v1": True,
            "publisher_trusted": True,
            "revoked": False,
        },
    }


def _fake_npack(tmp_path: Path, body: dict) -> Path:
    fake = tmp_path / "npack"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        "print(json.dumps(" + repr(body) + "))\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    return fake


def test_resolve_rejects_revoked_or_untrusted(tmp_path):
    with pytest.raises(Exception, match="signature"):
        resolve("npub1abc/npkapp", relay="wss://x", npack_bin=str(_fake_npack(tmp_path, {})))
    # revoked variant
    body = _resolved()
    body["verification"]["revoked"] = True
    with pytest.raises(Exception, match="revoked"):
        resolve("npub1abc/npkapp", relay="wss://x", npack_bin=str(_fake_npack(tmp_path, body)))
    # untrusted publisher
    body = _resolved()
    body["verification"]["publisher_trusted"] = False
    with pytest.raises(Exception, match="not trusted"):
        resolve("npub1abc/npkapp", relay="wss://x", npack_bin=str(_fake_npack(tmp_path, body)))
    # happy path
    body = _resolved()
    result = resolve("npub1abc/npkapp", relay="wss://x", npack_bin=str(_fake_npack(tmp_path, body)))
    assert result["name"] == "npkapp"


def test_load_embedded_manifest_reads_native_manifest(tmp_path):
    payload_root = tmp_path / "payload"
    (payload_root / ".npack" / "nostrhost").mkdir(parents=True)
    (payload_root / NPK_NATIVE_MANIFEST).write_text(
        json.dumps({"app": {"id": "demo", "version": "1.0.0"}}), encoding="utf-8"
    )
    data = load_embedded_manifest(payload_root)
    assert data["app"] == {"id": "demo", "version": "1.0.0"}
    with pytest.raises(Exception, match="not a native"):
        (payload_root / NPK_NATIVE_MANIFEST).write_text("{}", encoding="utf-8")
        load_embedded_manifest(payload_root)


def test_verify_embedded_matches_canonical_digest():
    import hashlib

    data = {"app": {"id": "demo", "version": "1.0.0"}}
    # no expected digest -> no check
    verify_embedded_matches(data, {})
    good = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    verify_embedded_matches(data, {"manifest_sha256": good})
    with pytest.raises(Exception, match="mismatch"):
        verify_embedded_matches(data, {"manifest_sha256": "f" * 64})
