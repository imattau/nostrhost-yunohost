"""Tests for the npack integration module (hybrid staged store)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nostrhost.npk import NPK_NATIVE_MANIFEST, load_embedded_manifest, parse_coordinate, resolve, stage_local, verify_embedded_matches

# The fork's pinned npack submodule binary; skip tests that shell out to npack
# when it has not been built (cargo build --release in forks/npack), mirroring
# tools/tests/test_package_authoring.py's NEEDS_NPACK convention.
NPACK = Path(__file__).resolve().parents[2] / "npack" / "target" / "release" / "npack"
NEEDS_NPACK = pytest.mark.skipif(not NPACK.is_file(), reason="npack binary not built (cargo build --release in forks/npack)")
PUBLISHER = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"


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


@NEEDS_NPACK
def test_stage_local_installs_a_locally_built_npk(tmp_path):
    """stage_local() is the local-file counterpart to stage(): no relay, just
    `npack verify`/`hash`/`install` against a real .npk, same output shape."""
    from nostrhost.package_authoring import build_npk_artifact

    package_data = {
        "app": {"id": "npk-local-test", "version": "1.0.0"},
        "directories": {"install": {"path": "/opt/npk-local-test"}},
    }
    artifact = tmp_path / "out.npk"
    build_npk_artifact(
        package_data,
        payload_dir=None,
        output=artifact,
        publisher=PUBLISHER,
        npack_bin=str(NPACK),
    )

    store = tmp_path / "store"
    staged = stage_local(artifact, store=store, npack_bin=str(NPACK))
    assert staged["publisher"] == PUBLISHER
    assert staged["name"] == "npk-local-test"
    assert staged["version"] == "1.0.0"
    assert len(staged["artifact_sha256"]) == 64
    assert staged["store"] == str(store)

    manifest = load_embedded_manifest(staged["payload_root"])
    assert manifest["app"]["id"] == "npk-local-test"
    assert manifest["directories"]["install"]["path"] == "/opt/npk-local-test"


@NEEDS_NPACK
def test_stage_local_rejects_missing_file(tmp_path):
    with pytest.raises(Exception, match="not found"):
        stage_local(tmp_path / "missing.npk", store=tmp_path / "store", npack_bin=str(NPACK))


def test_remove_staged_runs_npack_remove_and_handles_missing_entries(tmp_path, monkeypatch):
    from nostrhost import npk as npk_module

    store = tmp_path / "store"
    store.mkdir()
    (store / "installed.json").write_text(json.dumps([
        {"publisher": "ab" * 32, "name": "hello", "version": "1.0.0"},
    ]))
    calls = []

    def fake_run(binary, args, *, store=None):
        import subprocess

        calls.append((binary, args, str(store)))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(npk_module, "_run", fake_run)

    result = npk_module.remove_staged("hello", store=store)
    assert result == {"publisher": "ab" * 32, "name": "hello", "version": "1.0.0", "store": str(store)}
    assert calls == [("npack", ["remove", f"{'ab' * 32}/hello"], str(store))]

    assert npk_module.remove_staged("missing", store=store) is None
    empty = tmp_path / "empty"
    empty.mkdir()
    assert npk_module.remove_staged("hello", store=empty) is None


def test_remove_staged_surfaces_npack_remove_failure(tmp_path, monkeypatch):
    import subprocess

    from nostrhost import npk as npk_module
    from nostrhost.package_engine import PackageError

    store = tmp_path / "store"
    store.mkdir()
    (store / "installed.json").write_text(json.dumps([{"publisher": "ab" * 32, "name": "hello"}]))
    monkeypatch.setattr(
        npk_module,
        "_run",
        lambda binary, args, *, store=None: subprocess.CompletedProcess(args, 1, "", "boom"),
    )
    with pytest.raises(PackageError, match="npack remove failed: boom"):
        npk_module.remove_staged("hello", store=store)
