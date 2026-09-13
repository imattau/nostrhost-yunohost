"""Tests for the Phase 5 catalogue verification op (catalog.verify).

Verification mirrors the checks the Go CLI applies on ingest/sync: canonical
event id, Schnorr signature, kind/tag schema and trusted-publisher membership.
Events are signed with the bootstrapped node's real publisher key so the
crypto path is exercised for real.
"""

from __future__ import annotations

import json

import pytest

from yunohost.nostr_identity import bootstrap_node
from yunohost.nostr_operations import OperationError
from yunohost.nostrhost import native_ops


@pytest.fixture()
def boot(tmp_path, monkeypatch):
    monkeypatch.setenv("NOSTRHOST_OPERATOR_CONFIG", str(tmp_path / "operator.toml"))
    monkeypatch.setenv("NOSTRHOST_NOTICE_CONFIG", str(tmp_path / "portal.toml"))
    monkeypatch.setenv("NOSTRHOST_CATALOGUE_ENV", str(tmp_path / "catalogue.env"))
    return bootstrap_node(force=True, write_relay=str(tmp_path / "relay.toml"))


def _declaration_event(sk, pubkey, *, app_id="nostrhost-test", commit="a" * 40, kind=32267):
    from yunohost.nostr_identity import _sign_event

    tags = [
        ["d", app_id],
        ["platform", "yunohost"],
        ["repository", "https://git.example.com/nostrhost-test.git"],
        ["version", "1.0.0"],
        ["commit", commit],
        ["manifest", f"sha256:{'b' * 64}"],
        ["content", f"sha256:{'c' * 64}"],
    ]
    content = json.dumps({"name": "NostrHost Test", "architectures": ["linux/amd64"]})
    return _sign_event(sk, pubkey, kind, content, tags)


def test_catalog_verify_accepts_valid_publisher_event(boot):
    event = _declaration_event(boot["publisher_sk"], boot["publisher_pubkey"])
    result = native_ops._safe_catalog_verify(json.dumps(event))
    assert result["valid"] is True
    assert result["app_id"] == "nostrhost-test"
    assert result["publisher"] == boot["publisher_pubkey"]


def test_catalog_verify_rejects_untrusted_publisher(boot):
    import secrets

    from nostr_sdk import Keys

    # A random key is not in this node's trusted publisher set (the env is
    # still pointed at the bootstrapped node, whose operator config holds the
    # only trusted publisher key).
    rogue_sk = secrets.token_hex(32)
    rogue_pubkey = Keys.parse(rogue_sk).public_key().to_hex()
    event = _declaration_event(rogue_sk, rogue_pubkey)
    with pytest.raises(OperationError, match="not a trusted catalogue publisher"):
        native_ops._safe_catalog_verify(json.dumps(event))


def test_catalog_verify_rejects_tampered_signature(boot):
    event = _declaration_event(boot["publisher_sk"], boot["publisher_pubkey"])
    event["sig"] = "f" * 128
    with pytest.raises(OperationError, match="signature is invalid"):
        native_ops._safe_catalog_verify(json.dumps(event))


def test_catalog_verify_rejects_wrong_kind(boot):
    event = _declaration_event(boot["publisher_sk"], boot["publisher_pubkey"], kind=1)
    with pytest.raises(OperationError, match="not a catalogue declaration"):
        native_ops._safe_catalog_verify(json.dumps(event))


def test_catalog_verify_rejects_missing_tags(boot):
    event = _declaration_event(boot["publisher_sk"], boot["publisher_pubkey"])
    event["tags"] = [["d", "nostrhost-test"]]
    with pytest.raises(OperationError, match="exactly one 'version'"):
        native_ops._safe_catalog_verify(json.dumps(event))


def test_catalog_verify_rejects_naddr(boot):
    with pytest.raises(OperationError, match="does not yet support naddr"):
        native_ops._safe_catalog_verify("naddr1...something")


def test_catalog_verify_rejects_non_json():
    with pytest.raises(OperationError, match="JSON"):
        native_ops._safe_catalog_verify("not json at all")
