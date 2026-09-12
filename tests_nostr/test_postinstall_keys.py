"""Postinstall key generation + safe-keeping helpers (POSTINSTALL-KEYS.md).

Covers the five-key bootstrap (server/operator/notice/publisher/notifier),
the nsec1/hex normalization, the show-once recovery bundle + keys.recovery
file, and the notify/catalogue config rendering. The node-key requirement on
restore is asserted through the keys-file loader (the restore path itself
needs root + a state source).
"""

from __future__ import annotations

import os
import stat
import tomllib
from pathlib import Path

import pytest

from nostrhost import cli as cli_module
from nostrhost.cli import (
    _load_keys_file,
    _normalize_sk,
    _recovery_bundle,
    _render_catalogue_env,
    _render_keys_recovery,
    _render_notify_config,
)

NODE_KEYS = ("operator_sk", "server_sk", "notice_sk", "publisher_sk", "notifier_sk")
NODE_PUBKEYS = ("operator_pubkey", "server_pubkey", "notice_pubkey", "publisher_pubkey", "notifier_pubkey")


@pytest.fixture()
def boot(tmp_path: Path, monkeypatch):
    """A fresh five-key bootstrap in a tmp config root."""
    from yunohost.nostr_identity import bootstrap_node

    monkeypatch.setenv("NOSTRHOST_OPERATOR_CONFIG", str(tmp_path / "operator.toml"))
    monkeypatch.setenv("NOSTRHOST_NOTICE_CONFIG", str(tmp_path / "portal.toml"))
    return bootstrap_node(force=True, write_relay=str(tmp_path / "relay.toml"))


def _set_render_paths(tmp_path: Path, monkeypatch):
    for k, name in (
        ("NOSTRHOST_NOTIFY_CONFIG", "notify.toml"),
        ("NOSTRHOST_CATALOGUE_ENV", "catalogue.env"),
        ("NOSTRHOST_KEYS_RECOVERY", "keys.recovery"),
        ("NOSTRHOST_NOTIFY_STATE_DIR", "state/notifications"),
    ):
        monkeypatch.setenv(k, str(tmp_path / name))


# --------------------------------------------------------------------------- #
# normalize

def test_normalize_sk_accepts_hex_and_nsec1(tmp_path: Path, monkeypatch, boot):
    from nostr_sdk import SecretKey

    hex_sk = boot["operator_sk"]
    nsec1 = SecretKey.parse(hex_sk).to_bech32()
    assert _normalize_sk(hex_sk) == hex_sk
    assert _normalize_sk(nsec1) == hex_sk


def test_normalize_sk_rejects_garbage():
    with pytest.raises(cli_module.NostrHostError):
        _normalize_sk("not-a-key")


# --------------------------------------------------------------------------- #
# recovery bundle + keys.recovery

def test_recovery_bundle_is_nsec1_and_npubs(boot):
    bundle = _recovery_bundle(boot)
    assert set(bundle["keys"]) == set(NODE_KEYS)
    assert set(bundle["npubs"]) == set(NODE_PUBKEYS)
    assert all(v.startswith("nsec1") for v in bundle["keys"].values())
    assert all(v.startswith("npub1") for v in bundle["npubs"].values())


def test_keys_recovery_round_trip(tmp_path: Path, monkeypatch, boot):
    _set_render_paths(tmp_path, monkeypatch)
    path = _render_keys_recovery(boot)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert path.read_text().startswith("# nostrhost keys recovery bundle")

    loaded = _load_keys_file(path)
    assert loaded == {k: boot[k] for k in NODE_KEYS}


def test_keys_file_missing_key_rejected(tmp_path: Path, monkeypatch, boot):
    _set_render_paths(tmp_path, monkeypatch)
    path = tmp_path / "partial.recovery"
    path.write_text('[keys]\noperator_sk = "a" * 64\n')
    with pytest.raises(cli_module.NostrHostError, match="missing"):
        _load_keys_file(path)


# --------------------------------------------------------------------------- #
# rendered configs

def test_notify_config_holds_only_notifier_key(tmp_path: Path, monkeypatch, boot):
    _set_render_paths(tmp_path, monkeypatch)
    path = _render_notify_config(boot["notifier_sk"], "ws://127.0.0.1:4848")
    data = tomllib.loads(path.read_text())
    assert data["notifier_private_key"] == boot["notifier_sk"]
    assert data["relay_url"] == "ws://127.0.0.1:4848"
    text = path.read_text()
    for k in ("operator_sk", "server_sk", "notice_sk", "publisher_sk"):
        assert boot[k] not in text, f"{k} leaked into the notify config"


def test_catalogue_env_lists_publisher(tmp_path: Path, monkeypatch, boot):
    _set_render_paths(tmp_path, monkeypatch)
    path = _render_catalogue_env(boot["publisher_pubkey"])
    assert f"NOSTRHOST_CATALOG_PUBLISHERS={boot['publisher_pubkey']}" in path.read_text()
