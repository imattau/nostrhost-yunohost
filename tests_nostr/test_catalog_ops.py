"""Native catalogue surface (MCP transition Phase 5): catalog.list/get/publish.

The ops shell out to the `nostrhost-catalog` CLI; these tests stub the CLI
with a fake so no Go binary or relay is needed. catalog.publish is the key
case: it must build a kind-32267 declaration from the trusted projection and
sign it with the node's **publisher** key (operator.toml), never the operator
key.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from yunohost.nostr_operations import TOOLS, KNOWN_SCOPES, OperationError


@pytest.fixture()
def boot(tmp_path: Path, monkeypatch):
    from yunohost.nostr_identity import bootstrap_node

    monkeypatch.setenv("NOSTRHOST_OPERATOR_CONFIG", str(tmp_path / "operator.toml"))
    monkeypatch.setenv("NOSTRHOST_NOTICE_CONFIG", str(tmp_path / "portal.toml"))
    monkeypatch.setenv("NOSTRHOST_CATALOG_BIN", "/nonexistent/nostrhost-catalog")
    state = tmp_path / "catalogue.json"
    monkeypatch.setenv("NOSTRHOST_CATALOG_STATE", str(state))
    state.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "declaration": {
                            "AppID": "nostrhost-test",
                            "Repository": "https://git.example.com/nostrhost-test.git",
                            "Version": "1.0.0",
                            "Commit": "a" * 40,
                            "ManifestHash": "b" * 64,
                            "ContentHash": "c" * 64,
                            "Architectures": ["linux/amd64"],
                            "PackagePath": "package.toml",
                        },
                        "event_id": "d" * 64,
                    }
                ]
            }
        )
    )
    return bootstrap_node(force=True, write_relay=str(tmp_path / "relay.toml"))


@pytest.fixture()
def cli_fake(monkeypatch):
    """Replace native_ops._catalog_cli with a recorder returning canned JSON."""
    import nostrhost.native_ops as no

    calls: list[tuple[list[str], bytes | None]] = []

    def fake(sub: list[str], stdin_data: bytes | None = None):
        calls.append((sub, stdin_data))
        if sub[0] == "publish":
            assert stdin_data is not None
            return {"event_id": json.loads(stdin_data)["id"], "published": 1, "failed": 0, "relays": [{"relay": "ws://127.0.0.1:4848"}]}
        if sub[0] == "ingest":
            assert stdin_data is not None
            return {"changed": True, "event_id": json.loads(stdin_data)["id"]}
        if sub[0] == "list":
            return {"entries": []}
        if sub[0] == "get":
            return {"app_id": sub[1]}
        raise AssertionError(f"unexpected subcommand {sub}")

    monkeypatch.setattr(no, "_catalog_cli", fake)
    return calls


# --------------------------------------------------------------------------- #
# registry

def test_catalog_ops_registered_with_catalog_scopes():
    for name, scope in (("catalog.list", "catalog.inspect"), ("catalog.get", "catalog.inspect"), ("catalog.publish", "catalog.publish")):
        spec = TOOLS[name]
        assert spec.scope == scope
        assert spec.scope in KNOWN_SCOPES
    assert TOOLS["catalog.list"].require_approval is False
    assert TOOLS["catalog.get"].require_approval is False
    assert TOOLS["catalog.publish"].require_approval is True


# --------------------------------------------------------------------------- #
# reads

def test_catalog_list_and_get(boot, cli_fake):
    import nostrhost.native_ops as no

    assert no._safe_catalog_list() == {"entries": []}
    assert no._safe_catalog_get(app_id="nostrhost-test") == {"app_id": "nostrhost-test"}
    assert [c[0][0] for c in cli_fake] == ["list", "get"]


def test_catalog_get_requires_app_id():
    import nostrhost.native_ops as no

    with pytest.raises(OperationError):
        no._safe_catalog_get(app_id="")


# --------------------------------------------------------------------------- #
# publish signs with the publisher key

def test_catalog_publish_signs_with_publisher_key(boot, cli_fake):
    import nostrhost.native_ops as no

    result = no._safe_catalog_publish(app_id="nostrhost-test", relays="ws://127.0.0.1:4848")
    assert result["publisher_pubkey"] == boot["publisher_pubkey"]

    pub_call = next(c for c in cli_fake if c[0][0] == "publish")
    event = json.loads(pub_call[1])
    assert event["pubkey"] == boot["publisher_pubkey"]
    assert event["pubkey"] != boot["operator_pubkey"]
    assert event["kind"] == 32267

    tags = dict((t[0], t[1]) for t in event["tags"])
    assert tags["d"] == "nostrhost-test"
    assert tags["platform"] == "yunohost"
    assert tags["repository"] == "https://git.example.com/nostrhost-test.git"
    assert tags["commit"] == "a" * 40
    assert tags["manifest"] == f"sha256:{'b' * 64}"
    assert tags["content"] == f"sha256:{'c' * 64}"
    assert tags["package"] == "package.toml"

    serialized = json.dumps([0, event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]], separators=(",", ":"), ensure_ascii=False).encode()
    assert hashlib.sha256(serialized).hexdigest() == event["id"]

    from coincurve import PublicKeyXOnly

    pubkey = PublicKeyXOnly(bytes.fromhex(event["pubkey"]))
    assert pubkey.verify(bytes.fromhex(event["sig"]), hashlib.sha256(serialized).digest())

    assert [c[0][0] for c in cli_fake] == ["publish", "ingest"]


def test_catalog_publish_unknown_app_rejected(boot, cli_fake):
    import nostrhost.native_ops as no

    with pytest.raises(OperationError, match="not in the trusted native catalogue"):
        no._safe_catalog_publish(app_id="does-not-exist")
