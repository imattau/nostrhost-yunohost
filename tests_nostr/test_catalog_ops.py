"""Native catalogue surface: catalog.list/get (the trusted, relay-synced
projection browsing/discovery reads - shared with npack releases since
Phase 2's ingestion adapter, not a git-specific mechanism).

The ops shell out to the `nostrhost-catalog` CLI; these tests stub the CLI
with a fake so no Go binary or relay is needed.
"""

from __future__ import annotations

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
        if "publish" in sub:
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
    for name, scope in (("catalog.list", "catalog.inspect"), ("catalog.get", "catalog.inspect")):
        spec = TOOLS[name]
        assert spec.scope == scope
        assert spec.scope in KNOWN_SCOPES
    assert TOOLS["catalog.list"].require_approval is False
    assert TOOLS["catalog.get"].require_approval is False


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
