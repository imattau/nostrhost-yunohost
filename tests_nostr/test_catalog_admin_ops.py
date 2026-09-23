"""Native catalogue admin-page surface: candidates/attest/history/trust/
reverify/profile/announce. Mirrors test_catalog_ops.py's approach - the CLI
is stubbed with a fake recorder so no Go binary or relay is needed, and
signing is exercised for real through nostr_sdk so a bad tag/kind shape
would fail verification.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from yunohost.nostr_operations import OperationError


@pytest.fixture()
def boot(tmp_path: Path, monkeypatch):
    from yunohost.nostr_identity import bootstrap_node

    monkeypatch.setenv("NOSTRHOST_OPERATOR_CONFIG", str(tmp_path / "operator.toml"))
    monkeypatch.setenv("NOSTRHOST_NOTICE_CONFIG", str(tmp_path / "portal.toml"))
    monkeypatch.setenv("NOSTRHOST_CATALOG_BIN", "/nonexistent/nostrhost-catalog")
    monkeypatch.setenv("NOSTRHOST_CATALOG_STATE", str(tmp_path / "catalogue.json"))
    return bootstrap_node(force=True, write_relay=str(tmp_path / "relay.toml"))


OTHER_PUBLISHER = "f" * 64


@pytest.fixture()
def cli_fake(monkeypatch, boot):
    """Replace native_ops._catalog_cli with a recorder returning canned JSON.

    Unlike test_catalog_ops.py's fixture, this one also accepts the
    extra_flags kwarg the trust/reverify handlers pass.
    """
    import nostrhost.native_ops as no

    calls: list[tuple[list[str], bytes | None, list[str] | None]] = []

    def fake(sub, stdin_data=None, extra_flags=None):
        calls.append((sub, stdin_data, extra_flags))
        if "publish" in sub:
            assert stdin_data is not None
            return {"event_id": json.loads(stdin_data)["id"], "published": 1, "failed": 0, "relays": [{"relay": "ws://127.0.0.1:4848"}]}
        if sub[0] == "ingest":
            assert stdin_data is not None
            return {"changed": True, "event_id": json.loads(stdin_data)["id"]}
        if sub[0] == "list":
            return {
                "entries": [
                    {
                        "declaration": {
                            "AppID": "other-app",
                            "Publisher": OTHER_PUBLISHER,
                            "Version": "1.0.0",
                            "Name": "Other App",
                        },
                        "event_id": "e" * 64,
                    }
                ]
            }
        if sub[0] == "get":
            return {
                "AppID": sub[1] if len(sub) > 1 else "nostrhost-test",
                "Publisher": boot["publisher_pubkey"],
                "Version": "1.0.0",
                "Commit": "a" * 40,
                "Repository": "https://git.example.com/nostrhost-test.git",
                "Name": "nostrhost-test",
            }
        if sub[0] == "trust":
            return [{"declaration": {"AppID": "nostrhost-test"}, "attestations": [], "verified": False, "accepted": True}]
        if sub[0] == "attest-release":
            return {"declaration": {"AppID": "nostrhost-test"}, "attestations": [], "verified": False, "accepted": True}
        raise AssertionError(f"unexpected subcommand {sub}")

    monkeypatch.setattr(no, "_catalog_cli", fake)
    return calls


@pytest.fixture()
def app_list_fake(monkeypatch):
    import nostrhost.cli as cli_module

    monkeypatch.setitem(cli_module._TOOL_HANDLERS, "app.list", lambda **_: {"apps": {"other-app": {}}})


# --------------------------------------------------------------------------- #
# candidates

def test_candidates_excludes_self_and_uninstalled(boot, cli_fake, app_list_fake):
    import nostrhost.native_ops as no

    result = no._safe_catalog_candidates()
    assert result["candidates"] == [
        {"app_id": "other-app", "publisher": OTHER_PUBLISHER, "version": "1.0.0", "name": "Other App"}
    ]


def test_candidates_excludes_already_attested(boot, cli_fake, app_list_fake, monkeypatch):
    import nostrhost.native_ops as no

    monkeypatch.setattr(
        no,
        "_catalog_endorsements",
        lambda: [{"app_id": "other-app", "publisher": OTHER_PUBLISHER}],
    )
    result = no._safe_catalog_candidates()
    assert result["candidates"] == []


# --------------------------------------------------------------------------- #
# attest

def test_attest_signs_endorsement_and_records_history(boot, cli_fake, monkeypatch):
    import nostrhost.native_ops as no

    def fake_endorsements():
        event = json.loads(next(c[1] for c in cli_fake if "publish" in c[0]))
        tags = dict((t[0], t[1]) for t in event["tags"])
        coordinate = tags["a"]
        return [
            {
                "app_id": coordinate.split(":")[2],
                "publisher": coordinate.split(":")[1],
                "claim": tags["claim"],
                "comment": event["content"],
                "event_id": event["id"],
                "created_at": event["created_at"],
            }
        ]

    monkeypatch.setattr(no, "_catalog_endorsements", fake_endorsements)

    result = no._safe_catalog_attest(app_id="other-app", publisher=OTHER_PUBLISHER, claim="recommend", comment="good app")
    assert result["event_id"]

    pub_call = next(c for c in cli_fake if "publish" in c[0])
    event = json.loads(pub_call[1])
    assert event["pubkey"] == boot["publisher_pubkey"]
    assert event["kind"] == 30079
    assert event["content"] == "good app"
    tags = dict((t[0], t[1]) for t in event["tags"])
    assert tags["a"] == f"32267:{OTHER_PUBLISHER}:other-app"
    assert tags["claim"] == "recommend"

    from nostr_sdk import Event

    assert Event.from_json(json.dumps(event)).verify()

    history = no._safe_catalog_history()["history"]
    assert len(history) == 1
    assert history[0]["app_id"] == "other-app"
    assert history[0]["claim"] == "recommend"


def test_attest_rejects_self_endorsement(boot, cli_fake):
    import nostrhost.native_ops as no

    with pytest.raises(OperationError, match="own declaration"):
        no._safe_catalog_attest(app_id="x", publisher=boot["publisher_pubkey"], claim="recommend")


def test_attest_rejects_invalid_claim(boot, cli_fake):
    import nostrhost.native_ops as no

    with pytest.raises(OperationError, match="recommend or tested"):
        no._safe_catalog_attest(app_id="other-app", publisher=OTHER_PUBLISHER, claim="bogus")


# --------------------------------------------------------------------------- #
# trust / reverify

def test_trust_passes_policy_flags_before_subcommand(boot, cli_fake):
    import nostrhost.native_ops as no

    result = no._safe_catalog_trust(attestation_policy="require", min_attestations=2, required_checks=["a", "b"])
    assert result["entries"][0]["declaration"]["AppID"] == "nostrhost-test"
    sub, _, extra_flags = next(c for c in cli_fake if c[0] == ["trust"])
    assert extra_flags == ["--attestation-policy", "require", "--min-attestations", "2", "--required-checks", "a,b"]


def test_attest_release_requires_publisher_name_version(boot, cli_fake):
    import nostrhost.native_ops as no

    with pytest.raises(OperationError, match="publisher, name, and version"):
        no._safe_catalog_attest_release(name="myapp", version="1.0.0")
    with pytest.raises(OperationError, match="publisher, name, and version"):
        no._safe_catalog_attest_release(publisher=OTHER_PUBLISHER, version="1.0.0")
    with pytest.raises(OperationError, match="publisher, name, and version"):
        no._safe_catalog_attest_release(publisher=OTHER_PUBLISHER, name="myapp")


def test_attest_release_passes_release_and_policy_flags_before_subcommand(boot, cli_fake):
    import nostrhost.native_ops as no

    result = no._safe_catalog_attest_release(
        publisher=OTHER_PUBLISHER, name="myapp", version="1.0.0", arch="x86_64",
        relays="wss://relay.example", attestation_policy="require", min_attestations=2,
        required_checks=["a", "b"],
    )
    assert result["declaration"]["AppID"] == "nostrhost-test"
    sub, _, extra_flags = next(c for c in cli_fake if c[0] == ["attest-release"])
    assert extra_flags == [
        "--relay", "wss://relay.example",
        "--publisher", OTHER_PUBLISHER,
        "--name", "myapp",
        "--version", "1.0.0",
        "--arch", "x86_64",
        "--attestation-policy", "require",
        "--min-attestations", "2",
        "--required-checks", "a,b",
    ]


# --------------------------------------------------------------------------- #
# profile

def test_profile_set_publishes_and_reads_back(boot, cli_fake, monkeypatch):
    import nostrhost.native_ops as no

    def fake_own_events(kinds):
        event = json.loads(next(c[1] for c in cli_fake if "publish" in c[0]))
        return [event]

    monkeypatch.setattr(no, "_catalog_own_events", fake_own_events)

    result = no._safe_catalog_profile_set(name="Node Publisher", about="hi")
    assert result["published_any"] is True

    pub_call = next(c for c in cli_fake if "publish" in c[0])
    event = json.loads(pub_call[1])
    assert event["kind"] == 0
    assert json.loads(event["content"]) == {"name": "Node Publisher", "about": "hi"}

    from nostr_sdk import Event

    assert Event.from_json(json.dumps(event)).verify()

    cached = no._safe_catalog_profile_get()
    assert cached["profile"] == {"name": "Node Publisher", "about": "hi"}
    assert cached["self_publisher"] == boot["publisher_pubkey"]


# --------------------------------------------------------------------------- #
# announce

def test_announce_signs_note_and_dedupes(boot, cli_fake, monkeypatch):
    import nostrhost.native_ops as no

    def fake_own_events(kinds):
        published = [c for c in cli_fake if "publish" in c[0]]
        return [json.loads(c[1]) for c in published]

    monkeypatch.setattr(no, "_catalog_own_events", fake_own_events)

    result = no._safe_catalog_announce(app_id="nostrhost-test")
    assert result["event_id"]

    pub_call = next(c for c in cli_fake if "publish" in c[0])
    event = json.loads(pub_call[1])
    assert event["kind"] == 1
    assert "nostrhost-test" in event["content"]
    tags = dict((t[0], t[1]) for t in event["tags"])
    assert tags["a"] == f"32267:{boot['publisher_pubkey']}:nostrhost-test"
    assert tags["version"] == "1.0.0"

    from nostr_sdk import Event

    assert Event.from_json(json.dumps(event)).verify()

    announcements = no._safe_catalog_announcements()["announcements"]
    assert len(announcements) == 1
    assert announcements[0]["app_id"] == "nostrhost-test"

    with pytest.raises(OperationError, match="already announced"):
        no._safe_catalog_announce(app_id="nostrhost-test")


def test_announce_rejects_other_publisher_declaration(boot, monkeypatch):
    import nostrhost.native_ops as no

    def fake(sub, stdin_data=None, extra_flags=None):
        if sub[0] == "get":
            return {"AppID": "other-app", "Publisher": OTHER_PUBLISHER, "Commit": "a" * 40}
        raise AssertionError(f"unexpected subcommand {sub}")

    monkeypatch.setattr(no, "_catalog_cli", fake)
    with pytest.raises(OperationError, match="own declarations"):
        no._safe_catalog_announce(app_id="other-app")
