"""Signer bridge tests: parked notice -> NIP-46 request -> validated 2201.

The NIP-46 signer and the control-relay publisher are both injected, so the
whole fan-out is exercised without a relay. The fake signer mirrors the
in-process signer used by the protocol tests.
"""

from __future__ import annotations

import json

from yunohost.nostr_identity import _sign_event
from yunohost.nostr_nip46 import NIP46_KIND, _decrypt, _encrypt
from yunohost.nostr_operations import _derive_pubkey, validate_signed_approval
from yunohost.nostr_signerd import (
    SignerBridge,
    SignerTarget,
    add_target,
    add_target_from_bunker_uri,
    ensure_client_key,
    load_targets,
    remove_target,
)
from conftest import new_key


def make_transport(signer_sk: str):
    signer_pubkey = _derive_pubkey(signer_sk)

    def transport(relays, event, responder_pubkey, timeout):
        body = json.loads(_decrypt(signer_sk, event["pubkey"], event["content"]))
        if body["method"] == "connect":
            plain = json.dumps({"id": body["id"], "result": body["params"][1]})
        else:
            unsigned = json.loads(body["params"][0])
            signed = _sign_event(
                signer_sk,
                signer_pubkey,
                unsigned["kind"],
                unsigned["content"],
                unsigned["tags"],
                created_at=unsigned["created_at"],
            )
            plain = json.dumps({"id": body["id"], "result": json.dumps(signed)})
        content = _encrypt(signer_sk, event["pubkey"], plain)
        return _sign_event(signer_sk, signer_pubkey, NIP46_KIND, content, [["p", event["pubkey"]]])

    return transport


def notice(request_id: str, tool: str = "app.upgrade", class_: str = "approval") -> dict:
    return {
        "kind": 2210,
        "content": json.dumps({"class": class_, "severity": "warning", "summary": "approval required", "request_id": request_id, "tool": tool}),
    }


def test_bridge_pushes_to_admin_signer_and_publishes_valid_approval(tmp_path):
    client_sk, _ = new_key()
    signer_sk, signer_pk = new_key()
    published = []
    bridge = SignerBridge(
        admin_pubkeys=[signer_pk],
        targets=[SignerTarget(signer_pubkey=signer_pk, relays=("wss://relay.example",), secret="s3cret")],
        client_sk=client_sk,
        publish=lambda relay, event: published.append((relay, event)),
        control_relay="ws://127.0.0.1:4848",
        transport=make_transport(signer_sk),
        state_path=tmp_path / "state.json",
    )
    request_id = "cd" * 32
    assert bridge.handle_notice(notice(request_id)) is True
    bridge.shutdown(wait=True)

    assert len(published) == 1
    relay, event = published[0]
    assert relay == "ws://127.0.0.1:4848"
    validated = validate_signed_approval(event, request_id)
    assert validated["pubkey"] == signer_pk
    assert ["t", "nip46"] in event["tags"]


def test_bridge_ignores_targets_that_are_not_admins(tmp_path):
    client_sk, _ = new_key()
    signer_sk, signer_pk = new_key()
    published = []
    bridge = SignerBridge(
        admin_pubkeys=["ff" * 32],
        targets=[SignerTarget(signer_pubkey=signer_pk, relays=("wss://relay.example",), secret=None)],
        client_sk=client_sk,
        publish=lambda relay, event: published.append(event),
        transport=make_transport(signer_sk),
        state_path=tmp_path / "state.json",
    )
    assert bridge.handle_notice(notice("cd" * 32)) is True
    bridge.shutdown(wait=True)
    assert published == []


def test_bridge_dedups_request_ids(tmp_path):
    client_sk, _ = new_key()
    signer_sk, signer_pk = new_key()
    published = []
    bridge = SignerBridge(
        admin_pubkeys=[signer_pk],
        targets=[SignerTarget(signer_pubkey=signer_pk, relays=("wss://relay.example",), secret=None)],
        client_sk=client_sk,
        publish=lambda relay, event: published.append(event),
        transport=make_transport(signer_sk),
        state_path=tmp_path / "state.json",
    )
    assert bridge.handle_notice(notice("cd" * 32)) is True
    # Second delivery (e.g. the relay replays the notice) is a no-op.
    assert bridge.handle_notice(notice("cd" * 32)) is False
    bridge.shutdown(wait=True)
    assert len(published) == 1


def test_bridge_ignores_non_approval_notices(tmp_path):
    client_sk, _ = new_key()
    _, signer_pk = new_key()
    bridge = SignerBridge(
        admin_pubkeys=[signer_pk],
        targets=[SignerTarget(signer_pubkey=signer_pk, relays=("wss://relay.example",))],
        client_sk=client_sk,
        publish=lambda relay, event: None,
        state_path=tmp_path / "state.json",
    )
    assert bridge.handle_notice(notice("cd" * 32, class_="security")) is False
    assert bridge.handle_notice({"kind": 2200, "content": "{}"}) is False


def test_targets_round_trip_from_bunker_uri(tmp_path):
    path = tmp_path / "targets.json"
    signer = "ab" * 32
    targets = add_target_from_bunker_uri(
        f"bunker://{signer}?relay=wss%3A%2F%2Frelay.example&secret=s3cret",
        label="laptop",
        path=path,
    )
    assert [t.signer_pubkey for t in targets] == [signer]
    loaded = load_targets(path)
    assert loaded[0].relays == ("wss://relay.example",)
    assert loaded[0].secret == "s3cret"
    assert loaded[0].label == "laptop"
    assert remove_target(signer, path=path) is True
    assert load_targets(path) == []
    assert remove_target(signer, path=path) is False


def test_add_target_registers_paired_signer_without_secret(tmp_path):
    path = tmp_path / "targets.json"
    signer = "ab" * 32
    targets = add_target(signer, ["wss://relay.example"], label="phone", path=path)
    assert [t.signer_pubkey for t in targets] == [signer]
    loaded = load_targets(path)
    assert loaded[0].secret is None
    assert loaded[0].relays == ("wss://relay.example",)
    # Re-registering the same signer refreshes rather than duplicates.
    add_target(signer, ["wss://relay2.example"], path=path)
    assert len(load_targets(path)) == 1


def test_ensure_client_key_is_stable(tmp_path):
    path = tmp_path / "client_sk"
    first = ensure_client_key(path)
    assert len(first) == 64
    assert ensure_client_key(path) == first
    assert oct(path.stat().st_mode & 0o777) == "0o600"
