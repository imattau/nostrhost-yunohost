"""NIP-46 client tests against an in-process fake signer.

The transport is injected, so the full request/encrypt/response/validate
flow is exercised without a relay. The fake signer mirrors the local test
bunker (testbed/e2e/nip46-bunker.js): NIP-44 v2, kind 24133, methods
connect/get_public_key/sign_event.
"""

from __future__ import annotations

import json

import pytest

from yunohost.nostr_nip46 import (
    NIP46_KIND,
    Nip46Error,
    Nip46Timeout,
    _decrypt,
    _encrypt,
    build_request_event,
    parse_bunker_uri,
    parse_response,
    sign_event_via_bunker,
)
from yunohost.nostr_identity import _sign_event
from yunohost.nostr_operations import _derive_pubkey, build_approval_template, validate_signed_approval
from conftest import new_key


def fake_signer(signer_sk: str):
    """An in-process signer: returns (transport, calls)."""
    signer_pubkey = _derive_pubkey(signer_sk)
    calls: list[dict] = []

    def transport(relays, event, responder_pubkey, timeout):
        calls.append({"event": event, "relays": list(relays), "timeout": timeout})
        body = json.loads(_decrypt(signer_sk, event["pubkey"], event["content"]))
        if body["method"] == "connect":
            plain = json.dumps({"id": body["id"], "result": body["params"][1]})
        elif body["method"] == "get_public_key":
            plain = json.dumps({"id": body["id"], "result": signer_pubkey})
        elif body["method"] == "sign_event":
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
        else:
            plain = json.dumps({"id": body["id"], "error": f"unknown method {body['method']}"})
        content = _encrypt(signer_sk, event["pubkey"], plain)
        return _sign_event(signer_sk, signer_pubkey, NIP46_KIND, content, [["p", event["pubkey"]]])

    return transport, calls


def test_parse_bunker_uri():
    signer = "ab" * 32
    parsed = parse_bunker_uri(
        f"bunker://{signer}?relay=wss%3A%2F%2Frelay.example.com&relay=wss%3A%2F%2Fbackup.example.com&secret=s3cret"
    )
    assert parsed["signer_pubkey"] == signer
    assert parsed["relays"] == ["wss://relay.example.com", "wss://backup.example.com"]
    assert parsed["secret"] == "s3cret"


@pytest.mark.parametrize(
    "uri",
    [
        "https://not-a-bunker",
        "bunker://not-a-hex-key?relay=wss://r.example",
        "bunker://" + "ab" * 32,  # no relay
    ],
)
def test_parse_bunker_uri_rejects_invalid(uri):
    with pytest.raises(Nip46Error):
        parse_bunker_uri(uri)


def test_sign_event_via_bunker_roundtrip_and_validates_as_approval():
    client_sk, _ = new_key()
    signer_sk, signer_pk = new_key()
    _, admin_pk = new_key()
    transport, calls = fake_signer(signer_sk)

    template = build_approval_template(admin_pk, "cd" * 32, note="go")
    # The signer's key must be the admin identity being approved, so point the
    # template at the signer to prove the returned event validates.
    template["pubkey"] = signer_pk

    signed = sign_event_via_bunker(
        client_sk=client_sk,
        signer_pubkey=signer_pk,
        relays=["wss://relay.example.com"],
        unsigned_event=template,
        secret="s3cret",
        transport=transport,
    )

    assert signed["pubkey"] == signer_pk
    # The returned event is exactly what the approval validator accepts.
    validated = validate_signed_approval(signed, "cd" * 32)
    assert validated["id"] == signed["id"]
    # connect + sign_event
    assert len(calls) == 2
    assert [json.loads(_decrypt(signer_sk, calls[1]["event"]["pubkey"], c["event"]["content"]))["method"] for c in calls] == [
        "connect",
        "sign_event",
    ]


def test_sign_event_without_connect_when_no_secret():
    client_sk, _ = new_key()
    signer_sk, signer_pk = new_key()
    transport, calls = fake_signer(signer_sk)
    template = build_approval_template(signer_pk, "cd" * 32)

    sign_event_via_bunker(
        client_sk=client_sk,
        signer_pubkey=signer_pk,
        relays=["wss://relay.example.com"],
        unsigned_event=template,
        transport=transport,
    )
    assert len(calls) == 1  # sign_event only


def test_sign_event_surfaces_signer_error():
    client_sk, _ = new_key()
    signer_sk, signer_pk = new_key()
    _, admin_pk = new_key()

    def transport(relays, event, responder_pubkey, timeout):
        body = json.loads(_decrypt(signer_sk, event["pubkey"], event["content"]))
        content = _encrypt(signer_sk, event["pubkey"], json.dumps({"id": body["id"], "error": "user denied"}))
        return _sign_event(signer_sk, signer_pk, NIP46_KIND, content, [["p", event["pubkey"]]])

    with pytest.raises(Nip46Error, match="denied"):
        sign_event_via_bunker(
            client_sk=client_sk,
            signer_pubkey=signer_pk,
            relays=["wss://relay.example.com"],
            unsigned_event=build_approval_template(signer_pk, "cd" * 32),
            transport=transport,
        )


def test_sign_event_times_out_when_signer_silent():
    client_sk, _ = new_key()
    _, signer_pk = new_key()
    with pytest.raises(Nip46Timeout):
        sign_event_via_bunker(
            client_sk=client_sk,
            signer_pubkey=signer_pk,
            relays=["wss://relay.example.com"],
            unsigned_event=build_approval_template(signer_pk, "cd" * 32),
            transport=lambda *_args, **_kwargs: None,
            timeout=0.01,
        )


def test_build_request_event_is_addressed_and_correlates():
    client_sk, client_pk = new_key()
    _, signer_pk = new_key()
    event = build_request_event(
        client_sk=client_sk,
        signer_pubkey=signer_pk,
        method="sign_event",
        params=["{}"],
        request_id="deadbeef",
    )
    assert event["kind"] == NIP46_KIND
    assert event["pubkey"] == client_pk
    assert ["p", signer_pk] in event["tags"]

    # Response parsing rejects a response from the wrong author.
    response = {**event, "pubkey": "ff" * 32}
    with pytest.raises(Nip46Error):
        parse_response(client_sk, signer_pk, response)
