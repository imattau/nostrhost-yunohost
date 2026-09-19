"""Node-initiated NIP-46 pairing registry tests.

The blocking NIP-46 wait and the target persistence are both injected, so the
whole async pairing lifecycle is exercised without a relay or a signer app.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from yunohost.nostr_nip46 import Nip46Timeout
from yunohost.nostr_operations import _derive_pubkey
from yunohost.nostr_signer_pairing import (
    STATUS_EXPIRED,
    STATUS_FAILED,
    STATUS_PAIRED,
    STATUS_PENDING,
    PairingRegistry,
)
from conftest import new_key


class FakeClock:
    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def make_registry(client_sk, *, pair_fn, save_target, clock=None, timeout=180.0, max_pending=8):
    return PairingRegistry(
        client_sk=client_sk,
        pair_fn=pair_fn,
        save_target=save_target,
        clock=clock or FakeClock(),
        timeout=timeout,
        max_pending=max_pending,
        start_thread=False,
    )


def test_start_builds_uri_with_secret_and_stays_pending():
    client_sk, _ = new_key()
    _, admin_pk = new_key()
    saved = []
    registry = make_registry(
        client_sk,
        pair_fn=lambda **_k: {"signer_pubkey": admin_pk, "relays": ["wss://r"]},
        save_target=lambda *a, **k: saved.append((a, k)),
    )
    pending = registry.start(admin_pubkey=admin_pk, relays=["wss://r.example"])

    assert pending.status == STATUS_PENDING
    assert pending.uri.startswith("nostrconnect://" + _derive_pubkey(client_sk))
    query = parse_qs(urlsplit(pending.uri).query)
    assert query["relay"] == ["wss://r.example"]
    assert query["secret"] == [pending.secret]
    # Nothing is persisted until the signer actually connects.
    assert saved == []
    assert registry.get(pending.pairing_id) is pending


def test_run_persists_target_and_marks_paired():
    client_sk, _ = new_key()
    _, admin_pk = new_key()
    calls = []

    def pair_fn(*, client_sk, relays, secret, timeout, is_admin):
        # The registry must only accept this admin's own identity.
        assert is_admin(admin_pk) is True
        assert is_admin(("ff" * 32)) is False
        calls.append((client_sk, relays, secret, timeout))
        return {"signer_pubkey": admin_pk, "relays": ["wss://signer.example"]}

    saved = []
    registry = make_registry(
        client_sk,
        pair_fn=pair_fn,
        save_target=lambda pubkey, relays, **k: saved.append((pubkey, relays, k)),
    )
    pending = registry.start(admin_pubkey=admin_pk, relays=["wss://relay.example"])
    registry._run(pending, "phone")

    assert calls and calls[0][1] == ["wss://relay.example"]
    assert saved == [(admin_pk, ["wss://signer.example"], {"label": "phone"})]
    assert pending.status == STATUS_PAIRED
    assert pending.signer_pubkey == admin_pk
    assert registry.get(pending.pairing_id).status == STATUS_PAIRED


def test_run_rejects_wrong_signer_identity():
    client_sk, _ = new_key()
    _, admin_pk = new_key()
    _, other_pk = new_key()
    saved = []
    registry = make_registry(
        client_sk,
        pair_fn=lambda **_k: {"signer_pubkey": other_pk, "relays": ["wss://r"]},
        save_target=lambda *a, **k: saved.append((a, k)),
    )
    pending = registry.start(admin_pubkey=admin_pk, relays=["wss://r"])
    registry._run(pending, None)

    assert pending.status == STATUS_FAILED
    assert "not this admin" in (pending.error or "")
    assert saved == []


def test_run_timeout_marks_expired():
    client_sk, _ = new_key()
    _, admin_pk = new_key()

    def pair_fn(**_k):
        raise Nip46Timeout("no signer paired within the timeout")

    registry = make_registry(client_sk, pair_fn=pair_fn, save_target=lambda *a, **k: None)
    pending = registry.start(admin_pubkey=admin_pk, relays=["wss://r"])
    assert pending.status == STATUS_PENDING
    registry._run(pending, None)
    assert pending.status == STATUS_EXPIRED


def test_save_failure_is_reported():
    client_sk, _ = new_key()
    _, admin_pk = new_key()

    def save_target(*_a, **_k):
        raise OSError("disk full")

    registry = make_registry(
        client_sk,
        pair_fn=lambda **_k: {"signer_pubkey": admin_pk, "relays": ["wss://r"]},
        save_target=save_target,
    )
    pending = registry.start(admin_pubkey=admin_pk, relays=["wss://r"])
    registry._run(pending, None)
    assert pending.status == STATUS_FAILED
    assert "could not save" in (pending.error or "")


def test_pending_expires_and_terminal_entries_are_purged():
    client_sk, _ = new_key()
    _, admin_pk = new_key()
    clock = FakeClock()
    registry = make_registry(
        client_sk,
        pair_fn=lambda **_k: {"signer_pubkey": admin_pk, "relays": ["wss://r"]},
        save_target=lambda *a, **k: None,
        clock=clock,
        timeout=10.0,
    )
    pending = registry.start(admin_pubkey=admin_pk, relays=["wss://r"])
    clock.now += 11.0
    assert registry.get(pending.pairing_id).status == STATUS_EXPIRED
    clock.now += 400.0
    assert registry.get(pending.pairing_id) is None


def test_start_requires_a_relay_and_bounds_pending():
    client_sk, _ = new_key()
    _, admin_pk = new_key()
    registry = make_registry(
        client_sk,
        pair_fn=lambda **_k: {"signer_pubkey": admin_pk, "relays": ["wss://r"]},
        save_target=lambda *a, **k: None,
        max_pending=1,
    )
    try:
        registry.start(admin_pubkey=admin_pk, relays=[])
        raise AssertionError("expected ValueError for no relay")
    except ValueError:
        pass

    registry.start(admin_pubkey=admin_pk, relays=["wss://r"])
    try:
        registry.start(admin_pubkey=admin_pk, relays=["wss://r"])
        raise AssertionError("expected ValueError for too many pending")
    except ValueError:
        pass
