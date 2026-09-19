"""Node-initiated NIP-46 pairing for the admin console ("approve anywhere").

The console can register the *node* (via nostr-signerd's own client key) as a
client of an admin's remote signer. The node generates a ``nostrconnect://``
URI; the admin opens/scans it in their signer app, which connects and
authorises the node's client key. Once paired, nostr-signerd pushes parked
approvals to the signer, so approvals no longer depend on a particular
browser session.

Pairing is asynchronous (the signer may take seconds to minutes) while the
HTTP request must return immediately, so a small in-process registry owns the
pending state:

- :meth:`PairingRegistry.start` builds the URI + secret and spawns a daemon
  thread running the blocking pairing wait.
- :meth:`PairingRegistry.get` observes ``pending`` / ``paired`` / ``failed`` /
  ``expired``.

This direction never stores the signer's secret: the node's own key is what
the signer authorises, and every signature is still confirmed in the signer
app. The registry is process-local, so a pending pairing is lost if
nostr-api restarts (start it again); a completed pairing is persisted with
:func:`~nostr_signerd.add_target` and picked up by the running bridge without
a restart.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from .nostr_nip46 import (
    Nip46Error,
    Nip46Timeout,
    build_nostrconnect_uri,
    pair_via_nostrconnect,
)

DEFAULT_TIMEOUT = 180.0
MAX_PENDING = 8
TERMINAL_RETENTION = 300.0

STATUS_PENDING = "pending"
STATUS_PAIRED = "paired"
STATUS_FAILED = "failed"
STATUS_EXPIRED = "expired"


@dataclass
class PendingPairing:
    """One in-flight (or recently finished) node<->signer pairing attempt."""

    pairing_id: str
    admin_pubkey: str
    relay: str
    uri: str
    secret: str
    expires_at: float
    status: str = STATUS_PENDING
    signer_pubkey: str | None = None
    error: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "pairing_id": self.pairing_id,
            "status": self.status,
            "uri": self.uri,
            "relays": [self.relay],
            "expires_at": int(self.expires_at),
            "signer_pubkey": self.signer_pubkey,
            "error": self.error,
        }


class PairingRegistry:
    """Thread-safe registry of pending node-initiated signer pairings.

    Inject ``pair_fn`` / ``save_target`` / ``clock`` in tests; production uses
    the real NIP-46 pairing and :func:`~nostr_signerd.add_target`.
    """

    def __init__(
        self,
        *,
        client_sk: str,
        pair_fn: Callable[..., dict[str, Any]] | None = None,
        save_target: Callable[..., Any] | None = None,
        clock: Callable[[], float] = time.time,
        timeout: float = DEFAULT_TIMEOUT,
        max_pending: int = MAX_PENDING,
        start_thread: bool = True,
    ) -> None:
        from .nostr_operations import _derive_pubkey

        self._client_sk = client_sk
        self._client_pubkey = _derive_pubkey(client_sk)
        self._pair_fn = pair_fn or pair_via_nostrconnect
        if save_target is None:
            from .nostr_signerd import add_target

            save_target = add_target
        self._save_target = save_target
        self._clock = clock
        self._timeout = timeout
        self._max_pending = max_pending
        self._start_thread = start_thread
        self._lock = threading.Lock()
        self._pairings: dict[str, PendingPairing] = {}

    def _purge_locked(self) -> None:
        now = self._clock()
        for pairing_id, pending in list(self._pairings.items()):
            if pending.status == STATUS_PENDING and now >= pending.expires_at:
                pending.status = STATUS_EXPIRED
            if pending.status != STATUS_PENDING and now >= pending.expires_at + TERMINAL_RETENTION:
                del self._pairings[pairing_id]

    def start(
        self,
        *,
        admin_pubkey: str,
        relays: list[str],
        label: str | None = None,
    ) -> PendingPairing:
        cleaned = [str(r) for r in relays if r]
        if not cleaned:
            raise ValueError("at least one relay is required")
        relay = cleaned[0]
        with self._lock:
            self._purge_locked()
            pending_count = sum(
                1 for p in self._pairings.values() if p.status == STATUS_PENDING
            )
            if pending_count >= self._max_pending:
                raise ValueError("too many pending signer pairings; try again shortly")
            secret = secrets.token_hex(16)
            pending = PendingPairing(
                pairing_id=secrets.token_hex(16),
                admin_pubkey=str(admin_pubkey).lower(),
                relay=relay,
                uri=build_nostrconnect_uri(self._client_pubkey, [relay], secret),
                secret=secret,
                expires_at=self._clock() + self._timeout,
            )
            self._pairings[pending.pairing_id] = pending
        if self._start_thread:
            threading.Thread(
                target=self._run,
                args=(pending, label),
                name=f"signer-pair-{pending.pairing_id[:8]}",
                daemon=True,
            ).start()
        return pending

    def get(self, pairing_id: str) -> PendingPairing | None:
        with self._lock:
            self._purge_locked()
            return self._pairings.get(pairing_id)

    def _run(self, pending: PendingPairing, label: str | None) -> None:
        def is_admin(pubkey: str) -> bool:
            return str(pubkey).lower() == pending.admin_pubkey

        try:
            result = self._pair_fn(
                client_sk=self._client_sk,
                relays=[pending.relay],
                secret=pending.secret,
                timeout=self._timeout,
                is_admin=is_admin,
            )
        except Nip46Timeout as exc:
            self._finish(pending, STATUS_EXPIRED, error=str(exc) or "timed out")
            return
        except (Nip46Error, Exception) as exc:  # noqa: BLE001 - thread must not die silently
            self._finish(pending, STATUS_FAILED, error=str(exc) or type(exc).__name__)
            return

        signer_pubkey = str(result.get("signer_pubkey") or "").lower()
        if signer_pubkey != pending.admin_pubkey:
            self._finish(pending, STATUS_FAILED, error="the signer's identity is not this admin")
            return
        relays = [str(r) for r in (result.get("relays") or [pending.relay]) if r] or [pending.relay]
        try:
            self._save_target(signer_pubkey, relays, label=label)
        except Exception as exc:  # noqa: BLE001 - surface why the pairing failed
            self._finish(pending, STATUS_FAILED, error=f"could not save the pairing: {exc}")
            return
        self._finish(pending, STATUS_PAIRED, signer_pubkey=signer_pubkey)

    def _finish(
        self,
        pending: PendingPairing,
        status: str,
        *,
        signer_pubkey: str | None = None,
        error: str | None = None,
    ) -> None:
        with self._lock:
            pending.status = status
            pending.signer_pubkey = signer_pubkey
            pending.error = error
