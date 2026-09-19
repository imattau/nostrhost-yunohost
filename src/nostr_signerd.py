"""Signer bridge (nostr-signerd) — push parked approvals to remote signers.

When ``nostr-operationsd`` parks a request for approval it publishes a
structured kind-2210 notice with class ``approval``. This service consumes
that notice and, for every registered admin remote signer, sends a NIP-46
``sign_event`` request for the unsigned kind-2201 approval to the signer's
own relays (see :mod:`nostr_nip46`). The signer's owner approves on their
signer; the bridge validates the returned event and publishes it to the
control relay, where the existing executor state machine advances the
operation.

It never signs anything itself and holds only its own NIP-46 client key: a
signer target is a ``bunker://`` pairing (signer pubkey + relays + secret)
registered by the operator. Every returned event is validated with
``nostr_operations.validate_signed_approval`` before publication; a signer
that returns an event from the wrong identity is ignored.

Targets and state are small JSON files (root-only): registering a
``bunker://`` URI stores the pairing secret, so the file is 0600 and the
service is a no-op when it is absent.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .nostr_identity import _operator_config, publish_to_relay
from .nostr_nip46 import (
    Nip46Error,
    Nip46Timeout,
    parse_bunker_uri,
    sign_event_via_bunker,
)
from .nostr_operations import (
    build_approval_template,
    validate_signed_approval,
)

logger = logging.getLogger("nostr-signerd")

DEFAULT_TARGETS_PATH = env_targets = os.environ.get(
    "NOSTRHOST_SIGNER_TARGETS", "/etc/nostrhost/signer_targets.json"
)
DEFAULT_CLIENT_KEY_PATH = os.environ.get(
    "NOSTRHOST_SIGNER_CLIENT_KEY", "/etc/nostrhost/signer_client_sk"
)
DEFAULT_STATE_PATH = os.environ.get(
    "NOSTRHOST_SIGNER_STATE", "/var/lib/nostrhost/signer_bridge_state.json"
)

APPROVAL_CLASS = "approval"
HANDLED_HISTORY_LIMIT = 5000


@dataclass(frozen=True)
class SignerTarget:
    """A registered remote signer to push approval requests to."""

    signer_pubkey: str
    relays: tuple[str, ...]
    secret: str | None = None
    label: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "signer_pubkey": self.signer_pubkey,
            "relays": list(self.relays),
            "secret": self.secret,
            "label": self.label,
        }


# --------------------------------------------------------------------------- #
# persistence

def load_targets(path: str | Path | None = None) -> list[SignerTarget]:
    """Load registered signer targets (empty on missing/unreadable file)."""
    target_path = Path(path or DEFAULT_TARGETS_PATH)
    try:
        raw = json.loads(target_path.read_text())
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as exc:  # noqa: BLE001 - a broken file is a no-op
        logger.warning("could not read signer targets %s: %s", target_path, exc)
        return []
    out: list[SignerTarget] = []
    for entry in raw.get("targets", []) if isinstance(raw, dict) else []:
        if not isinstance(entry, dict):
            continue
        pubkey = str(entry.get("signer_pubkey") or "").lower()
        relays = tuple(str(r) for r in (entry.get("relays") or []) if r)
        if not pubkey or not relays:
            continue
        secret = entry.get("secret")
        out.append(
            SignerTarget(
                signer_pubkey=pubkey,
                relays=relays,
                secret=str(secret) if secret else None,
                label=str(entry.get("label")) if entry.get("label") else None,
            )
        )
    return out


def save_targets(targets: list[SignerTarget], path: str | Path | None = None) -> Path:
    """Persist targets 0600 (the file may hold pairing secrets)."""
    target_path = Path(path or DEFAULT_TARGETS_PATH)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(json.dumps({"targets": [t.to_json() for t in targets]}, indent=2) + "\n")
    os.chmod(target_path, 0o600)
    return target_path


def add_target_from_bunker_uri(
    uri: str,
    *,
    label: str | None = None,
    path: str | Path | None = None,
) -> list[SignerTarget]:
    """Register (or refresh) a signer target from a ``bunker://`` URI."""
    parsed = parse_bunker_uri(uri)
    target = SignerTarget(
        signer_pubkey=parsed["signer_pubkey"],
        relays=tuple(parsed["relays"]),
        secret=parsed["secret"],
        label=label,
    )
    targets = [t for t in load_targets(path) if t.signer_pubkey != target.signer_pubkey]
    targets.append(target)
    save_targets(targets, path)
    return targets


def add_target(
    signer_pubkey: str,
    relays: list[str] | tuple[str, ...],
    *,
    label: str | None = None,
    path: str | Path | None = None,
) -> list[SignerTarget]:
    """Register an already-paired signer (no stored secret).

    Used by the ``nostrconnect://`` flow: the signer authorised the node's
    client key during pairing, so no third-party secret is persisted.
    """
    target = SignerTarget(
        signer_pubkey=str(signer_pubkey).lower(),
        relays=tuple(str(r) for r in relays if r),
        secret=None,
        label=label,
    )
    if not target.relays:
        raise ValueError("at least one relay is required")
    targets = [t for t in load_targets(path) if t.signer_pubkey != target.signer_pubkey]
    targets.append(target)
    save_targets(targets, path)
    return targets


def remove_target(signer_pubkey: str, *, path: str | Path | None = None) -> bool:
    pubkey = signer_pubkey.lower()
    targets = load_targets(path)
    remaining = [t for t in targets if t.signer_pubkey != pubkey]
    if len(remaining) == len(targets):
        return False
    save_targets(remaining, path)
    return True


def ensure_client_key(path: str | Path | None = None) -> str:
    """Return the bridge's stable NIP-46 client secret key (hex), creating it
    on first use. This key only ever *asks* a signer; it holds no authority."""
    key_path = Path(path or DEFAULT_CLIENT_KEY_PATH)
    try:
        existing = key_path.read_text().strip()
        if existing:
            return existing
    except FileNotFoundError:
        pass
    from nostr_sdk import Keys

    secret = Keys.generate().secret_key().to_hex()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(secret + "\n")
    os.chmod(key_path, 0o600)
    return secret


# --------------------------------------------------------------------------- #
# bridge

class SignerBridge:
    """Turns parked-approval notices into NIP-46 signer requests.

    Fully injectable: ``transport`` is the NIP-46 transport, ``publish`` is
    the control-relay publisher, and ``signer`` is the NIP-46 call (both
    default to the real implementations). Tests drive :meth:`handle_notice`
    directly.
    """

    def __init__(
        self,
        *,
        admin_pubkeys: tuple[str, ...] | list[str],
        targets: list[SignerTarget],
        client_sk: str,
        publish: Callable[[str, dict[str, Any]], None] | None = None,
        control_relay: str | None = None,
        transport: Any = None,
        signer: Callable[..., dict[str, Any]] | None = None,
        timeout: float = 60.0,
        max_workers: int = 4,
        state_path: str | Path | None = None,
        targets_loader: Callable[[], list[SignerTarget]] | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self._admins = {str(a).lower() for a in admin_pubkeys if isinstance(a, str)}
        # When set, the bridge re-reads the target file before every notice so
        # an admin registering/removing a signer through the console takes
        # effect without restarting the service. Left ``None`` for the
        # injected-targets tests, where the constructor list is authoritative.
        self._targets_loader = targets_loader
        # Only push to signers that hold an admin identity; the executor would
        # ignore a 2201 from anyone else anyway.
        self._targets = [t for t in targets if t.signer_pubkey in self._admins]
        self._client_sk = client_sk
        self._publish = publish or (lambda relay, event: publish_to_relay(relay, event))
        self._control_relay = control_relay
        self._transport = transport
        self._signer = signer or sign_event_via_bunker
        self._timeout = timeout
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="signerd")
        self._state_path = Path(state_path or DEFAULT_STATE_PATH)
        self._handled: set[str] = set()
        self._lock = threading.Lock()
        self._load_state()

    # -- state ------------------------------------------------------------- #

    def _load_state(self) -> None:
        try:
            raw = json.loads(self._state_path.read_text())
            handled = raw.get("handled", []) if isinstance(raw, dict) else []
            self._handled = {str(h) for h in handled}
        except (FileNotFoundError, OSError, ValueError):
            self._handled = set()

    def _save_state(self) -> None:
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            history = list(self._handled)[-HANDLED_HISTORY_LIMIT:]
            self._state_path.write_text(json.dumps({"handled": history}) + "\n")
            os.chmod(self._state_path, 0o600)
        except OSError as exc:  # noqa: BLE001 - state persistence is best-effort
            logger.warning("could not persist signer bridge state: %s", exc)

    def mark_handled(self, request_id: str) -> None:
        with self._lock:
            self._handled.add(request_id)
        self._save_state()

    # -- intake ------------------------------------------------------------ #

    def reload_targets(self) -> None:
        """Re-read the target file so console registrations take effect live.

        A no-op when no loader was supplied (tests inject targets directly).
        Targets whose signer pubkey is not an admin are dropped, matching the
        construction-time filter.
        """
        if self._targets_loader is None:
            return
        try:
            targets = self._targets_loader()
        except Exception:  # noqa: BLE001 - a broken file must not stop dispatch
            logger.warning("could not reload signer targets", exc_info=True)
            return
        self._targets = [t for t in targets if t.signer_pubkey in self._admins]

    def targets_for(self, request_id: str) -> list[SignerTarget]:
        return list(self._targets)

    def handle_notice(self, event: dict[str, Any]) -> bool:
        """Dispatch a kind-2210 approval notice. Returns True if dispatched."""
        if int(event.get("kind") or 0) not in (2210, 2211):
            return False
        try:
            body = json.loads(event.get("content") or "{}")
        except ValueError:
            return False
        if not isinstance(body, dict) or body.get("class") != APPROVAL_CLASS:
            return False
        request_id = str(body.get("request_id") or "")
        if len(request_id) != 64:
            return False
        with self._lock:
            if request_id in self._handled:
                return False
            self._handled.add(request_id)
        self._save_state()
        self.reload_targets()
        tool = str(body.get("tool") or "")
        targets = self.targets_for(request_id)
        if not targets:
            logger.info("approval %s parked but no admin has a remote signer", request_id[:16])
            return True
        for target in targets:
            self._pool.submit(self._push, target, request_id, tool)
        return True

    def _push(self, target: SignerTarget, request_id: str, tool: str) -> None:
        template = build_approval_template(target.signer_pubkey, request_id)
        try:
            signed = self._signer(
                client_sk=self._client_sk,
                signer_pubkey=target.signer_pubkey,
                relays=list(target.relays),
                unsigned_event=template,
                secret=target.secret,
                transport=self._transport,
                timeout=self._timeout,
            )
        except (Nip46Timeout, Nip46Error) as exc:
            logger.warning(
                "signer %s did not approve %s (%s: %s)",
                target.signer_pubkey[:12],
                request_id[:16],
                type(exc).__name__,
                exc,
            )
            return
        try:
            validated = validate_signed_approval(signed, request_id)
        except Exception as exc:  # noqa: BLE001 - never publish an invalid approval
            logger.warning("signer %s returned an invalid approval for %s: %s", target.signer_pubkey[:12], request_id[:16], exc)
            return
        if validated["pubkey"] != target.signer_pubkey:
            logger.warning("signer %s returned approval from another identity", target.signer_pubkey[:12])
            return
        logger.info("publishing approval %s signed by %s (%s)", request_id[:16], target.signer_pubkey[:12], tool)
        try:
            self._publish(self._control_relay or "", validated)
        except Exception:  # noqa: BLE001 - one relay failure must not stop the bridge
            logger.exception("failed to publish approval %s", request_id[:16])

    def shutdown(self, *, wait: bool = False) -> None:
        self._pool.shutdown(wait=wait)


# --------------------------------------------------------------------------- #
# daemon entry point

def run() -> None:  # pragma: no cover - wires real relay/transport
    import asyncio
    import secrets as _secrets

    import websockets

    from .nostr_identity import (
        _configure_daemon_logging,
        _init_headless_yunohost,
        _require_bootstrapped,
        _sign_auth_event,
        _wait_auth_ok_async,
        default_auth,
    )

    _configure_daemon_logging()
    _init_headless_yunohost()
    _require_bootstrapped()

    cfg = _operator_config()
    targets = load_targets()
    if not targets:
        logger.info("no signer targets registered; the bridge will idle")
    bridge = SignerBridge(
        admin_pubkeys=cfg.admins,
        targets=targets,
        client_sk=ensure_client_key(),
        control_relay=cfg.control_relay,
        targets_loader=load_targets,
    )

    async def _main() -> None:
        while True:
            try:
                async with websockets.connect(cfg.control_relay, ping_interval=None, ping_timeout=None) as ws:
                    sub_id = "nostrhost-signerd-" + _secrets.token_hex(4)
                    await ws.send(json.dumps(["REQ", sub_id, {"kinds": [2210, 2211]}]))
                    logger.info("signer bridge subscribed to %s", cfg.control_relay)
                    async for raw in ws:
                        message = json.loads(raw)
                        if message[0] == "AUTH":
                            auth = default_auth()
                            if auth is not None:
                                challenge = message[1] if len(message) > 1 else ""
                                auth_event = _sign_auth_event(auth[0], auth[1], cfg.control_relay, challenge, sub_id)
                                await ws.send(json.dumps(["AUTH", auth_event]))
                                await _wait_auth_ok_async(ws, auth_event["id"])
                            continue
                        if message[0] == "EVENT":
                            bridge.handle_notice(message[2])
            except Exception:  # noqa: BLE001 - reconnect with backoff
                logger.exception("signer bridge subscription dropped; reconnecting")
                await asyncio.sleep(5)

    try:
        asyncio.run(_main())
    except KeyboardInterrupt:  # pragma: no cover
        pass
    finally:
        bridge.shutdown()


if __name__ == "__main__":  # pragma: no cover
    run()
