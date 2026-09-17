"""Operator npub blocklist for ``nsite.discover`` (NIP-51 kind-10000 mute list).

The operator publishes a standard kind-10000 mute list (``p`` tags) to the
local control relay; ``nsite.discover`` reads it at scan time and excludes
those pubkeys from its results.

The list is a full replacement: ``publish_blocklist`` replaces whatever was
previously published with exactly the given pubkeys (``nostrhost nsite block
set``). ``add``/``remove`` are read-modify-write conveniences over the same
kind-10000 event, so the newest event always carries the full set.
"""

from __future__ import annotations

from typing import Any, Callable

BLOCK_KIND = 10000  # NIP-51 mute list
_BLOCK_FETCH_TIMEOUT = 3.0


def _newest_block_event(events: list[dict[str, Any]], operator_pubkey: str) -> dict[str, Any] | None:
    own = [e for e in events if str(e.get("pubkey", "")) == operator_pubkey]
    if not own:
        return None
    return max(own, key=lambda e: (int(e.get("created_at", 0)), str(e.get("id", ""))))


def parse_blocked(event: dict[str, Any]) -> list[str]:
    """The ``p``-tag pubkeys of one mute-list event, deduped in order."""
    out: list[str] = []
    for tag in event.get("tags") or []:
        if isinstance(tag, list) and len(tag) > 1 and tag[0] == "p" and isinstance(tag[1], str):
            if tag[1] not in out:
                out.append(tag[1])
    return out


def current_blocklist(
    *,
    operator_sk: str | None = None,
    control_relay: str | None = None,
    fetch: Callable[..., list[dict[str, Any]]] | None = None,
) -> list[str]:
    """Read the operator's kind-10000 mute list back from the control relay.

    The newest operator-signed event wins (mute lists are replaceable). A
    relay hiccup or an unbootstrapped node yields an empty list — the read is
    best-effort and must never fail ``nsite.discover``.
    """
    from yunohost.nostr_identity import _operator_config

    try:
        cfg = _operator_config(operator_sk, control_relay)
        if fetch is None:
            from yunohost.nostr_operations import fetch_chain_events

            fetch = fetch_chain_events
        events = fetch(cfg.control_relay, kinds=(BLOCK_KIND,), timeout=_BLOCK_FETCH_TIMEOUT)
    except Exception:  # noqa: BLE001 - best-effort read
        return []
    newest = _newest_block_event(events, cfg.operator_pubkey)
    return parse_blocked(newest) if newest else []


def publish_blocklist(
    pubkeys_or_npubs: list[str],
    *,
    operator_sk: str | None = None,
    control_relay: str | None = None,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Author + publish the kind-10000 mute list as the operator.

    NIP-51 mute lists are the full set, not a delta: this call *replaces*
    whatever was previously blocked with exactly ``pubkeys_or_npubs`` (an
    empty list clears the blocklist). Pubkeys/npubs are normalised to hex and
    sorted for a deterministic event body.
    """
    from yunohost.nostr_identity import _operator_config, _parse_pubkey, _sign_event, publish_to_relay

    pubkeys = sorted({_parse_pubkey(value) for value in pubkeys_or_npubs})
    cfg = _operator_config(operator_sk, control_relay)
    event = _sign_event(cfg.operator_sk, cfg.operator_pubkey, BLOCK_KIND, "", [["p", pk] for pk in pubkeys])
    (transport or publish_to_relay)(cfg.control_relay, event)
    return {"event_id": event["id"], "pubkeys": pubkeys, "published_at": int(event.get("created_at", 0))}
