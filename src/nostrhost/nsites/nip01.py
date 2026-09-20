"""Shared NIP-01 event identity/signature verification.

Both the manifest and curated-collection validators must verify that an event's
``id`` is the sha256 of the canonical serialization and that its ``sig``
matches. ``nostr_sdk``'s ``Event`` does both with ``verify_id`` /
``verify_signature``; this module is the single established-library path, so
the validators do not hand-roll the NIP-01 serialization or parse.
"""

from __future__ import annotations

import json
from typing import Any


def verify_event(event: dict[str, Any]) -> tuple[bool, bool]:
    """Verify a NIP-01 event, returning ``(id_ok, signature_ok)``.

    Delegates to ``nostr_sdk`` so the id and signature checks come from the
    established library. Any event ``nostr_sdk`` cannot parse (malformed JSON,
    non-hex pubkey, missing/invalid ``sig``, etc.) yields ``(False, False)``;
    the caller decides how to report that structural failure.
    """
    from nostr_sdk import Event

    try:
        parsed = Event.from_json(json.dumps(event, ensure_ascii=False))
        return parsed.verify_id(), parsed.verify_signature()
    except Exception:
        return False, False