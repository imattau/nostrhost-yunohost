"""Curated nsite collection (NIP-51 kind-30004 extension profile) validation.

This is the pure, network-free half of the curated-lists feature
(``docs/NSITES-CURATED-LISTS.md``). A collection is a kind-30004 curation set
marked ``t = nsite`` whose entries reference NIP-5A sites: live root/named
sites as ``a`` tags (``15128:<pubkey>:`` / ``35128:<pubkey>:<d>``) and pinned
kind-5128 snapshots as ``e`` tags. Tag order is display order. The module
shares the manifest validator's identity/signature machinery and the same
stable-reason-code convention as ``tools/tests/nsites``.

The wire profile is an *extension profile*: NIP-51 currently describes
kind-30004 sets whose expected entries are kind-1 notes and kind-30023
articles, so this validator is deliberately strict about the ``t = nsite``
marker and the entry shapes. It must agree with the Admin's
``src/lib/nsite/collection.ts`` digest/event builder.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from .nip01 import verify_event

COLLECTION_KIND = 30004

# Bounds (NSITES-CURATED-LISTS.md "Suggested initial bounds").
MAX_ENTRIES = 100
MAX_D = 64
MAX_TITLE = 120
MAX_DESCRIPTION = 500
MAX_IMAGE = 2048
MAX_RELAY = 4096

_D_RULE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
_COORD = re.compile(r"^(15128|35128):([0-9a-f]{64}):([a-zA-Z0-9_-]*)$")
_COLLECTION_COORD = re.compile(r"^30004:([0-9a-f]{64}):([a-zA-Z0-9_-]*)$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE = re.compile(r"^https://[^\s/$.?#][^\s]*$")
_RELAY = re.compile(r"^wss?://[^\s/$.?#][^\s]*$")


@dataclass
class CollectionEntry:
    """One entry in a collection, in display order."""

    kind: str  # "live-root" | "live-named" | "pinned"
    ref: str  # "15128:pubkey:" / "35128:pubkey:d" coordinate, or 5128 event id
    relay: str = ""


@dataclass
class CollectionVerdict:
    """Result of validating one kind-30004 collection event."""

    valid: bool
    errors: list[str] = field(default_factory=list)
    pubkey: str | None = None
    event_id: str | None = None
    d: str | None = None
    title: str = ""
    description: str = ""
    image: str = ""
    entries: list[CollectionEntry] = field(default_factory=list)
    coordinate: str | None = None


def is_valid_d(d: str) -> bool:
    return bool(_D_RULE.fullmatch(d))


def is_valid_coordinate(value: str) -> bool:
    """A full collection coordinate ``30004:<pubkey>:<d>`` (used to address and
    resolve a collection)."""
    return bool(_COLLECTION_COORD.fullmatch(value))


def is_valid_site_coordinate(value: str) -> bool:
    """A NIP-5A site coordinate used in an ``a`` entry (``15128:<pubkey>:`` or
    ``35128:<pubkey>:<d>``). Distinct from the collection coordinate above."""
    return bool(_COORD.fullmatch(value))


def is_sha256_hex(value: str) -> bool:
    return bool(_SHA256.fullmatch(value))


def coordinate(kind: int, pubkey: str, d: str = "") -> str:
    return f"{kind}:{pubkey}:{d}"


def _valid_relay_hint(value: str) -> bool:
    """A 3rd-tag relay hint is a bare ws/wss URL, no credentials/fragment."""
    if len(value) > MAX_RELAY or not _RELAY.fullmatch(value):
        return False
    return "://" in value and "@" not in value and "#" not in value


def _valid_image(value: str) -> bool:
    if len(value) > MAX_IMAGE or not _IMAGE.fullmatch(value):
        return False
    return "@" not in value and "#" not in value


def collection_plan_digest(
    *,
    pubkey: str,
    d: str,
    title: str,
    description: str,
    image: str,
    entries: list[list[str]],
    relays: list[str],
) -> str:
    """The plan digest binding a collection's signed content.

    Covers exactly what a curator commits to by signing: the author pubkey,
    ``d`` coordinate, metadata and the *ordered* entry tags (display order is
    meaningful in NIP-51) plus the exact destination relay set (sorted, so
    order among relays does not matter). ``nsite.collection.publish`` rejects
    a signed event whose recomputed digest does not match the planned value,
    exactly like ``nsite.publish`` stale-plan rejection.
    """
    values: list[Any] = [pubkey, d, title, description, image, entries, sorted(set(relays))]
    payload = json.dumps(values, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def validate_collection(
    event: dict[str, Any],
    *,
    forbidden_pubkeys: frozenset[str] = frozenset(),
    max_entries: int = MAX_ENTRIES,
) -> CollectionVerdict:
    """Validate one kind-30004 ``t = nsite`` collection event."""
    if not isinstance(event, dict):
        return CollectionVerdict(valid=False, errors=["not_json"])

    errors: list[str] = []
    pubkey = str(event.get("pubkey") or "")
    kind = event.get("kind")
    created_at = event.get("created_at")
    tags = event.get("tags")
    content = event.get("content")
    event_id = str(event.get("id") or "")

    if not isinstance(kind, int) or not isinstance(tags, list):
        return CollectionVerdict(valid=False, errors=["not_json"])

    if (
        not isinstance(created_at, int)
        or not isinstance(content, str)
        or not is_sha256_hex(event_id)
    ):
        return CollectionVerdict(valid=False, errors=["bad_id"])
    id_ok, signature_ok = verify_event(event)
    if not id_ok:
        return CollectionVerdict(valid=False, errors=["bad_id"])
    if not is_sha256_hex(pubkey) or not signature_ok:
        return CollectionVerdict(valid=False, errors=["bad_signature"])

    if pubkey in forbidden_pubkeys:
        errors.append("forbidden_signer")

    if kind != COLLECTION_KIND:
        errors.append("bad_kind")

    d_values = [
        t[1] for t in tags if isinstance(t, list) and len(t) > 1 and t[0] == "d"
    ]
    if not d_values:
        errors.append("missing_d")
    elif len(d_values) > 1 or not is_valid_d(str(d_values[0])):
        errors.append("bad_d")

    t_values = [
        t[1] for t in tags if isinstance(t, list) and len(t) > 1 and t[0] == "t"
    ]
    if "nsite" not in [str(v) for v in t_values]:
        errors.append("missing_t")

    title = ""
    description = ""
    for t in tags:
        if not isinstance(t, list) or len(t) < 2 or not isinstance(t[1], str):
            continue
        if t[0] == "title" and not title:
            title = t[1]
        elif t[0] == "description" and not description:
            description = t[1]
    if len(title) > MAX_TITLE:
        errors.append("bad_title")
    if len(description) > MAX_DESCRIPTION:
        errors.append("bad_description")

    image = ""
    image_tags = [t for t in tags if isinstance(t, list) and len(t) > 1 and t[0] == "image"]
    if len(image_tags) > 1:
        errors.append("multiple_image")
    for t in image_tags[:1]:
        if isinstance(t[1], str) and _valid_image(t[1]):
            image = t[1]
        else:
            errors.append("bad_image")

    # Ordered entries: `a` for live sites, `e` for pinned snapshots. A 3rd tag
    # value is a relay hint (not authority). Duplicate coordinates/event ids
    # are rejected; tag order is display order.
    entries: list[CollectionEntry] = []
    seen: set[str] = set()
    entry_tags = [t for t in tags if isinstance(t, list) and t and t[0] in ("a", "e")]
    if len(entry_tags) > max_entries:
        errors.append("oversize_entry_count")
    for t in entry_tags[:max_entries]:
        if len(t) < 2 or not isinstance(t[1], str):
            errors.append("bad_entry_shape")
            continue
        relay = t[2] if len(t) > 2 and isinstance(t[2], str) else ""
        if relay and not _valid_relay_hint(relay):
            errors.append("bad_relay")
            relay = ""
        ref = t[1]
        if t[0] == "a":
            m = _COORD.fullmatch(ref)
            if not m:
                errors.append("bad_a_shape")
                continue
            entry_kind = "live-root" if m.group(1) == "15128" else "live-named"
        elif t[0] == "e":
            if not is_sha256_hex(ref):
                errors.append("bad_e_shape")
                continue
            entry_kind = "pinned"
        else:  # pragma: no cover - filtered above
            continue
        if ref in seen:
            errors.append("duplicate_entry")
            continue
        seen.add(ref)
        entries.append(CollectionEntry(kind=entry_kind, ref=ref, relay=relay))

    errors = list(dict.fromkeys(errors))

    d = str(d_values[0]) if d_values and isinstance(d_values[0], str) else None
    coord = coordinate(COLLECTION_KIND, pubkey, d) if (pubkey and d is not None) else None
    return CollectionVerdict(
        valid=not errors,
        errors=errors,
        pubkey=pubkey,
        event_id=event_id,
        d=d,
        title=title,
        description=description,
        image=image,
        entries=entries,
        coordinate=coord,
    )