"""NIP-5A manifest validation and label codec.

Pure functions, no network access. This is the Phase 0 (task 0.3) Python
validator; it must agree with the Go implementation to come in Phase 1 and with
the generator in ``tools/tests/nsites/``. The conformance corpus
(``tools/tests/nsites/corpus`` in the parent repo) and
``tests_nostr/test_nsites_manifest.py`` are what force that agreement.

Pinned revision: ``nostr-protocol/nips@5d6b4322`` (``5A.md``, 2026-06-16).
Reason codes are stable strings shared with the corpus ``expect.errors``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

KIND_ROOT = 15128
KIND_NAMED = 35128
KIND_SNAPSHOT = 5128

_BASE36_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
_B36_50 = re.compile(r"^[0-9a-z]{50}$")
_NAMED_LABEL = re.compile(r"^[0-9a-z]{50}[a-z0-9-]{1,13}$")
_D_RULE = re.compile(r"^[a-z0-9-]{1,13}$")
_REF = re.compile(r"^\d+:([0-9a-f]{64}):([a-zA-Z0-9_\-]*)$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class Verdict:
    """Result of validating one NIP-5A event."""

    valid: bool
    errors: list[str] = field(default_factory=list)
    site_type: str | None = None  # root | named | snapshot
    pubkey: str | None = None
    event_id: str | None = None
    d: str | None = None
    paths: list[tuple[str, str]] = field(default_factory=list)
    aggregate_hash: str | None = None
    label: str | None = None


# ---------------------------------------------------------------------------
# Aggregate hash and primitive checks (mirrors tools/tests/nsites/spec.py).
# ---------------------------------------------------------------------------


def aggregate_hash(paths: list[tuple[str, str]]) -> str:
    """Deterministic hash of a manifest's ``path`` tags (NIP-5A "Aggregate Hash")."""
    lines = [f"{h} {p}\n" for p, h in paths]
    lines.sort()
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def is_sha256_hex(value: str) -> bool:
    return bool(_SHA256.fullmatch(value))


def is_valid_d(d: str) -> bool:
    return bool(_D_RULE.fullmatch(d)) and not d.endswith("-")


def is_valid_ref(value: str) -> bool:
    return bool(_REF.fullmatch(value))


def b36_encode_32(bytes32_hex: str) -> str:
    n = int.from_bytes(bytes.fromhex(bytes32_hex), "big")
    if n == 0:
        return "0" * 50
    out = ""
    while n:
        n, rem = divmod(n, 36)
        out = _BASE36_ALPHABET[rem] + out
    return out.zfill(50)


def b36_decode_50(label50: str) -> str:
    n = 0
    for ch in label50:
        n = n * 36 + _BASE36_ALPHABET.index(ch)
    return n.to_bytes(32, "big").hex()


# ---------------------------------------------------------------------------
# Labels (NIP-5A "Address Formats").
# ---------------------------------------------------------------------------


def root_label(npub: str) -> str:
    return npub


def named_label(pubkey_hex: str, d: str) -> str:
    return b36_encode_32(pubkey_hex) + d


def snapshot_label(event_id_hex: str) -> str:
    return "v" + b36_encode_32(event_id_hex)


def canonical_site_url(label: str, gateway_domain: str) -> str:
    return f"{label}.{gateway_domain}"


def decode_label(label: str) -> tuple[str | None, str | None, str | None]:
    """Decode one DNS label to ``(site_type, hex, d)``.

    ``hex`` is the pubkey (root/named) or event id (snapshot); ``d`` is the
    identifier for named sites. Returns ``(None, None, None)`` when the label
    does not parse, which the caller must treat as site-not-found.
    """
    if label.startswith("npub1"):
        from nostr_sdk import PublicKey

        try:
            return "root", PublicKey.parse(label).to_hex(), None
        except Exception:
            return None, None, None
    if (
        _B36_50.fullmatch(label[1:] if label.startswith("v") else "")
        and len(label) == 51
    ):
        return "snapshot", b36_decode_50(label[1:]), None
    if _NAMED_LABEL.fullmatch(label) and not label.endswith("-"):
        return "named", b36_decode_50(label[:50]), label[50:]
    return None, None, None


# ---------------------------------------------------------------------------
# Validation.
# ---------------------------------------------------------------------------


def _id_hex(
    pubkey: str, created_at: int, kind: int, tags: list[list[str]], content: str
) -> str:
    serialized = json.dumps(
        [0, pubkey, created_at, kind, tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _verify_signature(event: dict[str, Any]) -> bool:
    from nostr_sdk import Event

    try:
        return Event.from_json(json.dumps(event)).verify_signature()
    except Exception:
        return False


def _path_is_bad(path: str) -> bool:
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in path):
        return True
    if "\\" in path:
        return True
    for segment in path.split("/"):
        if segment == "..":
            return True
    return False


def _path_has_extension(path: str) -> bool:
    last = path.rsplit("/", 1)[-1]
    return "." in last and last != "." and not last.startswith("..")


def validate_manifest(
    event: dict[str, Any],
    *,
    forbidden_pubkeys: frozenset[str] = frozenset(),
    max_paths: int = 5000,
) -> Verdict:
    """Validate a NIP-5A manifest event against the pinned spec revision.

    ``forbidden_pubkeys`` is the set of host keys that may never sign a user
    manifest (operator/server/catalogue publisher keys). ``max_paths`` bounds
    the accepted ``path`` tag count.
    """
    if not isinstance(event, dict):
        return Verdict(valid=False, errors=["not_json"])

    errors: list[str] = []
    pubkey = str(event.get("pubkey") or "")
    kind = event.get("kind")
    created_at = event.get("created_at")
    tags = event.get("tags")
    content = event.get("content")
    event_id = str(event.get("id") or "")

    if not isinstance(kind, int) or not isinstance(tags, list):
        return Verdict(valid=False, errors=["not_json"])

    # Identity and signature first: a forged body invalidates every later check.
    if (
        not isinstance(created_at, int)
        or not isinstance(content, str)
        or not is_sha256_hex(event_id)
    ):
        return Verdict(valid=False, errors=["bad_id"])
    if _id_hex(pubkey, created_at, kind, tags, content) != event_id:
        return Verdict(valid=False, errors=["bad_id"])
    if not is_sha256_hex(pubkey) or not _verify_signature(event):
        return Verdict(valid=False, errors=["bad_signature"])

    # Host keys may not sign user manifests (D7 / signer guard).
    if pubkey in forbidden_pubkeys:
        errors.append("forbidden_signer")

    if kind not in (KIND_ROOT, KIND_NAMED, KIND_SNAPSHOT):
        errors.append("bad_kind")

    d_values = [
        t[1] for t in tags if isinstance(t, list) and len(t) > 1 and t[0] == "d"
    ]
    if kind == KIND_NAMED:
        if not d_values:
            errors.append("missing_d")
        elif len(d_values) > 1 or not is_valid_d(str(d_values[0])):
            errors.append("bad_d")
    elif kind == KIND_ROOT and d_values:
        errors.append("d_on_root")

    path_tags = [t for t in tags if isinstance(t, list) and t and t[0] == "path"]
    if not path_tags:
        errors.append("no_paths")

    seen_paths: dict[str, int] = {}
    valid_paths: list[tuple[str, str]] = []
    for t in path_tags:
        if not isinstance(t, list) or len(t) != 3 or t[0] != "path":
            errors.append("bad_path_shape")
            continue
        path = str(t[1])
        blob_hash = str(t[2])
        if not path.startswith("/"):
            errors.append("relative_path")
            continue
        if not _path_has_extension(path):
            errors.append("no_extension")
            continue
        if _path_is_bad(path):
            errors.append("bad_path_chars")
            continue
        if not is_sha256_hex(blob_hash):
            errors.append("bad_hash_hex")
            continue
        if path in seen_paths:
            errors.append("duplicate_path")
        else:
            seen_paths[path] = len(valid_paths)
        valid_paths.append((path, blob_hash))

    if len(path_tags) > max_paths:
        errors.append("oversize_path_count")

    computed = aggregate_hash(valid_paths) if valid_paths else None

    x_tags = [t for t in tags if isinstance(t, list) and t and t[0] == "x"]
    if kind == KIND_SNAPSHOT:
        if not x_tags:
            errors.append("missing_aggregate_x")
        elif len(x_tags) > 1:
            errors.append("multiple_aggregate_x")
    for t in x_tags:
        if (
            not isinstance(t, list)
            or len(t) != 3
            or t[2] != "aggregate"
            or not is_sha256_hex(str(t[1]))
        ):
            errors.append("bad_x_shape")
        elif computed is not None and str(t[1]) != computed:
            errors.append("bad_aggregate_x")

    a_tags = [t for t in tags if isinstance(t, list) and len(t) > 1 and t[0] == "a"]
    A_tags = [t for t in tags if isinstance(t, list) and len(t) > 1 and t[0] == "A"]
    if kind == KIND_SNAPSHOT or a_tags or A_tags:
        if not a_tags:
            errors.append("missing_a")
        elif len(a_tags) > 1:
            errors.append("multiple_a")
        if a_tags and not A_tags and kind != KIND_SNAPSHOT:
            errors.append("missing_A")
        elif A_tags and not a_tags:
            errors.append("missing_a")
        if len(A_tags) > 1:
            errors.append("multiple_A")
        for t in a_tags:
            if not is_valid_ref(str(t[1])):
                errors.append("bad_a_shape")
        for t in A_tags:
            if not is_valid_ref(str(t[1])):
                errors.append("bad_A_shape")

    # Deterministic, deduped error list so tests can compare exactly.
    errors = list(dict.fromkeys(errors))

    site_type = {KIND_ROOT: "root", KIND_NAMED: "named", KIND_SNAPSHOT: "snapshot"}.get(
        kind
    )
    d = d_values[0] if d_values and isinstance(d_values[0], str) else None
    label = None
    if site_type == "root":
        label = _npub_for(pubkey)
    elif site_type == "named":
        label = named_label(pubkey, d) if d else None
    elif site_type == "snapshot":
        label = snapshot_label(event_id)

    return Verdict(
        valid=not errors,
        errors=errors,
        site_type=site_type,
        pubkey=pubkey,
        event_id=event_id,
        d=d,
        paths=valid_paths,
        aggregate_hash=computed,
        label=label,
    )


def _npub_for(pubkey_hex: str) -> str | None:
    from nostr_sdk import PublicKey

    try:
        return PublicKey.parse(pubkey_hex).to_bech32()
    except Exception:
        return None
