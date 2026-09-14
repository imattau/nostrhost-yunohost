"""Host-key signer guard (D7 / implementation plan §3.1).

The server validates but never signs user manifests, and no host key may ever
sign one: ``operator_sk``, ``server_sk`` and the catalogue ``publisher_sk``
must all be rejected as a manifest signer. This module derives that
forbidden-pubkey set from the root-only operator config, or from explicit
test fixtures.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

OPERATOR_CONFIG = "/etc/nostrhost/operator.toml"

# Host secret-key fields in operator.toml whose derived pubkey may never sign
# a user manifest.
_HOST_KEY_FIELDS = ("server_sk", "operator_sk", "publisher_sk")

_pubkey_cache: tuple[str, frozenset[str]] | None = None


def _pubkey(sk: str) -> str:
    from nostr_sdk import Keys

    return Keys.parse(sk).public_key().to_hex()


def forbidden_signer_pubkeys(
    *, operator_config: str | Path | None = None, force_refresh: bool = False
) -> frozenset[str]:
    """The set of host pubkeys that may never sign a user manifest.

    Derived from ``operator.toml`` (root-only, 0600): every host secret-key
    field resolves to a pubkey that is added to the forbidden set. Cached per
    config path; ``force_refresh`` re-reads. Missing/unreadable config yields
    an empty set (the callers that need the guard must pass explicit keys in
    tests; in production the node is bootstrapped before nsites are used).
    """
    global _pubkey_cache
    path = operator_config or os.environ.get(
        "NOSTRHOST_OPERATOR_CONFIG", OPERATOR_CONFIG
    )
    key = str(path)
    if _pubkey_cache is not None and _pubkey_cache[0] == key and not force_refresh:
        return _pubkey_cache[1]
    forbidden: set[str] = set()
    try:
        with open(key, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        data = {}
    for field in _HOST_KEY_FIELDS:
        sk = data.get(field)
        if isinstance(sk, str) and len(sk) == 64:
            try:
                forbidden.add(_pubkey(sk))
            except Exception:  # noqa: BLE001 - malformed key: skip, do not fail the guard
                continue
    result = frozenset(forbidden)
    _pubkey_cache = (key, result)
    return result
