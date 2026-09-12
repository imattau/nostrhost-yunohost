"""Nostr-native free hostname (W4 Phase E): identity-backed Dynette.

The legacy way to get a free ``*.nohost.me`` address was ``yunohost dyndns
subscribe``: prove the host is yours to the Dynette service (TOTP) and it
issues a TSIG key the node then uses for updates. Phase E makes that step
*nostr-native*: the node's own Nostr identity replaces the TOTP dance as the
ownership proof.

``nostrhost dns subscribe foo.nohost.me`` (op ``dns.subscribe``):

* validates the label is under a free-hostname zone (``nohost.me``,
  ``noho.st``, ``ynh.fr`` — the legacy Dynette namespaces);
* signs a NIP-01 *claim* event with the operator key (the identity's
  ownership proof) and persists it root-0600 under
  ``state/free-hostnames/<hostname>.json``;
* provisions the TSIG secret (given, kept on re-subscribe, or freshly
  generated) into the credential broker as ``secret:dns/dynette/<hostname>``.

That broker ref is exactly what :class:`DynetteProvider` resolves, so a
host subscribed this way registers natively with ``domain.add
--provider-type dynette`` and *no* credential — the identity-backed
compat conditional in the ``domain.add`` gate, replacing the legacy key
file the TOTP subscription used to write.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, Callable

from ..core import NostrHostError
from .. import credentials

FREE_HOSTNAME_ZONES = ("nohost.me", "noho.st", "ynh.fr")
CLAIM_KIND = 39910  # custom kind: nostrhost free-hostname ownership claim
DEFAULT_SECRET_BYTES = 32


def zone_for(hostname: str) -> str | None:
    """The free-hostname zone ``hostname`` lives under, or ``None``.

    ``foo.nohost.me`` -> ``nohost.me``; the bare apex ``nohost.me`` and any
    host outside the Dynette namespaces are not free hostnames.
    """
    for zone in FREE_HOSTNAME_ZONES:
        if hostname.endswith("." + zone):
            return zone
    return None


def is_free_hostname(hostname: str) -> bool:
    return zone_for(hostname) is not None


def subscriptions_dir(state_dir: Path) -> Path:
    return state_dir / "free-hostnames"


def subscription_path(state_dir: Path, hostname: str) -> Path:
    return subscriptions_dir(state_dir) / f"{hostname}.json"


def read_subscription(state_dir: Path, hostname: str) -> dict[str, Any] | None:
    path = subscription_path(state_dir, hostname)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):  # pragma: no cover - defensive
        return None


def list_subscriptions(state_dir: Path) -> list[dict[str, Any]]:
    base = subscriptions_dir(state_dir)
    out: list[dict[str, Any]] = []
    if not base.is_dir():
        return out
    for path in sorted(base.glob("*.json")):
        record = read_subscription(state_dir, path.stem)
        if record:
            out.append(_public_record(record))
    return out


def _default_signer(sk: str, pubkey: str, kind: int, content: str, tags: list[list[str]]) -> dict[str, Any]:
    """The default claim signer: the fork's own NIP-01 event signing."""
    from yunohost.nostr_identity import _sign_event

    return _sign_event(sk, pubkey, kind, content, tags)


def _default_operator() -> tuple[str, str]:
    """(secret_key, pubkey) of the node's operator identity."""
    from yunohost.nostr_identity import _operator_config

    config = _operator_config()
    return config.operator_sk, config.operator_pubkey


def _public_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "hostname": record.get("hostname"),
        "zone": record.get("zone"),
        "provider": record.get("provider"),
        "pubkey": record.get("pubkey"),
        "claim_id": (record.get("claim") or {}).get("id"),
        "secret_ref": record.get("secret_ref"),
        "created_at": record.get("created_at"),
    }


def subscribe(
    state_dir: Path,
    hostname: str,
    *,
    secret: str | None = None,
    rotate: bool = False,
    operator: tuple[str, str] | None = None,
    signer: Callable[[str, str, int, str, list[list[str]]], dict[str, Any]] | None = None,
    credential_dir: Path | None = None,
) -> dict[str, Any]:
    """Claim a free hostname with the node's Nostr identity.

    Returns the subscription record: the signed claim (the ownership proof),
    the broker reference the Dynette provider resolves, and the exact
    ``domain.add`` invocation to register the host natively.
    """
    zone = zone_for(hostname)
    if zone is None:
        raise NostrHostError(
            f"{hostname} is not a free hostname: claim a <label> under "
            + ", ".join(FREE_HOSTNAME_ZONES)
        )
    if operator is None:
        operator = _default_operator()
    sk, pubkey = operator
    ref = f"secret:dns/dynette/{hostname}"
    cred_dir = credential_dir or credentials.credentials_dir(state_dir)
    sign = signer or _default_signer

    secret_value = secret
    if secret_value is None:
        prior = read_subscription(state_dir, hostname)
        if prior is not None and not rotate:
            try:
                secret_value = credentials.read_secret(ref, dir=cred_dir)
            except credentials.CredentialError:
                secret_value = None
    if secret_value is None:
        secret_value = base64.b64encode(secrets.token_bytes(DEFAULT_SECRET_BYTES)).decode()

    claim = sign(
        sk,
        pubkey,
        CLAIM_KIND,
        json.dumps({"hostname": hostname, "zone": zone}, sort_keys=True),
        [["free-hostname", hostname], ["provider", "dynette"]],
    )

    credentials.set_secret(ref, secret_value, dir=cred_dir)

    record = {
        "hostname": hostname,
        "zone": zone,
        "provider": "dynette",
        "pubkey": pubkey,
        "secret_ref": ref,
        "claim": claim,
        "created_at": int(time.time()),
        "rotated": bool(rotate),
    }
    base = subscriptions_dir(state_dir)
    base.mkdir(parents=True, exist_ok=True)
    os.chmod(base, 0o700)
    path = subscription_path(state_dir, hostname)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)

    return {
        "hostname": hostname,
        "zone": zone,
        "provider": "dynette",
        "pubkey": pubkey,
        "claim_id": claim["id"],
        "claim": claim,
        "secret_ref": ref,
        "created_at": record["created_at"],
        "rotated": record["rotated"],
        "state": str(path),
        "next": f"nostrhost domain add {hostname} --provider-type dynette",
    }


def unsubscribe(state_dir: Path, hostname: str, *, credential_dir: Path | None = None) -> dict[str, Any]:
    """Release a free-hostname subscription and drop its broker secret."""
    path = subscription_path(state_dir, hostname)
    if not path.is_file():
        raise NostrHostError(f"{hostname} has no nostr free-hostname subscription")
    ref = f"secret:dns/dynette/{hostname}"
    cred_dir = credential_dir or credentials.credentials_dir(state_dir)
    removed = False
    if credentials.exists(ref, dir=cred_dir):
        credentials.remove_secret(ref, dir=cred_dir)
        removed = True
    path.unlink()
    return {"hostname": hostname, "secret_ref": ref, "secret_removed": removed, "unsubscribed": True}
