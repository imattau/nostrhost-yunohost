"""NIP-51 permission-membership projection (roadmap §25 Phase 2).

LDAP's remaining real job in the auth/authz surface is membership: which
pubkeys/accounts may use which app permission
(``_sync_permissions_with_ldap`` in the fork's ``permission.py``) or access a
given portal domain (``user_is_allowed_on_domain`` in
``authenticators/ldap_ynhuser.py``). This module replaces that membership
source with signed Nostr events instead of an LDAP write/read.

Shape: one NIP-51 "follow set" (kind 30000) event per permission, addressed
by its ``d`` tag (the YunoHost permission name, e.g. ``"myapp.main"``), with
one ``p`` tag per member pubkey -- the standard NIP-51 people-list
convention. An optional ``["public", "true"]`` tag marks the permission as
visitor-accessible (mirrors the projection's existing ``public`` flag). Being
kind 30000 (parameterized replaceable), a new event with the same
``(author, kind, d)`` replaces the previous membership list outright -- no
diffing needed, the latest event is the full membership.

Only events authored by a configured admin are accepted, mirroring
``nostr_identityd``'s identity-projection trust model (§4 Phase 3): the
relay enforces transport, this module enforces permission semantics.

This is deliberately additive during the migration: ``merge_projection()``
unions NIP-51-resolved usernames into the existing (LDAP-sourced) permission
projection rather than replacing it, so deploying this cannot revoke access
anyone already has via LDAP. Once permission grants have moved to NIP-51 in
practice, the LDAP-sourced membership in ``build_permissions_projection()``
can be dropped -- see ``docs/LDAP-RETIREMENT.md`` Phase 2.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger("nostr-permissiond")

PERMISSION_LIST_KIND = 30000  # NIP-51 "follow sets" (people list)
DEFAULT_STORE_PATH = Path("/etc/nostrhost/nip51_permissions.json")


@dataclass(frozen=True)
class PermissionGrant:
    """One permission's current NIP-51-sourced membership."""

    permission: str
    pubkeys: tuple[str, ...]
    public: bool
    event_id: str
    created_at: int


def _tag_values(event: dict[str, Any], name: str) -> list[str]:
    return [
        tag[1]
        for tag in event.get("tags") or []
        if isinstance(tag, list) and len(tag) >= 2 and tag[0] == name
    ]


def _d_tag(event: dict[str, Any]) -> str | None:
    values = _tag_values(event, "d")
    return values[0] if values else None


def _is_public(event: dict[str, Any]) -> bool:
    values = _tag_values(event, "public")
    return bool(values) and values[0].strip().lower() in ("1", "true", "yes")


class PermissionStore:
    """Root-owned JSON persistence for the latest grant per permission.

    Same atomic-write style as ``nostrhost.permissions``'s projection file --
    this is working state for the projector, not the final world-readable
    projection the authd reads.
    """

    def __init__(self, path: Path = DEFAULT_STORE_PATH) -> None:
        self.path = path
        self._grants: dict[str, PermissionGrant] = {}
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return
        for permission, info in (raw or {}).items():
            try:
                self._grants[permission] = PermissionGrant(
                    permission=permission,
                    pubkeys=tuple(info["pubkeys"]),
                    public=bool(info.get("public", False)),
                    event_id=str(info.get("event_id", "")),
                    created_at=int(info.get("created_at", 0)),
                )
            except (KeyError, TypeError, ValueError):
                logger.warning("ignoring malformed stored grant for %s", permission)

    def _save(self) -> None:
        payload = {
            grant.permission: {
                "pubkeys": list(grant.pubkeys),
                "public": grant.public,
                "event_id": grant.event_id,
                "created_at": grant.created_at,
            }
            for grant in self._grants.values()
        }
        data = json.dumps(payload, indent=1, sort_keys=True).encode() + b"\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=".nip51-permissions-")
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def get(self, permission: str) -> PermissionGrant | None:
        return self._grants.get(permission)

    def all_grants(self) -> dict[str, PermissionGrant]:
        return dict(self._grants)

    def apply_event(self, event: dict[str, Any], *, admin_pubkeys: tuple[str, ...] | list[str]) -> bool:
        """Validate and apply one permission-list event. Returns True if applied.

        Rejects: wrong kind, non-admin author, missing 'd' tag. A stale
        replay (older or equal ``created_at`` than what's already stored for
        this permission) is accepted-but-ignored, since parameterized
        replaceable events can arrive out of order during relay replay.
        """
        if event.get("kind") != PERMISSION_LIST_KIND:
            return False

        author = event.get("pubkey")
        if author not in admin_pubkeys:
            logger.warning("permission-list event authored by non-admin %s ignored", author)
            return False

        permission = _d_tag(event)
        if not permission:
            logger.warning("permission-list event without a 'd' tag ignored")
            return False

        created_at = int(event.get("created_at") or 0)
        existing = self._grants.get(permission)
        if existing is not None and created_at <= existing.created_at:
            logger.debug("stale permission-list event for %s ignored", permission)
            return True

        pubkeys = tuple(dict.fromkeys(_tag_values(event, "p")))  # de-dup, keep order
        grant = PermissionGrant(
            permission=permission,
            pubkeys=pubkeys,
            public=_is_public(event),
            event_id=str(event.get("id") or ""),
            created_at=created_at,
        )
        self._grants[permission] = grant
        self._save()
        logger.info(
            "applied permission-list for %s: %d member(s), public=%s",
            permission,
            len(pubkeys),
            grant.public,
        )
        return True


def resolve_usernames(
    grant: PermissionGrant, *, resolve_pubkey: Callable[[str], Any]
) -> list[str]:
    """Resolve a grant's member pubkeys to usernames at read time.

    Resolution happens here rather than at ingestion so an identity link
    made *after* the permission event was published is still honoured, and a
    later revocation removes access without needing to re-publish the
    permission list.
    """
    usernames: list[str] = []
    for pubkey in grant.pubkeys:
        try:
            identity = resolve_pubkey(pubkey)
        except Exception:  # noqa: BLE001 - unavailable store shouldn't break the projection
            identity = None
        if identity is not None and getattr(identity, "username", None):
            usernames.append(identity.username)
    return usernames


def merge_projection(
    permissions: dict[str, Any],
    store: PermissionStore,
    *,
    resolve_pubkey: Callable[[str], Any],
) -> dict[str, Any]:
    """Union NIP-51-resolved membership into an existing permissions
    projection dict (the ``permissions`` value of
    ``nostrhost.permissions.build_permissions_projection()``'s return).

    Additive by design: never removes a user or clears the ``public`` flag
    that the LDAP-sourced projection already granted -- see module
    docstring. A permission with no matching entry in ``permissions`` (e.g.
    an app not yet installed) is skipped rather than fabricating one, since
    the URL/auth_header/uris data has no other source yet.
    """
    for name, grant in store.all_grants().items():
        entry = permissions.get(name)
        if entry is None:
            continue
        nip51_users = resolve_usernames(grant, resolve_pubkey=resolve_pubkey)
        entry["users"] = sorted(set(entry.get("users", [])) | set(nip51_users))
        if grant.public:
            entry["public"] = True
    return permissions
