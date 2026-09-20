"""Declarative registry of NIP-51 list / NIP-78 preference coordinates (WP4).

Every list/preference family the host projects has one entry here: its kind,
its addressable ``d`` coordinate (or ``None`` for replaceable events), who may
author it, whether self-service publication is allowed, and how it merges with
operator policy and mandatory server restrictions.

This module is the single source of truth for *coordinate ownership* and
*merge semantics*. The projectors read it to decide whether an event is
addressed to a family they own, and the self-service publisher reads it to
enforce that a user may only publish to their own coordinates and can never
influence a host capability.

Merge order (deterministic, highest wins):

1. **mandatory** — server restrictions that no preference may override;
2. **operator** — admin-authored list membership / settings;
3. **user** — an end user's own preference for their own coordinate.

For membership sets the merge is *additive* (operator ∪ user) except where a
family declares it mandatory-restricted; for scalar preferences the higher
priority source wins outright.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

# NIP-51 / NIP-65 / NIP-78 kinds the host projects (WP4). One-release aliases
# of the canonical nostrhost-protocol constants.
from nostrhost_protocol import KindAppData as KIND_APP_DATA
from nostrhost_protocol import KindBlockedRelays as KIND_BLOCKED_RELAYS
from nostrhost_protocol import KindMuteList as KIND_MUTE_LIST
from nostrhost_protocol import KindPermissionSet as KIND_PERMISSION_SET
from nostrhost_protocol import KindRelayList as KIND_RELAY_LIST

#: Namespace prefix for every host-defined ``d`` coordinate, so a user's
#: unrelated app-data events can never collide with a host family.
HOST_NAMESPACE = "nostrhost"

MergeStrategy = Literal["additive", "operator-wins", "user-wins", "mandatory-wins"]


@dataclass(frozen=True)
class ListSpec:
    """One list/preference family.

    ``d`` is ``None`` for replaceable (non-addressable) kinds. ``d_prefix``
    is set for addressable families whose subject is a free namespace (e.g. a
    permission name or ``user-preferences:<pubkey>``).

    ``subject`` defines what the *event key* is:

    * ``"coordinate"`` — the ``d`` coordinate (permission sets, NIP-78 docs);
    * ``"author"`` — the event author's pubkey (replaceable per-user lists
      such as NIP-65 relay lists and NIP-51 mute lists: every author owns
      their own slot);
    * ``"operator"`` — a single host-wide slot regardless of author.
    """

    name: str
    kind: int
    d: str | None = None
    d_prefix: str | None = None
    subject: Literal["coordinate", "author", "operator"] = "coordinate"
    authors: tuple[str, ...] = ("server-admin",)
    self_service: bool = False
    merge: MergeStrategy = "operator-wins"
    mandatory: bool = False
    projection: str = ""
    description: str = ""

    def event_key(self, coordinate: str | None, author: str) -> str:
        """Stable store key for one event of this family."""
        if self.subject == "author":
            return f"{self.kind}:{author.lower()}"
        if self.subject == "operator":
            return f"{self.kind}:operator"
        return f"{self.kind}:{coordinate or ''}"

    def owns_event(self, coordinate: str | None, author: str) -> bool:
        """Whether ``author`` may self-publish this event.

        Coordinate-subject families encode ownership in the coordinate;
        author-subject families are owned by their author; operator-subject
        families are never self-service.
        """
        if self.subject == "author":
            return bool(author)
        if self.subject == "operator":
            return False
        return is_self_service_coordinate(coordinate or "", author)

    def owns_coordinate(self, coordinate: str | None) -> bool:
        if self.d is not None:
            return coordinate == self.d
        if self.d_prefix is not None:
            return bool(coordinate) and str(coordinate).startswith(self.d_prefix)
        return coordinate in (None, "")


# --------------------------------------------------------------------------- #
# The families
# --------------------------------------------------------------------------- #

#: Trusted catalogue publishers the node accepts declarations from. Authored
#: by the operator; rendered into catalogue.env for the catalogue service.
TRUSTED_PUBLISHERS = "trusted-publishers"
#: Approved repositories (NIP-51 people-set of `r` repository URLs + `p`
#: publishers). Authored by the operator.
APPROVED_REPOSITORIES = "approved-repositories"

SPECS: dict[str, ListSpec] = {
    # 1. Preferred / blocked relays + nsite discovery.
    "preferred-relays": ListSpec(
        name="preferred-relays",
        kind=KIND_RELAY_LIST,
        subject="author",
        authors=("server-admin", "end-user"),
        self_service=True,
        merge="additive",
        projection="forks/yunohost/src/nostrhost/connectivity.py",
        description="NIP-65 relay list; every author owns their own slot and the server merges its defaults with a user's own relays (never replaces).",
    ),
    "blocked-relays": ListSpec(
        name="blocked-relays",
        kind=KIND_BLOCKED_RELAYS,
        subject="operator",
        authors=("server-admin",),
        merge="mandatory-wins",
        mandatory=True,
        projection="forks/yunohost/src/nostrhost/connectivity.py",
        description="NIP-51 blocked relays; a mandatory server restriction no preference may re-enable.",
    ),
    "blocked-site-owners": ListSpec(
        name="blocked-site-owners",
        kind=KIND_MUTE_LIST,
        subject="operator",
        authors=("server-admin",),
        merge="mandatory-wins",
        mandatory=True,
        projection="forks/yunohost/src/nostrhost/nsites/blocklist.py",
        description="NIP-51 mute list of site-owner pubkeys excluded from nsite.discover.",
    ),
    # 2. Trusted publishers + approved repositories.
    TRUSTED_PUBLISHERS: ListSpec(
        name=TRUSTED_PUBLISHERS,
        kind=KIND_PERMISSION_SET,
        d=f"{HOST_NAMESPACE}:{TRUSTED_PUBLISHERS}",
        authors=("server-admin",),
        merge="operator-wins",
        projection="forks/yunohost/src/nostrhost/catalogue_lists.py",
        description="People set of publisher pubkeys the catalogue trusts.",
    ),
    APPROVED_REPOSITORIES: ListSpec(
        name=APPROVED_REPOSITORIES,
        kind=KIND_PERMISSION_SET,
        d=f"{HOST_NAMESPACE}:{APPROVED_REPOSITORIES}",
        authors=("server-admin",),
        merge="operator-wins",
        projection="forks/yunohost/src/nostrhost/catalogue_lists.py",
        description="People set of approved package repository coordinates.",
    ),
    # 3. App/domain permission membership.
    "permissions": ListSpec(
        name="permissions",
        kind=KIND_PERMISSION_SET,
        d_prefix="",
        authors=("server-admin",),
        merge="additive",
        projection="forks/yunohost/src/nostrhost/permissions.py",
        description="NIP-51 permission sets: d = the permission name; merged additively with LDAP membership.",
    ),
    # 4. Portal / per-user preferences.
    "portal-settings": ListSpec(
        name="portal-settings",
        kind=KIND_APP_DATA,
        d=f"{HOST_NAMESPACE}:portal-settings",
        authors=("server-admin",),
        merge="operator-wins",
        projection="forks/yunohost/src/nostrhost/portal_settings.py",
        description="Server-admin portal appearance/settings document.",
    ),
    "user-preferences": ListSpec(
        name="user-preferences",
        kind=KIND_APP_DATA,
        # d = "nostrhost:user-preferences:<pubkey>" — one per linked pubkey.
        d_prefix=f"{HOST_NAMESPACE}:user-preferences:",
        authors=("end-user",),
        self_service=True,
        merge="user-wins",
        projection="forks/yunohost/src/nostrhost/user_preferences.py",
        description="A user's own portal preferences; server restrictions always win.",
    ),
}

#: Kinds the WP4 producers publish (the relay allowlist must include these).
PRODUCED_KINDS: tuple[int, ...] = tuple(sorted({spec.kind for spec in SPECS.values()}))


def spec_for_name(name: str) -> ListSpec:
    try:
        return SPECS[name]
    except KeyError as exc:  # pragma: no cover - programming error
        raise KeyError(f"unknown list/preference family: {name}") from exc


def user_preferences_coordinate(pubkey: str) -> str:
    """The ``d`` coordinate a user owns for their own preferences."""
    return f"{HOST_NAMESPACE}:user-preferences:{pubkey}"


def coordinate_owner(coordinate: str) -> str | None:
    """The pubkey encoded in a per-user coordinate, or ``None``.

    Per-user coordinates are self-describing (``...:<pubkey>``), so ownership
    is checkable without consulting any store: a user may publish only to the
    coordinate that names their own authenticated pubkey.
    """
    prefix = f"{HOST_NAMESPACE}:user-preferences:"
    if coordinate.startswith(prefix):
        candidate = coordinate[len(prefix):]
        if len(candidate) == 64 and all(c in "0123456789abcdefABCDEF" for c in candidate):
            return candidate.lower()
    return None


def is_self_service_coordinate(coordinate: str, pubkey: str) -> bool:
    """True when ``pubkey`` may self-publish to ``coordinate``.

    Only the per-user preference family is self-service, and only for the
    caller's own pubkey. Every host list (trusted publishers, approved repos,
    permission sets, portal settings) is operator-only and explicitly *not*
    self-service, so a user can never grant themselves a host capability by
    publishing a list.
    """
    owner = coordinate_owner(coordinate)
    if owner is None:
        return False
    return owner == str(pubkey or "").lower()
