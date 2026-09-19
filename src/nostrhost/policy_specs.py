"""Declarative registry of kind-31101 policy coordinates (WP6).

WP6 migrates the host's small, non-secret policy documents onto signed relay
events: notification recipients/rules, the desired Restic schedule/retention/
paths, and the host operation safeguards currently in ``policy.toml``. Every
document is a kind-31101 addressable, schema-versioned declaration whose
envelope carries ``schema``/``revision``/``value`` (see
``authority/event-protocol/schemas/31101-policy.schema.json``).

Each family has one entry here: its addressable ``d`` coordinate, who may
author it, and which on-disk file (if any) a projector renders from the folded
document. Secrets are never part of a policy document: Restic's repo URL +
password stay in the root-only ``restic.toml`` and are preserved verbatim by
the projector when it writes the desired fields; the desired fields themselves
are the only thing the document carries.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

#: Kind-31101 trust/policy declaration (addressable, schema-versioned).
KIND_TRUST_POLICY = 31101

#: Namespace prefix for every host-defined ``d`` coordinate, so no event can
#: ever collide with a host policy family.
HOST_NAMESPACE = "nostrhost"

PolicyAuthor = Literal["server-admin", "server"]


@dataclass(frozen=True)
class PolicySpec:
    """One 31101 policy family.

    ``subject`` defines the event key: ``"coordinate"`` means the ``d`` tag is
    the key (all WP6 families are coordinate-subject). ``renderer`` names the
    on-disk target the projector writes from the folded document; ``None``
    means the document is read on demand (no rendered file).
    """

    name: str
    d: str
    authors: tuple[PolicyAuthor, ...] = ("server-admin",)
    subject: Literal["coordinate"] = "coordinate"
    schema: int = 1
    renderer: str | None = None
    description: str = ""

    def event_key(self, coordinate: str) -> str:
        return f"{self.kind}:{coordinate}"

    @property
    def kind(self) -> int:
        return KIND_TRUST_POLICY

    def owns_coordinate(self, coordinate: str | None) -> bool:
        return bool(coordinate) and coordinate == self.d


def _d(name: str) -> str:
    return f"{HOST_NAMESPACE}:{name}"


# --------------------------------------------------------------------------- #
# The families
# --------------------------------------------------------------------------- #

#: Notification recipients + delivery rules. Folded into the Go notify
#: daemon's ``recipients.toml`` + ``policy.toml`` inputs so delivery keeps
#: working unchanged (the projection renders the TOML the daemon already reads).
NOTIFICATION_RULES = "notification-rules"
#: Desired Restic schedule/retention/paths. The secret repo URL + password are
#: NOT part of this document; the projector merges desired fields into the
#: root-only ``/etc/nostrhost/restic.toml`` preserving the secrets.
RESTIC_POLICY = "restic-policy"
#: Host operation safeguards currently in ``/etc/nostrhost/policy.toml``
#: (free-space / recent-backup requirements, confirmation and owner-signature
#: flags) — the non-secret rules the policy adapter evaluates.
HOST_POLICY = "host-policy"

SPECS: dict[str, PolicySpec] = {
    NOTIFICATION_RULES: PolicySpec(
        name=NOTIFICATION_RULES,
        d=_d(NOTIFICATION_RULES),
        authors=("server-admin",),
        renderer="notify",
        description="Notification recipients and delivery rules (npubs, classes, severity, delivery mode, scope) rendered into the Go notify daemon's recipients.toml/policy.toml.",
    ),
    RESTIC_POLICY: PolicySpec(
        name=RESTIC_POLICY,
        d=_d(RESTIC_POLICY),
        authors=("server-admin",),
        renderer="restic",
        description="Desired Restic schedule/retention/paths; the repo URL + password stay in the root-only restic.toml and are never part of this document.",
    ),
    HOST_POLICY: PolicySpec(
        name=HOST_POLICY,
        d=_d(HOST_POLICY),
        authors=("server-admin",),
        renderer="host-policy",
        description="Host operation safeguards (free-space/backup requirements, confirmation flags) rendered into /etc/nostrhost/policy.toml.",
    ),
}

#: Kinds the WP6 producers publish (the relay allowlist must include these).
PRODUCED_KINDS: tuple[int, ...] = (KIND_TRUST_POLICY,)


def spec_for_name(name: str) -> PolicySpec:
    try:
        return SPECS[name]
    except KeyError as exc:  # pragma: no cover - programming error
        raise KeyError(f"unknown policy family: {name}") from exc


#: Reverse index: ``d`` coordinate -> spec (built once at import).
_SPECS_BY_COORDINATE: dict[str, PolicySpec] = {spec.d: spec for spec in SPECS.values()}


def spec_for_coordinate(coordinate: str | None) -> PolicySpec | None:
    return _SPECS_BY_COORDINATE.get(coordinate or "")
