"""Persisted, rebuildable capability/authorization projection (WP3).

Roadmap / docs/RELAY-STATE-MIGRATION-PLAN.md WP3: kind ``31100`` capability
grants and the ``27236``/``27237`` delegation lifecycle are authoritative on
the control relay, but today the executor holds them only in memory
(``OperationEngine.scopes``/``delegations``) and rebuilds them on every start
via a NIP-33 ``preload_capabilities`` workaround. This module makes the
authorization read model explicit, durable and rebuildable:

* :class:`CapabilityProjection` — a pure, serialisable fold of the accepted
  grant/delegation events with the same authorization semantics the executor
  applies (admin bypass, direct scope, delegated scope clipped by expiry and
  the delegator's own authority);
* :class:`CapabilityProjector` — a WP2 :class:`~nostr_projector.Projector`
  that validates/administers the events and atomically writes the projection
  to ``/var/lib/nostrhost/capabilities.json``;
* :func:`load_capabilities` / :func:`capabilities_are_fresh` — the
  cross-process read + freshness guard used by the HTTP authorizer so a
  revoked grant is never honoured past its projection revision.

The projection is deliberately JSON, like the NIP-51 permission projection:
it has two writers (the executor at ingest, ``bin/nostr-projector`` on
rebuild) and several readers across privilege domains, and the file is the
shared contract between them.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from nostrhost_projection import (
    DEFAULT_CURSOR_DIR,
    Projector,
    ProjectionResult,
    _atomic_write,
)
from .nostr_operations import (
    DELEGATION_MAX_LIFETIME,
    KIND_CAPABILITY,
    KIND_DELEGATION,
    KIND_DELEGATION_REVOCATION,
    KNOWN_SCOPES,
)

logger = logging.getLogger("nostr-capability-projection")

PROJECTION_NAME = "capabilities"

#: The materialised authorization read model. Lives beside the Restic/state
#: area rather than under /etc: it is a disposable projection and a lost file
#: only costs a relay replay.
DEFAULT_CAPABILITY_PROJECTION = "/var/lib/nostrhost/capabilities.json"

#: A projection older than this is considered stale by the HTTP authorizer,
#: which then re-reads the relay once and fails closed on error (WP3
#: deliverable 5). The executor writes the revision on every accepted event,
#: so a live node is always far inside this window.
FRESHNESS_WINDOW_SECONDS = 300.0

CAPABILITY_KINDS = (KIND_CAPABILITY, KIND_DELEGATION, KIND_DELEGATION_REVOCATION)


def projection_path_from_env() -> str:
    return os.environ.get("NOSTRHOST_CAPABILITY_PROJECTION", DEFAULT_CAPABILITY_PROJECTION)


@dataclass
class CapabilityProjection:
    """Deterministic fold of grants + delegations.

    The shape is intentionally close to the executor's in-memory structures so
    :meth:`OperationEngine` can adopt it without changing decision semantics.
    """

    scopes: dict[str, list[str]] = field(default_factory=dict)
    delegations: dict[str, dict[str, Any]] = field(default_factory=dict)
    revoked: list[str] = field(default_factory=list)
    revision: str = ""
    updated_at: float = 0.0
    #: Per-subject ``(created_at, event_id)`` stamp of the grant that produced
    #: ``scopes``. NIP-33 replaceable semantics: the newest grant wins, and an
    #: older replay must not clobber a newer revoke/regrant.
    stamps: dict[str, list[str]] = field(default_factory=dict)

    def grant_is_newer(self, subject: str, event: dict[str, Any]) -> bool:
        stamp = self.stamps.get(subject)
        if not stamp:
            return True
        candidate = [str(int(event.get("created_at") or 0)), str(event.get("id") or "")]
        return candidate > stamp

    # -- decisions -------------------------------------------------------- #

    def direct_authorized(self, pubkey: str, scope: str, *, admins: Iterable[str] = ()) -> bool:
        """A direct scope grant (or static admin membership)."""
        pubkey = (pubkey or "").lower()
        if pubkey in {a.lower() for a in admins}:
            return True
        return scope in self.scopes.get(pubkey, ())

    def authorized(
        self,
        pubkey: str,
        scope: str,
        *,
        admins: Iterable[str] = (),
        now: int | None = None,
    ) -> bool:
        """Direct grant or a live delegation whose delegator is still authorized.

        Mirrors ``OperationEngine._authorized`` exactly: a delegation counts
        only while unexpired, unrevoked, and its delegator remains directly
        authorized for the scope (so revoking the delegator instantly removes
        the delegate's derived access).
        """
        if self.direct_authorized(pubkey, scope, admins=admins):
            return True
        pubkey = (pubkey or "").lower()
        now = int(time.time()) if now is None else now
        for delegation_id, delegation in self.delegations.items():
            if delegation_id in self.revoked:
                continue
            if delegation.get("delegate") != pubkey:
                continue
            if scope not in delegation.get("scopes", ()):
                continue
            if int(delegation.get("expiry") or 0) <= now:
                continue
            if self.direct_authorized(str(delegation.get("delegator") or ""), scope, admins=admins):
                return True
        return False

    def scopes_for(self, pubkey: str) -> list[str]:
        return sorted(self.scopes.get((pubkey or "").lower(), ()))

    # -- serialisation ---------------------------------------------------- #

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": 1,
            "revision": self.revision,
            "updated_at": self.updated_at,
            "scopes": {k: sorted(v) for k, v in sorted(self.scopes.items())},
            "stamps": {k: list(v) for k, v in sorted(self.stamps.items())},
            "delegations": self.delegations,
            "revoked": sorted(self.revoked),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CapabilityProjection":
        scopes_raw = raw.get("scopes") or {}
        scopes = {
            str(k).lower(): sorted({str(s) for s in (v or []) if isinstance(s, str)})
            for k, v in scopes_raw.items()
            if isinstance(v, (list, tuple, set))
        }
        delegations: dict[str, dict[str, Any]] = {}
        for key, value in (raw.get("delegations") or {}).items():
            if not isinstance(value, dict):
                continue
            delegations[str(key)] = {
                "delegator": str(value.get("delegator") or "").lower(),
                "delegate": str(value.get("delegate") or "").lower(),
                "scopes": sorted({str(s) for s in (value.get("scopes") or []) if isinstance(s, str)}),
                "expiry": int(value.get("expiry") or 0),
            }
        revoked = sorted({str(r) for r in (raw.get("revoked") or []) if isinstance(r, str)})
        stamps: dict[str, list[str]] = {}
        for key, value in (raw.get("stamps") or {}).items():
            if isinstance(value, (list, tuple)) and len(value) == 2:
                stamps[str(key).lower()] = [str(value[0]), str(value[1])]
        return cls(
            scopes=scopes,
            delegations=delegations,
            revoked=revoked,
            revision=str(raw.get("revision") or ""),
            updated_at=float(raw.get("updated_at") or 0.0),
            stamps=stamps,
        )

    def render(self) -> str:
        return json.dumps(self.as_dict(), indent=2, sort_keys=True) + "\n"


def load_capabilities(path: str | Path | None = None) -> CapabilityProjection:
    """Read the persisted projection; an absent/corrupt file is empty."""
    target = Path(path or projection_path_from_env())
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return CapabilityProjection()
    if not isinstance(raw, dict):
        return CapabilityProjection()
    return CapabilityProjection.from_dict(raw)


def save_capabilities(
    projection: CapabilityProjection,
    path: str | Path | None = None,
    *,
    revision: str | None = None,
) -> None:
    projection.updated_at = time.time()
    if revision is not None:
        projection.revision = revision
    elif not projection.revision:
        projection.revision = f"{int(projection.updated_at)}"
    _atomic_write(Path(path or projection_path_from_env()), projection.render(), mode=0o644)


def capabilities_are_fresh(projection: CapabilityProjection, *, window: float = FRESHNESS_WINDOW_SECONDS) -> bool:
    """True when the projection was written within the freshness window."""
    if not projection.revision or projection.updated_at <= 0:
        return False
    return (time.time() - projection.updated_at) <= window


def _event_revision(event: dict[str, Any]) -> str:
    """Content-stable revision label: newest event dominates the projection."""
    created_at = int(event.get("created_at") or 0)
    event_id = str(event.get("id") or "")
    return f"{created_at}:{event_id[:12]}"


class CapabilityProjector(Projector):
    """Projector that folds grant/delegation events into the persisted store.

    Validation is the authority gate: only admin-authored ``31100`` grants are
    accepted (the relay enforces this at write time too, but the projector
    re-checks so a relay-policy regression cannot silently expand scopes), and
    delegations must pass signature/scope/expiry/delegator-authority checks.
    """

    name = PROJECTION_NAME
    schema = 1

    def __init__(
        self,
        *,
        projection: CapabilityProjection | None = None,
        admin_pubkeys: tuple[str, ...] | list[str] = (),
        projection_path: str | Path | None = None,
        cursor_dir: str | Path = DEFAULT_CURSOR_DIR,
        time_fn: Callable[[], float] = time.time,
        server_pubkey: str = "",
    ) -> None:
        super().__init__(cursor_dir=cursor_dir)
        self.admin_pubkeys = tuple(a.lower() for a in admin_pubkeys)
        self.projection = projection if projection is not None else load_capabilities(projection_path)
        self.projection_path = Path(projection_path or projection_path_from_env())
        self._time = time_fn
        # The delegate authorization check during validation needs the
        # delegator's current authority; derive it from the in-progress fold.
        self.server_pubkey = server_pubkey

    # -- validation ------------------------------------------------------- #

    def validate(self, event: dict[str, Any]) -> Any:
        kind = event.get("kind")
        if kind == KIND_CAPABILITY:
            return self._validate_capability(event)
        if kind == KIND_DELEGATION:
            return self._validate_delegation(event)
        if kind == KIND_DELEGATION_REVOCATION:
            return self._validate_revocation(event)
        return None

    def _validate_capability(self, event: dict[str, Any]) -> Any:
        subject = next((t[1] for t in event.get("tags", []) if len(t) >= 2 and t[0] == "d"), None)
        if not subject or not self._is_hex(subject):
            self.quarantine(event, "capability without a hex subject 'd' tag")
            return None
        if str(event.get("pubkey") or "").lower() not in self.admin_pubkeys:
            self.quarantine(event, "capability authored by non-admin")
            return None
        try:
            body = json.loads(event.get("content") or "{}")
        except json.JSONDecodeError:
            self.quarantine(event, "capability content is not JSON")
            return None
        scopes = body.get("scopes")
        if not isinstance(scopes, list):
            self.quarantine(event, "capability content has no scopes list")
            return None
        return {
            "type": "capability",
            "subject": subject.lower(),
            "scopes": sorted({str(s) for s in scopes if isinstance(s, str)}),
            "created_at": int(event.get("created_at") or 0),
            "stamp": [str(int(event.get("created_at") or 0)), str(event.get("id") or "")],
        }

    def _validate_delegation(self, event: dict[str, Any]) -> Any:
        try:
            from .nostr_operationsd import _verify_delegation_event

            _verify_delegation_event(event)
            delegate = next(t[1] for t in event.get("tags", []) if len(t) >= 2 and t[0] == "p")
            server = next(t[1] for t in event.get("tags", []) if len(t) >= 2 and t[0] == "server")
            expiry = int(next(t[1] for t in event.get("tags", []) if len(t) >= 2 and t[0] == "expiry"))
            scopes = {t[1] for t in event.get("tags", []) if len(t) >= 2 and t[0] == "scope"}
            created_at = int(event["created_at"])
        except (KeyError, StopIteration, TypeError, ValueError, IndexError):
            self.quarantine(event, "malformed delegation event")
            return None
        if self.server_pubkey and server != self.server_pubkey:
            self.quarantine(event, "delegation for a different server key")
            return None
        if not self._is_hex(delegate) or not scopes or not scopes.issubset(KNOWN_SCOPES):
            self.quarantine(event, "delegation has an invalid delegate or scope set")
            return None
        now = int(self._time())
        if expiry <= now or expiry - created_at > DELEGATION_MAX_LIFETIME:
            self.quarantine(event, "delegation expired or exceeds max lifetime")
            return None
        if event["id"] in self.projection.revoked:
            self.quarantine(event, "delegation already revoked")
            return None
        if not all(self.projection.direct_authorized(event["pubkey"], scope, admins=self.admin_pubkeys) for scope in scopes):
            self.quarantine(event, "delegator is not directly authorized for every scope")
            return None
        return {
            "type": "delegation",
            "id": str(event["id"]),
            "delegator": str(event["pubkey"]).lower(),
            "delegate": delegate.lower(),
            "scopes": sorted(scopes),
            "expiry": expiry,
            "created_at": created_at,
        }

    def _validate_revocation(self, event: dict[str, Any]) -> Any:
        delegation_id = next((t[1] for t in event.get("tags", []) if len(t) >= 2 and t[0] == "e"), None)
        if not delegation_id or not self._is_hex(delegation_id):
            self.quarantine(event, "revocation without a delegation 'e' tag")
            return None
        record = self.projection.delegations.get(delegation_id)
        author = str(event.get("pubkey") or "").lower()
        if record is not None:
            if author not in (record.get("delegator"), *self.admin_pubkeys):
                self.quarantine(event, "revocation authored by neither delegator nor admin")
                return None
        elif author not in self.admin_pubkeys:
            self.quarantine(event, "revocation of an unknown delegation authored by non-admin")
            return None
        try:
            from .nostr_operationsd import _verify_delegation_event

            _verify_delegation_event(event, revocation=True)
        except (KeyError, TypeError, ValueError, IndexError):
            self.quarantine(event, "malformed delegation revocation")
            return None
        return {"type": "revocation", "id": str(delegation_id)}

    # -- fold + persist --------------------------------------------------- #

    def fold(self, current: CapabilityProjection | None, fact: dict[str, Any]) -> CapabilityProjection:
        state = current if current is not None else self.projection
        kind = fact.get("type")
        if kind == "capability":
            subject = fact["subject"]
            stamp = fact.get("stamp")
            if stamp is not None and not state.grant_is_newer(subject, {"created_at": stamp[0], "id": stamp[1]}):
                return state  # an older replaceable grant must not clobber a newer one
            if fact["scopes"]:
                state.scopes[subject] = list(fact["scopes"])
            else:
                # Empty scopes is grant_capability's own revoke convention.
                state.scopes.pop(subject, None)
            if stamp is not None:
                state.stamps[subject] = list(stamp)
        elif kind == "delegation":
            state.delegations[fact["id"]] = {
                "delegator": fact["delegator"],
                "delegate": fact["delegate"],
                "scopes": list(fact["scopes"]),
                "expiry": fact["expiry"],
            }
        elif kind == "revocation":
            state.revoked = sorted(set(state.revoked) | {fact["id"]})
            state.delegations.pop(fact["id"], None)
        return state

    def apply(self, event: dict[str, Any]) -> ProjectionResult:
        fact = self.validate(event)
        if fact is None:
            return ProjectionResult(accepted=False, reason="invalid")
        self.projection = self.fold(self.projection, fact)
        self.projection.revision = _event_revision(event)
        self._persist()
        self._advance(event)
        return ProjectionResult(accepted=True, changed=True)

    def _persist(self) -> None:
        try:
            save_capabilities(self.projection, self.projection_path)
        except OSError as exc:  # pragma: no cover - disk failure
            self.health_state.last_error = f"write failed: {exc}"
            logger.error("failed to persist capability projection: %s", exc)
            raise

    def clone(self) -> "CapabilityProjector":
        """A fresh projector on a temp path, for :func:`verify` (never writes
        the live projection)."""
        import tempfile

        tmp = tempfile.NamedTemporaryFile(prefix="capabilities-verify-", suffix=".json", delete=False)
        tmp.close()
        return CapabilityProjector(
            projection=CapabilityProjection(),
            admin_pubkeys=self.admin_pubkeys,
            projection_path=tmp.name,
            cursor_dir=self.cursor_dir,
            server_pubkey=self.server_pubkey,
        )

    def current(self) -> str:
        return self.projection.render()

    def render(self, state: Any) -> str | None:
        if isinstance(state, CapabilityProjection):
            return state.render()
        return self.projection.render()

    def commit(self, candidate: str) -> None:  # pragma: no cover - apply owns the write
        _atomic_write(self.projection_path, candidate, mode=0o644)

    # -- helpers ---------------------------------------------------------- #

    @staticmethod
    def _is_hex(value: Any) -> bool:
        text = str(value or "")
        return len(text) == 64 and all(c in "0123456789abcdefABCDEF" for c in text)


def rebuild_from_events(
    events: Iterable[dict[str, Any]],
    *,
    admin_pubkeys: tuple[str, ...] | list[str],
    server_pubkey: str = "",
    projection_path: str | Path | None = None,
    cursor_dir: str | Path = DEFAULT_CURSOR_DIR,
) -> dict[str, Any]:
    """Refold ``events`` into a fresh projection and persist it (WP3 rebuild)."""
    from nostrhost_projection import rebuild as _rebuild

    projector = CapabilityProjector(
        projection=CapabilityProjection(),
        admin_pubkeys=admin_pubkeys,
        projection_path=projection_path,
        cursor_dir=cursor_dir,
        server_pubkey=server_pubkey,
    )
    report = _rebuild(events, projector=projector)
    report["projection"] = projector.projection.as_dict()
    return report


def rebuild_from_relay(
    relay_url: str,
    *,
    admin_pubkeys: tuple[str, ...] | list[str],
    server_pubkey: str = "",
    projection_path: str | Path | None = None,
    cursor_dir: str | Path = DEFAULT_CURSOR_DIR,
) -> dict[str, Any]:
    """Query the relay for grant/delegation events and rebuild (WP3)."""
    from .nostrhost.events import query_chain_events

    events: list[dict[str, Any]] = []
    # Per-kind queries: the badger store truncates NIP-33 replaceable events
    # when they share a REQ with the chain kinds, so a combined query would
    # lose every grant but the newest (the preload_capabilities rationale).
    for kind in CAPABILITY_KINDS:
        events.extend(query_chain_events(relay_url, kinds=(kind,), limit=500))
    return rebuild_from_events(
        events,
        admin_pubkeys=admin_pubkeys,
        server_pubkey=server_pubkey,
        projection_path=projection_path,
        cursor_dir=cursor_dir,
    )
