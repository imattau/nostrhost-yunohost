"""NIP-51/NIP-78 list and preference projection (WP4).

WP4 migrates the host's list and preference families onto signed relay events:
preferred/blocked relays, the nsite discovery blocklist, trusted publishers,
approved repositories, permission membership and portal/per-user preferences.

This module is the projection side: a single :class:`ListStore` holds the
latest folded state per ``(kind, d)`` coordinate, validated against the
declarative :mod:`nostrhost.list_specs` registry, and :class:`ListProjector`
keeps it current on the WP2 :class:`~nostr_projector.ProjectionRuntime`.

Merge semantics (deterministic; see :mod:`nostrhost.list_specs`):

* **membership lists** (people sets) merge *additively* where the spec says
  so, but a ``mandatory`` server restriction always wins;
* **settings documents** (NIP-78) merge field-by-field, with mandatory server
  restrictions overriding any user preference.

Family readers (``trusted_publishers``, ``approved_repositories``,
``blocked_relays``, ``portal_settings``, ``user_preferences``) return the
merged, effective view other modules consume, so behaviour is identical before
and after the event-first cutover.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from yunohost.nostr_projector import (
    DEFAULT_CURSOR_DIR,
    Projector,
    ProjectionResult,
)

from nostrhost.events import _d_tag
from nostrhost.list_specs import (
    KIND_APP_DATA,
    KIND_MUTE_LIST,
    KIND_PERMISSION_SET,
    KIND_RELAY_LIST,
    SPECS,
    ListSpec,
    spec_for_name,
)

logger = logging.getLogger("nostr-list-projection")

DEFAULT_LIST_STORE = Path("/etc/nostrhost/lists.json")
PROJECTION_NAME = "lists"

#: Every kind this projection consumes.
LIST_KINDS = (KIND_MUTE_LIST, KIND_RELAY_LIST, KIND_PERMISSION_SET, KIND_APP_DATA)


@dataclass
class ListEntry:
    """One folded slot: a membership set and/or a settings document.

    ``key`` is the family's stable event key (the coordinate for addressable
    families, the author pubkey for per-author replaceable lists, the literal
    ``operator`` for host-wide lists).
    """

    kind: int
    coordinate: str
    key: str
    entries: list[str] = field(default_factory=list)
    settings: dict[str, Any] = field(default_factory=dict)
    public: bool = False
    event_id: str = ""
    created_at: int = 0
    author: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "coordinate": self.coordinate,
            "key": self.key,
            "entries": list(self.entries),
            "settings": dict(self.settings),
            "public": bool(self.public),
            "event_id": self.event_id,
            "created_at": self.created_at,
            "author": self.author,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ListEntry":
        return cls(
            kind=int(raw.get("kind") or 0),
            coordinate=str(raw.get("coordinate") or ""),
            key=str(raw.get("key") or raw.get("coordinate") or ""),
            entries=[str(e) for e in raw.get("entries") or []],
            settings=dict(raw.get("settings") or {}),
            public=bool(raw.get("public", False)),
            event_id=str(raw.get("event_id") or ""),
            created_at=int(raw.get("created_at") or 0),
            author=str(raw.get("author") or ""),
        )


class ListStore:
    """Atomic JSON persistence for folded list/preference coordinates."""

    def __init__(self, path: Path = DEFAULT_LIST_STORE) -> None:
        self.path = Path(path)
        self._entries: dict[str, ListEntry] = {}
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return
        for key, info in (raw or {}).items():
            try:
                self._entries[key] = ListEntry.from_dict(info)
            except (TypeError, ValueError):
                logger.warning("ignoring malformed stored list entry %s", key)

    def _save(self) -> None:
        payload = {key: entry.as_dict() for key, entry in self._entries.items()}
        data = json.dumps(payload, indent=1, sort_keys=True).encode() + b"\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=".lists-")
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def get(self, key: str) -> ListEntry | None:
        return self._entries.get(key)

    def get_by_coordinate(self, kind: int, coordinate: str | None) -> ListEntry | None:
        return self._entries.get(f"{kind}:{coordinate or ''}")

    def get_for_author(self, kind: int, author: str) -> ListEntry | None:
        return self._entries.get(f"{kind}:{str(author).lower()}")

    def put(self, entry: ListEntry) -> bool:
        existing = self._entries.get(entry.key)
        if existing is not None and entry.created_at <= existing.created_at:
            return False  # stale replay: replaceable, newest wins
        self._entries[entry.key] = entry
        self._save()
        return True

    def by_coordinate(self, coordinate: str) -> ListEntry | None:
        for entry in self._entries.values():
            if entry.coordinate == coordinate:
                return entry
        return None

    def entries_for(self, kind: int) -> list[ListEntry]:
        return [entry for entry in self._entries.values() if entry.kind == kind]

    def all_entries(self) -> list[ListEntry]:
        return list(self._entries.values())


def _tag_values(event: dict[str, Any], name: str) -> list[str]:
    return [
        tag[1]
        for tag in event.get("tags") or []
        if isinstance(tag, list) and len(tag) >= 2 and tag[0] == name and isinstance(tag[1], str)
    ]


def _is_public(event: dict[str, Any]) -> bool:
    values = _tag_values(event, "public")
    return bool(values) and values[0].strip().lower() in ("1", "true", "yes")


def _spec_for_event(event: dict[str, Any]) -> ListSpec | None:
    """The family an event addresses, or None when it is not a host list."""
    kind = int(event.get("kind") or 0)
    coordinate = _d_tag(event)
    for spec in SPECS.values():
        if spec.kind != kind:
            continue
        if spec.d is not None and coordinate != spec.d:
            continue
        if spec.d_prefix is not None and not (
            coordinate and coordinate.startswith(spec.d_prefix)
        ):
            # "" prefix means "any coordinate of this kind" (permission sets).
            if spec.d_prefix != "":
                continue
        if spec.d is None and spec.d_prefix is None and coordinate not in (None, ""):
            continue
        return spec
    return None


class ListProjector(Projector):
    """Fold NIP-51/NIP-78 events into :class:`ListStore` + compatibility files."""

    name = PROJECTION_NAME
    schema = 1

    def __init__(
        self,
        *,
        store: ListStore | None = None,
        admin_pubkeys: tuple[str, ...] | list[str] = (),
        validate_self_service: Callable[[str, str], bool] | None = None,
        on_change: Callable[[ListEntry], None] | None = None,
        cursor_dir: str | Path = DEFAULT_CURSOR_DIR,
    ) -> None:
        super().__init__(cursor_dir=cursor_dir)
        self.store = store or ListStore()
        self.admin_pubkeys = tuple(a.lower() for a in admin_pubkeys)
        self._validate_self_service = validate_self_service
        self._on_change = on_change

    # -- lifecycle -------------------------------------------------------- #

    def validate(self, event: dict[str, Any]) -> Any:
        spec = _spec_for_event(event)
        if spec is None:
            return None
        coordinate = _d_tag(event)
        author = str(event.get("pubkey") or "").lower()
        if author in self.admin_pubkeys:
            return (spec, coordinate)
        # Not an admin: only permitted where the family allows self-service and
        # the caller is publishing to their own coordinate.
        if not spec.self_service:
            self.quarantine(event, f"{spec.name} is operator-only")
            return None
        # Ownership is family-specific: per-author lists are owned by their
        # author; addressable families encode the owner in the coordinate.
        owns = self._validate_self_service(coordinate or "", author) if self._validate_self_service else spec.owns_event(coordinate, author)
        if spec.subject == "author":
            owns = bool(author)
        if not owns:
            self.quarantine(event, f"{spec.name}: not the owner")
            return None
        return (spec, coordinate)

    def apply(self, event: dict[str, Any]) -> ProjectionResult:
        validated = self.validate(event)
        if validated is None:
            return ProjectionResult(accepted=False, reason="invalid")
        spec, coordinate = validated
        entry = self._fold_event(spec, coordinate, event)
        stored = self.store.put(entry)
        if stored and self._on_change is not None:
            try:
                self._on_change(entry)
            except Exception as exc:  # noqa: BLE001 - keep the projector alive
                self.health_state.last_error = f"render failed: {exc}"
                logger.error("failed to render %s: %s", spec.name, exc)
        self._advance(event)
        return ProjectionResult(accepted=True, changed=stored)

    def _fold_event(self, spec: ListSpec, coordinate: str | None, event: dict[str, Any]) -> ListEntry:
        body: dict[str, Any] = {}
        try:
            parsed = json.loads(event.get("content") or "{}")
            if isinstance(parsed, dict):
                body = parsed
        except (ValueError, TypeError):
            body = {}
        author = str(event.get("pubkey") or "").lower()
        entries = list(dict.fromkeys(_tag_values(event, "p") + _tag_values(event, "r")))
        return ListEntry(
            kind=spec.kind,
            coordinate=coordinate or "",
            key=spec.event_key(coordinate, author),
            entries=entries,
            settings=body,
            public=_is_public(event),
            event_id=str(event.get("id") or ""),
            created_at=int(event.get("created_at") or 0),
            author=author,
        )

    def clone(self) -> "ListProjector":
        import tempfile as _tempfile

        tmp = _tempfile.NamedTemporaryFile(prefix="lists-verify-", suffix=".json", delete=False)
        tmp.close()
        return ListProjector(
            store=ListStore(Path(tmp.name)),
            admin_pubkeys=self.admin_pubkeys,
            validate_self_service=self._validate_self_service,
            on_change=None,
            cursor_dir=str(self.cursor_dir),
        )

    def current(self) -> str:
        return json.dumps(self._digest(), sort_keys=True)

    def render(self, state: Any) -> str | None:
        return json.dumps(self._digest(), sort_keys=True)

    def commit(self, candidate: str) -> None:  # pragma: no cover - store owns the write
        raise NotImplementedError("list projection is written by ListStore.put")

    def _digest(self) -> dict[str, Any]:
        return {
            key: entry.as_dict()
            for key, entry in sorted(self.store._entries.items())
        }


# --------------------------------------------------------------------------- #
# family readers: the merged, effective view


def trusted_publishers(store: ListStore | None = None) -> list[str]:
    """Effective trusted catalogue publisher pubkeys (operator people-set)."""
    spec = spec_for_name("trusted-publishers")
    store = store or ListStore()
    entry = store.get(spec.event_key(spec.d, ""))
    return list(entry.entries) if entry else []


def approved_repositories(store: ListStore | None = None) -> list[str]:
    """Effective approved repository coordinates (operator people-set)."""
    spec = spec_for_name("approved-repositories")
    store = store or ListStore()
    entry = store.get(spec.event_key(spec.d, ""))
    return list(entry.entries) if entry else []


def blocked_relays(store: ListStore | None = None) -> list[str]:
    """Mandatory blocked-relay URLs (NIP-51 10006)."""
    spec = spec_for_name("blocked-relays")
    store = store or ListStore()
    entry = store.get(spec.event_key(None, ""))
    return list(entry.entries) if entry else []


def preferred_relays(author: str | None = None, *, store: ListStore | None = None) -> list[str]:
    """A user's own preferred relays (NIP-65 10002), or all authors' when None."""
    spec = spec_for_name("preferred-relays")
    store = store or ListStore()
    if author is not None:
        entry = store.get_for_author(spec.kind, author)
        return list(entry.entries) if entry else []
    merged: list[str] = []
    for entry in store.entries_for(spec.kind):
        merged.extend(entry.entries)
    return list(dict.fromkeys(merged))


def blocked_site_owners(store: ListStore | None = None) -> list[str]:
    """Mandatory blocked site-owner pubkeys (NIP-51 mute list, kind 10000)."""
    spec = spec_for_name("blocked-site-owners")
    store = store or ListStore()
    entry = store.get(spec.event_key(None, ""))
    return list(entry.entries) if entry else []


def merge_user_relays(
    server_relays: Iterable[str],
    user_relays: Iterable[str],
    *,
    store: ListStore | None = None,
) -> list[str]:
    """Additive relay merge: the server's relay set plus the user's own.

    Never lets a user *remove* a server relay (mandatory destinations stay);
    a blocked relay (operator 10006) is excluded from either side.
    """
    blocked = {url.rstrip("/").casefold() for url in blocked_relays(store)}
    merged = list(dict.fromkeys([*server_relays, *user_relays]))
    return [url for url in merged if url.rstrip("/").casefold() not in blocked]


def portal_settings(store: ListStore | None = None) -> dict[str, Any]:
    """Effective server admin portal settings document (NIP-78)."""
    spec = spec_for_name("portal-settings")
    store = store or ListStore()
    entry = store.get(spec.event_key(spec.d, ""))
    return dict(entry.settings) if entry else {}


def user_preferences(pubkey: str, *, store: ListStore | None = None) -> dict[str, Any]:
    """Effective preferences for ``pubkey``: mandatory restrictions win.

    The merge is field-by-field: a user preference is applied on top of the
    server defaults, then any ``mandatory_restrictions`` key in the server
    portal-settings document is re-applied, so a user can never override a
    server-forced value (e.g. a locked theme or a disabled email edit).
    """
    from .list_specs import user_preferences_coordinate

    store = store or ListStore()
    spec = spec_for_name("user-preferences")
    entry = store.get(spec.event_key(user_preferences_coordinate(pubkey), pubkey))
    prefs = dict(entry.settings) if entry else {}

    server = portal_settings(store)
    mandatory = server.get("mandatory_restrictions")
    if isinstance(mandatory, dict):
        for key, value in mandatory.items():
            prefs[key] = value
        prefs["mandatory"] = sorted(mandatory)
    return prefs


# --------------------------------------------------------------------------- #
# importers: publish signed initial events without changing effective access


def import_trusted_publishers(
    pubkeys: list[str],
    *,
    control_relay: str | None = None,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Publish the current trusted publishers as a signed people-set event."""
    spec = spec_for_name("trusted-publishers")
    return _publish_people_set(spec, pubkeys, control_relay=control_relay, transport=transport)


def import_approved_repositories(
    repositories: list[str],
    *,
    control_relay: str | None = None,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Publish the current approved repositories as a signed people-set event."""
    spec = spec_for_name("approved-repositories")
    return _publish_people_set(spec, repositories, control_relay=control_relay, transport=transport, tag="r")


def _publish_people_set(
    spec: ListSpec,
    values: list[str],
    *,
    control_relay: str | None = None,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
    tag: str = "p",
) -> dict[str, Any]:
    from yunohost.nostr_identity import _operator_config, _sign_event, publish_to_relay

    cfg = _operator_config(None, control_relay)
    tags = [["d", spec.d or ""], *[[tag, value] for value in values]]
    event = _sign_event(cfg.operator_sk, cfg.operator_pubkey, spec.kind, "", tags)
    (transport or publish_to_relay)(cfg.control_relay, event)
    return event


def publish_user_preferences(
    pubkey: str,
    settings: dict[str, Any],
    *,
    signer_sk: str,
    control_relay: str | None = None,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Publish a user's own preferences (kind 30078, self-owned coordinate).

    The caller supplies the *user's* signer key: this is the self-service path,
    so the event is authored by the user, not the operator. The coordinate is
    derived from the signer's own pubkey; a mismatch is refused by the
    publisher so a user can never write another user's preferences.
    """
    from .list_specs import user_preferences_coordinate
    from yunohost.nostr_identity import (
        _is_hex64,
        _operator_config,
        _pubkey,
        _sign_event,
        publish_to_relay,
    )

    if not _is_hex64(signer_sk):
        raise ValueError("signer_sk must be a 64-hex secret key")
    author = _pubkey(signer_sk)
    if author.lower() != str(pubkey).lower():
        raise ValueError("signer key does not match the target pubkey")
    coordinate = user_preferences_coordinate(author.lower())
    cfg = _operator_config(None, control_relay)
    event = _sign_event(signer_sk, author, KIND_APP_DATA, json.dumps(settings), [["d", coordinate]])
    (transport or publish_to_relay)(cfg.control_relay, event)
    return event
