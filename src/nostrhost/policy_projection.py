"""Kind-31101 policy projection (WP6).

WP6 migrates the host's small non-secret policy documents onto signed,
addressable kind-31101 declarations (``d = nostrhost:<family>``), keeping the
on-disk files the existing services read as *rendered compatibility outputs*
the projector writes — exactly like WP4's list projection does for
``lists.json`` + the portal files.

Families (see :mod:`nostrhost.policy_specs`):

* ``notification-rules`` → renders the Go notify daemon's ``recipients.toml``
  and ``policy.toml`` inputs, so NIP-17/NIP-59 delivery keeps working
  unchanged;
* ``restic-policy`` → renders the desired ``paths``/``retention``/``schedule``
  into the root-only ``/etc/nostrhost/restic.toml``, *preserving* the secret
  ``repo`` + ``password`` fields verbatim;
* ``host-policy`` → renders ``/etc/nostrhost/policy.toml`` (the non-secret
  operation-safeguard overrides the policy library evaluates).

The secret-first invariant is structural: a policy document carries only
desired, non-secret state. No event fixture, relay query or rendered file
introduces a credential.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from yunohost.nostr_projector import (
    DEFAULT_CURSOR_DIR,
    Projector,
    ProjectionResult,
)

from nostrhost.events import _d_tag
from nostrhost.policy_specs import (
    HOST_POLICY,
    KIND_TRUST_POLICY,
    NOTIFICATION_RULES,
    RESTIC_POLICY,
    PolicySpec,
    spec_for_coordinate,
    spec_for_name,
)

logger = logging.getLogger("nostr-policy-projection")

DEFAULT_POLICY_STORE = Path("/etc/nostrhost/policy-projection.json")
PROJECTION_NAME = "policy"
#: Every kind this projection consumes.
POLICY_KINDS = (KIND_TRUST_POLICY,)

#: Default render targets (overridable through env for tests).
NOTIFY_RECIPIENTS_PATH = os.environ.get(
    "NOSTRHOST_NOTIFY_RECIPIENTS",
    str(Path(os.environ.get("NOSTRHOST_NOTIFY_STATE_DIR", "/var/lib/nostrhost/state/notifications")) / "recipients.toml"),
)
NOTIFY_POLICY_PATH = os.environ.get(
    "NOSTRHOST_NOTIFY_POLICY",
    str(Path(os.environ.get("NOSTRHOST_NOTIFY_STATE_DIR", "/var/lib/nostrhost/state/notifications")) / "policy.toml"),
)
RESTIC_CONFIG_PATH = os.environ.get("NOSTRHOST_RESTIC_CONFIG", "/etc/nostrhost/restic.toml")
HOST_POLICY_PATH = os.environ.get("NOSTRHOST_POLICY_FILE", "/etc/nostrhost/policy.toml")


@dataclass
class PolicyEntry:
    """One folded policy coordinate: the document's value + envelope."""

    coordinate: str
    key: str
    value: dict[str, Any] = field(default_factory=dict)
    schema: int = 1
    revision: int = 0
    enabled: bool = True
    event_id: str = ""
    created_at: int = 0
    author: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "coordinate": self.coordinate,
            "key": self.key,
            "value": dict(self.value),
            "schema": self.schema,
            "revision": self.revision,
            "enabled": bool(self.enabled),
            "event_id": self.event_id,
            "created_at": self.created_at,
            "author": self.author,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "PolicyEntry":
        return cls(
            coordinate=str(raw.get("coordinate") or ""),
            key=str(raw.get("key") or raw.get("coordinate") or ""),
            value=dict(raw.get("value") or {}),
            schema=int(raw.get("schema") or 1),
            revision=int(raw.get("revision") or 0),
            enabled=bool(raw.get("enabled", True)),
            event_id=str(raw.get("event_id") or ""),
            created_at=int(raw.get("created_at") or 0),
            author=str(raw.get("author") or ""),
        )


class PolicyStore:
    """Atomic JSON persistence for folded policy coordinates."""

    def __init__(self, path: Path = DEFAULT_POLICY_STORE) -> None:
        self.path = Path(path)
        self._entries: dict[str, PolicyEntry] = {}
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return
        for key, info in (raw or {}).items():
            try:
                self._entries[key] = PolicyEntry.from_dict(info)
            except (TypeError, ValueError):
                logger.warning("ignoring malformed stored policy entry %s", key)

    def _save(self) -> None:
        payload = {key: entry.as_dict() for key, entry in self._entries.items()}
        data = json.dumps(payload, indent=1, sort_keys=True).encode() + b"\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=".policy-")
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def get(self, key: str) -> PolicyEntry | None:
        return self._entries.get(key)

    def get_by_coordinate(self, coordinate: str) -> PolicyEntry | None:
        return self._entries.get(f"{KIND_TRUST_POLICY}:{coordinate}")

    def put(self, entry: PolicyEntry) -> bool:
        existing = self._entries.get(entry.key)
        # Addressable document: greatest revision wins; equal revisions are
        # tie-broken by (created_at, event_id) per the WP1 event protocol.
        if existing is not None:
            if entry.revision < existing.revision:
                return False
            if entry.revision == existing.revision:
                if (entry.created_at, entry.event_id) <= (existing.created_at, existing.event_id):
                    return False
        if not entry.enabled:
            # An explicit revoke removes the document's effective state.
            self._entries[entry.key] = PolicyEntry(
                coordinate=entry.coordinate,
                key=entry.key,
                value={},
                enabled=False,
                event_id=entry.event_id,
                created_at=entry.created_at,
                author=entry.author,
            )
        else:
            self._entries[entry.key] = entry
        self._save()
        return True

    def all_entries(self) -> list[PolicyEntry]:
        return list(self._entries.values())

    def enabled_entries(self) -> list[PolicyEntry]:
        return [entry for entry in self._entries.values() if entry.enabled]


def _parse_body(event: dict[str, Any]) -> tuple[dict[str, Any], int, int, bool]:
    """Extract the 31101 envelope from the event content.

    Returns ``(value, schema, revision, enabled)``. A missing schema is a
    validation error per the event protocol; a malformed body is quarantined
    by the projector (never folded).
    """
    try:
        parsed = json.loads(event.get("content") or "{}")
    except (ValueError, TypeError):
        raise ValueError("policy content is not valid JSON") from None
    if not isinstance(parsed, dict):
        raise ValueError("policy content must be a JSON object")
    schema = int(parsed.get("schema") or 0)
    if schema < 1:
        raise ValueError("31101 must carry an envelope 'schema'")
    value = parsed.get("value")
    if not isinstance(value, dict):
        raise ValueError("31101 envelope 'value' must be an object")
    revision = int(parsed.get("revision") or 0)
    enabled = bool(parsed.get("enabled", True))
    return value, schema, revision, enabled


class PolicyProjector(Projector):
    """Fold kind-31101 declarations into :class:`PolicyStore` + rendered files."""

    name = PROJECTION_NAME
    schema = 1

    def __init__(
        self,
        *,
        store: PolicyStore | None = None,
        admin_pubkeys: tuple[str, ...] | list[str] = (),
        on_change: Callable[[PolicyEntry], None] | None = None,
        cursor_dir: str | Path = DEFAULT_CURSOR_DIR,
    ) -> None:
        super().__init__(cursor_dir=cursor_dir)
        self.store = store or PolicyStore()
        self.admin_pubkeys = tuple(a.lower() for a in admin_pubkeys)
        self._on_change = on_change

    # -- lifecycle -------------------------------------------------------- #

    def validate(self, event: dict[str, Any]) -> Any:
        spec = spec_for_coordinate(_d_tag(event))
        if spec is None:
            return None
        author = str(event.get("pubkey") or "").lower()
        if author in self.admin_pubkeys:
            return spec
        self.quarantine(event, f"{spec.name} is operator-only")
        return None

    def apply(self, event: dict[str, Any]) -> ProjectionResult:
        validated = self.validate(event)
        if validated is None:
            return ProjectionResult(accepted=False, reason="invalid")
        spec = validated
        try:
            value, schema, revision, enabled = _parse_body(event)
        except ValueError as exc:
            self.quarantine(event, str(exc))
            return ProjectionResult(accepted=False, reason="invalid")
        coordinate = _d_tag(event) or ""
        author = str(event.get("pubkey") or "").lower()
        entry = PolicyEntry(
            coordinate=coordinate,
            key=spec.event_key(coordinate),
            value=value,
            schema=schema,
            revision=revision,
            enabled=enabled,
            event_id=str(event.get("id") or ""),
            created_at=int(event.get("created_at") or 0),
            author=author,
        )
        stored = self.store.put(entry)
        if stored and self._on_change is not None:
            try:
                self._on_change(entry)
            except Exception as exc:  # noqa: BLE001 - keep the projector alive
                self.health_state.last_error = f"render failed: {exc}"
                logger.error("failed to render %s: %s", spec.name, exc)
        self._advance(event)
        return ProjectionResult(accepted=True, changed=stored)

    def clone(self) -> "PolicyProjector":
        import tempfile as _tempfile

        tmp = _tempfile.NamedTemporaryFile(prefix="policy-verify-", suffix=".json", delete=False)
        tmp.close()
        return PolicyProjector(
            store=PolicyStore(Path(tmp.name)),
            admin_pubkeys=self.admin_pubkeys,
            on_change=None,
            cursor_dir=str(self.cursor_dir),
        )

    def current(self) -> str:
        return json.dumps(self._digest(), sort_keys=True)

    def render(self, state: Any) -> str | None:
        return json.dumps(self._digest(), sort_keys=True)

    def commit(self, candidate: str) -> None:  # pragma: no cover - store owns the write
        raise NotImplementedError("policy projection is written by PolicyStore.put")

    def _digest(self) -> dict[str, Any]:
        return {
            key: entry.as_dict()
            for key, entry in sorted(self.store._entries.items())
        }


# --------------------------------------------------------------------------- #
# family readers: the effective, folded view


def notification_rules(store: PolicyStore | None = None) -> dict[str, Any]:
    """Effective notification recipients + rules document (folded 31101)."""
    spec = spec_for_name(NOTIFICATION_RULES)
    store = store or PolicyStore()
    entry = store.get(spec.event_key(spec.d))
    return dict(entry.value) if entry else {}


def restic_policy(store: PolicyStore | None = None) -> dict[str, Any]:
    """Desired Restic schedule/retention/paths (never the secret repo/password)."""
    spec = spec_for_name(RESTIC_POLICY)
    store = store or PolicyStore()
    entry = store.get(spec.event_key(spec.d))
    return dict(entry.value) if entry else {}


def host_policy(store: PolicyStore | None = None) -> dict[str, Any]:
    """Effective host operation-safeguard overrides (folded 31101)."""
    spec = spec_for_name(HOST_POLICY)
    store = store or PolicyStore()
    entry = store.get(spec.event_key(spec.d))
    return dict(entry.value) if entry else {}


# --------------------------------------------------------------------------- #
# renderers: write the compatibility files the existing services read


def render_notification_files(entry: PolicyEntry) -> dict[str, Any]:
    """Write recipients.toml + policy.toml for the Go notify daemon."""
    value = entry.value or {}
    recipients = value.get("recipients") or []
    rules = value.get("rules") or []

    recipients_lines = ["# notification recipients (rendered from kind-31101 notification-rules)\n"]
    for item in recipients:
        if not isinstance(item, dict):
            continue
        npub = str(item.get("npub") or "")
        if not npub:
            continue
        recipients_lines.append("\n[[recipient]]\n")
        recipients_lines.append(f'npub = "{npub}"\n')
        recipients_lines.append(f'role = "{item.get("role") or "admin"}"\n')

    policy_lines = ["# notification policy (rendered from kind-31101 notification-rules)\n"]
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        recipient = str(rule.get("recipient") or "")
        if not recipient:
            continue
        classes = rule.get("classes") or ["approval", "operation", "security", "backup"]
        classes = ", ".join(f'"{c}"' for c in classes)
        policy_lines.append("\n[[rule]]\n")
        policy_lines.append(f'recipient = "{recipient}"\n')
        policy_lines.append(f"classes = [{classes}]\n")
        policy_lines.append(f'severity_min = "{rule.get("severity_min") or "warning"}"\n')
        policy_lines.append(f'delivery = "{rule.get("delivery") or "immediate"}"\n')
        policy_lines.append(f'scope = "{rule.get("scope") or "external"}"\n')

    recipients_path = Path(NOTIFY_RECIPIENTS_PATH)
    policy_path = Path(NOTIFY_POLICY_PATH)
    _atomic_write(recipients_path, "".join(recipients_lines))
    _atomic_write(policy_path, "".join(policy_lines))
    return {"recipients": str(recipients_path), "policy": str(policy_path)}


def render_restic_desired(entry: PolicyEntry) -> dict[str, Any]:
    """Merge desired paths/retention/schedule into restic.toml, preserving
    the secret repo + password verbatim."""
    value = entry.value or {}
    path = Path(RESTIC_CONFIG_PATH)
    if not path.exists():
        return {"written": False, "reason": "restic.toml missing (backup not configured)"}
    with path.open("rb") as fh:
        try:
            conf = tomllib.load(fh)
        except tomllib.TOMLDecodeError as exc:  # pragma: no cover - guarded
            return {"written": False, "reason": f"restic.toml invalid: {exc}"}

    conf["paths"] = [str(p) for p in (value.get("paths") or [])]
    retention = value.get("retention")
    if isinstance(retention, dict):
        conf["retention"] = {str(k): int(v) for k, v in retention.items()}
    schedule = value.get("schedule")
    if isinstance(schedule, dict):
        conf["schedule"] = {
            "enabled": bool(schedule.get("enabled", False)),
            "calendar": str(schedule.get("calendar") or "daily"),
        }
    # Secrets are preserved because they are never read from the document;
    # they simply stay in the existing TOML table and are re-serialised.
    import tomli_w

    _atomic_write(path, tomli_w.dumps(conf))
    return {"written": True}


def render_host_policy(entry: PolicyEntry) -> dict[str, Any]:
    """Write /etc/nostrhost/policy.toml from the folded safeguards."""
    value = entry.value or {}
    overrides = value.get("policy")
    if not isinstance(overrides, dict) or not overrides:
        return {"written": False, "reason": "host-policy document carries no [policy.*] overrides"}
    lines = ["# host operation safeguards (rendered from kind-31101 host-policy)\n"]
    for key, rule in overrides.items():
        if not isinstance(rule, dict):
            continue
        lines.append(f"\n[policy.{key}]\n")
        for toml_key, candidate in rule.items():
            if toml_key not in ("require_confirmation", "require_backup", "require_owner_signature"):
                continue
            lines.append(f"{toml_key} = {str(bool(candidate)).lower()}\n")
        if "minimum_free_space" in rule:
            lines.append(f'minimum_free_space = "{rule["minimum_free_space"]}"\n')
        if "max_backup_age" in rule:
            lines.append(f'max_backup_age = "{rule["max_backup_age"]}"\n')
    path = Path(HOST_POLICY_PATH)
    _atomic_write(path, "".join(lines))
    return {"written": True}


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".policy-render-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def render_entry(entry: PolicyEntry) -> dict[str, Any] | None:
    """Dispatch a folded entry to its family renderer."""
    spec = spec_for_coordinate(entry.coordinate)
    if spec is None or spec.renderer is None:
        return None
    try:
        if spec.renderer == "notify":
            return render_notification_files(entry)
        if spec.renderer == "restic":
            return render_restic_desired(entry)
        if spec.renderer == "host-policy":
            return render_host_policy(entry)
    except Exception as exc:  # noqa: BLE001 - a render failure must not kill the loop
        logger.error("policy render %s failed: %s", spec.name, exc)
        raise
    return None


# --------------------------------------------------------------------------- #
# importers: publish signed initial documents without changing effective state


def publish_policy_document(
    spec: PolicySpec,
    value: dict[str, Any],
    *,
    control_relay: str | None = None,
    revision: int = 1,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Publish a signed kind-31101 document for ``spec`` (operator-authored).

    The envelope carries ``schema`` (required for 31101), ``revision`` and the
    ``value`` object — the shape the event protocol freezes.
    """
    from yunohost.nostr_identity import _operator_config, _sign_event, publish_to_relay

    cfg = _operator_config(None, control_relay)
    content = json.dumps({"schema": spec.schema, "revision": revision, "value": value}, sort_keys=True)
    event = _sign_event(cfg.operator_sk, cfg.operator_pubkey, KIND_TRUST_POLICY, content, [["d", spec.d]])
    (transport or publish_to_relay)(cfg.control_relay, event)
    return event


def import_notification_rules(
    recipients: list[dict[str, Any]],
    rules: list[dict[str, Any]],
    *,
    control_relay: str | None = None,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Publish the current notify recipients/policy as a signed document."""
    return publish_policy_document(
        spec_for_name(NOTIFICATION_RULES),
        {"recipients": recipients, "rules": rules},
        control_relay=control_relay,
        transport=transport,
    )


def import_restic_policy(
    paths: list[str],
    retention: dict[str, int],
    schedule: dict[str, Any],
    *,
    control_relay: str | None = None,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Publish the current desired Restic schedule/retention/paths."""
    return publish_policy_document(
        spec_for_name(RESTIC_POLICY),
        {"paths": paths, "retention": retention, "schedule": schedule},
        control_relay=control_relay,
        transport=transport,
    )


def import_host_policy(
    overrides: dict[str, dict[str, Any]],
    *,
    control_relay: str | None = None,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Publish the current host-policy overrides as a signed document."""
    return publish_policy_document(
        spec_for_name(HOST_POLICY),
        {"policy": overrides},
        control_relay=control_relay,
        transport=transport,
    )
