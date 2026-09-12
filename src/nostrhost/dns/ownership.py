"""DNS zone-state persistence + ownership markers (W4).

NostrHost never assumes it owns a whole DNS zone. Every record NostrHost
created is mirrored here with its ``owner`` (``nostrhost``, ``domain:<id>``
or ``app:<id>``) so reconciliation, drift detection and domain/app removal
are bounded: only records we own are ever mutated.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from .models import DnsRecord


def dns_state_dir(state_dir: Path) -> Path:
    return state_dir / "dns"


def zone_state_path(state_dir: Path, zone: str) -> Path:
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", zone)
    return dns_state_dir(state_dir) / f"{safe}.json"


def load_zone_state(state_dir: Path, zone: str) -> dict[str, Any]:
    """Raw zone state: ``{"zone", "provider", "records": {id: {...}}}``."""
    path = zone_state_path(state_dir, zone)
    if not path.is_file():
        return {"zone": zone, "provider": "manual", "records": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):  # pragma: no cover - defensive
        return {"zone": zone, "provider": "manual", "records": {}}
    if not isinstance(data, dict) or not isinstance(data.get("records"), dict):
        return {"zone": zone, "provider": "manual", "records": {}}
    return data


def save_zone_state(state_dir: Path, zone: str, state: dict[str, Any]) -> None:
    path = zone_state_path(state_dir, zone)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def zone_provider_id(state_dir: Path, zone: str) -> str:
    return str(load_zone_state(state_dir, zone).get("provider", "manual"))


def set_zone_provider(state_dir: Path, zone: str, provider: str) -> None:
    state = load_zone_state(state_dir, zone)
    state["provider"] = provider
    save_zone_state(state_dir, zone, state)


def owned_records(state_dir: Path, zone: str) -> list[DnsRecord]:
    """All records NostrHost created for ``zone`` (any owner)."""
    state = load_zone_state(state_dir, zone)
    records: list[DnsRecord] = []
    for raw in state.get("records", {}).values():
        try:
            records.append(DnsRecord(**raw))
        except Exception:  # noqa: BLE001 - skip broken entries
            continue
    return records


def record_entry(record: DnsRecord) -> dict[str, Any]:
    return record.dict()


def create_record_entry(state_dir: Path, record: DnsRecord) -> str:
    """Add one owned record to the zone state; returns the stable id."""
    state = load_zone_state(state_dir, record.zone)
    record_id = record.fingerprint()
    state.setdefault("records", {})[record_id] = record_entry(record)
    save_zone_state(state_dir, record.zone, state)
    return record_id


def update_record_entry(state_dir: Path, record_id: str, record: DnsRecord) -> None:
    state = load_zone_state(state_dir, record.zone)
    state.setdefault("records", {})[record_id] = record_entry(record)
    save_zone_state(state_dir, record.zone, state)


def delete_record_entry(state_dir: Path, zone: str, record_id: str) -> bool:
    state = load_zone_state(state_dir, zone)
    records = state.get("records", {})
    if record_id in records:
        del records[record_id]
        save_zone_state(state_dir, zone, state)
        return True
    return False


def delete_record_by_provider_id(state_dir: Path, zone: str, provider_id: str) -> bool:
    """Delete the mirror entry whose provider record id matches (used by
    providers whose ids differ from the fingerprint, e.g. Cloudflare)."""
    state = load_zone_state(state_dir, zone)
    records = state.get("records", {})
    for record_id, raw in list(records.items()):
        if isinstance(raw, dict) and raw.get("provider_id") == provider_id:
            del records[record_id]
            save_zone_state(state_dir, zone, state)
            return True
    return False


def owned_record_ids(state_dir: Path, zone: str) -> set[str]:
    return set(load_zone_state(state_dir, zone).get("records", {}).keys())


def record_id_to_record(state_dir: Path, zone: str, record_id: str) -> DnsRecord | None:
    raw = load_zone_state(state_dir, zone).get("records", {}).get(record_id)
    if raw is None:
        return None
    try:
        return DnsRecord(**raw)
    except Exception:  # noqa: BLE001 - defensive
        return None
