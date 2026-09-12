"""Ownership-bounded DNS reconciliation (W4).

Desired state -> provider's actual state -> diff -> DNS plan -> apply ->
verify. Only records NostrHost owns are ever mutated; external records in a
zone are preserved and reported.
"""

from __future__ import annotations

from typing import Any, Protocol

from .models import DnsChange, DnsPlan, DnsRecord


class ProviderLike(Protocol):
    def list_records(self, zone: str) -> list[DnsRecord]:
        ...

    def create_record(self, record: DnsRecord) -> str:
        ...

    def update_record(self, provider_id: str, record: DnsRecord) -> None:
        ...

    def delete_record(self, provider_id: str) -> None:
        ...

    def verify_record(self, record: DnsRecord) -> dict:
        ...


def _index(records: list[DnsRecord]) -> dict[tuple[str, str, str], DnsRecord]:
    return {record.diff_key(): record for record in records}


def _owned(record: DnsRecord) -> bool:
    owner = record.owner or ""
    return owner.startswith(("nostrhost", "domain:", "app:"))


def build_plan(desired: list[DnsRecord], actual: list[DnsRecord]) -> DnsPlan:
    """Diff desired vs actual for one zone.

    Records absent from ``desired`` that NostrHost created (owned) are
    planned for deletion; foreign records are preserved and surfaced.

    ``actual`` entries come from the provider's ``list_records``: providers
    tag the records NostrHost created with their ``owner`` (via the local
    ownership mirror) so external records keep a non-owned owner and are
    never planned for mutation.
    """
    if not desired:
        return DnsPlan(zone="", changes=[], preserved=[])
    zone = desired[0].zone
    actual_index = _index(actual)
    desired_index = _index(desired)

    changes: list[DnsChange] = []
    preserved: list[DnsRecord] = []

    for record in desired:
        current = actual_index.get(record.diff_key())
        if current is None:
            changes.append(DnsChange(action="create", record=record, note="missing on provider"))
        elif current.value != record.value or current.ttl != record.ttl:
            changes.append(DnsChange(action="update", record=record, provider_id=current.provider_id or record.fingerprint(), note="value/ttl differs"))
        else:
            changes.append(DnsChange(action="keep", record=record, provider_id=current.provider_id or record.fingerprint()))

    for record in actual:
        if record.diff_key() in desired_index:
            continue
        if _owned(record):
            changes.append(DnsChange(action="delete", record=record, provider_id=record.provider_id or record.fingerprint(), note="no longer desired"))
        else:
            preserved.append(record)

    return DnsPlan(zone=zone, changes=changes, preserved=preserved)


def apply_plan(plan: DnsPlan, provider: ProviderLike) -> list[dict[str, Any]]:
    """Execute the plan; returns per-change results."""
    results: list[dict[str, Any]] = []
    for change in plan.changes:
        if change.action == "create":
            provider_id = provider.create_record(change.record)
            results.append({"action": "create", "record": change.record.fingerprint(), "provider_id": provider_id})
        elif change.action == "update":
            if change.provider_id is None:
                results.append({"action": "update", "record": change.record.fingerprint(), "error": "no provider record id"})
                continue
            provider.update_record(change.provider_id, change.record)
            results.append({"action": "update", "record": change.record.fingerprint(), "provider_id": change.provider_id})
        elif change.action == "delete":
            if change.provider_id is None:
                results.append({"action": "delete", "record": change.record.fingerprint(), "error": "no provider record id"})
                continue
            provider.delete_record(change.provider_id)
            results.append({"action": "delete", "record": change.record.fingerprint(), "provider_id": change.provider_id})
        else:
            results.append({"action": "keep", "record": change.record.fingerprint()})
    return results


def verify_plan(records: list[DnsRecord], provider: ProviderLike) -> list[dict[str, Any]]:
    """Best-effort resolution check for each record."""
    return [provider.verify_record(record) for record in records]
