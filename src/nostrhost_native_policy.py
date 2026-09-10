"""Adapter from native resource-engine plans to the shared host policy.

The policy library stays framework-free; this module is the YunoHost-plane
adapter that supplies free-space and backup facts and turns a package plan
into the corresponding policy tier.  Importing the daemon must still work on
older installations where the optional policy library is not installed.
"""

from __future__ import annotations

import os
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable


def _native_policy_key(tool: str, args: dict[str, Any]) -> str:
    if tool == "backup.restore":
        return "backups.restore"
    if tool == "package.reconcile":
        plan = args.get("plan")
        operations = plan.get("operations", []) if isinstance(plan, dict) else plan or []
        names = {str(op.get("name", "")) for op in operations if isinstance(op, dict)}
        if any(name.endswith(".remove") or name == "package.remove" for name in names):
            return "apps.remove"
        return "apps.upgrade"
    return tool


def _backup_created_at() -> dict[str, float]:
    try:
        from .backup import backup_list

        archives = backup_list(with_info=True).get("archives", {})
    except Exception:
        return {}
    result: dict[str, float] = {}
    for name, info in archives.items():
        if not isinstance(info, dict):
            continue
        created_at = info.get("created_at")
        if isinstance(created_at, datetime):
            result[str(name)] = created_at.timestamp()
        elif isinstance(created_at, (int, float)):
            result[str(name)] = float(created_at)
        elif isinstance(created_at, str):
            try:
                result[str(name)] = datetime.fromisoformat(created_at).timestamp()
            except ValueError:
                continue
    return result


class NativePolicyAdapter:
    """Callable policy bridge used by :class:`OperationEngine`.

    ``rules``, ``free_bytes`` and ``backup_created_at`` are injectable so the
    hard checks remain deterministic in tests and do not require YunoHost.
    """

    def __init__(
        self,
        rules: dict[str, Any],
        *,
        free_bytes: Callable[[], int] | None = None,
        backup_created_at: Callable[[], dict[str, float]] | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.rules = rules
        self.free_bytes = free_bytes or (lambda: shutil.disk_usage("/").free)
        self.backup_created_at = backup_created_at or _backup_created_at
        self.now = now

    def __call__(self, tool: str, args: dict[str, Any], actor: str) -> dict[str, Any]:
        del actor  # retained in the engine callback contract for audit context
        key = _native_policy_key(tool, args)
        rule = self.rules.get(key)
        if rule is None:
            return {"allow": True, "policy_key": key}

        from nostrhost_policy.policy.rules import check_free_space, check_recent_backup

        check_free_space(rule, free_bytes=self.free_bytes())
        check_recent_backup(rule, archive_created_at=self.backup_created_at(), now=self.now())
        return {
            "allow": True,
            "policy_key": key,
            "require_confirmation": bool(rule.require_confirmation),
            "owner_signature_required": bool(rule.require_owner_signature),
        }


def build_native_policy_adapter() -> NativePolicyAdapter | None:
    """Load the installed shared policy rules, if this host has them."""
    try:
        from nostrhost_policy.policy.rules import load_policy

        path = Path(os.environ.get("NOSTRHOST_POLICY_FILE", "/etc/nostrhost/policy.toml"))
        return NativePolicyAdapter(load_policy(path))
    except ImportError:
        return None
