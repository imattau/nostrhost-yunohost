"""Assisted rollback planning and controlled restoration (roadmap §7.5 / Stage B).

Rollback is orchestrated, not a blind ``git revert``: different changes have
different reversibility (see `docs/STATELAYER.md` §8.5 for the change-class
table). The plan generator classifies each semantic change and produces a
machine-readable plan; execution is gated by an explicit approval and runs
*through the operation chain* (the same narrow tool registry the executor
runs), plus Restic restore for data-affecting steps.

    select previous state (default: latest known-good)
          |
          v
    semantic diff (from -> to)
          |
          v
    build_rollback_plan -> change-class aware steps
          |
          v
    policy / approval gate (approve=True / --approve)
          |
          v
    apply_rollback_plan -> controlled execution + re-validation

A plan step is executed automatically only when its reverse action is backed
by a tool in the operation registry and its change class is reversible
without manual intervention. Steps that need a Restic restore are executed
through the provided :class:`ResticClient`. Everything else is reported as
``manual`` and deliberately not executed: repository authority never bypasses
operational authority.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Callable

from .nostr_restic import ResticClient, ResticError
from .nostr_state import StateRepo

ROLLBACK_SCHEMA = 1

# Reversibility vocabulary (STATELAYER.md §8.5 table).
REV_AUTOMATIC = "automatic"
REV_OFTEN = "often"
REV_CONDITIONAL = "conditional"
REV_RESTORE_REQUIRED = "restore-required"
REV_MANUAL = "manual"
REV_IMPOSSIBLE = "impossible"


@dataclass(frozen=True)
class ChangeClass:
    """One row of the change-class table: reversibility + whether the reverse
    may run automatically through the operation chain."""

    name: str
    reversibility: str
    example: str
    automatic: bool
    restore_required: bool = False


CHANGE_CLASSES: dict[str, ChangeClass] = {
    "declarative-config": ChangeClass("declarative-config", REV_AUTOMATIC, "firewall rule, service enabled", True),
    "runtime-setting": ChangeClass("runtime-setting", REV_AUTOMATIC, "systemd unit state", True),
    "package-install": ChangeClass("package-install", REV_OFTEN, "new app", True),
    "package-upgrade": ChangeClass("package-upgrade", REV_CONDITIONAL, "1.4 to 1.5", False),
    "database-migration": ChangeClass("database-migration", REV_MANUAL, "schema change", False),
    "data-deletion": ChangeClass("data-deletion", REV_RESTORE_REQUIRED, "app removal", False, restore_required=True),
    "external-side-effect": ChangeClass("external-side-effect", REV_IMPOSSIBLE, "DNS API, payment, message", False),
    "credential-rotation": ChangeClass("credential-rotation", REV_MANUAL, "replace key", False),
}

# Section -> (default change class, reverse tool). Refined by the diff action
# for the apps/services sections.
_SECTION_REVERSE: dict[str, tuple[str, str | None]] = {
    "system": ("declarative-config", "tools.regenerate_conf"),
    "domains": ("declarative-config", "tools.regenerate_conf"),
    "network": ("declarative-config", "tools.regenerate_conf"),
    "dns": ("external-side-effect", None),
    "certificates": ("declarative-config", "tools.regenerate_conf"),
    "services": ("runtime-setting", "service.control"),
    "apps": ("package-install", "app.remove"),
    "identities": ("credential-rotation", None),
    "capabilities": ("declarative-config", None),
    "backups": ("data-deletion", "backup.restore"),
    "schedules": ("declarative-config", None),
    "package-versions": ("package-upgrade", None),
}


class RollbackError(ValueError):
    """The rollback plan is invalid or cannot be executed as requested."""


def classify_change(section: str, action: str) -> ChangeClass:
    """Classify one semantic change (``action`` in add/modify/delete) into a
    change class, refining the section default where a specific class exists
    (e.g. an app deletion is a data-deletion, not a package install)."""
    base, _tool = _SECTION_REVERSE.get(section, ("declarative-config", None))
    if section == "apps":
        if action == "delete":
            return CHANGE_CLASSES["data-deletion"]
        if action == "modify":
            return CHANGE_CLASSES["package-upgrade"]
        return CHANGE_CLASSES["package-install"]
    if section == "backups":
        return CHANGE_CLASSES["data-deletion"]
    return CHANGE_CLASSES.get(base, CHANGE_CLASSES["declarative-config"])


def _file_id(path: str) -> str:
    """Strip the ``.toml`` suffix from a state file path."""
    return path[:-5] if path.endswith(".toml") else path


def _reverse_step(section: str, action: str, path: str) -> dict[str, Any]:
    """Build one plan step for a semantic change between the from and to
    revisions. ``action`` is add/modify/delete *between from and to*; the
    reverse action undoes it (delete an added file, restore a deleted one)."""
    cls = classify_change(section, action)
    _, tool = _SECTION_REVERSE.get(section, ("declarative-config", None))
    step: dict[str, Any] = {
        "section": section,
        "file": path,
        "action": action,
        "change_class": cls.name,
        "reversibility": cls.reversibility,
        "automatic": cls.automatic,
        "restore_required": cls.restore_required,
        "tool": tool,
        "args": {},
    }
    file_id = _file_id(path.split("/", 1)[-1])
    if section == "apps":
        if action == "add":
            step.update(reverse="remove", tool="app.remove", args={"app": file_id, "purge": True})
        elif action == "delete":
            step.update(reverse="reinstall", tool="app.install", args={"app": file_id}, restore_required=True)
        else:
            step.update(reverse="downgrade", tool="app.upgrade", args={"app": file_id}, restore_required=True)
    elif section == "services":
        step.update(reverse="control", tool="service.control", args={"name": file_id, "action": "restart"})
    elif section in ("system", "domains", "network", "certificates"):
        step["reverse"] = "regenerate"
        step["args"] = {"force": False}
    elif section == "identities":
        step["reverse"] = "manual"
    elif section == "capabilities":
        step["reverse"] = "manual"
    elif section == "backups":
        step.update(reverse="restore", tool="backup.restore", args={}, restore_required=True)
    elif section == "package-versions":
        step["reverse"] = "manual"
    else:
        step["reverse"] = "manual"
    return step


def _manifest_restic(repo: StateRepo, rev: str) -> tuple[str, bool]:
    """Read the restic linkage (snapshot id, required) from a revision's
    manifest. Best-effort: a missing manifest means no linkage."""
    try:
        text = repo.show(rev, "manifest.toml")
    except Exception:  # noqa: BLE001 - no manifest -> no linkage
        return "", False
    import tomllib

    try:
        data = tomllib.loads(text)
        backup = data.get("backup") or {}
        return str(backup.get("restic_snapshot") or ""), bool(backup.get("required"))
    except Exception:  # noqa: BLE001
        return "", False


def build_rollback_plan(
    repo: StateRepo,
    *,
    from_rev: str | None = None,
    to_rev: str | None = None,
    restic_snapshot: str | None = None,
) -> dict[str, Any]:
    """Generate an assisted rollback plan: semantic diff from ``from_rev``
    (default: the latest known-good revision) to ``to_rev`` (default HEAD),
    classified per change class with reversibility and Restic linkage.

    The plan is declarative and never executed implicitly; it must pass the
    approval gate (``apply_rollback_plan``).
    """
    frm = from_rev or repo.known_good_revision()
    if not frm:
        raise RollbackError("no known-good revision to roll back to; mark a state with --known-good first")
    to = to_rev or repo.revision()
    if not to:
        raise RollbackError("no state history yet")
    if frm == to:
        raise RollbackError("from and to revisions are identical; nothing to roll back")

    steps: list[dict[str, Any]] = []
    for status, path in repo.diff_names(frm, to):
        if not path or path == "manifest.toml" or path == "state":
            continue
        action = {"A": "add", "M": "modify", "D": "delete"}.get(status)
        if not action:
            continue
        section = path.split("/", 1)[0]
        steps.append(_reverse_step(section, action, path))

    snapshot, required = _manifest_restic(repo, frm)
    if restic_snapshot and not snapshot:
        snapshot = restic_snapshot

    summary = {
        "total": len(steps),
        "automatic": sum(1 for s in steps if s["automatic"]),
        "manual": sum(1 for s in steps if not s["automatic"] and s["reversibility"] not in (REV_IMPOSSIBLE,)),
        "restore_required": sum(1 for s in steps if s["restore_required"]),
        "impossible": sum(1 for s in steps if s["reversibility"] == REV_IMPOSSIBLE),
    }

    return {
        "schema": ROLLBACK_SCHEMA,
        "generated_at": int(time.time()),
        "from": frm,
        "to": to,
        "restic_snapshot": snapshot,
        "restic_required": bool(required),
        "steps": steps,
        "summary": summary,
        "approved": False,
    }


def render_plan(plan: dict[str, Any]) -> str:
    """Human-readable summary of a rollback plan."""
    s = plan["summary"]
    lines = [
        f"rollback plan: {plan['from'][:16]} -> {plan['to'][:16]}",
        f"  steps: {s['total']}  (automatic {s['automatic']}, manual {s['manual']}, "
        f"restore-required {s['restore_required']}, impossible {s['impossible']})",
        f"  restic snapshot: {plan['restic_snapshot'] or '(none)'}",
    ]
    for step in plan["steps"]:
        lines.append(
            f"  - {step['section']}/{step['file']}  {step['action']} "
            f"[{step['change_class']}/{step['reversibility']}] reverse={step.get('reverse', 'manual')}"
            + (f" tool={step['tool']}" if step.get("tool") else " (manual)")
        )
    return "\n".join(lines)


def apply_rollback_plan(
    plan: dict[str, Any],
    *,
    backend: Any,
    restic: ResticClient | None = None,
    approve: bool = False,
) -> list[dict[str, Any]]:
    """Execute an assisted rollback plan through the operation chain.

    Requires ``approve=True`` (the policy / approval gate; the full path flows
    approval through Nostr policy, this is the bounded local gate). Automatic
    steps run through ``backend.execute(tool, args)`` — the same narrow
    registry the operation engine runs — *only* when the tool exists there.
    Restore-required steps use ``restic.restore`` of the plan's linked
    snapshot. Manual/impossible steps are reported and never executed.

    Returns a per-step execution report.
    """
    if not approve:
        raise RollbackError("rollback plan not approved (pass approve=True / --approve)")
    if not plan.get("steps"):
        raise RollbackError("rollback plan has no steps")
    if plan.get("approved"):
        raise RollbackError("rollback plan already executed")

    report: list[dict[str, Any]] = []
    failures = 0
    for step in plan["steps"]:
        entry: dict[str, Any] = {"step": step, "status": "skipped", "detail": ""}
        try:
            if step["reversibility"] == REV_IMPOSSIBLE:
                entry.update(status="blocked", detail="external side effect; not reversible")
            elif step["restore_required"]:
                if not plan.get("restic_snapshot"):
                    entry.update(status="blocked", detail="restore required but plan has no restic snapshot")
                elif restic is None:
                    entry.update(status="blocked", detail="restore required but no restic client provided")
                else:
                    restic.restore(plan["restic_snapshot"], "/", include=[step["file"]])
                    entry.update(status="restored", detail=f"snapshot {plan['restic_snapshot'][:16]}")
            elif step["automatic"] and step.get("tool"):
                from .nostr_operations import tool_spec

                if tool_spec(step["tool"]) is None:
                    entry.update(status="manual", detail=f"tool {step['tool']} not in the operation registry")
                else:
                    backend.execute(step["tool"], step["args"])
                    entry.update(status="executed", detail=f"{step['tool']} {json.dumps(step['args'], sort_keys=True)}")
            else:
                entry.update(status="manual", detail="requires manual intervention")
        except Exception as exc:  # noqa: BLE001 - a failed step is reported, not fatal
            failures += 1
            entry.update(status="failed", detail=str(exc))
        report.append(entry)

    plan["approved"] = True
    plan["_report"] = report
    plan["_ok"] = failures == 0
    return report


def write_plan(path: str, plan: dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(plan, fh, indent=2, sort_keys=True)
        fh.write("\n")


def read_plan(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)