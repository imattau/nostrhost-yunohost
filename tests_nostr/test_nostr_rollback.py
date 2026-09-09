"""Stage B tests: change-class aware rollback plan generation and its
approval-gated, registry-bounded execution, against a temp git state repo.

The plan never executes by itself: an unapproved plan is rejected, automatic
steps only run when their reverse tool is in the operation registry, restore
steps go through a Restic client, and manual/impossible steps are reported
rather than executed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from yunohost.nostr_operations import tool_spec
from yunohost.nostr_restic import ResticClient, ResticError
from yunohost.nostr_rollback import (
    REV_IMPOSSIBLE,
    REV_RESTORE_REQUIRED,
    RollbackError,
    apply_rollback_plan,
    build_rollback_plan,
    classify_change,
    render_plan,
    write_plan,
    read_plan,
)
from yunohost.nostr_state import StateRepo, export_state


class FakeBackend:
    """The state export backend for snapshots (stable, readable data)."""

    def hostname(self) -> str:
        return "testhost"

    def os(self) -> dict:
        return {"machine": "x86_64", "release": "6.1.0"}

    def settings(self) -> dict:
        return {"security.root_access": "restricted"}

    def domains(self) -> dict:
        return {"nostrhost.test": {"main": True, "apps": []}}

    def apps(self) -> dict:
        return {"hello_nostr_ynh": {"label": "Hello", "version": "1.0.0~ynh1", "domain": "nostrhost.test", "path": "/hello", "status": "running"}}

    def services(self) -> dict:
        return {"dnsmasq": {"status": "running", "type": "system"}}

    def users(self) -> dict:
        return {"matt": {"fullname": "Matt", "groups": ["all_users", "admins"]}}

    def packages(self) -> dict:
        return {"yunohost": "12.1.41.2", "python3": "3.11"}


class ExecBackend:
    """Records tool executions like the operation engine's backend."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def execute(self, tool: str, args: dict) -> dict:
        self.calls.append((tool, args))
        return {"ok": tool}


def _seed_repo(tmp_path: Path) -> tuple[StateRepo, dict]:
    repo = StateRepo(tmp_path / "state", "a" * 64)
    good = export_state(FakeBackend())
    repo.commit(good, op_event_id="k" * 64, phase="post", known_good=True, health="passed", restic_snapshot="R1234" + "b" * 60, required=True)
    return repo, good


def test_classify_change_table():
    assert classify_change("services", "modify").name == "runtime-setting"
    assert classify_change("apps", "add").name == "package-install"
    assert classify_change("apps", "modify").name == "package-upgrade"
    assert classify_change("apps", "delete").reversibility == REV_RESTORE_REQUIRED
    assert classify_change("backups", "delete").reversibility == REV_RESTORE_REQUIRED
    assert classify_change("dns", "modify").reversibility == REV_IMPOSSIBLE
    assert classify_change("identities", "modify").name == "credential-rotation"
    assert classify_change("system", "modify").reversibility == "automatic"


def test_build_plan_from_known_good(tmp_path: Path):
    repo, good = _seed_repo(tmp_path)
    changed = dict(good)
    changed["services"] = {"dnsmasq.toml": {"status": "dead", "type": "system"}}
    changed["apps"] = dict(good["apps"])
    changed["apps"]["new_app_ynh.toml"] = {"label": "New", "version": "1.0", "status": "running"}
    repo.commit(changed, op_event_id="c" * 64, phase="post", known_good=False, health="failed")

    plan = build_rollback_plan(repo)
    assert plan["from"] == repo.known_good_revision()
    assert plan["to"] == repo.revision()
    assert plan["restic_snapshot"].startswith("R1234")  # linked from the known-good manifest
    steps = {s["section"]: s for s in plan["steps"]}
    assert steps["services"]["change_class"] == "runtime-setting"
    assert steps["services"]["reversibility"] == "automatic"
    assert steps["apps"]["file"].endswith("new_app_ynh.toml")
    assert steps["apps"]["change_class"] == "package-install"
    assert plan["summary"]["total"] == 2


def test_build_plan_requires_known_good(tmp_path: Path):
    repo = StateRepo(tmp_path / "state", "a" * 64)
    repo.commit(export_state(FakeBackend()), op_event_id="x" * 64, phase="post", health="failed")
    with pytest.raises(RollbackError, match="no known-good"):
        build_rollback_plan(repo)


def test_build_plan_identical_revisions(tmp_path: Path):
    repo, _ = _seed_repo(tmp_path)
    with pytest.raises(RollbackError, match="identical"):
        build_rollback_plan(repo)


def test_app_delete_is_restore_required(tmp_path: Path):
    repo, good = _seed_repo(tmp_path)
    changed = dict(good)
    changed["apps"] = {}  # app removed since known-good
    repo.commit(changed, op_event_id="d" * 64, phase="post", known_good=False, health="failed")
    plan = build_rollback_plan(repo)
    assert len(plan["steps"]) == 1
    step = plan["steps"][0]
    assert step["section"] == "apps"
    assert step["action"] == "delete"
    assert step["change_class"] == "data-deletion"
    assert step["restore_required"] is True
    assert plan["summary"]["restore_required"] == 1


def test_apply_requires_approval(tmp_path: Path):
    repo, good = _seed_repo(tmp_path)
    changed = dict(good)
    changed["services"] = {"dnsmasq.toml": {"status": "dead", "type": "system"}}
    repo.commit(changed, op_event_id="e" * 64, phase="post", health="failed")
    plan = build_rollback_plan(repo)
    with pytest.raises(RollbackError, match="not approved"):
        apply_rollback_plan(plan, backend=ExecBackend())


def test_apply_executes_registry_tools_and_marks_unknown_manual(tmp_path: Path):
    repo, good = _seed_repo(tmp_path)
    changed = dict(good)
    changed["services"] = {"dnsmasq.toml": {"status": "dead", "type": "system"}}
    changed["apps"] = dict(good["apps"])
    changed["apps"]["new_app_ynh.toml"] = {"label": "New", "version": "1.0", "status": "running"}
    changed["identities"] = {"matt.toml": {"fullname": "Matt2", "groups": ["all_users", "admins"]}}
    repo.commit(changed, op_event_id="f" * 64, phase="post", health="failed")
    plan = build_rollback_plan(repo)

    assert tool_spec("service.control") is not None   # registry-backed -> auto
    assert tool_spec("app.remove") is not None         # registry-backed -> auto
    backend = ExecBackend()
    report = apply_rollback_plan(plan, backend=backend, approve=True)

    by_section = {e["step"]["section"]: e for e in report}
    assert by_section["services"]["status"] == "executed"
    assert by_section["apps"]["status"] == "executed"
    assert by_section["identities"]["status"] == "manual"  # credential-rotation, no tool
    executed_tools = [c[0] for c in backend.calls]
    assert "service.control" in executed_tools and "app.remove" in executed_tools
    assert plan["approved"] is True and plan["_ok"] is True


def test_apply_restore_step_blocked_without_restic(tmp_path: Path):
    repo, good = _seed_repo(tmp_path)
    changed = dict(good)
    changed["apps"] = {}
    repo.commit(changed, op_event_id="g" * 64, phase="post", health="failed")
    plan = build_rollback_plan(repo)
    assert plan["steps"][0]["restore_required"] is True
    report = apply_rollback_plan(plan, backend=ExecBackend(), restic=None, approve=True)
    assert report[0]["status"] == "blocked"


def test_apply_restore_step_uses_restic(tmp_path: Path):
    import textwrap

    fake = tmp_path / "restic"
    fake.write_text(
        textwrap.dedent(
            '''#!/usr/bin/env python3
import json, os, sys
if os.environ.get("RESTIC_PASSWORD") != "sekret-pass":
    sys.exit(9)
sid = next(a for a in sys.argv[1:] if not a.startswith("-"))
print(json.dumps({"message_type": "summary", "files_restored": 1, "snapshot_id": sid}))
'''
        )
    )
    fake.chmod(0o755)

    repo, good = _seed_repo(tmp_path)
    changed = dict(good)
    changed["apps"] = {}
    repo.commit(changed, op_event_id="h" * 64, phase="post", health="failed")
    plan = build_rollback_plan(repo)

    restic = ResticClient(repo="x", password="sekret-pass", binary=str(fake))
    report = apply_rollback_plan(plan, backend=ExecBackend(), restic=restic, approve=True)
    assert report[0]["status"] == "restored"
    assert "snapshot" in report[0]["detail"]


def test_apply_no_steps_raises(tmp_path: Path):
    with pytest.raises(RollbackError, match="no steps"):
        apply_rollback_plan({"steps": [], "approved": False}, backend=ExecBackend(), approve=True)


def test_plan_roundtrip_file(tmp_path: Path):
    repo, good = _seed_repo(tmp_path)
    changed = dict(good)
    changed["services"] = {"dnsmasq.toml": {"status": "dead", "type": "system"}}
    repo.commit(changed, op_event_id="i" * 64, phase="post", health="failed")
    plan = build_rollback_plan(repo)
    path = tmp_path / "plan.json"
    write_plan(path, plan)
    reloaded = read_plan(path)
    assert reloaded == plan
    assert "rollback plan" in render_plan(plan)


def test_render_plan_human_readable(tmp_path: Path):
    repo, good = _seed_repo(tmp_path)
    changed = dict(good)
    changed["dns"] = {"external.toml": {"provider": "cloudflare"}}
    repo.commit(changed, op_event_id="j" * 64, phase="post", health="failed")
    plan = build_rollback_plan(repo)
    text = render_plan(plan)
    assert "external-side-effect" in text
    assert plan["summary"]["impossible"] == 1