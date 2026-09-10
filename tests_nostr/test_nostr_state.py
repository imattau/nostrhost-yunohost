"""Stage A tests: semantic state export, the git-backed state repository, the
executor's automatic pre/post snapshots, and the NIP-34 repository
announcement.

Uses a fake Backend (no live server) and a real git repository under tmp_path
(git is a build/run-time dependency of the state layer).
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from yunohost.nostr_state import (
    DATA_AFFECTING_TOOLS,
    STATE_SCHEMA,
    StateRecorder,
    StateRepo,
    StateError,
    apply_reconciliation_plan,
    build_repository_announcement,
    export_state,
    state_dir_from_env,
)
from yunohost.nostr_operations import build_approval, build_capability, build_operation_request
from yunohost.nostr_operations_state import OpState
from yunohost.nostr_operationsd import OperationEngine


class FakeBackend:
    """Minimal Backend surface with stable, readable data."""

    def hostname(self) -> str:
        return "testhost"

    def os(self) -> dict:
        return {"machine": "x86_64", "release": "6.1.0"}

    def settings(self) -> dict:
        return {"security.root_access": "restricted"}

    def domains(self) -> dict:
        return {"nostrhost.test": {"main": True, "apps": []}, "extra.test": {"main": False, "apps": []}}

    def apps(self) -> dict:
        return {"hello_nostr_ynh": {"label": "Hello Nostr", "version": "1.0.0~ynh1", "domain": "nostrhost.test", "path": "/hello", "status": "running"}}

    def services(self) -> dict:
        return {"dnsmasq": {"status": "running", "type": "system"}}

    def certificates(self) -> dict:
        return {"nostrhost.test": {"CA_type": "letsencrypt", "validity_days": 60, "summary": "letsencrypt"}}

    def users(self) -> dict:
        return {"matt": {"fullname": "Matt", "groups": ["all_users", "admins"]}}

    def packages(self) -> dict:
        return {"yunohost": "12.1.41.2", "python3": "3.11"}


def test_export_state_renders_semantic_tree():
    tree = export_state(FakeBackend(), capabilities={"abc" * 21 + "a": ["server.read"]})
    assert tree["system"]["host.toml"]["hostname"] == "testhost"
    assert tree["domains"]["nostrhost.test.toml"]["main"] is True
    assert tree["apps"]["hello_nostr_ynh.toml"]["version"] == "1.0.0~ynh1"
    assert tree["services"]["dnsmasq.toml"]["status"] == "running"
    assert tree["certificates"]["nostrhost.test.toml"]["summary"] == "letsencrypt"
    assert tree["identities"]["matt.toml"]["groups"] == ["all_users", "admins"]
    assert tree["package-versions"]["versions.toml"]["yunohost"] == "12.1.41.2"
    caps = tree["capabilities"]
    assert list(caps) == ["abc" * 21 + "a.toml"]
    assert caps["abc" * 21 + "a.toml"]["scopes"] == ["server.read"]
    # no capabilities argument -> section omitted (never fabricated)
    assert "capabilities" not in export_state(FakeBackend())


def test_state_repo_commit_history_known_good_and_diff(tmp_path: Path):
    repo = StateRepo(tmp_path / "state", "a" * 64)
    tree = export_state(FakeBackend())

    first = repo.commit(tree, op_event_id="e" * 64, phase="pre", health="pending", plan_sha256="p" * 64)
    second = repo.commit(tree, op_event_id="e" * 64, phase="post", known_good=True, health="passed")

    assert first != second
    assert repo.revision() == second
    assert repo.known_good_revision() == second
    assert not repo.is_dirty()

    # files rendered
    manifest = tomllib.loads((tmp_path / "state" / "manifest.toml").read_text())
    assert manifest["state"]["schema"] == STATE_SCHEMA
    assert manifest["state"]["known_good"] is True
    assert manifest["operation"]["event"] == "e" * 64
    assert manifest["operation"]["phase"] == "post"
    assert manifest["operation"]["plan_sha256"] == ""
    assert manifest["health"]["result"] == "passed"
    assert (tmp_path / "state" / "apps" / "hello_nostr_ynh.toml").exists()
    assert tomllib.loads(repo.show(first, "manifest.toml"))["operation"]["plan_sha256"] == "p" * 64

    hist = repo.history()
    assert len(hist) == 2
    assert hist[0]["op_event_id"] == "e" * 64 and hist[0]["known_good"] is True

    # a real semantic change shows up in the diff
    changed = export_state(FakeBackend())
    changed["services"]["dnsmasq.toml"] = {"status": "dead", "type": "system"}
    third = repo.commit(changed, op_event_id="f" * 64, phase="post", known_good=False, health="failed")
    diff = repo.diff(second, third)
    assert "dnsmasq.toml" in diff and "running" in diff and "dead" in diff
    assert repo.known_good_revision() == second  # known-good tag did not move


def test_state_repo_restic_linkage(tmp_path: Path):
    repo = StateRepo(tmp_path / "state", "a" * 64)
    repo.commit(
        export_state(FakeBackend()),
        op_event_id="d" * 64,
        phase="post",
        known_good=True,
        restic_snapshot="R1234abcd",
        required=True,
        health="passed",
    )
    manifest = tomllib.loads((tmp_path / "state" / "manifest.toml").read_text())
    assert manifest["backup"]["restic_snapshot"] == "R1234abcd"
    assert manifest["backup"]["required"] is True


def test_state_repo_bundle_round_trip(tmp_path: Path):
    repo = StateRepo(tmp_path / "state", "a" * 64)
    revision = repo.commit(export_state(FakeBackend()), known_good=True, health="passed")
    bundle = repo.create_bundle(tmp_path / "replica" / "state.bundle")

    assert bundle.stat().st_mode & 0o777 == 0o600
    assert revision in StateRepo.verify_bundle(bundle)
    restored = StateRepo.restore_bundle(bundle, tmp_path / "restored")
    restored_repo = StateRepo(restored, "a" * 64)
    assert restored_repo.revision() == revision
    assert restored_repo.known_good_revision() == revision


def test_reconciliation_plan_is_report_only(tmp_path: Path):
    repo = StateRepo(tmp_path / "state", "a" * 64)
    desired = export_state(FakeBackend())
    repo.commit(desired, known_good=True, health="passed")

    current = export_state(FakeBackend())
    current["services"]["dnsmasq.toml"] = {"status": "dead", "type": "system"}
    plan = repo.reconciliation_plan(current)

    assert plan["apply"] is False
    assert plan["changes"] == [
        {
            "path": "services/dnsmasq.toml",
            "status": "M",
            "action": "update",
            "risk": "low",
            "tool": "service.control",
            "args": {"name": "dnsmasq", "action": "start"},
            "automatic": True,
        }
    ]


def test_reconciliation_apply_requires_approval_and_is_bounded(tmp_path: Path):
    repo = StateRepo(tmp_path / "state", "a" * 64)
    repo.commit(export_state(FakeBackend()), known_good=True, health="passed")
    current = export_state(FakeBackend())
    current["services"]["dnsmasq.toml"] = {"status": "dead", "type": "system"}
    plan = repo.reconciliation_plan(current)
    backend = type("Backend", (), {"calls": [], "execute": lambda self, tool, args: self.calls.append((tool, args))})()

    with pytest.raises(StateError, match="not approved"):
        apply_reconciliation_plan(plan, backend=backend, repo=repo)
    report = apply_reconciliation_plan(plan, backend=backend, approve=True, repo=repo)
    assert report[0]["status"] == "executed"
    assert backend.calls == [("service.control", {"name": "dnsmasq", "action": "start"})]


def test_executor_records_auto_pre_post_snapshots(tmp_path: Path):
    """The engine's automatic snapshot hook: a full chain produces a pre and
    a post commit, the post one linked to the request and known-good."""
    import os

    from coincurve import PublicKeyXOnly

    def key():
        s = os.urandom(32).hex()
        return s, PublicKeyXOnly.from_secret(bytes.fromhex(s)).format().hex()

    server_sk, server_pk = key()
    admin_sk, admin_pk = key()
    agent_sk, agent_pk = key()

    class RecBackend:
        def execute(self, tool, args):
            return {"ok": tool}

    published = []
    repo = StateRepo(tmp_path / "state", server_pk)
    engine = OperationEngine(
        publish=published.append,
        server_sk=server_sk,
        admins=[admin_pk],
        backend=RecBackend(),
        state=StateRecorder(repo, FakeBackend(), capabilities=lambda: {pk: sorted(s) for pk, s in engine.scopes.items()}),
    )

    assert engine.handle_event(build_capability(admin_sk, admin_pk, agent_pk, "agent", ["server.read"]))
    req = build_operation_request(agent_sk, agent_pk, "system.version", {})
    assert engine.handle_event(req)
    assert engine.handle_event(build_approval(admin_sk, admin_pk, req["id"]))
    assert engine.state(req["id"]) == OpState.SUCCEEDED

    hist = repo.history()
    assert len(hist) == 2
    # both commits link the request event; the post one is known-good
    pre, post = hist[1], hist[0]
    assert pre["op_event_id"] == req["id"]
    assert post["op_event_id"] == req["id"]
    assert post["known_good"] is True
    # the pre snapshot was health=pending, the post health=passed
    assert "health=pending" in pre["message"] and "phase=pre" in pre["message"]
    assert "health=passed" in post["message"] and "phase=post" in post["message"]
    # capabilities from the engine's projected grants are captured
    assert (tmp_path / "state" / "capabilities" / f"{agent_pk}.toml").exists()


def test_executor_failure_marks_post_not_known_good(tmp_path: Path):
    import os

    from coincurve import PublicKeyXOnly

    def key():
        s = os.urandom(32).hex()
        return s, PublicKeyXOnly.from_secret(bytes.fromhex(s)).format().hex()

    server_sk, server_pk = key()
    admin_sk, admin_pk = key()
    agent_sk, agent_pk = key()

    class BoomBackend:
        def execute(self, tool, args):
            raise RuntimeError("boom failed")

    published = []
    repo = StateRepo(tmp_path / "state", server_pk)
    engine = OperationEngine(
        publish=published.append,
        server_sk=server_sk,
        admins=[admin_pk],
        backend=BoomBackend(),
        state=StateRecorder(repo, FakeBackend()),
    )
    assert engine.handle_event(build_capability(admin_sk, admin_pk, agent_pk, "agent", ["server.read"]))
    req = build_operation_request(agent_sk, agent_pk, "system.version", {})
    assert engine.handle_event(req)
    assert engine.handle_event(build_approval(admin_sk, admin_pk, req["id"]))
    assert engine.state(req["id"]) == OpState.FAILED

    pre, post = repo.history()[1], repo.history()[0]
    assert "health=failed" in post["message"]
    assert post["known_good"] is False
    assert repo.known_good_revision() == ""


def test_data_affecting_tools_warrant_restic_linkage():
    for tool in ("app.install", "app.upgrade", "app.remove", "package.reconcile", "backup.create", "backup.restore"):
        assert tool in DATA_AFFECTING_TOOLS
    assert "service.restart" not in DATA_AFFECTING_TOOLS


def test_native_reconcile_pre_snapshot_requests_restic_link(tmp_path: Path):
    calls = []
    repo = StateRepo(tmp_path / "state", "a" * 64)
    recorder = StateRecorder(repo, FakeBackend(), restic_hook=lambda: calls.append("snapshot") or "snap-1")
    recorder.pre("e" * 64, "package.reconcile", {"plan": {"plan_sha256": "p" * 64}})
    assert calls == ["snapshot"]
    manifest = tomllib.loads((tmp_path / "state" / "manifest.toml").read_text())
    assert manifest["backup"]["restic_snapshot"] == "snap-1"
    assert manifest["operation"]["plan_sha256"] == "p" * 64


def test_repository_announcement_kind_and_tags():
    server_sk = "ab" * 32
    server_pk = "cd" * 32
    ev = build_repository_announcement(server_sk, server_pk)
    assert ev["kind"] == 30617
    assert ev["pubkey"] == server_pk
    tags = dict((t[0], t[1]) for t in ev["tags"])
    assert tags["d"] == "nostrhost-state"
    assert tags["n"] == "nostr"
    assert tags["r"] == "nostrhost-state.git"
    assert len(tags["i"]) == 64  # repo id = sha256 hex


def test_state_dir_env_override(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("NOSTRHOST_STATE_DIR", str(tmp_path / "alt"))
    assert state_dir_from_env() == tmp_path / "alt"


def test_toml_serializer_handles_nested_and_ordered(tmp_path: Path):
    """Nested dicts (OrderedDict from yunohost settings) and lists of dicts
    must never fail a snapshot: they are preserved as JSON strings."""
    from collections import OrderedDict

    from yunohost.nostr_state import _dump_toml

    out = _dump_toml(
        {
            "hostname": "h",
            "settings": {"security.root_access": OrderedDict([("root", True), ("www-data", False)])},
            "apps": [{"id": "x", "n": 1}],
        }
    )
    assert "security.root_access" in out
    assert "root" in out  # OrderedDict preserved as JSON text inside the string

    repo = StateRepo(tmp_path / "state", "a" * 64)
    tree = export_state(FakeBackend())
    tree["system"]["host.toml"]["settings"] = OrderedDict([("security.root_access", OrderedDict([("root", True)]))])
    repo.commit(tree, op_event_id="c" * 64, phase="post", known_good=True, health="passed")
    assert repo.known_good_revision()  # commit succeeded despite nested data
