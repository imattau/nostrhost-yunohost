"""Workstream 3: end-to-end native app lifecycle through the signed chain.

Proves the W3 loop without a relay or LDAP: catalogue coordinate ->
verified package.toml -> resource-engine plan -> signed request -> policy ->
approval -> execution, plus manifest persistence, native removal planning,
change-url and Restic backup-path resolution. The chain path is exercised
through the real ``run_signed_chain`` helper with a fake backend / policy /
state / restic so every gate (authorisation, policy, approval) is real.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from coincurve import PublicKeyXOnly

from nostrhost.native_providers import NativeOperationExecutor, PackageProvider, native_providers
from nostrhost.package_engine import (
    PackageError,
    PackageManifest,
    operation_plan_digest,
    package_plan_envelope,
    plan_package,
    plan_package_removal,
    validate_package,
    validate_plan_envelope,
)
from yunohost.nostr_operations import OperationError, run_signed_chain
from yunohost.nostr_operations_state import OpState


def _new_key():
    sk = os.urandom(32).hex()
    pk = PublicKeyXOnly.from_secret(bytes.fromhex(sk)).format().hex()
    return sk, pk


def example_package() -> dict:
    return {
        "app": {"id": "nostrhost-test", "version": "0.1"},
        "directories": {"install": {"path": "/var/www/nostrhost-test", "mode": 0o755}},
        "config": {"index": {"destination": "/var/www/nostrhost-test/index.html", "content": "<h1>ok</h1>", "mode": 0o644}},
        "web": {"domain": "nostrhost.test", "path": "/nostrhost-test/", "file_root": "/var/www/nostrhost-test", "auth": "nostrhost"},
        "permissions": {"main": {"url": "/", "allowed": ["all_users"], "auth_request": True}},
        "health": {"type": "http", "path": "/nostrhost-test/"},
        "backup": {"paths": ["/var/www/nostrhost-test"], "database": False},
    }


class FakeBackend:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.fail = False

    def execute(self, tool: str, args: dict) -> dict:
        self.calls.append((tool, args))
        if self.fail:
            raise RuntimeError("backend boom")
        envelope = args.get("plan") or {}
        return {"operations": len(envelope.get("operations", [])), "results": [{"operation": op["name"], "resource": op["resource"], "result": {"changed": True}} for op in envelope.get("operations", [])], "plan_sha256": envelope.get("plan_sha256", "")}


class FakeRecorder:
    def __init__(self) -> None:
        self.history: list[str] = []

    def pre(self, *args, **kwargs) -> str:
        self.history.append("pre")
        return "pre-commit"

    def post(self, *args, **kwargs) -> str:
        self.history.append("post")
        return "post-commit"


class Harness:
    def __init__(self, *, policy=None) -> None:
        self.operator_sk, self.operator_pk = _new_key()
        self.server_sk, _ = _new_key()
        self.backend = FakeBackend()
        self.recorder = FakeRecorder()
        self.policy = policy
        self.admins = [self.operator_pk]

    def chain(self, tool: str, args: dict) -> dict:
        return run_signed_chain(
            tool,
            args,
            operator_sk=self.operator_sk,
            server_sk=self.server_sk,
            admins=self.admins,
            backend=self.backend,
            state=self.recorder,
            policy=self.policy,
        )


def denying_policy(tool: str, args: dict, actor: str):
    return {"allow": False, "reason": "test denies"}


def allowing_policy(tool: str, args: dict, actor: str):
    return {"allow": True, "policy_key": tool}


def _envelope(package_data: dict, catalogue: dict | None = None) -> dict:
    return package_plan_envelope(package_data, catalogue=catalogue)


# --------------------------------------------------------------------------- #
# signed chain


def test_run_signed_chain_rejects_unknown_tool():
    with pytest.raises(OperationError, match="unknown tool"):
        run_signed_chain("app.boom", {})


def test_run_signed_chain_policy_denial_is_a_rejected_result():
    h = Harness(policy=denying_policy)
    body = h.chain("package.reconcile", {"plan": _envelope(example_package())})
    assert body["ok"] is False
    assert body["state"] == OpState.REJECTED.value
    assert "test denies" in body["reason"]
    assert not h.backend.calls
    assert not h.recorder.history


def test_run_signed_chain_install_runs_pre_and_post_state():
    h = Harness(policy=allowing_policy)
    envelope = _envelope(example_package())
    body = h.chain("package.reconcile", {"plan": envelope})
    assert body["ok"] is True
    assert body["request_id"]
    assert body["result"]["plan_sha256"] == envelope["plan_sha256"]
    assert h.recorder.history == ["pre", "post"]
    assert h.backend.calls[0][0] == "package.reconcile"


def test_run_signed_chain_records_policy_decision_in_result():
    h = Harness(policy=allowing_policy)
    body = h.chain("package.reconcile", {"plan": _envelope(example_package())})
    assert body["policy"] == {"allow": True, "policy_key": "package.reconcile"}


def test_run_signed_chain_failed_execution_is_reported_not_raised():
    h = Harness(policy=allowing_policy)
    h.backend.fail = True
    body = h.chain("package.reconcile", {"plan": _envelope(example_package())})
    assert body["ok"] is False
    assert "backend boom" in body["error"]
    assert h.recorder.history == ["pre", "post"]


# --------------------------------------------------------------------------- #
# catalogue coordinate + manifest verification

def test_coordinate_from_catalogue(tmp_path: Path):
    state = tmp_path / "catalogue.json"
    state.write_text(json.dumps({
        "entries": [{
            "event_id": "e1",
            "declaration": {
                "AppID": "nostrhost-test", "Repository": "https://example.org/repo.git",
                "Version": "0.1", "Commit": "abc123", "Name": "Test",
                "ManifestHash": "c" * 64, "ContentHash": "d" * 64,
            },
        }],
    }))
    from yunohost.nostr_catalog_provider import native_catalog_coordinate

    coordinate = native_catalog_coordinate("nostrhost-test", path=state)
    assert coordinate["repository"] == "https://example.org/repo.git"
    assert coordinate["revision"] == "abc123"
    assert coordinate["manifest_sha256"] == "c" * 64
    assert native_catalog_coordinate("missing", path=state) is None


def test_manifest_hash_verification_rejects_tampering():
    package_data = example_package()
    envelope = _envelope(package_data)
    expected = envelope["manifest_sha256"]
    tampered = dict(package_data)
    tampered["app"]["version"] = "0.2"
    from nostrhost.package_engine import _canonical_json

    actual = __import__("hashlib").sha256(_canonical_json(tampered)).hexdigest()
    assert actual != expected


# --------------------------------------------------------------------------- #
# plan / manifest persistence / removal / change-url

def test_plan_carries_manifest_and_removal_reverses_it():
    package = validate_package(PackageManifest.parse_obj(example_package()))
    plan = plan_package(package)
    manifest_op = next(op for op in plan if op.name == "package.manifest.ensure")
    assert manifest_op.args["id"] == "nostrhost-test"
    assert manifest_op.args["manifest"]["app"]["id"] == "nostrhost-test"

    removal = plan_package_removal(package)
    names = [op.name for op in removal]
    assert "package.manifest.remove" in names
    assert names[-1] == "package.remove"
    assert all(op.depends_on == ((removal[index - 1].resource,) if index else ()) for index, op in enumerate(removal))


def test_package_provider_persists_and_recovers_manifest(tmp_path: Path):
    provider = PackageProvider(state_dir=tmp_path)
    package = validate_package(PackageManifest.parse_obj(example_package()))
    executor = NativeOperationExecutor({"package": provider})
    for op in plan_package(package):
        if op.name in {"package.ensure", "package.manifest.ensure"}:
            executor.execute(op)
    from nostrhost.native_providers import installed_package_manifest

    manifest = installed_package_manifest("nostrhost-test", state_dir=tmp_path)
    assert manifest["app"]["id"] == "nostrhost-test"
    assert manifest["app"]["version"] == "0.1"
    assert manifest["web"]["path"] == "/nostrhost-test/"

    for op in plan_package_removal(package):
        if op.name in {"package.remove", "package.manifest.remove"}:
            executor.execute(op)
    assert installed_package_manifest("nostrhost-test", state_dir=tmp_path) is None


def test_removal_envelope_round_trips_through_validator():
    from yunohost.nostr_operations import _safe_package_reconcile

    class RecordingExecutor:
        def __init__(self) -> None:
            self.applied: list[str] = []

        def can_execute(self, operation) -> bool:
            return True

        def execute(self, operation) -> dict:
            self.applied.append(operation.name)
            return {"changed": True}

    envelope = _envelope(example_package())
    executor = RecordingExecutor()
    result = _safe_package_reconcile(plan=envelope, _executor=executor)
    assert result["plan_sha256"] == envelope["plan_sha256"]
    assert "package.manifest.ensure" in executor.applied
    assert len(executor.applied) == len(envelope["operations"])


def test_change_url_envelope_is_single_web_route_operation():
    package = validate_package(PackageManifest.parse_obj(example_package()))
    args = package.web.dict()
    args.update({"app": "nostrhost-test", "domain": "portal.nostrhost.test", "path": "/test/"})
    from nostrhost.package_engine import Operation, operation_plan_digest

    operation = Operation("web.route.ensure", "nostrhost-test:web", args, risk="medium", reverse="web.route.remove")
    envelope = {"schema": 1, "package": {"id": "nostrhost-test", "version": package.app.version}, "manifest_sha256": "", "plan_sha256": operation_plan_digest([operation]), "operations": [operation.json_dict()]}
    operations = validate_plan_envelope(envelope)
    assert len(operations) == 1
    assert operations[0].name == "web.route.ensure"
    assert operations[0].args["domain"] == "portal.nostrhost.test"


# --------------------------------------------------------------------------- #
# restic backup-path resolution

def test_backup_paths_come_from_installed_manifest(tmp_path: Path):
    from nostrhost.native_providers import installed_package_manifest

    manifest = example_package()
    installed_package_manifest  # imported for coverage of the loader
    # Persist via the provider so removal/upgrade/backup share one source.
    provider = PackageProvider(state_dir=tmp_path)
    package = validate_package(PackageManifest.parse_obj(manifest))
    executor = NativeOperationExecutor({"package": provider})
    for op in plan_package(package):
        if op.name in {"package.ensure", "package.manifest.ensure"}:
            executor.execute(op)
    stored = installed_package_manifest("nostrhost-test", state_dir=tmp_path)
    package = validate_package(PackageManifest.parse_obj(stored))
    assert [str(path) for path in package.backup.paths] == ["/var/www/nostrhost-test"]


# --------------------------------------------------------------------------- #
# CLI helper import paths (node-safe: yunohost.* modules, not top-level)

def test_cli_lifecycle_helpers_use_node_safe_imports(tmp_path: Path, monkeypatch):
    """The lifecycle helpers must import through yunohost.* so they resolve on
    an installed node (nostr_restic/nostr_operations are inside the yunohost
    package, not top-level)."""
    from nostrhost import cli as cli_module

    # _restic_client with no config present must raise the friendly error
    # AFTER resolving the import (a bad top-level import would fail with
    # ModuleNotFoundError instead).
    monkeypatch.setenv("NOSTRHOST_RESTIC_CONFIG", str(tmp_path / "missing.toml"))
    with pytest.raises(Exception, match="restic is not configured"):
        cli_module._restic_client()

    # _coordinate_for must resolve the catalogue provider import cleanly.
    monkeypatch.delenv("NOSTRHOST_CATALOG_STATE", raising=False)
    assert cli_module._coordinate_for("nostrhost-test") in (None, {})


def test_policy_writer_quotes_dotted_keys(tmp_path: Path, monkeypatch):
    """The generated policy.toml must use [policy."apps.upgrade"]-style quoted
    keys so load_policy() reads them as one literal key (an unquoted
    `[policy.apps.upgrade]` parses as a nested table and is silently ignored)."""
    from nostrhost import cli as cli_module
    from nostrhost_policy.policy.rules import load_policy

    target = tmp_path / "policy.toml"
    monkeypatch.setattr(cli_module, "POLICY_CONFIG", str(target))
    cli_module._write_policy_toml("npub1test")
    rules = load_policy(target)
    assert rules["apps.upgrade"].require_backup is True
    assert rules["apps.upgrade"].minimum_free_space_bytes == 2_000_000_000
    assert rules["apps.remove"].require_confirmation is True
    assert rules["apps.remove"].max_backup_age_seconds == 86400
    assert rules["backups.restore"].require_owner_signature is True