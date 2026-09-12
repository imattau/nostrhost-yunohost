"""Stage B tests: the Restic client (fake `restic` binary), its config, and
the StateRecorder snapshot hook.

No real repository is touched: a small fake `restic` executable simulates the
CLI's `--json` output and asserts the password only ever arrives via the
RESTIC_PASSWORD environment variable, never on argv.
"""

from __future__ import annotations

import json
import os
import subprocess
import textwrap
from pathlib import Path

import pytest

from yunohost.nostr_restic import (
    ResticClient,
    ResticError,
    load_restic_config,
    restic_client,
    restic_snapshot_hook,
)

PASSWORD = "sekret-pass"


def make_fake_restic(tmp_path: Path, fail: bool = False) -> Path:
    """Write an executable fake `restic` that mimics the --json commands."""
    body = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
pw = os.environ.get("RESTIC_PASSWORD", "")
if pw != "sekret-pass":
    print("password not passed via env", file=sys.stderr); sys.exit(9)
if any(pw in a for a in args):
    print("password leaked on argv", file=sys.stderr); sys.exit(10)
if os.environ.get("FAKE_RESTIC_FAIL"):
    print("boom", file=sys.stderr); sys.exit(1)
cmd = args[0]
if cmd == "backup":
    print(json.dumps({"message_type": "status", "percent_done": 1.0}))
    print(json.dumps({"message_type": "summary", "snapshot_id": "b"*64, "files_new": 2}))
elif cmd == "snapshots":
    print(json.dumps([{"id": "b"*64, "short_id": "bbbb", "time": "2026-01-01T00:00:00Z",
                       "tags": ["nostrhost"], "paths": ["/opt/yunohost"]}]))
elif cmd == "restore":
    sid = next(a for a in args[2:] if not a.startswith("-"))
    print(json.dumps({"message_type": "summary", "files_restored": 1, "snapshot_id": sid}))
elif cmd == "check":
    pass
else:
    print(f"fake restic: unexpected {cmd}", file=sys.stderr); sys.exit(2)
'''
    script = tmp_path / "restic"
    script.write_text(textwrap.dedent(body))
    script.chmod(0o755)
    if fail:  # a second fake that always fails (for hook error tests)
        failer = tmp_path / "restic-fail"
        failer.write_text("#!/usr/bin/env python3\nimport sys\nprint('boom', file=sys.stderr)\nsys.exit(1)\n")
        failer.chmod(0o755)
    return script


def make_client(tmp_path: Path, **kw) -> ResticClient:
    binary = make_fake_restic(tmp_path)
    return ResticClient(repo="s3:https://example.invalid/restic", password=PASSWORD, binary=str(binary), **kw)


def write_config(tmp_path: Path, extra: dict | None = None) -> Path:
    import json as _json

    conf = {
        "repo": "s3:https://example.invalid/restic",
        "password": PASSWORD,
        "paths": ["/opt/yunohost", "/home"],
        **({"binary": str(tmp_path / "restic")} if (tmp_path / "restic").exists() else {}),
        **(extra or {}),
    }
    path = tmp_path / "restic.toml"
    text = "\n".join(k + " = " + (_json.dumps(v) if isinstance(v, str) else repr(list(v))) for k, v in conf.items())
    path.write_text(text + "\n")
    return path


def test_config_load_and_defaults(tmp_path: Path):
    path = write_config(tmp_path, {"host": "host1", "tag": "data"})
    cfg = load_restic_config(path)
    assert cfg.repo == "s3:https://example.invalid/restic"
    assert cfg.password == PASSWORD
    assert cfg.paths == ("/opt/yunohost", "/home")
    assert cfg.host == "host1" and cfg.tag == "data"
    assert cfg.restore_target == "/"


def test_config_missing_returns_none(tmp_path: Path):
    assert load_restic_config(tmp_path / "nope.toml") is None


def test_config_invalid_raises(tmp_path: Path):
    with pytest.raises(ResticError):
        load_restic_config(write_config(tmp_path, {"password": ""}))
    with pytest.raises(ResticError):
        load_restic_config(write_config(tmp_path, {"paths": []}))


def test_snapshot_returns_id_and_env_password(tmp_path: Path):
    client = make_client(tmp_path)
    sid = client.snapshot(["/opt/yunohost"])
    assert sid == "b" * 64  # fake restic asserts password-on-env + not-on-argv


def test_snapshot_requires_paths(tmp_path: Path):
    client = make_client(tmp_path)
    with pytest.raises(ResticError, match="at least one path"):
        client.snapshot([])


def test_snapshots_lists_and_filters(tmp_path: Path):
    client = make_client(tmp_path)
    snaps = client.snapshots(tag="nostrhost")
    assert snaps[0]["id"] == "b" * 64
    assert snaps[0]["paths"] == ["/opt/yunohost"]


def test_snapshots_default_lists_all_tags(tmp_path: Path, monkeypatch):
    # The configured tag is a creation default, not a listing filter: policy
    # backup evidence and `backup list` must see per-app/system snapshots too.
    recorder = tmp_path / "recorded-args.json"
    monkeypatch.setenv("RECORD_ARGS", str(recorder))

    def make_recording_restic() -> Path:
        body = r'''#!/usr/bin/env python3
import json, os, sys
open(os.environ["RECORD_ARGS"], "w").write(json.dumps(sys.argv[1:]))
print(json.dumps([{"id": "b"*64, "time": "2026-01-01T00:00:00Z", "tags": ["nostrhost"]}]))
'''
        script = tmp_path / "restic-record"
        script.write_text(textwrap.dedent(body))
        script.chmod(0o755)
        return script

    client = ResticClient(
        repo="x", password=PASSWORD, binary=str(make_recording_restic()),
        host="host1", tag="nostrhost",
    )
    client.snapshots()
    recorded = json.loads(recorder.read_text())
    assert "--tag" not in recorded

    client.snapshots(tag="data")
    recorded = json.loads(recorder.read_text())
    assert "--tag" in recorded
    assert recorded[recorded.index("--tag") + 1] == "data"


def test_restore_parses_summary(tmp_path: Path):
    client = make_client(tmp_path)
    summary = client.restore("b" * 64, "/restore", include=["/opt/yunohost"])
    assert summary["files_restored"] == 1
    assert summary["snapshot_id"] == "b" * 64


def test_check_ok(tmp_path: Path):
    assert make_client(tmp_path).check() == {"ok": True}


def test_missing_binary_raises(tmp_path: Path):
    client = ResticClient(repo="x", password=PASSWORD, binary=str(tmp_path / "missing-restic"))
    with pytest.raises(ResticError, match="not found"):
        client.snapshot(["/opt"])


def test_failing_command_raises(tmp_path: Path):
    fake = make_fake_restic(tmp_path)
    client = ResticClient(repo="x", password=PASSWORD, binary=str(fake))
    os.environ["FAKE_RESTIC_FAIL"] = "1"
    try:
        with pytest.raises(ResticError, match="boom"):
            client.snapshot(["/opt"])
    finally:
        del os.environ["FAKE_RESTIC_FAIL"]


def test_restic_client_from_config(tmp_path: Path):
    make_fake_restic(tmp_path)
    path = write_config(tmp_path)
    client = restic_client(load_restic_config(path))
    assert client.repo.startswith("s3:")
    assert client.snapshot(["/opt/yunohost"]) == "b" * 64


def test_snapshot_hook_empty_without_config(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("NOSTRHOST_RESTIC_CONFIG", str(tmp_path / "absent.toml"))
    assert restic_snapshot_hook()() == ""


def test_snapshot_hook_returns_id_when_configured(tmp_path: Path):
    make_fake_restic(tmp_path)
    path = write_config(tmp_path)
    assert restic_snapshot_hook(load_restic_config(path))() == "b" * 64


def test_snapshot_hook_swallows_failures(tmp_path: Path):
    failer = tmp_path / "restic-fail"
    failer.write_text("#!/usr/bin/env python3\nimport sys\nprint('boom', file=sys.stderr)\nsys.exit(1)\n")
    failer.chmod(0o755)
    conf = load_restic_config(write_config(tmp_path, {"binary": str(failer)}))
    assert restic_snapshot_hook(conf)() == ""


def test_subprocess_never_sees_password_in_env_shell(tmp_path: Path):
    """End-to-end: run the real client via subprocess and confirm the fake's
    own env assertions pass (password via env only, never argv)."""
    make_fake_restic(tmp_path)
    client = make_client(tmp_path)
    sid = client.snapshot(["/opt/yunohost"], tag="nostrhost", host="vm1")
    assert sid == "b" * 64