"""Tests for the multi-tenant-runtime control-plane helpers (design plan WP2)."""

from pathlib import Path

import pytest

from nostrhost.runtime_instances import (
    RuntimeInstanceError,
    bridge_unit_name,
    count_socket_connections,
    ensure_instance_running,
    instance_idle,
    instance_unit_name,
    reap_idle_instances,
    running_instance_usernames,
)


def test_instance_unit_name_rejects_unsafe_input():
    assert instance_unit_name("myapp", "alice") == "myapp@alice.service"
    with pytest.raises(RuntimeInstanceError):
        instance_unit_name("../myapp", "alice")
    with pytest.raises(RuntimeInstanceError):
        instance_unit_name("myapp", "../etc")


def test_bridge_unit_name_rejects_unsafe_input():
    assert bridge_unit_name("myapp", "alice") == "myapp-bridge@alice.service"
    with pytest.raises(RuntimeInstanceError):
        bridge_unit_name("../myapp", "alice")
    with pytest.raises(RuntimeInstanceError):
        bridge_unit_name("myapp", "../etc")


def test_ensure_instance_running_uses_bounded_systemctl_arguments():
    calls = []
    unit = ensure_instance_running("myapp", "alice", command=lambda args, **kwargs: calls.append((args, kwargs)))
    assert unit == "myapp@alice.service"
    assert calls == [(["systemctl", "start", "myapp@alice.service"], {"check": True})]


PROC_NET_UNIX_HEADER = "Num       RefCount Protocol Flags    Type St Inode Path\n"


def test_count_socket_connections_matches_by_path(tmp_path: Path):
    proc = tmp_path / "net_unix"
    proc.write_text(
        PROC_NET_UNIX_HEADER
        + "0: 00000002 00000000 00010000 0001 01 12345 /run/myapp/alice.sock\n"
        + "0: 00000002 00000000 00010000 0001 01 12346 /run/myapp/alice.sock\n"
        + "0: 00000002 00000000 00010000 0001 01 12347 /run/myapp/bob.sock\n"
    )
    assert count_socket_connections("/run/myapp/alice.sock", proc_net_unix=proc) == 2
    assert count_socket_connections("/run/myapp/bob.sock", proc_net_unix=proc) == 1
    assert count_socket_connections("/run/myapp/carol.sock", proc_net_unix=proc) == 0


def test_count_socket_connections_tolerates_missing_proc_file(tmp_path: Path):
    assert count_socket_connections("/run/myapp/alice.sock", proc_net_unix=tmp_path / "missing") == 0


def test_instance_idle_reflects_connection_count(tmp_path: Path):
    proc = tmp_path / "net_unix"
    proc.write_text(PROC_NET_UNIX_HEADER + "0: 00000002 00000000 00010000 0001 01 1 /run/myapp/alice.sock\n")
    assert instance_idle("/run/myapp/alice.sock", proc_net_unix=proc) is False
    assert instance_idle("/run/myapp/bob.sock", proc_net_unix=proc) is True


def test_running_instance_usernames_parses_systemctl_list_units():
    class Result:
        stdout = "myapp@alice.service loaded active running Foo\nmyapp@bob.service loaded active running Foo\n"

    calls = []

    def command(args, **kwargs):
        calls.append((args, kwargs))
        return Result()

    usernames = running_instance_usernames("myapp", command=command)
    assert usernames == ["alice", "bob"]
    assert calls[0][0][:2] == ["systemctl", "list-units"]


def test_reap_idle_instances_stops_only_idle_instances(tmp_path: Path):
    proc = tmp_path / "net_unix"
    proc.write_text(PROC_NET_UNIX_HEADER + "0: 00000002 00000000 00010000 0001 01 1 /run/myapp/alice.sock\n")

    class ListResult:
        stdout = "myapp@alice.service loaded active running Foo\nmyapp@bob.service loaded active running Foo\n"

    calls = []

    def command(args, **kwargs):
        calls.append(args)
        if args[:2] == ["systemctl", "list-units"]:
            return ListResult()
        return None

    stopped = reap_idle_instances("myapp", "/run/myapp/%i.sock", command=command, proc_net_unix=proc)
    # alice has an open connection (idle=False); bob has none (idle=True).
    assert stopped == ["bob"]
    # Stops the bridge (BindsTo= cascades the stop to the backend), not the
    # backend instance directly.
    assert ["systemctl", "stop", "myapp-bridge@bob.service"] in calls
    assert ["systemctl", "stop", "myapp@alice.service"] not in calls
