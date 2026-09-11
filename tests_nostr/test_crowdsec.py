"""CrowdSec policy resource: native provider, state snapshot, and round-trip."""

from pathlib import Path

import pytest

from nostrhost.native_providers import NativeOperationExecutor, PolicyProvider, native_providers
from nostrhost.package_engine import PackageManifest, apply_reconciled_plan, plan_package


def _scenario(name: str = "example-auth-bf") -> str:
    return (
        "type: leaky\n"
        f"name: example/{name}\n"
        "description: \"Example brute-force\"\n"
        "filter: \"evt.Meta.log_type == 'http_access-log'\"\n"
        "leakspeed: 60s\n"
        "capacity: 10\n"
        "groupby: evt.Meta.source_ip\n"
    )


def test_crowdsec_policy_literal_is_accepted():
    manifest = PackageManifest.parse_obj(
        {"app": {"id": "x", "version": "1"}, "policies": {"auth": {"type": "crowdsec", "name": "auth", "content": _scenario()}}}
    )
    assert manifest.policies["auth"].type == "crowdsec"


def test_crowdsec_policy_writes_yaml_scenario_and_reloads(tmp_path: Path):
    calls: list = []
    provider = PolicyProvider(root=tmp_path, command=lambda args, **kwargs: calls.append((args, kwargs)))
    desired = {"type": "crowdsec", "name": "example-auth-bf", "content": _scenario()}
    provider.apply(provider.plan(desired)[0])
    target = tmp_path / "etc/crowdsec/scenarios/nostrhost-example-auth-bf.yaml"
    assert target.read_text() == desired["content"]
    assert calls == [(["systemctl", "reload", "crowdsec"], {"check": False})]


def test_crowdsec_policy_remove_reloads_and_unlinks(tmp_path: Path):
    calls: list = []
    provider = PolicyProvider(root=tmp_path, command=lambda args, **kwargs: calls.append((args, kwargs)))
    desired = {"type": "crowdsec", "name": "example-auth-bf", "content": _scenario()}
    provider.apply(provider.plan(desired)[0])
    target = tmp_path / "etc/crowdsec/scenarios/nostrhost-example-auth-bf.yaml"
    assert target.exists()
    provider.apply(provider.remove(desired)[0])
    assert not target.exists()
    assert calls[-1] == (["systemctl", "reload", "crowdsec"], {"check": False})


def test_non_crowdsec_policy_does_not_reload(tmp_path: Path):
    calls: list = []
    provider = PolicyProvider(root=tmp_path, command=lambda args, **kwargs: calls.append((args, kwargs)))
    desired = {"type": "fail2ban", "name": "example", "content": "[example]\nenabled=true\n"}
    provider.apply(provider.plan(desired)[0])
    assert calls == []


def test_crowdsec_suffix_is_yaml_not_local(tmp_path: Path):
    provider = PolicyProvider(root=tmp_path)
    desired = {"type": "crowdsec", "name": "example", "content": _scenario("example")}
    target = provider._target(desired)
    assert target.name == "nostrhost-example.yaml"


def test_crowdsec_snapshot_state_records_enabled_scenarios(tmp_path: Path):
    calls: list = []
    state_dir = tmp_path / "var/lib/nostrhost/state"
    provider = PolicyProvider(root=tmp_path, command=lambda args, **kwargs: calls.append((args, kwargs)), state_dir=state_dir)
    provider.apply(provider.plan({"type": "crowdsec", "name": "one", "content": _scenario("one")})[0])
    provider.apply(provider.plan({"type": "crowdsec", "name": "two", "content": _scenario("two")})[0])
    snapshot = state_dir / "security/intrusion-protection.toml"
    assert snapshot.is_file()
    text = snapshot.read_text()
    assert "nostrhost-one" in text
    assert "nostrhost-two" in text


def test_crowdsec_round_trip_through_reconciliation(tmp_path: Path):
    manifest = PackageManifest.parse_obj(
        {
            "app": {"id": "example", "version": "1.2.0"},
            "policies": {"auth": {"type": "crowdsec", "name": "auth", "content": _scenario()}},
        }
    )
    plan = plan_package(manifest)
    calls: list = []
    executor = NativeOperationExecutor(native_providers(root=tmp_path, command=lambda args, **kwargs: calls.append((args, kwargs))))
    apply_reconciled_plan(plan, executor)
    scenario = tmp_path / "etc/crowdsec/scenarios/nostrhost-auth.yaml"
    assert scenario.read_text() == _scenario()
    assert any(args == ["systemctl", "reload", "crowdsec"] for args, _ in calls)


def test_crowdsec_unsupported_type_is_rejected(tmp_path: Path):
    provider = PolicyProvider(root=tmp_path)
    with pytest.raises(Exception):
        provider._target({"type": "nope", "name": "x", "content": _scenario()})