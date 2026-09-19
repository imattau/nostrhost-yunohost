"""WP6 tests: kind-31101 policy declaration projection.

Covers the coordinate registry, the addressable fold semantics (greatest
revision wins, equal-revision tie-break, revoke), operator-only authorship,
quarantine of malformed/missing-schema documents, the family readers, the
compatibility renderers (notify TOML, restic desired merge preserving
secrets, host policy TOML) and the operator publish/import path.
"""

from __future__ import annotations

import json

from conftest import new_key
from yunohost.nostr_identity import _sign_event
from yunohost.nostrhost.policy_projection import (
    KIND_TRUST_POLICY,
    PolicyProjector,
    PolicyStore,
    host_policy,
    notification_rules,
    render_host_policy,
    render_notification_files,
    render_restic_desired,
    restic_policy,
)
from yunohost.nostrhost.policy_specs import (
    HOST_NAMESPACE,
    KIND_TRUST_POLICY as SPEC_KIND,
    SPECS,
    spec_for_coordinate,
    spec_for_name,
)


def _event(sk, pk, coordinate, *, value, revision=1, created_at=None, enabled=True, schema=1):
    body = {"schema": schema, "revision": revision, "value": value}
    if not enabled:
        body["enabled"] = False
    event = _sign_event(
        sk, pk, KIND_TRUST_POLICY, json.dumps(body), [["d", coordinate]], created_at=created_at
    )
    return event


def _projector(tmp_path, admin_pk):
    return PolicyProjector(
        store=PolicyStore(tmp_path / "policy.json"),
        admin_pubkeys=[admin_pk],
        cursor_dir=tmp_path / "cursors",
    )


# --------------------------------------------------------------------------- #
# coordinate registry


def test_families_are_addressable_and_operator_authored():
    assert set(SPECS) == {"notification-rules", "restic-policy", "host-policy"}
    for name, spec in SPECS.items():
        assert spec.d == f"{HOST_NAMESPACE}:{name}"
        assert spec.kind == SPEC_KIND == KIND_TRUST_POLICY
        assert spec.authors == ("server-admin",)


def test_spec_for_coordinate_matches_d_tags():
    assert spec_for_coordinate(f"{HOST_NAMESPACE}:notification-rules").name == "notification-rules"
    assert spec_for_coordinate("unrelated:coordinate") is None


# --------------------------------------------------------------------------- #
# fold semantics


def test_greatest_revision_wins(tmp_path):
    sk, pk = new_key()
    p = _projector(tmp_path, pk)
    p.apply(_event(sk, pk, f"{HOST_NAMESPACE}:restic-policy", value={"paths": ["/etc"]}, revision=1, created_at=100))
    p.apply(_event(sk, pk, f"{HOST_NAMESPACE}:restic-policy", value={"paths": ["/etc", "/var"]}, revision=2, created_at=200))
    doc = restic_policy(p.store)
    assert doc == {"paths": ["/etc", "/var"]}


def test_equal_revision_newer_timestamp_wins(tmp_path):
    sk, pk = new_key()
    p = _projector(tmp_path, pk)
    p.apply(_event(sk, pk, f"{HOST_NAMESPACE}:host-policy", value={"policy": {"a": {}}}, revision=1, created_at=100))
    p.apply(_event(sk, pk, f"{HOST_NAMESPACE}:host-policy", value={"policy": {"b": {}}}, revision=1, created_at=200))
    doc = host_policy(p.store)
    assert doc == {"policy": {"b": {}}}


def test_enabled_false_revokes_document(tmp_path):
    sk, pk = new_key()
    p = _projector(tmp_path, pk)
    p.apply(_event(sk, pk, f"{HOST_NAMESPACE}:notification-rules", value={"rules": []}, revision=1, created_at=100))
    p.apply(_event(sk, pk, f"{HOST_NAMESPACE}:notification-rules", value={"rules": []}, revision=2, created_at=200, enabled=False))
    assert notification_rules(p.store) == {}


def test_non_admin_author_is_quarantined(tmp_path):
    sk, pk = new_key()
    other_sk, other_pk = new_key()
    p = _projector(tmp_path, pk)
    result = p.apply(_event(other_sk, other_pk, f"{HOST_NAMESPACE}:restic-policy", value={"paths": []}))
    assert result.accepted is False
    assert restic_policy(p.store) == {}


def test_missing_schema_is_quarantined(tmp_path):
    sk, pk = new_key()
    p = _projector(tmp_path, pk)
    body = {"revision": 1, "value": {"paths": []}}
    event = _sign_event(sk, pk, KIND_TRUST_POLICY, json.dumps(body), [["d", f"{HOST_NAMESPACE}:restic-policy"]])
    result = p.apply(event)
    assert result.accepted is False
    assert restic_policy(p.store) == {}


# --------------------------------------------------------------------------- #
# renderers


def test_render_notification_files(tmp_path, monkeypatch):
    from yunohost.nostrhost.policy_projection import PolicyEntry

    monkeypatch.setattr("yunohost.nostrhost.policy_projection.NOTIFY_RECIPIENTS_PATH", str(tmp_path / "recipients.toml"))
    monkeypatch.setattr("yunohost.nostrhost.policy_projection.NOTIFY_POLICY_PATH", str(tmp_path / "policy.toml"))
    entry = PolicyEntry(
        coordinate=f"{HOST_NAMESPACE}:notification-rules",
        key=f"{KIND_TRUST_POLICY}:{HOST_NAMESPACE}:notification-rules",
        value={
            "recipients": [{"npub": "npub1admin", "role": "admin"}],
            "rules": [{"recipient": "npub1admin", "classes": ["approval", "security"], "severity_min": "warning"}],
        },
    )
    out = render_notification_files(entry)
    assert out["recipients"] == str(tmp_path / "recipients.toml")
    recipients = (tmp_path / "recipients.toml").read_text()
    policy = (tmp_path / "policy.toml").read_text()
    assert 'npub = "npub1admin"' in recipients
    assert 'recipient = "npub1admin"' in policy
    assert 'classes = ["approval", "security"]' in policy


def test_render_restic_preserves_secrets(tmp_path, monkeypatch):
    from yunohost.nostrhost.policy_projection import PolicyEntry

    restic_file = tmp_path / "restic.toml"
    restic_file.write_text('repo = "sftp://host/repo"\npassword = "sekret"\npaths = ["/etc"]\n')
    monkeypatch.setattr("yunohost.nostrhost.policy_projection.RESTIC_CONFIG_PATH", str(restic_file))
    entry = PolicyEntry(
        coordinate=f"{HOST_NAMESPACE}:restic-policy",
        key=f"{KIND_TRUST_POLICY}:{HOST_NAMESPACE}:restic-policy",
        value={
            "paths": ["/etc", "/var/lib/nostrhost/state"],
            "retention": {"keep_last": 7, "keep_daily": 7},
            "schedule": {"enabled": True, "calendar": "daily"},
        },
    )
    out = render_restic_desired(entry)
    assert out["written"] is True
    text = restic_file.read_text()
    assert 'repo = "sftp://host/repo"' in text
    assert 'password = "sekret"' in text
    assert '"/var/lib/nostrhost/state"' in text
    assert "keep_last = 7" in text
    assert 'calendar = "daily"' in text


def test_render_host_policy(tmp_path, monkeypatch):
    from yunohost.nostrhost.policy_projection import PolicyEntry

    monkeypatch.setattr("yunohost.nostrhost.policy_projection.HOST_POLICY_PATH", str(tmp_path / "policy.toml"))
    entry = PolicyEntry(
        coordinate=f"{HOST_NAMESPACE}:host-policy",
        key=f"{KIND_TRUST_POLICY}:{HOST_NAMESPACE}:host-policy",
        value={
            "policy": {
                "apps.remove": {"require_confirmation": True, "require_backup": True, "max_backup_age": "24h"},
                "firewall.write": {"require_confirmation": True, "require_owner_signature": True},
            }
        },
    )
    out = render_host_policy(entry)
    assert out["written"] is True
    text = (tmp_path / "policy.toml").read_text()
    assert "[policy.apps.remove]" in text
    assert "require_confirmation = true" in text
    assert 'max_backup_age = "24h"' in text
    assert "[policy.firewall.write]" in text


# --------------------------------------------------------------------------- #
# import / publish path


def test_publish_policy_document_signs_31101(tmp_path, monkeypatch):
    from yunohost.nostrhost import policy_projection as pp

    published: list[dict] = []
    monkeypatch.setattr(
        "yunohost.nostr_identity.publish_to_relay",
        lambda relay, event: published.append(event),
    )
    sk, pk = new_key()
    monkeypatch.setenv("NOSTRHOST_OPERATOR_CONFIG", str(tmp_path / "operator.toml"))
    monkeypatch.setenv("NOSTRHOST_NOTICE_CONFIG", str(tmp_path / "portal.toml"))
    monkeypatch.setenv("NOSTRHOST_CATALOG_STATE", str(tmp_path / "catalogue.json"))

    # Bootstrap an operator config so _operator_config() resolves.
    from yunohost.nostr_identity import bootstrap_node

    bootstrap_node(force=True, write_relay=str(tmp_path / "relay.toml"))

    spec = spec_for_name("notification-rules")
    event = pp.publish_policy_document(
        spec,
        {"recipients": [{"npub": "npub1admin", "role": "admin"}], "rules": []},
    )
    assert event["kind"] == KIND_TRUST_POLICY
    assert ["d", spec.d] in event["tags"]
    body = json.loads(event["content"])
    assert body["schema"] == 1
    assert body["revision"] == 1
    assert body["value"]["recipients"] == [{"npub": "npub1admin", "role": "admin"}]
    assert published and published[0]["id"] == event["id"]
