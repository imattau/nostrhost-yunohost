"""WP7 tests: generated service configuration as a provenance-tracked projection.

Covers the service-spec registry, the shared render/provenance/drift/reconcile
plumbing, the nsite/notify/oidc render paths, the OIDC credential-store secret
resolution (secrets never in the document), and the native validators.
"""

from __future__ import annotations

import json
import tomllib
from dataclasses import replace
from pathlib import Path

import pytest

from yunohost.nostr_identity import _sign_event
from yunohost.nostrhost.service_projection import (
    check_drift,
    provenance_path,
    read_provenance,
    render_managed,
    validate_notify,
    validate_nsite,
    validate_oidc,
)
from yunohost.nostrhost.service_specs import SERVICE_SPECS, spec_for_name
from yunohost.nostrhost.policy_projection import (
    KIND_TRUST_POLICY,
    OIDC_CLIENTS,
    PolicyProjector,
    PolicyStore,
    render_oidc_clients,
    _validate_oidc,
)
from yunohost.nostrhost.policy_specs import HOST_NAMESPACE, spec_for_name as policy_spec_for_name
from yunohost.nostrhost.credentials import read_secret, set_secret


def _spec_at(name: str, tmp_path: Path):
    return replace(spec_for_name(name), path=str(tmp_path / f"{name}.toml"))


def _oidc_event(sk, pk, *, clients, revision=1, created_at=100):
    body = {"schema": 1, "revision": revision, "value": {"clients": clients}}
    return _sign_event(sk, pk, KIND_TRUST_POLICY, json.dumps(body), [["d", f"{HOST_NAMESPACE}:{OIDC_CLIENTS}"]], created_at=created_at)


def _projector(tmp_path, admin_pk, monkeypatch):
    monkeypatch.setenv("NOSTRHOST_OIDC_CONFIG", str(tmp_path / "oidc.toml"))
    return PolicyProjector(
        store=PolicyStore(tmp_path / "policy.json"),
        admin_pubkeys=[admin_pk],
        cursor_dir=tmp_path / "cursors",
    )


# --------------------------------------------------------------------------- #
# service-spec registry


def test_service_specs_registry_complete():
    assert set(SERVICE_SPECS) == {"nsite", "notify", "oidc"}
    for name, spec in SERVICE_SPECS.items():
        assert spec.path
        assert spec.source
        assert spec.provenance_path() == spec.path + ".source.json"


def test_spec_for_name_unknown():
    with pytest.raises(KeyError):
        spec_for_name("nope")


# --------------------------------------------------------------------------- #
# render_managed: atomic write + provenance sidecar + unchanged detection


def test_render_managed_writes_provenance(tmp_path):
    spec = _spec_at("notify", tmp_path)
    target = Path(spec.path)
    result = render_managed(
        spec,
        'relay_url = "ws://127.0.0.1:4848"\n',
        source_revision="local:test",
        renderer="test",
        validate=False,
        reload=False,
    )
    assert result["changed"] is True
    assert result["rendered_sha256"]
    assert target.is_file()
    sidecar = read_provenance(target)
    assert sidecar is not None
    assert sidecar["source"] == spec.source
    assert sidecar["source_revision"] == "local:test"
    assert sidecar["renderer"] == "test"
    assert sidecar["rendered_sha256"] == result["rendered_sha256"]


def test_render_managed_noop_when_unchanged(tmp_path):
    spec = _spec_at("notify", tmp_path)
    target = Path(spec.path)
    content = 'relay_url = "ws://127.0.0.1:4848"\n'
    render_managed(spec, content, source_revision="r1", renderer="t", validate=False, reload=False)
    first = target.read_text(encoding="utf-8")
    result = render_managed(spec, content, source_revision="r1", renderer="t", validate=False, reload=False)
    assert result["changed"] is False
    assert target.read_text(encoding="utf-8") == first


# --------------------------------------------------------------------------- #
# drift detection


def test_check_drift_clean(tmp_path):
    spec = _spec_at("notify", tmp_path)
    target = Path(spec.path)
    content = 'relay_url = "ws://127.0.0.1:4848"\n'
    render_managed(spec, content, source_revision="r1", renderer="t", validate=False, reload=False)
    report = check_drift(spec, target=target)
    assert report["drifted"] is False
    assert report["source_revision"] == "r1"


def test_check_drift_manual_edit(tmp_path):
    spec = _spec_at("notify", tmp_path)
    target = Path(spec.path)
    render_managed(spec, "a\n", source_revision="r1", renderer="t", validate=False, reload=False)
    target.write_text("b\n", encoding="utf-8")
    report = check_drift(spec, target=target)
    assert report["drifted"] is True
    assert report["reason"].startswith("manual edit")


def test_check_drift_missing_file(tmp_path):
    spec = _spec_at("notify", tmp_path)
    report = check_drift(spec, target=Path(spec.path))
    assert report["drifted"] is True
    assert report["present"] is False


def test_check_drift_no_provenance(tmp_path):
    spec = _spec_at("notify", tmp_path)
    target = Path(spec.path)
    target.write_text("x\n", encoding="utf-8")
    report = check_drift(spec, target=target)
    assert report["drifted"] is True
    assert "no provenance" in report["reason"]


# --------------------------------------------------------------------------- #
# native validators


def test_validate_notify_accepts_rendered(tmp_path, monkeypatch):
    content = (
        'relay_url = "ws://127.0.0.1:4848"\n'
        'notifier_private_key = "abcd"\n'
        'recipients_path = "/x/recipients.toml"\n'
        'policy_path = "/x/policy.toml"\n'
        'state_path = "/x/state.json"\n'
        'digest_interval = "1h"\n'
        'outbound_relays = ["wss://relay.example"]\n'
    )
    validate_notify(content)  # no raise


def test_validate_notify_rejects_missing_secret():
    with pytest.raises(Exception):
        validate_notify('relay_url = "ws://127.0.0.1:4848"\ndigest_interval = "1h"\n')


def test_validate_oidc_accepts(tmp_path, monkeypatch):
    content = (
        "[clients.app1]\n"
        'redirect_uris = ["https://app.example/oidc/callback"]\n'
        'client_secret = "sekret"\n'
    )
    validate_oidc(content)


def test_validate_nsite_when_binary_missing(monkeypatch):
    # The Go binary is not installed in the test env; the checker is skipped.
    monkeypatch.setenv("NOSTRHOST_NSITE_BINARY", "/nonexistent/nsite")
    validate_nsite('domain = "sites.example.org"\n')  # no raise


def test_validate_nsite_rejects_via_fake_binary(monkeypatch):
    fake = Path(__file__).parent / "_fake_nsite_check.py"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "content = open(sys.argv[sys.argv.index('-config') + 1]).read()\n"
        "sys.exit(1 if 'bogus' in content else 0)\n"
    )
    fake.chmod(0o755)
    monkeypatch.setenv("NOSTRHOST_NSITE_BINARY", str(fake))
    validate_nsite('domain = "sites.example.org"\n')  # accepted
    with pytest.raises(Exception):
        validate_nsite('mode = "bogus"\n')


# --------------------------------------------------------------------------- #
# oidc-clients fold + render (WP7)


def test_oidc_clients_fold_and_render(tmp_path, monkeypatch):
    from conftest import new_key

    sk, pk = new_key()
    p = _projector(tmp_path, pk, monkeypatch)
    monkeypatch.setenv("NOSTRHOST_STATE_DIR", str(tmp_path))
    event = _oidc_event(
        sk,
        pk,
        clients=[{"id": "app1", "redirect_uris": ["https://app.example/oidc/callback"]}],
    )
    result = p.apply(event)
    assert result.accepted
    entry = p.store.get(policy_spec_for_name(OIDC_CLIENTS).event_key(f"{HOST_NAMESPACE}:{OIDC_CLIENTS}"))
    assert entry is not None
    render_oidc_clients(entry)
    rendered = tomllib.loads((tmp_path / "oidc.toml").read_text(encoding="utf-8"))
    assert set(rendered["clients"]) == {"app1"}
    assert rendered["clients"]["app1"]["redirect_uris"] == ["https://app.example/oidc/callback"]
    assert len(rendered["clients"]["app1"]["client_secret"]) >= 32
    # The secret is in the rendered file but never in the folded document store.
    assert "client_secret" not in json.dumps(entry.value)
    # Provenance sidecar exists and points at the event revision.
    sidecar = read_provenance(tmp_path / "oidc.toml")
    assert sidecar is not None
    assert sidecar["source_revision"] == "rev:1"
    assert sidecar["source"] == spec_for_name("oidc").source


def test_oidc_secret_persisted_and_reused(tmp_path, monkeypatch):
    from conftest import new_key

    sk, pk = new_key()
    p = _projector(tmp_path, pk, monkeypatch)
    monkeypatch.setenv("NOSTRHOST_STATE_DIR", str(tmp_path))
    p.apply(
        _oidc_event(
            sk,
            pk,
            clients=[{"id": "app1", "redirect_uris": ["https://app.example/oidc/callback"]}],
            revision=1,
        )
    )
    entry = p.store.get(policy_spec_for_name(OIDC_CLIENTS).event_key(f"{HOST_NAMESPACE}:{OIDC_CLIENTS}"))
    render_oidc_clients(entry)
    first = tomllib.loads((tmp_path / "oidc.toml").read_text(encoding="utf-8"))["clients"]["app1"][
        "client_secret"
    ]
    # A second render (same doc, re-apply) must reuse the stored secret.
    p.apply(
        _oidc_event(
            sk,
            pk,
            clients=[{"id": "app1", "redirect_uris": ["https://app.example/oidc/callback"]}],
            revision=2,
            created_at=200,
        )
    )
    entry = p.store.get(policy_spec_for_name(OIDC_CLIENTS).event_key(f"{HOST_NAMESPACE}:{OIDC_CLIENTS}"))
    render_oidc_clients(entry)
    second = tomllib.loads((tmp_path / "oidc.toml").read_text(encoding="utf-8"))["clients"]["app1"][
        "client_secret"
    ]
    assert first == second
    assert read_secret("secret:oidc/app1", state_dir=tmp_path) == first


def test_oidc_validation_rejects_bad_client(tmp_path, monkeypatch):
    from conftest import new_key

    sk, pk = new_key()
    p = _projector(tmp_path, pk, monkeypatch)
    p.apply(_oidc_event(sk, pk, clients=[{"id": "bad id", "redirect_uris": ["not-a-url"]}]))
    assert p.quarantined()
    assert "oidc-clients" in p.quarantined()[0]["reason"]


def test_validate_oidc_rejects_missing_clients():
    with pytest.raises(ValueError):
        _validate_oidc({})


# --------------------------------------------------------------------------- #
# nsite render path (via NsiteService.render_config)


def test_nsite_render_writes_provenance(tmp_path, monkeypatch):

    from yunohost.nostrhost.nsites.models import GatewayConfig
    from yunohost.nostrhost.nsites.service import NsiteService

    config_path = tmp_path / "nsite.toml"
    service = NsiteService(
        state_dir=tmp_path,
        caddy=None,
        systemctl=lambda *a: "",
        config_path=config_path,
        verify_dns=None,
    )
    config = GatewayConfig(domain="sites.example.org")
    service.render_config(config)
    assert config_path.is_file()
    text = config_path.read_text(encoding="utf-8")
    assert 'domain = "sites.example.org"' in text
    sidecar = read_provenance(config_path)
    assert sidecar is not None
    assert sidecar["source"] == spec_for_name("nsite").source
    assert sidecar["renderer"] == "nsites.service.render_config"
    assert sidecar["rendered_sha256"]


def test_nsite_render_is_atomic_and_unchanged_noop(tmp_path, monkeypatch):
    from yunohost.nostrhost.nsites.models import GatewayConfig
    from yunohost.nostrhost.nsites.service import NsiteService

    config_path = tmp_path / "nsite.toml"
    service = NsiteService(
        state_dir=tmp_path,
        caddy=None,
        systemctl=lambda *a: "",
        config_path=config_path,
        verify_dns=None,
    )
    service.render_config(GatewayConfig(domain="sites.example.org"))
    first = config_path.read_text(encoding="utf-8")
    service.render_config(GatewayConfig(domain="sites.example.org"))
    assert config_path.read_text(encoding="utf-8") == first
    assert provenance_path(config_path).is_file()


# --------------------------------------------------------------------------- #
# notify render path (via cli._render_notify_config)


def test_notify_render_routes_through_framework(tmp_path, monkeypatch):
    for k, name in (
        ("NOSTRHOST_NOTIFY_CONFIG", "notify.toml"),
        ("NOSTRHOST_NOTIFY_STATE_DIR", "state/notifications"),
    ):
        monkeypatch.setenv(k, str(tmp_path / name))
    from yunohost.nostrhost.cli import _render_notify_config

    path = _render_notify_config("abcd" * 16, "ws://127.0.0.1:4848")
    assert path.is_file()
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    assert data["notifier_private_key"] == "abcd" * 16
    sidecar = read_provenance(path)
    assert sidecar is not None
    assert sidecar["source"] == spec_for_name("notify").source


# --------------------------------------------------------------------------- #
# credential broker oidc namespace


def test_credential_broker_oidc_namespace(tmp_path):
    set_secret("secret:oidc/app1", "tok-123", state_dir=tmp_path)
    assert read_secret("secret:oidc/app1", state_dir=tmp_path) == "tok-123"
    path = tmp_path.parent / "credentials" / "oidc" / "app1"
    assert path.is_file()
    # DNS refs still resolve through the two-segment layout.
    set_secret("secret:dns/duckdns/main", "tok", state_dir=tmp_path)
    assert read_secret("secret:dns/duckdns/main", state_dir=tmp_path) == "tok"


def test_credential_broker_rejects_bad_ref(tmp_path):
    with pytest.raises(Exception):
        read_secret("secret:../evil", state_dir=tmp_path)
