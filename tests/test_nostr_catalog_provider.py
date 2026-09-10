from __future__ import annotations

import json

import pytest

from yunohost.nostr_catalog_provider import load_native_catalog


def test_load_native_catalog_maps_verified_projection(tmp_path):
    path = tmp_path / "catalogue.json"
    path.write_text(json.dumps([{
        "declaration": {
            "AppID": "hello_nostr",
            "Repository": "https://github.com/example/hello_nostr_ynh",
            "Version": "1.0.0~ynh1",
            "Commit": "c" * 40,
            "Name": "Hello Nostr",
            "Description": "A native package",
            "Architectures": ["amd64"],
        },
        "event_id": "a" * 64,
        "created_at": 1,
    }]))

    result = load_native_catalog(path)
    assert result["hello_nostr"]["source"] == "nostr"
    assert result["hello_nostr"]["git"]["revision"] == "c" * 40
    assert result["hello_nostr"]["manifest"]["name"] == {"en": "Hello Nostr"}
    assert result["hello_nostr"]["native"]["package_path"] == "package.toml"
    assert result["hello_nostr"]["native"]["app_id"] == "hello_nostr"


def test_load_native_catalog_ignores_bad_state(tmp_path):
    path = tmp_path / "catalogue.json"
    path.write_text("not json")
    assert load_native_catalog(path) == {}


@pytest.mark.parametrize("mode", ["require", "REQUIRE"])
def test_load_native_catalog_require_filters_unattested_apps(tmp_path, monkeypatch, mode):
    path = tmp_path / "catalogue.json"
    declaration = {
        "AppID": "hello_nostr",
        "Repository": "https://github.com/example/hello_nostr_ynh",
        "Version": "1.0.0~ynh1",
        "Commit": "c" * 40,
        "ManifestHash": "sha256:" + "a" * 64,
        "ContentHash": "sha256:" + "b" * 64,
    }
    path.write_text(json.dumps({"entries": [{"declaration": declaration}], "attestations": []}))
    monkeypatch.setenv("NOSTRHOST_CATALOG_ATTESTATION_MODE", mode)
    assert load_native_catalog(path) == {}


def test_load_native_catalog_prefer_marks_exact_passing_attestation(tmp_path, monkeypatch):
    path = tmp_path / "catalogue.json"
    declaration = {
        "AppID": "hello_nostr",
        "Repository": "https://github.com/example/hello_nostr_ynh",
        "Version": "1.0.0~ynh1",
        "Commit": "c" * 40,
        "ManifestHash": "sha256:" + "a" * 64,
        "ContentHash": "sha256:" + "b" * 64,
    }
    attestation = {key: declaration[key] for key in ("AppID", "Repository", "Commit", "ManifestHash", "ContentHash")}
    attestation["Result"] = "pass"
    path.write_text(json.dumps({"entries": [{"declaration": declaration}], "attestations": [{"attestation": attestation}]}))
    monkeypatch.setenv("NOSTRHOST_CATALOG_ATTESTATION_MODE", "prefer")
    assert load_native_catalog(path)["hello_nostr"]["nostr_verified"] is True


def test_native_backend_is_explicitly_selectable(monkeypatch):
    from yunohost import app_catalog

    monkeypatch.setenv("NOSTRHOST_CATALOG_BACKEND", "nostr")
    assert app_catalog.NATIVE_CATALOG_MODE_ENV == "NOSTRHOST_CATALOG_BACKEND"
