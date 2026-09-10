from __future__ import annotations

import json

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


def test_load_native_catalog_ignores_bad_state(tmp_path):
    path = tmp_path / "catalogue.json"
    path.write_text("not json")
    assert load_native_catalog(path) == {}
