"""Unit tests for the projection-health diagnoser (WP2).

Bypasses Diagnoser.__init__ (the full moulinette i18n stack is out of scope
for the lightweight tests_nostr suite); run() only reads cursor files. The
diagnoser is imported through the ``yunohost`` package alias set up in
conftest, so its relative ``..diagnosis`` import resolves.
"""

from __future__ import annotations

import importlib
import json



def _load():
    return importlib.import_module("yunohost.diagnosers.65-projections")


def _run(monkeypatch, tmp_path, cursors, now=10_000.0):
    module = _load()
    monkeypatch.setattr(module, "CURSOR_DIR", str(tmp_path))
    for name, body in cursors.items():
        (tmp_path / name).write_text(json.dumps(body), encoding="utf-8")
    monkeypatch.setattr("time.time", lambda: now)
    diagnoser = object.__new__(module.MyDiagnoser)
    return list(module.MyDiagnoser.run(diagnoser))


def test_no_cursors_is_informational(monkeypatch, tmp_path):
    items = _run(monkeypatch, tmp_path, {})
    assert [i["summary"] for i in items] == ["diagnosis_projection_no_cursors"]
    assert items[0]["status"] == "INFO"


def test_fresh_projection_success(monkeypatch, tmp_path):
    items = _run(
        monkeypatch,
        tmp_path,
        {"identity.json": {"name": "identity", "revision": "rev:3", "updated_at": 9_999.0}},
    )
    assert items[0]["summary"] == "diagnosis_projection_fresh"
    assert items[0]["status"] == "SUCCESS"
    assert items[0]["meta"]["revision"] == "rev:3"


def test_stale_projection_warns(monkeypatch, tmp_path):
    items = _run(
        monkeypatch,
        tmp_path,
        {"identity.json": {"name": "identity", "revision": "rev:3", "updated_at": 1.0}},
    )
    assert items[0]["summary"] == "diagnosis_projection_stale"
    assert items[0]["status"] == "WARNING"


def test_missing_revision_warns(monkeypatch, tmp_path):
    items = _run(
        monkeypatch,
        tmp_path,
        {"identity.json": {"name": "identity", "revision": "", "updated_at": 9_999.0}},
    )
    assert items[0]["summary"] == "diagnosis_projection_no_revision"
    assert items[0]["status"] == "WARNING"


def test_malformed_cursor_ignored(monkeypatch, tmp_path):
    module = _load()
    monkeypatch.setattr(module, "CURSOR_DIR", str(tmp_path))
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    diagnoser = object.__new__(module.MyDiagnoser)
    items = list(module.MyDiagnoser.run(diagnoser))
    assert items[0]["summary"] == "diagnosis_projection_no_cursors"
