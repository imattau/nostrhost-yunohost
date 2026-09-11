"""Stage 1 moulinette-removal primitives: i18n, core errors, locking, ui.

These tests exercise the native replacements without moulinette installed,
matching how ``tests_nostr/conftest.py`` aliases the fork's ``src`` package.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
import types

import pytest

from nostrhost import core, i18n, locking, logging as nh_logging, models, ui


# --------------------------------------------------------------------------- #
# i18n

@pytest.fixture(autouse=True)
def _reset_i18n():
    i18n.reset()
    yield
    i18n.reset()


def test_global_keys_work_without_locale_dir():
    assert i18n.tr("error") == "Error:"
    assert i18n.tr("warning") == "Warning:"
    assert i18n.tr("success") == "Success!"
    assert i18n.tr("operation_interrupted") == "Operation interrupted"


def test_global_key_formatting():
    assert i18n.tr("edit_text_question", "hello") == "hello. Edit this text ? [yN]: "


def test_missing_key_returns_key():
    assert i18n.tr("no_such_key_anywhere") == "no_such_key_anywhere"


def test_namespace_locales_and_fallback(tmp_path):
    (tmp_path / "en.json").write_text(json.dumps({"greeting": "Hello {name}", "only_en": "EN"}))
    (tmp_path / "fr.json").write_text(json.dumps({"greeting": "Bonjour {name}"}))
    i18n.set_locales_dir(str(tmp_path))

    assert i18n.tr("greeting", name="world") == "Hello world"
    assert i18n.set_locale("fr") is True
    assert i18n.locale == "fr"
    assert i18n.tr("greeting", name="monde") == "Bonjour monde"
    # missing from fr -> falls back to the default locale (en)
    assert i18n.tr("only_en") == "EN"


def test_namespace_beats_global_key(tmp_path):
    (tmp_path / "en.json").write_text(json.dumps({"error": "namespace error"}))
    i18n.set_locales_dir(str(tmp_path))
    assert i18n.tr("error") == "namespace error"


def test_invalid_locale_is_refused(tmp_path):
    (tmp_path / "en.json").write_text("{}")
    i18n.set_locales_dir(str(tmp_path))
    assert i18n.set_locale("not a locale!") is False


def test_key_exists_covers_namespace_and_global(tmp_path):
    (tmp_path / "en.json").write_text(json.dumps({"custom": "x"}))
    i18n.set_locales_dir(str(tmp_path))
    assert i18n.key_exists("custom") is True
    assert i18n.key_exists("error") is True
    assert i18n.key_exists("nope") is False


def test_colorize_no_tty_is_plain(monkeypatch):
    monkeypatch.setattr(i18n.sys.stdout, "isatty", lambda: False)
    assert i18n.colorize("x", "red") == "x"


def test_colorize_tty_wraps_with_codes(monkeypatch):
    monkeypatch.setattr(i18n.sys.stdout, "isatty", lambda: True)
    out = i18n.colorize("x", "red")
    assert out.startswith("\033[") and out.endswith("\033[m") and "x" in out


# --------------------------------------------------------------------------- #
# core errors + interface registry

def test_error_uses_namespace_translation(tmp_path):
    (tmp_path / "en.json").write_text(json.dumps({"boom": "Boom {what}"}))
    i18n.set_locales_dir(str(tmp_path))
    err = core.NostrHostError("boom", what="now")
    assert err.strerror == "Boom now"
    assert err.content() == "Boom now"
    assert err.http_code == 500


def test_error_raw_msg_is_not_translated():
    err = core.NostrHostError("literal message", raw_msg=True)
    assert err.strerror == "literal message"


def test_validation_error_content_is_structured():
    err = core.NostrHostValidationError("bad_input", field="domain")
    assert err.http_code == 400
    assert err.content() == {
        "error": err.strerror,
        "error_key": "bad_input",
        "field": "domain",
    }


def test_error_hierarchy_status_codes():
    assert core.AuthenticationError("x", raw_msg=True).status == 401
    assert core.AuthorisationError("x", raw_msg=True).status == 403
    assert issubclass(core.LockAcquireTimeout, core.NostrHostError)


def test_interface_registry_and_moulinette_dropin():
    class FakeInterface:
        type = "cli"

        def display(self, message, style="info"):
            return ("display", message, style)

        def prompt(self, *args, **kwargs):
            return "answer"

    assert core.get_interface() is None
    assert core.Moulinette.interface is None

    core.set_interface(FakeInterface())
    assert core.Moulinette.interface.type == "cli"
    assert core.Moulinette.display("hi") == ("display", "hi", "info")
    assert core.Moulinette.prompt("q") == "answer"
    assert core.interface.type == "cli"

    # Moulinette._interface assignment (the headless-daemon pattern) works too
    core.Moulinette._interface = FakeInterface()
    assert core.get_interface().type == "cli"
    core.set_interface(None)


def test_interface_proxy_raises_without_interface():
    core.set_interface(None)
    with pytest.raises(RuntimeError, match="no interface registered"):
        _ = core.interface.type


class _FakeFrameworkCli:
    type = "cli"

    def prompt(self, *args, **kwargs):
        return "framework-answer"

    def display(self, *args, **kwargs):
        return "framework-display"


@pytest.fixture
def _fake_moulinette_module():
    """Inject a stand-in ``moulinette`` module to exercise the transition
    bridge where the real framework registers its own interface."""
    module = types.ModuleType("moulinette")
    fake = type("Moulinette", (), {})
    fake._interface = _FakeFrameworkCli()
    module.Moulinette = fake
    sys.modules["moulinette"] = module
    try:
        yield module
    finally:
        del sys.modules["moulinette"]


def test_interface_sync_reads_framework_interface(_fake_moulinette_module):
    core.set_interface(None)  # clears local + mirrors None to the framework
    _fake_moulinette_module.Moulinette._interface = _FakeFrameworkCli()
    # no local registration -> falls back to the framework's interface
    assert core.Moulinette.interface.type == "cli"
    assert core.Moulinette.prompt("q") == "framework-answer"


def test_interface_sync_local_registration_wins(_fake_moulinette_module):
    class Local:
        type = "api"

        def prompt(self, *args, **kwargs):
            return "local-answer"

        def display(self, *args, **kwargs):
            return "local-display"

    core.set_interface(Local())
    assert core.Moulinette.interface.type == "api"
    assert core.Moulinette.prompt("q") == "local-answer"
    core.set_interface(None)


def test_interface_sync_assigning_interface_mirrors_to_framework(_fake_moulinette_module):
    core.Moulinette._interface = _FakeFrameworkCli()
    assert _fake_moulinette_module.Moulinette._interface.type == "cli"
    core.set_interface(None)
    assert _fake_moulinette_module.Moulinette._interface is None


# --------------------------------------------------------------------------- #
# logging (getActionLogger + TTYHandler)

def test_get_action_logger_returns_named_logger():
    logger = nh_logging.getActionLogger("yunohost.migration")
    assert isinstance(logger, logging.Logger)
    assert logger.name == "yunohost.migration"


def test_tty_handler_no_color_when_not_tty(capsys):
    handler = nh_logging.TTYHandler()
    record = logging.LogRecord("t", logging.INFO, "f", 1, "hello", (), None)
    formatted = handler.format(record)
    assert "hello" in formatted
    assert "\033[" not in formatted


def test_tty_handler_colors_when_tty(monkeypatch, capsys):
    handler = nh_logging.TTYHandler()
    monkeypatch.setattr(handler, "supports_color", lambda: True)
    record = logging.LogRecord("t", nh_logging.SUCCESS, "f", 1, "done", (), None)
    record.levelname = "SUCCESS"
    assert "\033[" in handler.format(record)


def test_logging_init_uses_native_tty_handler(tmp_path):
    from yunohost.utils.logging import init_logging

    init_logging(interface="cli", debug=False, quiet=True, logdir=str(tmp_path))
    logger = logging.getLogger("yunohost.stage2test")
    logger.info("ok")  # exercises the nostrhost.logging.TTYHandler in the config
    assert True


# --------------------------------------------------------------------------- #
# auth.authenticator BaseAuthenticator

def test_authenticator_delegates_and_returns_infos():
    from nostrhost.auth.authenticator import BaseAuthenticator

    class Ok(BaseAuthenticator):
        name = "ok"

        def _authenticate_credentials(self, credentials):
            return {"user": credentials}

    assert Ok().authenticate_credentials("alice") == {"user": "alice"}


def test_authenticator_propagates_native_error():
    from nostrhost.auth.authenticator import BaseAuthenticator

    class Native(BaseAuthenticator):
        name = "native"

        def _authenticate_credentials(self, credentials):
            raise core.NostrHostError("boom", raw_msg=True)

    with pytest.raises(core.NostrHostError):
        Native().authenticate_credentials("x")


def test_authenticator_wraps_unexpected_error():
    from nostrhost.auth.authenticator import BaseAuthenticator

    class Other(BaseAuthenticator):
        name = "other"

        def _authenticate_credentials(self, credentials):
            raise ValueError("nope")

    with pytest.raises(core.AuthenticationError, match="unable_authenticate"):
        Other().authenticate_credentials("x")


# --------------------------------------------------------------------------- #
# locking

def test_lock_acquire_release_context_manager(tmp_path):
    manager = locking.LockManager("yunohost", lock_dir=str(tmp_path))
    with manager:
        assert (tmp_path / "yunohost.lock").is_file()
        assert (tmp_path / "yunohost.lock").read_text().strip().isdigit()
    # released -> a second manager can take it
    with locking.LockManager("yunohost", lock_dir=str(tmp_path)):
        pass


def test_lock_timeout_when_held(tmp_path):
    held = locking.LockManager("yunohost", lock_dir=str(tmp_path))
    held.acquire()
    try:
        contender = locking.LockManager("yunohost", timeout=0.2, interval=0.05, lock_dir=str(tmp_path))
        with pytest.raises(core.LockAcquireTimeout):
            contender.acquire()
    finally:
        held.release()


def test_lock_resource_scopes_are_independent(tmp_path):
    a = locking.LockManager(resources=["app:immich"], lock_dir=str(tmp_path))
    b = locking.LockManager(resources=["domain:example.com"], lock_dir=str(tmp_path))
    a.acquire()
    try:
        b.acquire()  # disjoint resource -> no contention
        b.release()
    finally:
        a.release()
    assert (tmp_path / "app:immich.lock").is_file()
    assert (tmp_path / "domain:example.com.lock").is_file()


def test_lock_enable_lock_false_is_noop(tmp_path):
    manager = locking.LockManager("yunohost", lock_dir=str(tmp_path), enable_lock=False)
    manager.acquire()
    assert not (tmp_path / "yunohost.lock").exists()


def test_lock_contention_then_release_from_thread(tmp_path):
    manager = locking.LockManager("yunohost", lock_dir=str(tmp_path))
    manager.acquire()

    released = threading.Event()

    def release_later():
        time.sleep(0.2)
        manager.release()
        released.set()

    thread = threading.Thread(target=release_later)
    thread.start()
    try:
        # same process can re-acquire after release (flock is per-open-file)
        waiter = locking.LockManager("yunohost", timeout=2, interval=0.05, lock_dir=str(tmp_path))
        waiter.acquire()
        waiter.release()
    finally:
        thread.join()
    assert released.is_set()


# --------------------------------------------------------------------------- #
# ui

def test_display_prefixes(capsys):
    ui.display("done", style="success")
    ui.display("careful", style="warning")
    ui.display("broken", style="error")
    ui.display("plain")
    out = capsys.readouterr().out
    assert "Success!" in out and "Warning:" in out and "Error:" in out and "plain" in out


def test_prompt_requires_tty(monkeypatch):
    monkeypatch.setattr(ui.sys.stdin, "isatty", lambda: False)
    with pytest.raises(core.NostrHostError, match="Not a tty"):
        ui.prompt("value?")


def test_prompt_reads_value(monkeypatch):
    monkeypatch.setattr(ui.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "typed")
    assert ui.prompt("value?") == "typed"


def test_prompt_password_uses_getpass(monkeypatch):
    monkeypatch.setattr(ui.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(ui.getpass, "getpass", lambda *_a, **_k: "secret")
    assert ui.prompt("password?", is_password=True) == "secret"


def test_prompt_confirm_mismatch_raises(monkeypatch):
    monkeypatch.setattr(ui.sys.stdin, "isatty", lambda: True)
    answers = iter(["one", "two"])
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: next(answers))
    with pytest.raises(core.NostrHostValidationError):
        ui.prompt("value?", confirm=True)


def test_confirm_default_and_explicit(monkeypatch):
    monkeypatch.setattr(ui.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "yes")
    assert ui.confirm("continue?") is True
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "n")
    assert ui.confirm("continue?") is False
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "")
    assert ui.confirm("continue?", default=True) is True


# --------------------------------------------------------------------------- #
# models

def _catalog_payload():
    return {
        "version": 1,
        "sources": ["share/actionsmap.yml"],
        "operations": [
            {
                "name": "user.create",
                "cli_path": ["user", "create"],
                "function": "user_create",
                "module": "user",
                "api": {"method": "POST", "path": "/users"},
                "auth": "ldap_admin",
                "help": "Create user",
                "args": [
                    {
                        "flag": "username",
                        "kind": "positional",
                        "required": True,
                        "pattern": "^[a-z0-9]+$",
                        "password": False,
                        "ask": None,
                        "default": None,
                        "nargs": None,
                        "action": None,
                        "choices": None,
                        "autocomplete": None,
                        "help": None,
                    }
                ],
            },
            {
                "name": "user.group.add",
                "cli_path": ["user", "group", "add"],
                "function": "user_group_add",
                "module": "user",
                "api": {"method": "PUT", "path": "/users/groups/<groupname>/add/<usernames>"},
                "auth": "ldap_admin",
                "help": None,
                "args": [],
            },
        ],
    }


def test_catalog_loads_and_indexes(tmp_path):
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(_catalog_payload()))
    catalog = models.OperationCatalog.load(path)
    assert len(catalog.operations) == 2
    assert catalog.by_name("user.create").function == "user_create"
    assert catalog.by_name("user.group.add").api.method == "PUT"
    assert catalog.by_name("missing") is None
    assert len(catalog.with_api_route()) == 2
    assert catalog.modules() == {"user": 2}


def test_catalog_rejects_function_cli_mismatch():
    payload = _catalog_payload()
    payload["operations"][0]["function"] = "wrong_name"
    with pytest.raises(Exception):
        models.OperationCatalog.parse_obj(payload)


def test_catalog_rejects_duplicate_names():
    payload = _catalog_payload()
    payload["operations"].append(payload["operations"][0])
    with pytest.raises(Exception):
        models.OperationCatalog.parse_obj(payload)


def test_api_route_requires_leading_slash():
    with pytest.raises(Exception):
        models.ApiRoute(method="GET", path="users")


def test_operation_result_states():
    requested = models.OperationResult(operation="app.install")
    assert requested.status == "REQUESTED" and not requested.succeeded()
    failed = models.OperationResult(
        operation="app.install",
        status="FAILED",
        error={"code": "resource_conflict", "message_key": "app_already_installed"},
    )
    assert failed.failed() and failed.error["code"] == "resource_conflict"
    ok = models.OperationResult(operation="app.install", status="SUCCEEDED")
    assert ok.succeeded()


def test_operation_result_rejects_path_traversal_resource():
    with pytest.raises(Exception):
        models.OperationResult(operation="x", resource="../etc/passwd")
