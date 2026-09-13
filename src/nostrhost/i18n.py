"""Native translation service (Moulinette i18n replacement).

This module is the ``moulinette.m18n`` equivalent for NostrHost.  It keeps
moulinette's semantics so the mechanical import removal (Stage 2) can swap
``from moulinette import m18n`` for ``from nostrhost.i18n import tr`` without
behaviour change:

* JSON locale files are loaded from a directory (``set_locales_dir``), the
  same ``<locale>.json`` format moulinette used, with the same
  default-locale fallback and ``str.format`` argument handling.
* The small set of *global* moulinette keys the fork still relies on
  (``error``, ``warning``, ``success``, ``info``, ``operation_interrupted``,
  ...) is vendored here as a built-in dictionary, since the upstream
  ``moulinette`` package will no longer provide ``/usr/share/moulinette/
  locales`` once removed.  ``tr`` consults the namespace first and falls back
  to these global keys, so both ``m18n.n`` and ``m18n.g`` map to one call.

Callers should use the module-level ``tr`` function.  The ``Translator``
class is public for testing and for headless daemons that want an isolated
instance.
"""

from __future__ import annotations

import json
import locale as _locale_module
import logging
import os
import re
import sys
from typing import Any

logger = logging.getLogger("nostrhost.i18n")

# The fork calls ``m18n.g`` for a handful of keys that only exist in
# moulinette's own locale files.  Keep them vendored so ``tr`` works without
# the moulinette package installed.
GLOBAL_KEYS: dict[str, str] = {
    "error": "Error:",
    "warning": "Warning:",
    "success": "Success!",
    "info": "Info:",
    "operation_interrupted": "Operation interrupted",
    "invalid_usage": "Invalid usage, pass --help to see help",
    "root_required": "You must be root to perform this action",
    "instance_already_running": "There is already a YunoHost operation running. Please wait for it to finish before running another one.",
    "password": "Password",
    "values_mismatch": "Values don't match",
    "edit_text_question": "{}. Edit this text ? [yN]: ",
    "confirm": "{prompt}. Confirm ?",
    "warn_the_user_about_waiting_lock": "Another command is running, waiting for it to finish...",
    "warn_the_user_about_waiting_lock_again": "Another command is still running, still waiting...",
    "warn_the_user_that_lock_is_acquired": "The previous command finished, continuing now.",
}

# ANSI color codes for ``colorize``.
_CLI_COLOR_TEMPLATE = "\033[{:d}m\033[1m"
_END_CLI_COLOR = "\033[m"
_COLORS = {
    "red": _CLI_COLOR_TEMPLATE.format(31),
    "green": _CLI_COLOR_TEMPLATE.format(32),
    "yellow": _CLI_COLOR_TEMPLATE.format(33),
    "blue": _CLI_COLOR_TEMPLATE.format(34),
    "purple": _CLI_COLOR_TEMPLATE.format(35),
    "cyan": _CLI_COLOR_TEMPLATE.format(36),
    "white": _CLI_COLOR_TEMPLATE.format(37),
}


class Translator:
    """JSON-file translation table with default-locale fallback.

    Mirrors moulinette's ``Translator``: loads ``<locale>.json`` dictionaries
    keyed by translation key, formats the value with ``str.format``, and falls
    back to the default locale (then to the key itself) when a key is missing
    from the current locale.
    """

    def __init__(self, locale_dir: str, default_locale: str = "en") -> None:
        self.locale_dir = locale_dir
        self.default_locale = default_locale
        self.locale = default_locale
        self._translations: dict[str, dict[str, str]] = {}
        if not self._load_translations(default_locale):
            logger.error(
                "unable to load locale '%s' from '%s'. Does the file '%s/%s.json' exist?",
                default_locale,
                locale_dir,
                locale_dir,
                default_locale,
            )

    def get_locales(self) -> list[str]:
        try:
            return sorted(
                f[:-5] for f in os.listdir(self.locale_dir) if f.endswith(".json")
            )
        except OSError:
            return []

    def key_exists(self, key: str) -> bool:
        return key in self._translations.get(self.default_locale, {})

    def set_locale(self, locale_: str) -> bool:
        if locale_ not in self._translations and not self._load_translations(locale_):
            logger.debug(
                "unable to load locale '%s' from '%s'. Falling back to %s",
                locale_,
                self.locale_dir,
                self.default_locale,
            )
            self.locale = self.default_locale
            return False
        self.locale = locale_
        return True

    def translate(self, key: str, *args: Any, **kwargs: Any) -> str:
        for candidate in (self.locale, self.default_locale):
            table = self._translations.get(candidate, {})
            if key not in table:
                continue
            try:
                return table[key].format(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001 - match moulinette behaviour
                unformatted = table[key]
                logger.warning(
                    "failed to format translated string '%s': '%s' with arguments %s and %s, raising %s",
                    key,
                    unformatted,
                    args,
                    kwargs,
                    exc,
                )
                return unformatted
        logger.warning(
            "unable to retrieve string to translate with key '%s' for default locale 'locales/%s.json' file",
            key,
            self.default_locale,
        )
        return key

    def _load_translations(self, locale_: str, overwrite: bool = False) -> bool:
        if not overwrite and locale_ in self._translations:
            return True
        try:
            with open(f"{self.locale_dir}/{locale_}.json", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return False
        if not isinstance(data, dict):
            return False
        self._translations[locale_] = {str(k): str(v) for k, v in data.items()}
        return True


_default_locale = "en"
_locale = "en"
_namespace: Translator | None = None

# Namespaced state readable as attributes for Stage-2 drop-in compat with
# ``m18n.locale`` / ``m18n.default_locale``.
default_locale: str = _default_locale
locale: str = _locale

# Keep a global-key lookup independent of any locale directory so ``tr`` works
# even before ``set_locales_dir`` is called (e.g. in unit tests).
_GLOBAL_TABLE: dict[str, str] = dict(GLOBAL_KEYS)


def set_locales_dir(locales_dir: str) -> None:
    """Point the namespace translator at ``locales_dir`` and (re)load locales."""
    global _namespace
    _namespace = Translator(locales_dir, _default_locale)


def set_locale(locale_: str) -> bool:
    """Set the active locale, refusing invalid locale codes like moulinette."""
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_@.-]*", locale_ or ""):
        logger.warning("refusing to set locale '%s': not a valid locale code?", locale_)
        return False
    global _locale, locale
    _locale = locale_
    locale = locale_
    if _namespace is not None:
        _namespace.set_locale(locale_)
    return True


def get_locale() -> str:
    """Return the current user locale prefix (``LL``), mirroring moulinette."""
    try:
        lang = _locale_module.getdefaultlocale()[0]
    except Exception:  # noqa: BLE001 - locale lib is fragile in edge cases
        lang = os.getenv("LANG")
    if not lang:
        return ""
    return lang[:2]


def key_exists(key: str) -> bool:
    if _namespace is not None and _namespace.key_exists(key):
        return True
    return key in _GLOBAL_TABLE


def tr(key: str, *args: Any, **kwargs: Any) -> str:
    """Translate ``key`` to the current locale.

    Namespace (yunohost) locales take precedence, then the vendored global
    moulinette keys, then the key itself.  This is the single replacement for
    both ``m18n.n`` and ``m18n.g``.
    """
    if _namespace is not None:
        table = _namespace._translations.get(_namespace.locale, {})
        if key in table:
            try:
                return table[key].format(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001 - match moulinette behaviour
                logger.warning(
                    "failed to format translated string '%s' for locale '%s': %s",
                    key,
                    _namespace.locale,
                    exc,
                )
                return table[key]
        if _namespace.locale != _namespace.default_locale:
            default_table = _namespace._translations.get(_namespace.default_locale, {})
            if key in default_table:
                try:
                    return default_table[key].format(*args, **kwargs)
                except Exception as exc:  # noqa: BLE001 - match moulinette behaviour
                    logger.warning(
                        "failed to format translated string '%s' for default locale '%s': %s",
                        key,
                        _namespace.default_locale,
                        exc,
                    )
                    return default_table[key]
    if key in _GLOBAL_TABLE:
        try:
            return _GLOBAL_TABLE[key].format(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001 - match moulinette behaviour
            logger.warning(
                "failed to format global key '%s': %s", key, exc
            )
            return _GLOBAL_TABLE[key]
    return key


def colorize(text: str, color: str) -> str:
    """Colorize ``text`` when stdout is a tty, like moulinette's CLI helper."""
    if not sys.stdout.isatty():
        return text
    try:
        return "{:s}{:s}{:s}".format(_COLORS[color], text, _END_CLI_COLOR)
    except KeyError:
        return text


def reset() -> None:
    """Reset module state (mainly for tests)."""
    global _locale, _namespace, locale
    _locale = _default_locale
    locale = _default_locale
    _namespace = None
