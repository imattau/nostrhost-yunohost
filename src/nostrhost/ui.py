"""Native interactive CLI layer (Moulinette interface ``prompt``/``display``).

The fork calls ``Moulinette.prompt`` / ``Moulinette.display`` for
interactive confirmation and password entry.  Moulinette implemented these
on the CLI interface with ``prompt_toolkit``; this module is a stdlib-only
replacement with the same signature and semantics:

* ``prompt`` refuses to run when stdin is not a tty (the fork guards every
  interactive call with ``os.isatty(1)`` anyway), and supports password
  masking, a confirmation second-entry, a default/prefill value, multiline
  editing via ``$EDITOR``, and tab-completion hints (accepted for API
  compatibility; completion is best-effort).
* ``display`` renders the ``success``/``warning``/``error``/``info`` prefixes
  exactly as moulinette did, so the CLI output does not change.

The ``Interface`` class below is what a driver registers with
``nostrhost.core.set_interface`` / ``Moulinette._interface``; the module
functions are the direct call path for new code.
"""

from __future__ import annotations

import getpass
import os
import sys
import tempfile
from typing import Any

from .core import NostrHostError, NostrHostValidationError
from .i18n import colorize, tr


class Interface:
    """Command-line interface object (moulinette CLI ``Interface`` shape)."""

    type = "cli"

    def prompt(
        self,
        message: str,
        is_password: bool = False,
        confirm: bool = False,
        color: str = "blue",
        prefill: str = "",
        is_multiline: bool = False,
        autocomplete: list[str] | None = None,
        help: str | None = None,  # noqa: A002 - moulinette signature
    ) -> str:
        return prompt(
            message,
            is_password=is_password,
            confirm=confirm,
            color=color,
            prefill=prefill,
            is_multiline=is_multiline,
            autocomplete=autocomplete or [],
            help=help,
        )

    def display(self, message: str, style: str = "info") -> None:
        return display(message, style)

    def confirm(self, question: str, default: bool = False) -> bool:
        return confirm(question, default)

    def ask(self, *args: Any, **kwargs: Any) -> str:
        return self.prompt(*args, **kwargs)


def _require_tty() -> None:
    if not sys.stdin.isatty():
        raise NostrHostError(
            "Not a tty, can't do interactive prompts", raw_msg=True
        )


def _read_value(
    message: str,
    is_password: bool,
    color: str,
    prefill: str,
    is_multiline: bool,
    autocomplete: list[str],
    help: str | None,  # noqa: A002 - moulinette signature
) -> str:
    if is_multiline:
        value = input(colorize(tr("edit_text_question", message), color)).strip().lower()
        if value in ("", "n", "no"):
            return prefill
        return _edit_via_editor(prefill)
    prompt_text = colorize(message, color) + ": "
    if is_password:
        return getpass.getpass(prompt_text)
    if autocomplete:
        # Best-effort: expose completion candidates via the readline completer
        # when available; the signature stays compatible with moulinette.
        _install_completion(autocomplete)
    return input(prompt_text) if prefill == "" else (
        input(prompt_text) or prefill
    )


def _install_completion(autocomplete: list[str]) -> None:
    try:
        import readline  # noqa: PLC0415 - only needed for interactive input

        def completer(text: str, state: int) -> str | None:
            candidates = [c for c in autocomplete if c.startswith(text)]
            return candidates[state] if state < len(candidates) else None

        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")
    except ImportError:
        pass


def _edit_via_editor(prefill: str) -> str:
    editor = os.environ.get("EDITOR") or "editor"
    with tempfile.NamedTemporaryFile(suffix=".tmp", mode="w+", encoding="utf-8") as tf:
        tf.write(prefill)
        tf.flush()
        if os.system(f"{editor} {tf.name}") != 0:
            return prefill
        tf.seek(0)
        return tf.read()


def prompt(
    message: str,
    is_password: bool = False,
    confirm: bool = False,
    color: str = "blue",
    prefill: str = "",
    is_multiline: bool = False,
    autocomplete: list[str] | None = None,
    help: str | None = None,  # noqa: A002 - moulinette signature
) -> str:
    """Prompt for a value on the terminal, mirroring moulinette's CLI prompt."""
    _require_tty()
    value = _read_value(
        message, is_password, color, prefill, is_multiline, autocomplete or [], help
    )
    if confirm:
        m = message[0].lower() + message[1:]
        if _read_value(
            tr("confirm", prompt=m), is_password, color, prefill, False, [], None
        ) != value:
            raise NostrHostValidationError("values_mismatch")
    return value


def display(message: str, style: str = "info") -> None:
    """Display a message with the same prefixes as moulinette's CLI."""
    if style == "success":
        print("{} {}".format(colorize(tr("success"), "green"), message))
    elif style == "warning":
        print("{} {}".format(colorize(tr("warning"), "yellow"), message))
    elif style == "error":
        print("{} {}".format(colorize(tr("error"), "red"), message))
    else:
        print(message)


def confirm(question: str, default: bool = False) -> bool:
    """Yes/no confirmation returning a boolean."""
    suffix = " [Y/n]: " if default else " [y/N]: "
    value = prompt(question + suffix)
    if value.strip().lower() in ("y", "yes"):
        return True
    if value.strip().lower() in ("n", "no"):
        return False
    return default


# --------------------------------------------------------------------------- #
# result presentation (moulinette CLI output parity)

from collections import OrderedDict
from datetime import date, datetime
from json import JSONEncoder


def pretty_date(value: Any) -> str:
    """Render a date/datetime in the system-local time zone."""
    if isinstance(value, datetime):
        return value.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, date):
        return value.strftime("%Y-%m-%d")
    return value


def plain_print_dict(d: Any, depth: int = 0) -> None:
    """Print a value/dict/list recursively in a script-friendly way.

    Mirrors moulinette's CLI ``plain`` output:
        #key / ##nested / value / one value per line.
    """
    if depth == 0 and isinstance(d, dict) and len(d) == 1:
        _, d = d.popitem()
    if isinstance(d, (tuple, set)):
        d = list(d)
    if isinstance(d, list):
        for v in d:
            plain_print_dict(v, depth + 1)
    elif isinstance(d, dict):
        for k, v in d.items():
            print("{}#{}".format("#" * depth, k))
            plain_print_dict(v, depth + 1)
    else:
        print(d)


def pretty_print_dict(d: Any, depth: int = 0) -> None:
    """Pretty-print a result dict with colored keys (moulinette parity)."""
    keys = list(d.keys())
    if not isinstance(d, OrderedDict):
        keys = sorted(keys)
    for k in keys:
        v = d[k]
        k = colorize(str(k), "purple")
        if isinstance(v, (tuple, set)):
            v = list(v)
        if isinstance(v, list) and len(v) == 1:
            v = v[0]
        if isinstance(v, dict):
            print("{:s}{}: ".format("  " * depth, k))
            pretty_print_dict(v, depth + 1)
        elif isinstance(v, list):
            print("{:s}{}: ".format("  " * depth, k))
            for value in v:
                if isinstance(value, (dict, list)):
                    pretty_print_dict({str(k): value}, depth + 1)
                else:
                    print("{:s}- {}".format("  " * (depth + 1), pretty_date(value)))
        else:
            print("{:s}{}: {}".format("  " * depth, k, pretty_date(v)))


class JSONExtendedEncoder(JSONEncoder):
    """Extended JSON encoder that never raises (moulinette parity)."""

    def default(self, o: Any) -> Any:
        if isinstance(o, set) or (hasattr(o, "__iter__") and hasattr(o, "next")):
            return list(o)
        if isinstance(o, date):
            return pretty_date(o)
        return repr(o)


def format_result(result: Any, output_as: str | None) -> None:
    """Print an operation result according to ``--output-as``."""
    if output_as == "none" or result is None:
        return
    if output_as == "json":
        print(JSONExtendedEncoder().encode(result))
    elif output_as == "plain":
        plain_print_dict(result)
    elif isinstance(result, dict):
        pretty_print_dict(result)
    else:
        print(pretty_date(result))
