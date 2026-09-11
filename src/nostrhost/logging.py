"""Native logging helpers (Moulinette ``moulinette.utils.log`` /
``moulinette.interfaces.cli`` replacement).

The fork's ``utils.logging`` configures the ``yunohost`` logger tree with a
``moulinette.interfaces.cli.TTYHandler`` for CLI output.  This module ports
that handler (and the ``SUCCESS`` level it relies on) so the logging
configuration stops referencing the moulinette package; the CLI output format
is unchanged.  ``getActionLogger`` covers the one remaining
``moulinette.utils.log`` import in the fork.
"""

from __future__ import annotations

import logging
import sys

SUCCESS = 25

LEVELS_COLOR = {
    logging.NOTSET: "white",
    logging.DEBUG: "white",
    logging.INFO: "cyan",
    SUCCESS: "green",
    logging.WARNING: "yellow",
    logging.ERROR: "red",
    logging.CRITICAL: "red",
}

# Same ANSI template as moulinette's CLI so output stays identical.
CLI_COLOR_TEMPLATE = "\033[{:d}m\033[1m"
END_CLI_COLOR = "\033[m"
colors_codes = {
    "red": CLI_COLOR_TEMPLATE.format(31),
    "green": CLI_COLOR_TEMPLATE.format(32),
    "yellow": CLI_COLOR_TEMPLATE.format(33),
    "blue": CLI_COLOR_TEMPLATE.format(34),
    "purple": CLI_COLOR_TEMPLATE.format(35),
    "cyan": CLI_COLOR_TEMPLATE.format(36),
    "white": CLI_COLOR_TEMPLATE.format(37),
}


def getActionLogger(name: str) -> logging.Logger:
    """Return the logger for an operation/action name."""
    return logging.getLogger(name)


class TTYHandler(logging.StreamHandler):
    """TTY log handler (port of ``moulinette.interfaces.cli.TTYHandler``).

    Level names are colorized when the stream is a tty, and records at
    ``WARNING`` and above go to stderr (everything else to stdout).  The
    colorized level is stored on the record as ``level_with_color`` so a
    custom formatter can reference it.
    """

    def __init__(self, message_key: str = "message_with_color") -> None:
        super().__init__()
        self.message_key = message_key

    def format(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()
        level = record.levelname
        level_with_color = level
        if self.supports_color():
            color = LEVELS_COLOR.get(record.levelno, "white")
            level_with_color = f"{colors_codes[color]}{level}{END_CLI_COLOR}"
            if self.level == logging.DEBUG:
                level_with_color = level_with_color + " " * max(0, 7 - len(level))
        if self.formatter:
            record.__dict__["level_with_color"] = level_with_color
            return self.formatter.format(record)
        return level_with_color + " " + msg

    def emit(self, record: logging.LogRecord) -> None:
        if record.levelno >= logging.WARNING:
            self.stream = sys.stderr
        else:
            self.stream = sys.stdout
        super().emit(record)

    def supports_color(self) -> bool:
        return bool(getattr(self.stream, "isatty", lambda: False)())
