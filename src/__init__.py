#!/usr/bin/env python3
#
# Copyright (c) 2025 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nostrhost.locking import LockManager

from nostrhost.i18n import get_locale, set_locale, set_locales_dir

from .utils.logging import init_logging

# The legacy YunoHost framework entry points (``cli`` / ``api`` / ``portalapi``
# via moulinette) have been retired: the native administration surface is the
# ``nostrhost`` CLI and the ``nostr-api`` HTTP API.  This module keeps only the
# helpers the daemons, scripts and tests use.


def is_installed() -> bool:
    """Returns whether YunoHost is installed on the system."""
    return os.path.isfile("/etc/yunohost/installed")


def init(
    interface: str = "cli",
    debug: bool = False,
    quiet: bool = False,
    logdir: str = "/var/log/yunohost",
) -> "LockManager":
    """
    This is a small util function ONLY meant to be used to initialize a Yunohost
    context when ran from tests or from scripts.
    """
    init_logging(interface=interface, debug=debug, quiet=quiet, logdir=logdir)
    init_i18n()
    from nostrhost.locking import LockManager

    lock = LockManager("yunohost", timeout=30)
    lock.acquire()
    return lock


def init_i18n() -> None:
    """
    Initialize the i18n locale dir and locale, so callers can use tr() without
    going through a CLI/API framework.
    """
    set_locales_dir("/usr/share/yunohost/locales/")
    set_locale(get_locale())
