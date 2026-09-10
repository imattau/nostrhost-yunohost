#!/usr/bin/env python3
#
# Copyright (c) 2026 YunoHost Contributors
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


import shutil


def mail_stack_installed() -> bool:
    """
    Whether the (now optional, roadmap §18.2) local mail stack — Postfix,
    Dovecot, OpenDKIM — is present on this system. Core no longer depends on
    it: it's installed the same way any other app would be, so any code path
    that assumes a local mail server (diagnosis, domain regen-conf) must
    check this first instead of erroring out on missing binaries/services.
    """
    return all(shutil.which(b) for b in ("postfix", "dovecot", "opendkim"))


def get_pending_mails_nb() -> int:
    """
    Return number of pending mails in queue
    """
    from .process import check_output

    command = (
        'postqueue -p | grep -v "Mail queue is empty" | grep -c "^[A-Z0-9]" || true'
    )
    output = check_output(command)
    return int(output)
