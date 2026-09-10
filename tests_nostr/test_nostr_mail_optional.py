"""Tests for the mail-stack-is-optional guards (roadmap §18.2 Phase 3).

Mail (Postfix/Dovecot/OpenDKIM) is no longer part of the default platform:
code that used to assume it was always present must degrade gracefully
instead of erroring out when it isn't installed.
"""

from __future__ import annotations

from unittest.mock import patch

from yunohost.utils.mail import mail_stack_installed


def test_mail_stack_installed_true_when_all_binaries_present():
    with patch("shutil.which", return_value="/usr/sbin/x"):
        assert mail_stack_installed() is True


def test_mail_stack_installed_false_when_any_binary_missing():
    def which(name):
        return None if name == "dovecot" else "/usr/sbin/x"

    with patch("shutil.which", side_effect=which):
        assert mail_stack_installed() is False


def test_mail_stack_installed_false_when_none_present():
    with patch("shutil.which", return_value=None):
        assert mail_stack_installed() is False
