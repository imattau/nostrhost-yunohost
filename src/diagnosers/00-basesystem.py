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

import logging
import os
import re
from collections.abc import Generator
from typing import Any

from ..app_catalog import SecurityIssueInfos, _load_security_issues_list
from ..diagnosis import Diagnoser
from ..utils.file_utils import read_file
from ..utils.process import check_output
from ..utils.system import (
    debian_version,
    dpkg_compare_version,
    dpkg_list_installed_packages,
    dpkg_package_version,
    system_arch,
    system_virt,
    ynh_packages_version,
)

logger = logging.getLogger("yunohost.diagnosis")

# The kernel exposes per-vulnerability mitigation status here (>= 4.15).
MELTDOWN_STATUS_PATH = "/sys/devices/system/cpu/vulnerabilities/meltdown"


class MyDiagnoser(Diagnoser):  # type: ignore
    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 600
    dependencies: list[str] = []

    def run(self) -> Generator[dict[str, Any], None, None]:
        virt = system_virt()
        if virt.lower() == "none":
            virt = "bare-metal"

        # Detect arch
        arch = system_arch()
        hardware = dict(
            meta={"test": "hardware"},
            status="INFO",
            data={"virt": virt, "arch": arch},
            summary="diagnosis_basesystem_hardware",
        )

        # Also possibly the board / hardware name
        if os.path.exists("/proc/device-tree/model"):
            model = read_file("/proc/device-tree/model").strip().replace("\x00", "")
            hardware["data"]["model"] = model  # type: ignore
            hardware["details"] = ["diagnosis_basesystem_hardware_model"]
        elif os.path.exists("/sys/devices/virtual/dmi/id/sys_vendor"):
            model = read_file("/sys/devices/virtual/dmi/id/sys_vendor").strip()
            if os.path.exists("/sys/devices/virtual/dmi/id/product_name"):
                product_name = read_file(
                    "/sys/devices/virtual/dmi/id/product_name"
                ).strip()
                model = f"{model} {product_name}"
            hardware["data"]["model"] = model  # type: ignore
            hardware["details"] = ["diagnosis_basesystem_hardware_model"]

        yield hardware

        # Kernel version
        kernel_version = read_file("/proc/sys/kernel/osrelease").strip()
        yield dict(
            meta={"test": "kernel"},
            data={"kernel_version": kernel_version},
            status="INFO",
            summary="diagnosis_basesystem_kernel",
        )

        # Debian release
        yield dict(
            meta={"test": "host"},
            data={"debian_version": debian_version()},
            status="INFO",
            summary="diagnosis_basesystem_host",
        )

        # Yunohost packages versions
        # We check if versions are consistent (e.g. all 3.6 and not 3 packages with 3.6 and the other with 3.5)
        # This is a classical issue for upgrades that failed in the middle
        # (or people upgrading half of the package because they did 'apt upgrade' instead of 'dist-upgrade')
        # Here, ynh_core_version is for example "3.5.4.12", so [:3] is "3.5" and we check it's the same for all packages
        ynh_packages = ynh_packages_version()
        ynh_core_version = ynh_packages["yunohost"]["version"]
        consistent_versions = all(
            infos["version"][:3] == ynh_core_version[:3]
            for infos in ynh_packages.values()
        )
        ynh_version_details = [
            (
                "diagnosis_basesystem_ynh_single_version",
                {
                    "package": package,
                    "version": infos["version"],
                    "repo": infos["repo"],
                },
            )
            for package, infos in ynh_packages.items()
        ]

        yield dict(
            meta={"test": "ynh_versions"},
            data={
                "main_version": ynh_core_version,
                "repo": ynh_packages["yunohost"]["repo"],
            },
            status="INFO" if consistent_versions else "ERROR",
            summary=(
                "diagnosis_basesystem_ynh_main_version"
                if consistent_versions
                else "diagnosis_basesystem_ynh_inconsistent_versions"
            ),
            details=ynh_version_details,
        )

        if self.is_vulnerable_to_meltdown():
            yield dict(
                meta={"test": "meltdown"},
                status="ERROR",
                summary="diagnosis_security_vulnerable_to_meltdown",
                details=["diagnosis_security_vulnerable_to_meltdown_details"],
            )

        bad_sury_packages = list(self.bad_sury_packages())
        if bad_sury_packages:
            cmd_to_fix = "apt install --allow-downgrades " + " ".join(
                [f"{package}={version}" for package, version in bad_sury_packages]
            )
            yield dict(
                meta={"test": "packages_from_sury"},
                data={"cmd_to_fix": cmd_to_fix},
                status="WARNING",
                summary="diagnosis_package_installed_from_sury",
                details=["diagnosis_package_installed_from_sury_details"],
            )

        if self.backports_in_sources_list():
            yield dict(
                meta={"test": "backports_in_sources_list"},
                status="WARNING",
                summary="diagnosis_backports_in_sources_list",
            )

        # Using yunohost testing channel
        if (
            os.system(
                "grep -q '^\\s*deb\\s*.*yunohost.org.*\\stesting' /etc/apt/sources.list /etc/apt/sources.list.d/*"
            )
            == 0
        ):
            yield dict(
                meta={"test": "apt_yunohost_channel"},
                status="WARNING",
                summary="diagnosis_using_yunohost_testing",
                details=["diagnosis_using_yunohost_testing_details"],
            )

        # Apt being mapped to 'stable' (instead of 'buster/bullseye/bookworm/trixie/...')
        # will cause the machine to spontaenously upgrade everything as soon as next debian is released ...
        # Note that we grep this from the policy for libc6, because it's hard to know exactly which apt repo
        # is configured (it may not be simply debian.org)
        if (
            os.system(
                "apt policy libc6 2>/dev/null | grep '^\\s*500' | awk '{print $3}' | tr '/' ' ' | awk '{print $1}' | grep -q 'stable'"
            )
            == 0
        ):
            yield dict(
                meta={"test": "apt_debian_codename"},
                status="WARNING",
                summary="diagnosis_using_stable_codename",
                details=["diagnosis_using_stable_codename_details"],
            )

        if self.number_of_recent_auth_failure() > 750:
            yield dict(
                meta={"test": "high_number_auth_failure"},
                status="WARNING",
                summary="diagnosis_high_number_auth_failures",
            )

        rfkill_wifi = self.rfkill_wifi()
        if len(rfkill_wifi) > 0:
            yield dict(
                meta={"test": "rfkill_wifi"},
                status="ERROR",
                summary="diagnosis_rfkill_wifi",
                details=["diagnosis_rfkill_wifi_details"],
                data={"rfkill_wifi_error": rfkill_wifi},
            )

        yield from self.security_issues()

    def bad_sury_packages(self) -> Generator[tuple[str, str], None, None]:
        packages_to_check = ["openssl", "libssl1.1", "libssl-dev"]
        for package in packages_to_check:
            cmd = "dpkg --list | grep '^ii' | grep gbp | grep -q -w %s" % package
            # If version currently installed is not from sury, nothing to report
            if os.system(cmd) != 0:
                continue

            cmd = (
                "LC_ALL=C apt policy %s 2>&1 | grep http -B1 | tr -d '*' | grep '+deb' | grep -v 'gbp' | head -n 1 | awk '{print $1}'"
                % package
            )
            version_to_downgrade_to = check_output(cmd)
            yield (package, version_to_downgrade_to)

    def backports_in_sources_list(self) -> bool:
        cmd = "grep -q -nr '^ *deb .*-backports' /etc/apt/sources.list*"
        return os.system(cmd) == 0

    def number_of_recent_auth_failure(self) -> int:
        # Those syslog facilities correspond to auth and authpriv
        # c.f. https://unix.stackexchange.com/a/401398
        # and https://wiki.archlinux.org/title/Systemd/Journal#Facility
        cmd = "journalctl -q SYSLOG_FACILITY=10 SYSLOG_FACILITY=4 --since '1day ago' | grep 'authentication failure' | wc -l"

        n_failures = check_output(cmd)
        try:
            return int(n_failures)
        except Exception:
            logger.warning(
                "Failed to parse number of recent auth failures, expected an int, got '%s'"
                % n_failures
            )
            return -1

    def is_vulnerable_to_meltdown(self) -> bool:
        # Meltdown CVE: https://security-tracker.debian.org/tracker/CVE-2017-5754
        #
        # The kernel exposes the per-mitigation status directly (>= 4.15) at
        # /sys/devices/system/cpu/vulnerabilities/<name>, so read that instead
        # of shelling out to the 2018-era vendored spectre-meltdown-checker
        # script (whose expensive run was cached in /tmp). The interface is
        # x86-specific: when the file is absent (e.g. on ARM, where Meltdown
        # does not apply) there is nothing to diagnose.
        try:
            with open(MELTDOWN_STATUS_PATH, encoding="utf-8") as fh:
                status = fh.read().strip()
        except OSError:
            logger.debug("No kernel meltdown status interface at %s", MELTDOWN_STATUS_PATH)
            return False
        logger.debug("Kernel meltdown status: %s", status)
        return status.lower().startswith("vulnerable")

    def rfkill_wifi(self) -> str:
        if os.path.isfile("/etc/profile.d/wifi-check.sh"):
            cmd = "bash /etc/profile.d/wifi-check.sh"
            return check_output(cmd)  # type: ignore
        else:
            return ""

    def security_issues(self):
        installed_packages = dpkg_list_installed_packages()
        security_issues_list_per_pkg: dict[str, list[SecurityIssueInfos]] = (
            _load_security_issues_list()["system"]
        )
        for package, issues in security_issues_list_per_pkg.items():
            if package not in installed_packages and package != "kernel":
                continue

            if package != "kernel":
                current_version = dpkg_package_version(package)
            else:
                # NOT equivalent to uname -r ... we are looking for the
                # "mainline" kernel version, not the debian kernel version,
                # cf issues#2803
                raw_kernel_comment = read_file("/proc/sys/kernel/version").strip()
                version_matches = re.findall(r"\s[0-9]\S+", raw_kernel_comment)
                if len(version_matches) != 1:
                    logger.warning(
                        f"Unable to extract mainline kernel version from the kernel info '{raw_kernel_comment}' ... Therefore YunoHost will be unable to check for security issues related to the kernel. Please try to report this message to the YunoHost team to improve the situation"
                    )
                    continue
                current_version = version_matches[0].strip()
                # RPi have their mainline kernel version number somehow
                # starting with "1:" which messes up the version comparison
                # later
                if ":" in current_version:
                    current_version = current_version.split(":")[1]

                # FIXME : so far this whole kernel check is not reliable on every setup
                # because not every context has the kernel from Debian :
                # - RPI ships their own kernel possibly with more recent
                # versions than the standard Debian setup
                # - LXC/containers use the kernel from the host, which may be
                # in a totally different distribution therefore we can't just
                # expect the kernel version to be related to the debian version
                # we're running (e.g. 6.1.x for Bookworm, 6.12.x for Trixie)

            for issue in issues:
                raw_fixed_in_version = issue["fixed_in_version"]
                if isinstance(raw_fixed_in_version, dict):
                    if debian_version() not in raw_fixed_in_version:
                        logger.warning(
                            f"Not able to check versions in which security issue is fixed for package '{package}' (no version specified for Debian {debian_version()})"
                        )
                        continue
                    fixed_in_version = raw_fixed_in_version[debian_version()]
                else:
                    fixed_in_version = raw_fixed_in_version

                if dpkg_compare_version(current_version, fixed_in_version) >= 0:
                    # installed version is >= to the version which fixes the issue, therefore there's no issue to report
                    continue

                level = "error" if issue["level"] == "danger" else "warning"
                if isinstance(issue["more_infos"], list):
                    more_infos_list = ", ".join(issue["more_infos"])
                else:
                    more_infos_list = issue["more_infos"]
                yield dict(
                    meta={"package": package},
                    status=level.upper(),
                    # i18n: diagnosis_package_security_issue_warning
                    # i18n: diagnosis_package_security_issue_error
                    summary=f"diagnosis_package_security_issue_{level}",
                    data={
                        **issue,
                        "fixed_in_version": fixed_in_version,
                        "more_infos_list": more_infos_list,
                        "current_version": current_version,
                    },
                )
