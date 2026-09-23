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
import pwd
import re
import subprocess
import time
from importlib import import_module
from logging import getLogger
from typing import TYPE_CHECKING, Any, Callable, Literal, cast

from nostrhost.core import Moulinette
from nostrhost.i18n import tr
from typing_extensions import TypedDict

from .log import OperationLogger, is_unit_operation
from .utils.error import YunohostError, YunohostValidationError
from .utils.file_utils import read_yaml, write_to_yaml
from .utils.process import call_async_output
from .utils.system import (
    _apt_log_line_is_relevant,
    _dump_sources_list,
    _group_packages_per_categories,
    _list_upgradable_apt_packages,
    apt_dpkg_lock,
    dpkg_is_broken,
    dpkg_lock_available,
    ynh_packages_version,
)

if TYPE_CHECKING:
    from .app import AppInfo

MIGRATIONS_STATE_PATH = "/etc/yunohost/migrations.yaml"

if TYPE_CHECKING:
    from .utils.logging import YunohostLogger

    logger = cast(YunohostLogger, getLogger("yunohost.tools"))
else:
    logger = getLogger("yunohost.tools")


def tools_versions() -> dict[str, dict[str, str]]:
    return ynh_packages_version()


def tools_rootpw(new_password: str, check_strength: bool = True) -> None:
    from .utils.password import (
        assert_password_is_compatible,
        assert_password_is_strong_enough,
    )

    assert_password_is_compatible(new_password)
    if check_strength:
        assert_password_is_strong_enough("admin", new_password)

    proc = subprocess.run(
        ["passwd"],
        input=f"{new_password}\n{new_password}\n".encode("utf-8"),
        capture_output=True,
    )

    if proc.returncode == 0:
        logger.info(tr("root_password_changed"))
    else:
        logger.warning(proc.stdout)
        logger.warning(proc.stderr)
        logger.warning(tr("root_password_desynchronized"))


def _set_hostname(hostname: str, pretty_hostname: str | None = None) -> None:
    """
    Change the machine hostname using hostnamectl
    """

    if not pretty_hostname:
        pretty_hostname = f"(YunoHost/{hostname})"

    # First clear nsswitch cache for hosts to make sure hostname is resolved...
    subprocess.call(["nscd", "-i", "hosts"])

    # Then call hostnamectl
    commands = [
        "hostnamectl --static    set-hostname".split() + [hostname],
        "hostnamectl --transient set-hostname".split() + [hostname],
        "hostnamectl --pretty    set-hostname".split() + [pretty_hostname],
    ]

    for command in commands:
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        out, _ = p.communicate()

        if p.returncode != 0:
            logger.warning(command)
            logger.warning(out)
            logger.error(tr("domain_hostname_failed"))
        else:
            logger.debug(out)


@is_unit_operation(exclude=["dyndns_recovery_password", "password"])
def tools_postinstall(
    operation_logger: OperationLogger,
    domain: str,
    username: str,
    fullname: str,
    password: str,
    dyndns_recovery_password: str | None = None,
    ignore_dyndns: bool = False,
    force_diskspace: bool = False,
    overwrite_root_password: bool = True,
    i_have_read_terms_of_services: bool = False,
) -> None:
    """Legacy interactive postinstall wizard.

    Deprecated on NostrHost: fresh native installs use
    ``nostrhost postinstall new`` (root CLI) instead — no interactive
    admin/password flow, npub identity instead of LDAP. This entry point is
    retained for the admin SPA's legacy wizard and compatibility; a fresh
    NostrHost node no longer depends on it."""
    import psutil

    from .app_catalog import _update_apps_catalog
    from .domain import domain_add, domain_main_domain
    from .dyndns import _dyndns_available, dyndns_unsubscribe
    from .permission import _set_system_perms
    from .service import _run_service_command
    from .user import ADMIN_ALIASES, user_create
    from .utils.app_utils import _ask_confirmation
    from .utils.dns import is_yunohost_dyndns_domain
    from .utils.password import (
        assert_password_is_compatible,
        assert_password_is_strong_enough,
    )

    # Do some checks at first
    if os.path.isfile("/etc/yunohost/installed"):
        raise YunohostValidationError("yunohost_already_installed")

    if os.path.isdir("/etc/yunohost/apps") and os.listdir("/etc/yunohost/apps") != []:
        raise YunohostValidationError(
            "It looks like you're trying to re-postinstall a system that was already working previously ... If you recently had some bug or issues with your installation, please first discuss with the team on how to fix the situation instead of savagely re-running the postinstall ...",
            raw_msg=True,
        )

    if Moulinette.interface.type == "cli" and os.isatty(1):
        Moulinette.display(tr("tos_postinstall_acknowledgement"), style="warning")
        if not i_have_read_terms_of_services:
            # i18n: confirm_tos_acknowledgement
            _ask_confirmation("confirm_tos_acknowledgement", kind="soft")

    # Crash early if the username is already a system user, which is
    # a common confusion. We don't want to crash later and end up in an half-configured state.
    all_existing_usernames = {x.pw_name for x in pwd.getpwall()}
    if username in all_existing_usernames:
        raise YunohostValidationError("system_username_exists")

    if username in ADMIN_ALIASES:
        raise YunohostValidationError(
            f"Unfortunately, {username} cannot be used as a username", raw_msg=True
        )

    # Check there's at least 10 GB on the rootfs...
    disk_partitions = sorted(
        psutil.disk_partitions(all=True), key=lambda k: k.mountpoint
    )
    main_disk_partitions = [d for d in disk_partitions if d.mountpoint in ["/", "/var"]]
    main_space = sum(
        psutil.disk_usage(d.mountpoint).total for d in main_disk_partitions
    )
    GB = 1024**3
    if not force_diskspace and main_space < 10 * GB:
        raise YunohostValidationError("postinstall_low_rootfsspace")

    # Check password
    assert_password_is_compatible(password)
    assert_password_is_strong_enough("admin", password)

    # If this is a nohost.me/noho.st, actually check for availability
    dyndns = not ignore_dyndns and is_yunohost_dyndns_domain(domain)
    if dyndns:
        # Check if the domain is available...
        try:
            available = _dyndns_available(domain)
        # If an exception is thrown, most likely we don't have internet
        # connectivity or something. Assume that this domain isn't manageable
        # and inform the user that we could not contact the dyndns host server.
        except Exception:
            raise YunohostValidationError(
                "dyndns_provider_unreachable", provider="dyndns.yunohost.org"
            )
        else:
            if not available:
                if dyndns_recovery_password:
                    # Try to unsubscribe the domain so it can be subscribed again
                    # If successful, it will be resubscribed with the same recovery password
                    dyndns_unsubscribe(
                        domain=domain, recovery_password=dyndns_recovery_password
                    )
                else:
                    raise YunohostValidationError("dyndns_unavailable", domain=domain)

    if os.system("nft -V >/dev/null 2>/dev/null") != 0:
        raise YunohostValidationError(
            "nftables does not seems to be working on your setup. You may be in a container or your kernel does have the proper modules loaded. Sometimes, rebooting the machine may solve the issue.",
            raw_msg=True,
        )

    internet_ok = False
    if os.system("ping -c1 -w3 yunohost.org >/dev/null") == 0:
        internet_ok = True
    elif os.system("ping -c1 -w3 8.8.8.8 >/dev/null") == 0:
        if os.system("timeout 3 dig +short yunohost.org") == 0:
            # yunohost.org does resolves, and 8.8.8.8 pings ... most likely yunohost.org is down?
            logger.warning(
                "This machine can ping the Internet and resolve DNS, but not yunohost.org? Maybe there's currently an outage on yunohost.org infrastructure which may or may not impact the postinstall process..."
            )
        else:
            # yunohost.org doesnt ping, but 8.8.8.8 pings ... most likely DNS resolution is broken?
            logger.warning(
                "It looks like DNS resolution is broken on your server, which may impact the postinstall process..."
            )
    else:
        logger.warning(
            "It looks like internet connectivity is not available, which may or may not be what you're expecting ..."
        )

    operation_logger.start()
    logger.info(tr("yunohost_installing"))

    _set_system_perms(
        {
            "ssh": {"allowed": ["admins"]},
            "sftp": {"allowed": []},
            "mail": {"allowed": ["all_users"]},
        }
    )

    # New domain config
    domain_add(
        domain,
        dyndns_recovery_password=dyndns_recovery_password,
        ignore_dyndns=ignore_dyndns,
        skip_tos=True,  # skip_tos is here to prevent re-asking about the ToS when adding a dyndns service, because the ToS are already displayed right before in postinstall
    )
    domain_main_domain(domain)

    # First user
    user_create(username, domain, password, admin=True, fullname=fullname)

    if overwrite_root_password:
        tools_rootpw(password)

    # Try to fetch the apps catalog ...
    # we don't fail miserably if this fails,
    # because that could be for example an offline installation...
    if internet_ok is True:
        try:
            _update_apps_catalog()
        except Exception as e:
            logger.warning(str(e))
    else:
        logger.warning(
            "Skipping catalog initialization due to lack of Internet connectivity?"
        )

    # Init migrations (skip them, no need to run them on a fresh system)
    _skip_all_migrations()

    os.system("touch /etc/yunohost/installed")

    # Enable and start YunoHost firewall at boot time
    _run_service_command("enable", "nftables")

    tools_regen_conf(names=["ssh"], force=True)

    # Restore original ssh conf, as chosen by the
    # admin during the initial install
    #
    # c.f. the install script and in particular
    # https://github.com/YunoHost/install_script/pull/50
    # The user can now choose during the install to keep
    # the initial, existing sshd configuration
    # instead of YunoHost's recommended conf
    #
    original_sshd_conf = "/etc/ssh/sshd_config.before_yunohost"
    if os.path.exists(original_sshd_conf):
        os.rename(original_sshd_conf, "/etc/ssh/sshd_config")

    tools_regen_conf(force=True)

    logger.success(tr("yunohost_configured"))

    logger.warning(tr("yunohost_postinstall_end_tip"))


def tools_regen_conf(
    names: list[str] = [],
    with_diff: bool = False,
    force: bool = False,
    dry_run: bool = False,
    list_pending: bool = False,
) -> dict[str, dict[str, Any]]:
    from .regenconf import regen_conf

    if (names == [] or "nftables" in names) and tools_migrations_state()[
        "migrations"
    ].get("0032_firewall_config") not in ["skipped", "done"]:
        # Make sure the firewall conf is migrated before running the regenconf,
        # otherwise the nftable regenconf wont work
        try:
            tools_migrations_run(["0032_firewall_config"])
        except Exception as e:
            logger.error(e)

    return regen_conf(names, with_diff, force, dry_run, list_pending)


class AvailableUpdatesInfos(TypedDict):
    system: dict[str, list[dict[str, str]]]
    apps: list["AppInfo"]
    important_yunohost_upgrade: bool
    pending_migrations: list[dict[str, Any]]
    last_apt_update: int
    last_apps_catalog_update: int


def tools_update_norefresh() -> AvailableUpdatesInfos:
    return tools_update(no_refresh=True)


@is_unit_operation(sse_only=True)
def tools_update(
    operation_logger, target=None, no_refresh=False
) -> AvailableUpdatesInfos:
    """
    Update apps & system package cache
    """
    from .app_catalog import _update_apps_catalog

    refresh = not no_refresh

    if not target:
        target = "all"

    if target not in ["system", "apps", "all"]:
        raise YunohostError(
            f"Unknown target {target}, should be 'system', 'apps' or 'all'",
            raw_msg=True,
        )

    if refresh:
        operation_logger.start()

    upgradable_system_packages = []
    if target in ["system", "all"]:
        # Update APT cache
        # LC_ALL=C is here to make sure the results are in english
        command = "LC_ALL=C apt-get update --error-on=any -o Acquire::Retries=3 --allow-releaseinfo-change --error-on=any"

        # Filter boring message about "apt not having a stable CLI interface"
        # Also keep track of whether or not we encountered a warning...
        warnings = []

        def is_legit_warning(m: str) -> bool:
            legit_warning = (
                bool(m.rstrip())
                and "apt does not have a stable CLI interface" not in m.rstrip()
            )
            if legit_warning:
                warnings.append(m)
            return legit_warning

        callbacks = (
            # stdout goes to debug
            lambda l: logger.debug(l.rstrip()),
            # stderr goes to warning except for the boring apt messages
            lambda l: (
                logger.warning(l.rstrip())
                if is_legit_warning(l)
                else logger.debug(l.rstrip())
            ),
        )

        if refresh:
            logger.info(tr("updating_apt_cache"))

            returncode = call_async_output(command, callbacks, shell=True)

            if returncode != 0:
                raise YunohostError(
                    "update_apt_cache_failed",
                    sourceslist="\n".join(_dump_sources_list()),
                )
            elif warnings:
                logger.error(
                    tr(
                        "update_apt_cache_warning",
                        sourceslist="\n".join(_dump_sources_list()),
                    )
                )

            logger.debug(tr("done"))

        upgradable_system_packages = list(_list_upgradable_apt_packages())

    apps = []
    upgradable_apps = []
    if target in ["apps", "all"]:
        if refresh:
            try:
                _update_apps_catalog()
            except YunohostError as e:
                logger.error(str(e))

        apps = _list_apps_with_upgrade_infos()
        upgradable_apps = [
            app
            for app in apps
            if app["upgrade"]["status"] in ["upgradable", "fail_requirements"]
        ]

    if len(upgradable_apps) == 0 and len(upgradable_system_packages) == 0:
        logger.info(tr("already_up_to_date"))

    important_yunohost_upgrade = False
    if upgradable_system_packages and any(
        p["name"] == "yunohost" for p in upgradable_system_packages
    ):
        yunohost = [p for p in upgradable_system_packages if p["name"] == "yunohost"][0]
        current_version = yunohost["current_version"].split(".")[:2]
        new_version = yunohost["new_version"].split(".")[:2]
        important_yunohost_upgrade = current_version != new_version

    upgradable_system_packages_per_categories = _group_packages_per_categories(
        upgradable_system_packages
    )

    # Wrapping this in a try/except just in case for some reason we can't load
    # the migrations, which would result in the update/upgrade process being blocked...
    try:
        pending_migrations = tools_migrations_list(pending=True)["migrations"]
    except Exception as e:
        logger.error(e)
        pending_migrations = []

    try:
        last_apt_update_in_seconds = int(
            time.time() - os.stat("/var/cache/apt/pkgcache.bin").st_mtime
        )
    except Exception as e:
        logger.warning(f"Failed to compute last apt update time ? {e}")
        last_apt_update_in_seconds = 99999 * 3600

    try:
        last_apps_catalog_update_in_seconds = int(
            time.time() - os.stat("/var/cache/yunohost/repo/default.json").st_mtime
        )
    except Exception as e:
        logger.warning(f"Failed to compute last apps catalog update time ? {e}")
        last_apps_catalog_update_in_seconds = 99999 * 3600

    return {
        "system": upgradable_system_packages_per_categories,
        "apps": apps,
        "important_yunohost_upgrade": important_yunohost_upgrade,
        "pending_migrations": pending_migrations,
        "last_apt_update": last_apt_update_in_seconds,
        "last_apps_catalog_update": last_apps_catalog_update_in_seconds,
    }


def _list_apps_with_upgrade_infos(
    with_pre_upgrade_notifications: bool = True,
) -> list["AppInfo"]:
    from .app import _installed_apps, app_info

    apps = []
    for app_id in sorted(_installed_apps()):
        try:
            app_info_dict = app_info(
                app_id,
                with_upgrade_infos=True,
                with_pre_upgrade_notifications=with_pre_upgrade_notifications,
            )
        except Exception as e:
            logger.error(f"Failed to read info for {app_id} : {e}", exc_info=True)
            continue
        if app_info_dict["upgrade"]["status"] == "up_to_date":
            continue
        if app_info_dict["upgrade"]["requirements"]:
            app_info_dict["upgrade"]["requirements"] = {
                k: r
                for k, r in app_info_dict["upgrade"]["requirements"].items()
                if not r["passed"]
            }
        if "settings" in app_info_dict:
            del app_info_dict["settings"]

        apps.append(app_info_dict)

    if not with_pre_upgrade_notifications:
        return apps

    return apps


@is_unit_operation()
def tools_upgrade(operation_logger: OperationLogger, target: str | None = None) -> None:
    """
    Update apps & package cache, then display changelog

    Keyword arguments:
       apps -- List of apps to upgrade (or [] to update all apps)
       system -- True to upgrade system
    """

    from .app import app_upgrade

    if dpkg_is_broken():
        raise YunohostValidationError("dpkg_is_broken")

    # Check for obvious conflict with other dpkg/apt commands already running in parallel
    if not dpkg_lock_available():
        raise YunohostValidationError("dpkg_lock_not_available")

    if target not in ["apps", "system"]:
        raise YunohostValidationError(
            "Uhoh ?! tools_upgrade should have 'apps' or 'system' value for argument target",
            raw_msg=True,
        )

    #
    # Apps
    # This is basically just an alias to yunohost app upgrade ...
    #

    if target == "apps":
        # Make sure there's actually something to upgrade

        apps = _list_apps_with_upgrade_infos(with_pre_upgrade_notifications=False)
        upgradable_apps = [
            app["id"]
            for app in apps
            if app["upgrade"]["status"] in ["upgradable", "fail_requirements"]
        ]

        if not upgradable_apps:
            logger.info(tr("apps_already_up_to_date"))
            return

        # Actually start the upgrades

        try:
            app_upgrade(app=upgradable_apps)
        except Exception as e:
            logger.warning(f"unable to upgrade apps: {e}")
            logger.error(tr("app_upgrade_some_app_failed"))

        return

    #
    # System
    #

    if target == "system":
        # Check that there's indeed some packages to upgrade
        upgradables = list(_list_upgradable_apt_packages())
        if not upgradables:
            logger.info(tr("already_up_to_date"))

        logger.info(tr("upgrading_packages"))
        operation_logger.start()

        # Prepare dist-upgrade command
        dist_upgrade = "DEBIAN_FRONTEND=noninteractive"
        if Moulinette.interface.type == "api":
            dist_upgrade += " YUNOHOST_API_RESTART_WILL_BE_HANDLED_BY_YUNOHOST=yes"
        dist_upgrade += " APT_LISTCHANGES_FRONTEND=none"
        dist_upgrade += " apt-get"
        dist_upgrade += (
            " --fix-broken --show-upgraded --assume-yes --quiet -o=Dpkg::Use-Pty=0"
        )
        for conf_flag in ["old", "miss", "def"]:
            dist_upgrade += ' -o Dpkg::Options::="--force-conf{}"'.format(conf_flag)
        dist_upgrade += " dist-upgrade"

        logger.info(tr("tools_upgrade"))

        logger.debug("Running apt command :\n{}".format(dist_upgrade))

        callbacks = (
            lambda l: (
                logger.info("+ " + l.rstrip() + "\r")
                if _apt_log_line_is_relevant(l)
                else logger.debug(l.rstrip() + "\r")
            ),
            lambda l: (
                logger.warning(l.rstrip())
                if _apt_log_line_is_relevant(l)
                else logger.debug(l.rstrip())
            ),
        )
        # Serialized against app install/upgrade/remove (see apt_dpkg_lock's
        # docstring): without this, a concurrent app upgrade's apt-get and
        # this dist-upgrade can race, and a service restart triggered below
        # can kill the other operation's still-running postinst mid-transaction,
        # leaving a package half-configured for the next upgrade attempt to
        # trip over.
        with apt_dpkg_lock():
            returncode = call_async_output(dist_upgrade, callbacks, shell=True)

        # If yunohost is being upgraded from the webadmin
        if (
            any(p["name"] == "yunohost" for p in upgradables)
            and Moulinette.interface.type == "api"
        ):
            # Restart the API after 10 sec (at now doesn't support sub-minute times...)
            # We do this so that the API / webadmin still gets the proper HTTP response
            # It's then up to the webadmin to implement a proper UX process to wait 10 sec and then auto-fresh the webadmin
            cmd = 'at -M now >/dev/null 2>&1 <<< "sleep 10; systemctl restart yunohost-api"'
            # For some reason subprocess doesn't like the redirections so we have to use bash -c explicitly...
            subprocess.check_call(["bash", "-c", cmd])

        if returncode != 0:
            upgradables = list(_list_upgradable_apt_packages())
            packages_list = ", ".join([p["name"] for p in upgradables])
            # A failed dist-upgrade used to be reported as a plain warning
            # and the operation still logged "SUCCESS" -- dpkg could be left
            # half-configured with nothing surfacing it until the *next*
            # unrelated upgrade attempt tripped over dpkg_is_broken(). Fail
            # the operation instead, so the actual failure is what's reported.
            raise YunohostError(
                "tools_upgrade_incomplete", packages_list=packages_list
            )

        logger.success(tr("system_upgraded"))
        operation_logger.success()


@is_unit_operation()
def tools_shutdown(operation_logger: OperationLogger, force: bool = False) -> None:
    shutdown = force
    if not shutdown:
        try:
            # Ask confirmation for server shutdown
            i = Moulinette.prompt(tr("server_shutdown_confirm", answers="y/N"))
        except NotImplementedError:
            pass
        else:
            if i.lower() == "y" or i.lower() == "yes":
                shutdown = True

    if shutdown:
        operation_logger.start()
        logger.warning(tr("server_shutdown"))
        subprocess.check_call(["systemctl", "poweroff"])


@is_unit_operation()
def tools_reboot(operation_logger: OperationLogger, force: bool = False) -> None:
    reboot = force
    if not reboot:
        try:
            # Ask confirmation for restoring
            i = Moulinette.prompt(tr("server_reboot_confirm", answers="y/N"))
        except NotImplementedError:
            pass
        else:
            if i.lower() == "y" or i.lower() == "yes":
                reboot = True
    if reboot:
        operation_logger.start()
        logger.warning(tr("server_reboot"))
        subprocess.check_call(["systemctl", "reboot"])


# ############################################ #
#                                              #
#            Migrations management             #
#                                              #
# ############################################ #


def tools_migrations_list(
    pending: bool = False, done: bool = False
) -> dict[str, list[dict[str, Any]]]:
    """
    List existing migrations

    nostrhost has retired the upstream YunoHost migrations subsystem: this
    fork only ever installs onto a fresh bookworm/YunoHost 12 system, so no
    migration under migrations/ can ever legitimately apply, and pulling in
    a future upstream migration via a rebase could otherwise run silently
    against state nostrhost now manages itself (see e.g. 0032_firewall_config,
    which assumes a firewall.yml schema nostrhost may have already replaced).
    Rather than deleting the migration files (churn on every upstream rebase,
    same tradeoff as docs/LDAP-RETIREMENT.md), this always reports an empty
    list; see tools_migrations_run below for the matching no-op.
    """

    # Check for option conflict
    if pending and done:
        raise YunohostValidationError("migrations_list_conflict_pending_done")

    return {"migrations": []}


def tools_migrations_run(
    targets: list[str] = [],
    skip: bool = False,
    auto: bool = False,
    force_rerun: bool = False,
    accept_disclaimer: bool = False,
    skip_postmigrations: bool = False,
) -> None:
    """
    Perform migrations

    Permanently disabled on nostrhost -- see the docstring on
    tools_migrations_list above. Raises rather than silently no-op'ing so
    callers (admin UI, CLI, MCP tools) get an explicit signal instead of a
    fake "success" with nothing having happened.
    """
    raise YunohostValidationError("migrations_disabled_nostrhost")


def tools_migrations_state() -> dict[str, dict[Any, Any]]:
    """
    Show current migration state
    """
    if not os.path.exists(MIGRATIONS_STATE_PATH):
        return {"migrations": {}}

    return read_yaml(MIGRATIONS_STATE_PATH)  # type: ignore[return-value]


def _write_migration_state(migration_id, state):
    current_states = tools_migrations_state()
    current_states["migrations"][migration_id] = state
    write_to_yaml(MIGRATIONS_STATE_PATH, current_states)


def _get_migrations_list() -> list["Migration"]:
    # states is a datastructure that represents the last run migration
    # it has this form:
    # {
    #     "0001_foo": "skipped",
    #     "0004_baz": "done",
    #     "0002_bar": "skipped",
    #     "0005_zblerg": "done",
    # }
    # (in particular, pending migrations / not already ran are not listed
    states = tools_migrations_state()["migrations"]

    migrations = []
    migrations_folder = os.path.dirname(__file__) + "/migrations/"
    for migration_file in [
        x
        for x in os.listdir(migrations_folder)
        if re.match(r"^\d+_[a-zA-Z0-9_]+\.py$", x)
    ]:
        m = _load_migration(migration_file)
        m.state = states.get(m.id, "pending")
        migrations.append(m)

    return sorted(migrations, key=lambda m: m.id)


def _load_migration(migration_file: str) -> "Migration":
    migration_id = migration_file[: -len(".py")]

    logger.debug(tr("migrations_loading_migration", id=migration_id))

    try:
        # this is python builtin method to import a module using a name, we
        # use that to import the migration as a python object so we'll be
        # able to run it in the next loop
        module = import_module("yunohost.migrations.{}".format(migration_id))
        return module.MyMigration(migration_id)
    except Exception as e:
        import traceback

        traceback.print_exc()

        raise YunohostError(
            "migrations_failed_to_load_migration", id=migration_id, error=e
        )


def _skip_all_migrations() -> None:
    """
    Skip all pending migrations.
    This is meant to be used during postinstall to
    initialize the migration system.
    """
    all_migrations = _get_migrations_list()
    new_states: dict[Literal["migrations"], dict[str, str]] = {"migrations": {}}
    for migration in all_migrations:
        new_states["migrations"][migration.id] = "skipped"
    write_to_yaml(MIGRATIONS_STATE_PATH, new_states)  # type: ignore[arg-type]


def _tools_migrations_run_after_system_restore(backup_version: str) -> None:
    # nostrhost has retired the upstream migrations subsystem (see
    # tools_migrations_list/tools_migrations_run above): backups are always
    # created and restored within the same nostrhost/YunoHost 12.1.x
    # lineage, so no migration's run_after_system_restore hook can
    # legitimately apply, and invoking one from a legacy upstream migration
    # (e.g. 0032_firewall_config, 0033_rework_permission_infos) risks
    # touching state nostrhost now manages itself.
    return


def _tools_migrations_run_before_app_restore(
    backup_version, app_id, app_backup_in_archive
):
    # See _tools_migrations_run_after_system_restore above.
    return


class Migration:
    # Those are to be implemented by daughter classes

    state: Literal["pending", "done", "skipped"] | None = None
    mode: Literal["auto", "manual"] = "auto"

    # List of migration ids required before running this migration
    dependencies: list[str] = []

    # For migrations that have @ldap_migration
    ldap_migration_started = False

    # To skip the automatic run of the migrations following up the current one
    skip_postmigrations: bool = False

    @property
    def disclaimer(self) -> str | None:
        return None

    def run(self) -> None:
        raise NotImplementedError()

    # The followings shouldn't be overridden

    def __init__(self, id_: str) -> None:
        self.id = id_
        self.number = int(self.id.split("_", 1)[0])
        self.name = self.id.split("_", 1)[1]

    @property
    def description(self) -> str:
        return tr(f"migration_description_{self.id}")  # type: ignore

    @staticmethod
    def ldap_migration(run: Callable[[Any, str], None]) -> Callable[[Any], None]:
        def func(self: "Migration") -> None:
            # LDAP is retired (roadmap §25): there is no slapd to back up or
            # roll back. The wrapper still exists so historical migrations
            # decorated with @ldap_migration keep a stable signature, but the
            # LDAP backup/rollback is gone.
            try:
                run(self, "")
            except Exception:
                if self.ldap_migration_started:
                    logger.warning(
                        tr("migration_ldap_migration_failed_trying_to_rollback")
                    )
                raise

        return func
