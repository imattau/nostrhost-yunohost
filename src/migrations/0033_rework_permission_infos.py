"""Migration 0033: rework permission infos (obsolete with LDAP retired).

This migration originally migrated YunoHost <= 12.0 LDAP permission objects
into per-app settings (``_permissions``). LDAP is now retired outright
(roadmap §25, docs/LDAP-RETIREMENT.md), so there is no LDAP permission store
to migrate on any install this code runs on: fresh installs never see it, and
upgrading installs have already had their permissions reworked or have no
LDAP to read. It is kept as a no-op so the migration id stays registered and
upgrade ordering is unchanged.
"""

from logging import getLogger

from ..app import app_ssowatconf
from ..permission import _set_system_perms, _sync_permissions_with_ldap
from ..tools import Migration

logger = getLogger("yunohost.migration")

SYSTEM_PERMS = ["mail", "sftp", "ssh"]


class MyMigration(Migration):
    introduced_in_version = "12.1"
    dependencies = []

    @Migration.ldap_migration
    def run(self, backup_folder: str) -> None:
        # LDAP is retired: there is nothing to migrate. Ensure a sane system
        # permission set and the native projection exist, then mark done.
        _set_system_perms({p: {"allowed": []} for p in SYSTEM_PERMS})
        _sync_permissions_with_ldap()
        app_ssowatconf()

    def run_after_system_restore(self):
        _set_system_perms({p: {"allowed": []} for p in SYSTEM_PERMS})
        _sync_permissions_with_ldap()
        app_ssowatconf()

    def run_before_app_restore(self, app_id, app_backup_in_archive):
        # Pre-12.1 backups carried LDAP-backed permissions.yml; permission
        # restoration now goes through the native projection, so there is
        # nothing to restore from LDAP here.
        _sync_permissions_with_ldap()
        app_ssowatconf()