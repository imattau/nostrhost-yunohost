"""Native account store — the replacement for LDAP as the user/group
directory (roadmap §25, docs/LDAP-RETIREMENT.md Phases 3-5).

LDAP used to be the Unix account directory: ``user.py`` wrote user/group
records to slapd and ``libnss-ldapd``/``libpam-ldapd`` served them to the
kernel for real login. With LDAP retired outright, this module is the native
store: real Unix accounts are created/removed via ``useradd``/``usermod``/
``userdel`` and ``groupadd``/``groupdel``/``gpasswd`` (so ``getent passwd``
and file ownership keep working), and the YunoHost-specific metadata LDAP
carried (fullname, mail, mailbox quota, mail aliases/forwards, admin flag,
permission groups) lives in a root-owned JSON store.

Layout:

    /etc/nostrhost/accounts.json   user + group metadata (the LDAP extras)
    /etc/nostrhost/ssh-keys.json   per-user SSH public keys (was LDAP ``sshPublicKey``)

The JSON store is written atomically (tempfile + os.replace), same pattern
as ``nostrhost.permissions``' projection file. All reads are best-effort
against a missing/corrupt file (returns empty state), matching how the
native domain and permission planes tolerate a fresh node.
"""

from __future__ import annotations

import grp
import json
import logging
import os
import pwd
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger("nostrhost.accounts")

ACCOUNTS_STORE = Path(os.environ.get("NOSTRHOST_ACCOUNTS", "/etc/nostrhost/accounts.json"))
SSH_KEYS_STORE = Path(os.environ.get("NOSTRHOST_SSH_KEYS", "/etc/nostrhost/ssh-keys.json"))

DEFAULT_GROUPS = ("all_users", "admins", "visitors")


def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(payload, indent=1, sort_keys=True).encode() + b"\n"
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}-")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _load_store(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except Exception:  # noqa: BLE001 - a corrupt store degrades to empty state
        logger.warning("failed to read %s; treating as empty", path)
        return {}


def users() -> dict[str, dict[str, Any]]:
    """All stored user records (the LDAP metadata; real accounts are in
    /etc/passwd)."""
    store = _load_store(ACCOUNTS_STORE)
    return store.get("users", {})


def save_users(new_users: dict[str, dict[str, Any]]) -> None:
    store = _load_store(ACCOUNTS_STORE)
    store["users"] = new_users
    _atomic_write(ACCOUNTS_STORE, store)


def user_get(username: str) -> dict[str, Any] | None:
    return users().get(username)


def real_user_exists(username: str) -> bool:
    """A real /etc/passwd account (the thing LDAP+NSS used to serve)."""
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False


def user_mail(username: str) -> list[str]:
    """The user's mail addresses (main first, then aliases)."""
    record = user_get(username)
    if not record:
        return []
    mails = list(record.get("mail", []))
    if not mails and record.get("mail_primary"):
        mails = [str(record["mail_primary"])]
    return mails


def user_mail_domains(username: str) -> set[str]:
    """Set of domains the user has a mail address on (LDAP ``mail`` field
    used by ``user_is_allowed_on_domain`` for the email-domain access rule)."""
    domains: set[str] = set()
    for mail in user_mail(username):
        if "@" in mail:
            domains.add(mail.split("@", 1)[1])
    return domains


def user_is_admin(username: str) -> bool:
    record = user_get(username)
    if record is None:
        return False
    return bool(record.get("admin", False))


def groups() -> dict[str, dict[str, Any]]:
    """All stored group records (the LDAP metadata)."""
    store = _load_store(ACCOUNTS_STORE)
    return store.get("groups", {})


def ensure_base_groups() -> None:
    """Ensure the special groups (all_users/admins/visitors) exist in both the
    real /etc/group and the native store, so user/group operations that
    reference them (file ACLs, admin membership, permission defaults) work
    without an LDAP-era bootstrap.

    Idempotent; safe to call on every group read path.
    """
    _native = groups()
    changed = False
    for name, gid in (("all_users", "2000"), ("admins", "2001"), ("visitors", "2002")):
        if not real_group_exists(name):
            try:
                create_real_group(name, gid)
            except subprocess.CalledProcessError:
                pass  # raced with another create; group likely exists now
        if name not in _native:
            try:
                members = grp.getgrnam(name).gr_mem
            except KeyError:
                members = []
            _native[name] = {"gid": gid, "members": list(members)}
            changed = True
    if changed:
        save_groups(_native)


def save_groups(new_groups: dict[str, dict[str, Any]]) -> None:
    store = _load_store(ACCOUNTS_STORE)
    store["groups"] = new_groups
    _atomic_write(ACCOUNTS_STORE, store)


def group_get(groupname: str) -> dict[str, Any] | None:
    return groups().get(groupname)


def group_members(groupname: str) -> list[str]:
    record = group_get(groupname)
    if record is not None:
        return list(record.get("members", []))
    # Fall back to the real system group for groups not (yet) in the store
    # (e.g. the admins/all_users bootstrap before any user CRUD ran).
    try:
        return grp.getgrnam(groupname).gr_mem
    except KeyError:
        return []


def admins() -> list[str]:
    """Admin usernames (native, no LDAP — replaces the ``cn=admins`` read)."""
    return [u for u, rec in users().items() if rec.get("admin")]


def real_group_exists(groupname: str) -> bool:
    try:
        grp.getgrnam(groupname)
        return True
    except KeyError:
        return False


def create_real_user(
    username: str,
    *,
    uid: str,
    gid: str,
    shell: str,
    home: str = "/home/",
    password_hash: str | None = None,
) -> None:
    """Create a real /etc/passwd account (replaces LDAP add + libnss-ldapd).

    The primary group is created first (matching the group's gid) because
    ``useradd -g`` requires the group to exist; with LDAP gone there is no
    posixGroup entry to resolve. ``-U`` would create a group with a different
    gid numbering, so we create the named group at the requested gid first.
    """
    if not real_group_exists(username):
        create_real_group(username, gid)
    subprocess.check_call(
        [
            "useradd",
            "-u", uid,
            "-g", gid,
            "-d", os.path.join(home, username),
            "-s", shell,
            "-m",
            username,
        ]
    )
    # Record the primary group in the native store (membership is a
    # self-reference: the user's primary group always contains just them).
    _native = groups()
    if username not in _native:
        _native[username] = {"gid": gid, "members": [username]}
        save_groups(_native)
    if password_hash:
        subprocess.run(
            ["chpasswd", "-e"], input=f"{username}:{password_hash}\n", check=True, text=True
        )


def delete_real_user(username: str, purge: bool = False) -> None:
    """Remove a real /etc/passwd account (replaces LDAP remove)."""
    if not real_user_exists(username):
        return
    cmd = ["userdel", "-f" if not purge else "-r", username]
    subprocess.check_call(cmd)


def add_real_user_to_group(username: str, groupname: str) -> None:
    """Best-effort: mirror membership into the real /etc/group entry.

    The native store (``save_groups``) is the source of truth; a transient
    ``gpasswd`` failure here must not prevent that write from landing (it
    used to, silently losing membership - see the postinstall bootstrap
    path in ``nostrhost/cli.py``).
    """
    if real_group_exists(groupname):
        try:
            subprocess.check_call(["gpasswd", "-a", username, groupname])
        except subprocess.CalledProcessError as e:
            logger.warning(
                "Failed to add %s to real group %s (native store is still "
                "authoritative): %s", username, groupname, e
            )


def remove_real_user_from_group(username: str, groupname: str) -> None:
    if real_group_exists(groupname):
        try:
            subprocess.check_call(["gpasswd", "-d", username, groupname])
        except subprocess.CalledProcessError as e:
            logger.warning(
                "Failed to remove %s from real group %s (native store is "
                "still authoritative): %s", username, groupname, e
            )


def create_real_group(groupname: str, gid: str) -> None:
    subprocess.check_call(["groupadd", "-g", gid, groupname])


def delete_real_group(groupname: str) -> None:
    if real_group_exists(groupname):
        subprocess.check_call(["groupdel", groupname])


def ssh_keys() -> dict[str, list[str]]:
    return _load_store(SSH_KEYS_STORE)


def ssh_key_list(username: str) -> list[str]:
    return ssh_keys().get(username, [])


def ssh_key_add(username: str, key: str) -> None:
    store = ssh_keys()
    keys = list(store.get(username, []))
    if key not in keys:
        keys.append(key)
        store[username] = keys
        _atomic_write(SSH_KEYS_STORE, store)


def ssh_key_remove(username: str, key: str) -> None:
    store = ssh_keys()
    keys = list(store.get(username, []))
    if key in keys:
        keys.remove(key)
        if keys:
            store[username] = keys
        else:
            store.pop(username, None)
        _atomic_write(SSH_KEYS_STORE, store)


def _run_sudoers_check(domain: str | None = None) -> bool:
    """passwordless_sudo read: true when the admins group has NOPASSWD.

    Replaces the LDAP ``cn=admins,ou=sudo`` ``sudoOption`` read.
    """
    sudoers_files = [Path("/etc/sudoers.d/yunohost")]
    for path in sudoers_files:
        if not path.exists():
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if "NOPASSWD" in content and "%admins" in content:
            return True
    return False


def set_passwordless_sudo(enabled: bool) -> None:
    """Write the passwordless-sudo sudoers rule (replaces LDAP ou=sudo)."""
    path = Path("/etc/sudoers.d/yunohost")
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Managed by NostrHost (native settings; was LDAP ou=sudo)",
        "%admins ALL=(ALL) ALL",
    ]
    if enabled:
        lines.insert(1, "%admins ALL=(ALL) NOPASSWD: ALL")
    else:
        lines.append("%admins ALL=(ALL) NOPASSWD: ALL")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    subprocess.run(["chmod", "440", str(path)], check=True)


def passwordless_sudo() -> bool:
    return _run_sudoers_check()


# Keep a small stable surface for callers that used the LDAP client for
# basic directory reads.
current_user_is_admin: Callable[[str], bool] = user_is_admin