"""nostrhost cert export daemon (roadmap §7.2 / CADDY-MIGRATION P2).

Caddy owns ACME issuance and renewal; the exported store under
``/etc/yunohost/certs`` is what non-web TLS consumers read. With postfix and
dovecot retired, slapd (LDAP) is the sole non-web consumer today, but the
``post_cert_update`` hook is still fired so future consumers (or apps) can
react the same way they did under the legacy cert-manager.

The daemon is a thin, idempotent exporter, not a certificate authority:

- It reads Caddy's storage (default ``/var/lib/caddy``, override with the
  ``NOSTR_CADDY_STORAGE`` env var) and finds the newest ``crt``/``key`` pair
  for each domain Caddy is currently serving.
- It mirrors the legacy layout: each exported generation lives in
  ``/etc/yunohost/certs/<domain>-history/<timestamp>-<kind>/`` and the live
  ``/etc/yunohost/certs/<domain>`` entry is a symlink swapped atomically
  (write-then-rename semantics), so ``certificate_status``/``_get_status`` keep
  working unchanged against the exported store.
- A generation is written only when the fingerprint of Caddy's cert changed
  (Caddy renews ~30 days before expiry for Let's Encrypt, at 2/3 life for the
  short-lived test CA), so slapd is reloaded only on real change.

Run as ``python3 -m yunohost.nostr_certd --once`` (the systemd oneshot+timer
unit does exactly this every few minutes) or ``--status`` to print the current
Caddy->exported mapping without changing anything.
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from OpenSSL import crypto  # noqa: PLC0415  (same lazy dep as certificate.py)

logger = logging.getLogger("nostr-certd")

CERT_FOLDER = Path("/etc/yunohost/certs")
CADDY_STORAGE = Path(os.environ.get("NOSTR_CADDY_STORAGE", "/var/lib/caddy"))
CADDY_CERT_DIR = CADDY_STORAGE / "certificates"


class CertdError(RuntimeError):
    """The exporter failed (bad storage, unreadable cert, permissions, …)."""


def _leaf_not_after(crt_path: Path) -> datetime:
    """Not-after of the leaf (first) certificate in a PEM chain, naive-UTC."""
    with crt_path.open("rb") as f:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    return datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ")


def _leaf_issuer(crt_path: Path) -> str:
    """Issuer common name of the leaf certificate."""
    with crt_path.open("rb") as f:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    return cert.get_issuer().CN


def _pem_fingerprint(path: Path) -> str:
    """SHA-256 of the raw PEM file (the exported file is a byte copy)."""
    return sha256(path.read_bytes()).hexdigest()


def find_caddy_cert(domain: str) -> tuple[Path, Path] | None:
    """Newest ``(crt, key)`` pair Caddy stores for ``domain``, or ``None``.

    Caddy's storage is ``certificates/<ca>/<domain>/<san>.crt`` (+ ``.key``).
    Multiple SANs/CAs can coexist, so we walk the tree and keep the pair with
    the latest ``notAfter``.
    """
    if not CADDY_CERT_DIR.is_dir():
        return None

    best: tuple[Path, Path] | None = None
    best_not_after: datetime | None = None
    for root, _dirs, files in os.walk(CADDY_CERT_DIR):
        if os.path.basename(root) != domain:
            continue
        for name in files:
            if not name.endswith(".crt"):
                continue
            key = Path(root) / (name[:-4] + ".key")
            if not key.is_file():
                continue
            crt = Path(root) / name
            not_after = _leaf_not_after(crt)
            if best is None or not_after > best_not_after:  # type: ignore[operator]
                best = (crt, key)
                best_not_after = not_after
    return best


def exported_fingerprint(domain: str) -> str | None:
    """Fingerprint of the currently exported ``crt.pem``, if any."""
    crt = CERT_FOLDER / domain / "crt.pem"
    if not crt.is_file():
        return None
    return _pem_fingerprint(crt)


def _set_permissions(path: Path, user: str, group: str, mode: int) -> None:
    import grp
    import pwd

    os.chown(path, pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid)
    os.chmod(path, mode)


def _backup_current_cert(domain: str) -> None:
    """Move a legacy plain (non-symlink) cert dir into ``-backups/``."""
    live = CERT_FOLDER / domain
    date_tag = datetime.now(timezone.utc).strftime("%Y%m%d.%H%M%S")
    backup = Path(f"{live}-backups") / date_tag
    shutil.copytree(live, backup)


def _run_post_cert_update_hook(domain: str) -> None:
    """Fire the upstream ``post_cert_update`` hook (no-op if none installed)."""
    try:
        from yunohost.hook import hook_callback  # noqa: PLC0415

        hook_callback("post_cert_update", args=[domain])
    except Exception as e:  # the export itself must not fail because of a hook
        logger.warning("post_cert_update hook failed for %s: %s", domain, e)


def _reload_consumers(domain: str) -> None:
    """Restart the non-web TLS consumers; slapd is the only one today.

    slapd loads its TLS certificate/key at process start: ``systemctl reload``
    re-reads the LDAP config but not the cert material, so a restart is
    required for a rotated certificate to take effect.
    """
    try:
        subprocess.run(
            ["systemctl", "restart", "slapd"],
            check=False,
            capture_output=True,
        )
    except OSError as e:
        logger.warning("could not restart slapd: %s", e)
    _run_post_cert_update_hook(domain)


def _enable_certificate(domain: str, new_folder: Path) -> None:
    """Atomically point ``/etc/yunohost/certs/<domain>`` at the new generation.

    Mirrors ``certificate.py::_enable_certificate`` minus the retired nginx /
    dovecot restarts: back up any legacy plain dir, drop the old symlink, then
    create the new one before reloading consumers.
    """
    live = CERT_FOLDER / domain
    if os.path.islink(live):
        os.remove(live)
    elif live.exists():
        _backup_current_cert(domain)
        shutil.rmtree(live)
    os.symlink(new_folder, live)
    _reload_consumers(domain)


def export_domain(domain: str, dry_run: bool = False) -> bool:
    """Export Caddy's current cert for ``domain`` if it changed.

    Returns ``True`` when a new generation was (or would be, in dry-run)
    exported, ``False`` when Caddy has no cert for the domain or it is already
    exported.
    """
    pair = find_caddy_cert(domain)
    if pair is None:
        logger.debug("no Caddy cert for %s", domain)
        return False

    crt_path, key_path = pair
    if _pem_fingerprint(crt_path) == exported_fingerprint(domain):
        logger.debug("%s already exported", domain)
        return False

    date_tag = datetime.now(timezone.utc).strftime("%Y%m%d.%H%M%S")
    issuer = _leaf_issuer(crt_path)
    kind = "letsencrypt" if issuer == "Let's Encrypt" else "caddy"
    new_folder = CERT_FOLDER / f"{domain}-history" / f"{date_tag}-{kind}"

    if dry_run:
        logger.info("would export %s -> %s (issuer %s)", domain, new_folder, issuer)
        return True

    new_folder.mkdir(parents=True)
    _set_permissions(new_folder, "root", "root", 0o755)
    shutil.copy2(crt_path, new_folder / "crt.pem")
    shutil.copy2(key_path, new_folder / "key.pem")
    _set_permissions(new_folder / "crt.pem", "root", "ssl-cert", 0o640)
    _set_permissions(new_folder / "key.pem", "root", "ssl-cert", 0o640)

    _enable_certificate(domain, new_folder)
    logger.info("exported %s -> %s (issuer %s)", domain, new_folder, issuer)
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="do a single pass (default)")
    parser.add_argument(
        "--status", action="store_true", help="print the Caddy->exported mapping"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="report what would change only"
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=os.environ.get("NOSTR_CERTD_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    if args.status:
        _print_status()
        return 0

    changed = False
    for domain in _caddy_domains():
        if export_domain(domain, dry_run=args.dry_run):
            changed = True
    return 0 if not changed else 1


def _caddy_domains() -> set[str]:
    """Domains Caddy currently has certs for (any CA, any SAN set).

    A directory counts as a domain only if it directly holds a ``.crt`` +
    ``.key`` pair, so CA directories under ``certificates/`` are not mistaken
    for domains.
    """
    domains: set[str] = set()
    if not CADDY_CERT_DIR.is_dir():
        return domains
    for root, _dirs, _files in os.walk(CADDY_CERT_DIR):
        crt_files = [f for f in _files if f.endswith(".crt")]
        if any((Path(root) / (f[:-4] + ".key")).is_file() for f in crt_files):
            domains.add(os.path.basename(root))
    return domains


def _print_status() -> None:
    for domain in sorted(_caddy_domains()):
        pair = find_caddy_cert(domain)
        if pair is None:
            continue
        crt, _key = pair
        current = exported_fingerprint(domain)
        store = _pem_fingerprint(crt)
        if current is None:
            state = "not-exported"
        elif current == store:
            state = "in-sync"
        else:
            state = "out-of-sync"
        print(f"{domain}\t{state}\t{crt}")


if __name__ == "__main__":
    sys.exit(main())