"""Restic data-recovery client (roadmap §7.4 / Stage B).

Git/ngit is configuration-state history, not a replacement for data backup.
For data-affecting operations the state layer records a Restic snapshot id in
the state manifest alongside the pre-change config commit; the client here is
the thin, bounded wrapper around the ``restic`` CLI that produces, lists,
checks and restores those snapshots.

Secrets (repository URL + password) live in the root-only
``/etc/nostrhost/restic.toml`` (same convention as ``operator.toml``); they are
never written into the state repository. The password reaches ``restic`` via
the ``RESTIC_PASSWORD`` environment variable so it never appears on a command
line (visible in ``ps``).

The module is importable and unit-testable without ``restic`` installed: every
method parses restic's ``--json`` output, and tests inject a fake ``restic``
binary. A missing binary or config raises :class:`ResticError` with a clear
message; the recorder hook returns an empty snapshot id when Restic is not
configured so a snapshot never fails just because data backup is optional.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger("nostr-restic")

DEFAULT_RESTIC_CONFIG = "/etc/nostrhost/restic.toml"


class ResticError(RuntimeError):
    """The restic client or repository failed (binary, auth, repo, …)."""


@dataclass(frozen=True)
class ResticConfig:
    """Data-backup configuration from ``/etc/nostrhost/restic.toml``.

    ``paths`` are the filesystem paths a data snapshot includes (typically
    ``/opt/yunohost`` app data and homes). ``restore_target`` is the base
    directory restore writes into (paths are recreated under it). Secrets are
    the repo URL + password; both stay in this root-only file.
    """

    repo: str
    password: str
    paths: tuple[str, ...]
    binary: str = "restic"
    host: str = ""
    tag: str = "nostrhost"
    restore_target: str = "/"
    timeout: int = 3600


def load_restic_config(path: str | Path | None = None) -> ResticConfig | None:
    """Read the restic config, or None when it does not exist (backup not
    configured). Raises :class:`ResticError` for a present-but-invalid config."""
    path = Path(path or os.environ.get("NOSTRHOST_RESTIC_CONFIG", DEFAULT_RESTIC_CONFIG))
    if not path.exists():
        return None
    with path.open("rb") as fh:
        conf = tomllib.load(fh)
    repo = str(conf.get("repo") or "")
    password = str(conf.get("password") or "")
    if not repo or not password:
        raise ResticError(f"{path} must set both 'repo' and 'password'")
    paths = tuple(str(p) for p in (conf.get("paths") or []))
    if not paths:
        raise ResticError(f"{path} must set a non-empty 'paths' list")
    return ResticConfig(
        repo=repo,
        password=password,
        paths=paths,
        binary=str(conf.get("binary") or "restic"),
        host=str(conf.get("host") or ""),
        tag=str(conf.get("tag") or "nostrhost"),
        restore_target=str(conf.get("restore_target") or "/"),
        timeout=int(conf.get("timeout") or 3600),
    )


class ResticClient:
    """Bounded wrapper around the ``restic`` CLI.

    ``repo`` and ``password`` are required (config or direct). ``env`` allows
    tests/overrides to inject additional environment (e.g. a fake ``HOME``);
    it never overrides the password or repository.
    """

    def __init__(
        self,
        *,
        repo: str,
        password: str,
        binary: str = "restic",
        env: dict[str, str] | None = None,
        host: str = "",
        tag: str = "nostrhost",
        timeout: int = 3600,
    ) -> None:
        self.repo = repo
        self.password = password
        self.binary = binary
        self.host = host
        self.tag = tag
        self.timeout = timeout
        self._env = dict(env or {})

    # -- mechanics ---------------------------------------------------------- #

    def _run(self, args: list[str]) -> subprocess.CompletedProcess:
        env = {
            **os.environ,
            "RESTIC_REPOSITORY": self.repo,
            "RESTIC_PASSWORD": self.password,
            **self._env,
        }
        try:
            res = subprocess.run(
                [self.binary, *args],
                capture_output=True,
                text=True,
                env=env,
                timeout=self.timeout,
            )
        except FileNotFoundError as exc:
            raise ResticError(
                f"restic binary {self.binary!r} not found on PATH; install restic "
                "or set 'binary' in the restic config"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ResticError(f"restic {' '.join(args)} timed out") from exc
        if res.returncode != 0:
            raise ResticError(
                f"restic {' '.join(args)} failed (exit {res.returncode}): {res.stderr.strip() or res.stdout.strip()}"
            )
        return res

    @staticmethod
    def _json_lines(stdout: str) -> list[dict[str, Any]]:
        """Parse restic's `--json` output: both newline-delimited JSON objects
        (backup) and a single JSON array (snapshots) are flattened."""
        out: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            if not line.strip():
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:  # pragma: no cover - defensive
                continue
            if isinstance(parsed, list):
                out.extend(x for x in parsed if isinstance(x, dict))
            elif isinstance(parsed, dict):
                out.append(parsed)
        return out

    # -- operations --------------------------------------------------------- #

    def snapshot(self, paths: list[str] | None = None, *, tag: str | None = None, host: str | None = None) -> str:
        """Back up ``paths`` and return the new snapshot id."""
        include = list(paths or [])
        if not include:
            raise ResticError("snapshot requires at least one path")
        args = ["backup", "--json", "--tag", tag or self.tag]
        if host or self.host:
            args += ["--host", host or self.host]
        args += include
        res = self._run(args)
        snapshot_id = ""
        for line in self._json_lines(res.stdout):
            if line.get("message_type") in ("summary", "snapshot") and line.get("snapshot_id"):
                snapshot_id = str(line["snapshot_id"])
        if not snapshot_id:
            raise ResticError("restic backup succeeded but no snapshot id was reported")
        return snapshot_id

    def snapshots(self, *, tag: str | None = None, host: str | None = None) -> list[dict[str, Any]]:
        """List snapshots (optionally filtered by tag/host).

        By default every snapshot in the repository is listed: the configured
        tag is a default for *creating* snapshots, not a visibility filter, so
        per-app and system backups all count as backup evidence."""
        args = ["snapshots", "--json"]
        if tag:
            args += ["--tag", tag]
        if host or self.host:
            args += ["--host", host or self.host]
        res = self._run(args)
        return self._json_lines(res.stdout)

    def restore(self, snapshot_id: str, target: str, include: list[str] | None = None) -> dict[str, Any]:
        """Restore one snapshot under ``target`` (paths recreated relative to
        it); ``include`` limits restore to given paths within the snapshot."""
        args = ["restore", "--json", snapshot_id, "--target", target]
        for path in include or []:
            args += ["--include", path]
        res = self._run(args)
        summary: dict[str, Any] = {}
        for line in self._json_lines(res.stdout):
            if line.get("message_type") == "summary":
                summary = line
        return summary

    def check(self) -> dict[str, Any]:
        """Verify repository integrity. Returns {'ok': True} or raises."""
        self._run(["check"])
        return {"ok": True}


# --------------------------------------------------------------------------- #
# state-layer integration

def restic_client(cfg: ResticConfig | None = None) -> ResticClient:
    """Build a client from the configured restic.toml (raises when unset)."""
    conf = cfg or load_restic_config()
    if conf is None:
        raise ResticError(f"no restic config at {os.environ.get('NOSTRHOST_RESTIC_CONFIG', DEFAULT_RESTIC_CONFIG)}")
    return ResticClient(
        repo=conf.repo,
        password=conf.password,
        binary=conf.binary,
        host=conf.host,
        tag=conf.tag,
        timeout=conf.timeout,
    )


def restic_snapshot_hook(cfg: ResticConfig | None = None) -> Callable[[], str]:
    """Build the :class:`StateRecorder` restic hook: snapshot the configured
    data paths and return the new snapshot id, or ``""`` when Restic is not
    configured (data backup optional)."""

    def _hook() -> str:
        conf = cfg or load_restic_config()
        if conf is None:
            logger.debug("restic not configured; no data snapshot taken")
            return ""
        try:
            client = restic_client(conf)
            sid = client.snapshot(list(conf.paths))
            logger.info("restic data snapshot %s (%d paths)", sid[:16], len(conf.paths))
            return sid
        except ResticError as exc:  # noqa: BLE001 - a failed data snapshot must
            logger.error("restic snapshot failed: %s", exc)  # not break the op
            return ""

    return _hook