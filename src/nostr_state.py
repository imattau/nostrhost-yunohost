"""Durable semantic configuration-state layer (roadmap §7 / Stage A).

The state layer uses **ngit / NIP-34 as the Nostr-aligned repository model**
with normal Git objects underneath: plain Git remains the storage engine, but
repository identity, ownership and signed state align with the server's Nostr
identity (`docs/STATELAYER.md`).

Stage A — state history:

  operation request
        |
        v
  pre-change semantic snapshot     (commit, linked to the operation event)
        |
        v
  execute operation
        |
        v
  post-change semantic snapshot    (commit, known-good when the op succeeded)
        |
        v
  health validation

The state tree is *semantic desired configuration*, not a copy of ``/etc``:
sections for system, domains, apps, services, identities, capabilities and
package versions. Runtime truth belongs to Linux/systemd; this repository
records intent and history.

The executor (nostr_operationsd) drives pre/post snapshots automatically via
:class:`StateRecorder`; the ``nostrhost-state`` CLI exports, commits,
diffs and inspects history by hand; :func:`announce_state_repository`
publishes a NIP-34 repository announcement (kind 30617) signed by the server
key, making the state repository discoverable as
``nostr://<server-npub>/nostrhost-state``.

Repository authority is separate from operational authority: a repository
change never bypasses ``nostrhost-policy`` — it is applied through the same
operation chain. Secrets are never stored: the manifest references secret
identifiers (systemd credentials / age / SOPS) only.

Heavy dependencies (yunohost modules, git) are imported/executed lazily so the
module is importable and unit-testable without a live server.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any, Callable

from .nostr_identity import (
    _operator_config,
    _require_bootstrapped,
    _sign_event,
    publish_to_relay,
)

logger = logging.getLogger("nostr-state")

# State repository constants (overridable for tests / alternate roots).
STATE_SCHEMA = 1
STATE_REPO_NAME = "nostrhost-state"
DEFAULT_STATE_DIR = "/var/lib/nostrhost/state"
KNOWN_GOOD_TAG = "known-good"

# NIP-34 kind: repository announcement (replaceable, server-authoritative).
KIND_REPOSITORY_ANNOUNCEMENT = 30617

# Operations that can affect application data and therefore warrant a linked
# Restic data snapshot alongside the configuration-state commit.
DATA_AFFECTING_TOOLS = frozenset(
    {
        "app.install",
        "app.upgrade",
        "app.remove",
        "backup.create",
        "backup.restore",
    }
)


class StateError(RuntimeError):
    """The state repository or export failed."""


# --------------------------------------------------------------------------- #
# TOML helpers (the state manifest and section files are TOML; tomllib only
# reads, so a minimal writer for the flat schemas we produce is included).

def _tquote(s: str) -> str:
    """JSON string escaping is valid TOML basic-string syntax."""
    return json.dumps(str(s), ensure_ascii=False)


def _scalar(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        return _tquote(v)
    # Nested structures (OrderedDict from yunohost settings, lists of dicts,
    # datetimes, …) are preserved as JSON inside a TOML string so a snapshot
    # never fails on an unrepresentable value.
    if isinstance(v, dict):
        return _tquote(json.dumps(dict(v), default=str))
    if isinstance(v, (list, tuple)):
        if all(isinstance(x, (str, int, float, bool)) for x in v):
            return "[" + ", ".join(_scalar(x) for x in v) + "]"
        return _tquote(json.dumps(list(v), default=str))
    return _tquote(str(v))


def _dump_toml(data: dict[str, Any]) -> str:
    """Render a flat schema (scalars + one level of dict-of-scalars) as TOML."""
    lines: list[str] = []
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"[{key}]")
            for sub, v in value.items():
                lines.append(f"{sub} = {_scalar(v)}")
        else:
            lines.append(f"{key} = {_scalar(value)}")
    return "\n".join(lines).rstrip() + "\n"


def _manifest(
    *,
    known_good: bool = False,
    op_event_id: str = "",
    phase: str = "",
    restic_snapshot: str = "",
    required: bool = False,
    health: str = "pending",
) -> str:
    return (
        "[state]\n"
        f"schema = {STATE_SCHEMA}\n"
        f"known_good = {'true' if known_good else 'false'}\n"
        "\n"
        "[operation]\n"
        f"event = {_tquote(op_event_id)}\n"
        f"phase = {_tquote(phase)}\n"
        "\n"
        "[backup]\n"
        f"restic_snapshot = {_tquote(restic_snapshot)}\n"
        f"required = {'true' if required else 'false'}\n"
        "\n"
        "[health]\n"
        f"result = {_tquote(health)}\n"
    )


# --------------------------------------------------------------------------- #
# semantic state export

class Backend:
    """Source of truth for one semantic section. Production is
    :class:`YunohostBackend`; tests inject a fake with the same surface."""

    def hostname(self) -> str:  # pragma: no cover - interface
        raise NotImplementedError

    def os(self) -> dict[str, Any]:  # pragma: no cover - interface
        raise NotImplementedError

    def settings(self) -> dict[str, Any]:  # pragma: no cover - interface
        raise NotImplementedError

    def domains(self) -> dict[str, dict[str, Any]]:  # pragma: no cover - interface
        raise NotImplementedError

    def apps(self) -> dict[str, dict[str, Any]]:  # pragma: no cover - interface
        raise NotImplementedError

    def services(self) -> dict[str, dict[str, Any]]:  # pragma: no cover - interface
        raise NotImplementedError

    def users(self) -> dict[str, dict[str, Any]]:  # pragma: no cover - interface
        raise NotImplementedError

    def packages(self) -> dict[str, Any]:  # pragma: no cover - interface
        raise NotImplementedError


class YunohostBackend(Backend):
    """Exports the live machine's semantic desired state through the fork's
    own (decorated) functions. Each section is best-effort: a failing section
    records an empty dict rather than aborting the snapshot."""

    def __init__(self) -> None:
        # YunoHost's operation logger + moulinette interface are required to
        # call the decorated functions from a headless/CLI context.
        try:
            from .nostr_identity import _init_headless_yunohost

            _init_headless_yunohost()
        except Exception as exc:  # noqa: BLE001 - export is best-effort
            logger.debug("headless init unavailable: %s", exc)

    def hostname(self) -> str:
        return socket.gethostname()

    def os(self) -> dict[str, Any]:
        import platform

        return {"machine": platform.machine(), "release": platform.release()}

    def settings(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        try:
            from yunohost.settings import settings_get

            for key in ("security.root_access",):
                try:
                    out[key] = settings_get(key)
                except Exception:  # noqa: BLE001 - per-key best effort
                    continue
        except Exception as exc:  # noqa: BLE001
            logger.debug("settings export unavailable: %s", exc)
        return out

    def domains(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        try:
            from yunohost.domain import domain_list

            info = domain_list()
            main = info.get("main") or ""
            for domain in info.get("domains") or []:
                out[domain] = {"main": bool(domain == main), "apps": []}
        except Exception as exc:  # noqa: BLE001
            logger.warning("domains export failed: %s", exc)
        return out

    def apps(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        try:
            from yunohost.app import app_list

            for app in (app_list(full=True).get("apps") or []):
                app_id = str(app.get("id") or "")
                if not app_id:
                    continue
                out[app_id] = {
                    "label": str(app.get("label") or app.get("name") or ""),
                    "version": str(app.get("version") or ""),
                    "domain": str(app.get("domain") or ""),
                    "path": str(app.get("path") or ""),
                    "status": str(app.get("status") or ""),
                }
        except Exception as exc:  # noqa: BLE001
            logger.warning("apps export failed: %s", exc)
        return out

    def services(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        try:
            from yunohost.service import service_status

            for name, info in (service_status() or {}).items():
                out[name] = {
                    "status": str(info.get("status") or ""),
                    "type": str(info.get("type") or ""),
                }
        except Exception as exc:  # noqa: BLE001
            logger.warning("services export failed: %s", exc)
        return out

    def users(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        try:
            from yunohost.user import user_group_list, user_list

            users = (user_list().get("users") or {})
            groups = {name: list(info.get("members") or []) for name, info in (user_group_list().get("groups") or {}).items()}
            for username, info in users.items():
                out[username] = {
                    "fullname": str(info.get("fullname") or ""),
                    "groups": [g for g, members in groups.items() if username in members],
                }
        except Exception as exc:  # noqa: BLE001
            logger.warning("users export failed: %s", exc)
        return out

    def packages(self) -> dict[str, Any]:
        try:
            from yunohost.tools import tools_versions

            return {name: str(info.get("version") or "") for name, info in tools_versions().items()}
        except Exception as exc:  # noqa: BLE001
            logger.warning("packages export failed: %s", exc)
            return {}


def export_state(backend: Backend, capabilities: dict[str, list[str]] | None = None) -> dict[str, dict[str, dict[str, Any]]]:
    """Compose the semantic state tree.

    ``capabilities`` maps subject pubkey -> granted scopes (the projected
    31100 grants from the operations engine); when absent (CLI/standalone
    use) the capabilities section is omitted rather than fabricated.
    """
    tree: dict[str, dict[str, dict[str, Any]]] = {
        "system": {"host.toml": {"hostname": backend.hostname(), "os": backend.os(), "settings": backend.settings()}},
        "domains": {f"{name}.toml": data for name, data in backend.domains().items()},
        "apps": {f"{app}.toml": data for app, data in backend.apps().items()},
        "services": {f"{service}.toml": data for service, data in backend.services().items()},
        "identities": {f"{user}.toml": data for user, data in backend.users().items()},
        "package-versions": {"versions.toml": backend.packages()},
    }
    if capabilities:
        tree["capabilities"] = {
            f"{pubkey}.toml": {"type": "agent", "scopes": sorted(scopes)}
            for pubkey, scopes in capabilities.items()
            if scopes
        }
    return tree


# --------------------------------------------------------------------------- #
# git-backed state repository

class StateRepo:
    """A normal Git repository (``<path>/nostrhost-state``) whose identity is
    bound to the server's Nostr pubkey. Stage A keeps object storage local;
    NIP-34 announcement + outbound replication is Stage C."""

    def __init__(self, path: str | Path, server_pubkey: str) -> None:
        self.path = Path(path)
        self._state_dir = self.path
        self.server_pubkey = server_pubkey

    # -- mechanics ---------------------------------------------------------- #

    def _git(self, args: list[str]) -> str:
        res = subprocess.run(["git", "-C", str(self.path), *args], capture_output=True, text=True)
        if res.returncode != 0:
            raise StateError(f"git {' '.join(args)} failed: {res.stderr.strip()}")
        return res.stdout

    def ensure(self) -> None:
        """Initialise the repository and pin the git identity to the server."""
        self.path.mkdir(parents=True, exist_ok=True)
        if not (self.path / ".git").exists():
            self._git(["init", "-q"])
        self._git(["config", "user.name", "nostrhost-state"])
        self._git(["config", "user.email", f"{self.server_pubkey}@nostrhost"])

    def _render(self, tree: dict[str, dict[str, dict[str, Any]]]) -> None:
        # Remove stale files so a snapshot is an exact render of the tree.
        for stale in self.path.glob("*.toml"):
            stale.unlink()
        for section, files in tree.items():
            sec = self.path / section
            if sec.exists():
                shutil.rmtree(sec)
            sec.mkdir(parents=True, exist_ok=True)
            for name, data in files.items():
                (sec / name).write_text(_dump_toml(data) if isinstance(data, dict) else str(data))

    # -- snapshots ---------------------------------------------------------- #

    def commit(
        self,
        tree: dict[str, dict[str, dict[str, Any]]],
        *,
        op_event_id: str = "",
        phase: str = "",
        known_good: bool = False,
        restic_snapshot: str = "",
        required: bool = False,
        health: str = "pending",
        message: str | None = None,
    ) -> str:
        """Render the tree, write the manifest and commit; move the
        ``known-good`` tag when the snapshot is a validated state."""
        self.ensure()
        self._render(tree)
        (self.path / "manifest.toml").write_text(
            _manifest(known_good=known_good, op_event_id=op_event_id, phase=phase, restic_snapshot=restic_snapshot, required=required, health=health)
        )
        self._git(["add", "-A"])
        msg = message or "state snapshot"
        if phase:
            msg += f" phase={phase}"
        if op_event_id:
            msg += f" op={op_event_id}"
        if health:
            msg += f" health={health}"
        self._git(["commit", "-m", msg, "--allow-empty"])
        rev = self._git(["rev-parse", "HEAD"]).strip()
        if known_good:
            self._git(["tag", "-f", KNOWN_GOOD_TAG, rev])
        return rev

    # -- inspection --------------------------------------------------------- #

    def revision(self) -> str:
        try:
            return self._git(["rev-parse", "HEAD"]).strip()
        except StateError:
            return ""

    def known_good_revision(self) -> str:
        try:
            return self._git(["rev-parse", "--verify", f"refs/tags/{KNOWN_GOOD_TAG}"]).strip()
        except StateError:
            return ""

    def is_dirty(self) -> bool:
        try:
            return bool(self._git(["status", "--porcelain"]).strip())
        except StateError:
            return False

    def history(self, n: int = 20) -> list[dict[str, Any]]:
        fmt = "%H%x00%s%x00%ct"
        try:
            out = self._git(["log", f"-{n}", f"--format={fmt}", "--", "."])
        except StateError:
            return []
        kg = self.known_good_revision()
        entries: list[dict[str, Any]] = []
        for rec in out.splitlines():
            head, subject, ts = rec.split("\x00")
            entries.append(
                {
                    "revision": head,
                    "message": subject,
                    "created_at": int(ts),
                    "op_event_id": _op_id_from_message(subject),
                    "known_good": head == kg,
                }
            )
        return entries

    def diff(self, ref_a: str, ref_b: str) -> str:
        """Semantic diff between two state revisions (or a revision and HEAD)."""
        res = subprocess.run(["git", "-C", str(self.path), "diff", "--exit-code", ref_a, ref_b, "--", "."], capture_output=True, text=True)
        if res.returncode in (0, 1):
            return res.stdout
        raise StateError(f"git diff {ref_a} {ref_b} failed: {res.stderr.strip()}")

    def diff_names(self, ref_a: str, ref_b: str) -> list[tuple[str, str]]:
        """Structured per-file change list between two revisions.

        Returns ``(status, path)`` tuples with ``status`` in A/M/D (add,
        modify, delete) — the input the rollback planner classifies.
        """
        res = subprocess.run(
            ["git", "-C", str(self.path), "diff", "--no-renames", "--name-status", ref_a, ref_b, "--", "."],
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            raise StateError(f"git diff --name-status {ref_a} {ref_b} failed: {res.stderr.strip()}")
        out: list[tuple[str, str]] = []
        for line in res.stdout.splitlines():
            if "\t" in line:
                status, path = line.split("\t", 1)
                if status in ("A", "M", "D"):
                    out.append((status, path))
        return out

    def show(self, rev: str, path: str) -> str:
        """Read one file at a revision (e.g. a manifest for restic linkage)."""
        res = subprocess.run(["git", "-C", str(self.path), "show", f"{rev}:{path}"], capture_output=True, text=True)
        if res.returncode != 0:
            raise StateError(f"git show {rev}:{path} failed: {res.stderr.strip()}")
        return res.stdout


def _op_id_from_message(subject: str) -> str | None:
    marker = "op="
    idx = subject.find(marker)
    if idx < 0:
        return None
    candidate = subject[idx + len(marker) : idx + len(marker) + 64]
    return candidate if len(candidate) == 64 else None


# --------------------------------------------------------------------------- #
# executor integration (pre/post snapshots)

class StateRecorder:
    """Hooks the operation executor into the state layer: an automatic
    pre-change commit before execution and a post-change commit after, the
    latter marked known-good when the operation succeeded."""

    def __init__(
        self,
        repo: StateRepo,
        backend: Backend | None = None,
        capabilities: dict[str, list[str]] | Callable[[], dict[str, list[str]]] | None = None,
        restic_hook: Callable[[], str] | None = None,
    ) -> None:
        self.repo = repo
        self.backend = backend or YunohostBackend()
        self._capabilities = capabilities
        self._restic_hook = restic_hook

    def _caps(self) -> dict[str, list[str]]:
        if self._capabilities is None:
            return {}
        return self._capabilities() if callable(self._capabilities) else self._capabilities

    def pre(self, request_id: str, tool: str, args: dict[str, Any]) -> str:
        return self.snapshot(op_event_id=request_id, phase="pre", health="pending", tool=tool)

    def post(self, request_id: str, tool: str, ok: bool, result: dict[str, Any]) -> str:
        return self.snapshot(
            op_event_id=request_id,
            phase="post",
            known_good=bool(ok),
            health="passed" if ok else "failed",
            tool=tool,
            data_affecting=tool in DATA_AFFECTING_TOOLS,
        )

    def snapshot(
        self,
        *,
        op_event_id: str = "",
        phase: str = "",
        known_good: bool = False,
        health: str = "pending",
        tool: str = "",
        data_affecting: bool = False,
    ) -> str:
        tree = export_state(self.backend, self._caps())
        restic = ""
        if data_affecting and self._restic_hook is not None:
            restic = str(self._restic_hook() or "")
        return self.repo.commit(
            tree,
            op_event_id=op_event_id,
            phase=phase,
            known_good=known_good,
            restic_snapshot=restic,
            required=data_affecting,
            health=health,
            message=f"operation {tool}" if tool else None,
        )


# --------------------------------------------------------------------------- #
# NIP-34 repository announcement (discovery / ownership)

def build_repository_announcement(
    server_sk: str,
    server_pubkey: str,
    *,
    name: str = STATE_REPO_NAME,
    description: str = "NostrHost semantic configuration-state repository",
) -> dict[str, Any]:
    """Build (without publishing) a kind-30617 NIP-34 repository announcement.

    Tags per NIP-34: ``d`` = repository name, ``i`` = repository id (SHA-256
    of the repository's canonical identity, namespaced by the server pubkey),
    ``n`` = network, ``r`` = relative path. Content is the description.
    """
    repo_id = hashlib.sha256(f"{server_pubkey}:{name}".encode()).hexdigest()
    tags = [["d", name], ["i", repo_id], ["n", "nostr"], ["r", f"{name}.git"]]
    return _sign_event(server_sk, server_pubkey, KIND_REPOSITORY_ANNOUNCEMENT, description, tags)


def announce_state_repository(
    control_relay: str | None = None,
    transport: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Publish the server's state-repository announcement to the control relay
    (signed by the server key; NIP-42-authenticated by the operator)."""
    _require_bootstrapped()
    cfg = _operator_config()
    event = build_repository_announcement(cfg.server_sk, cfg.server_pubkey)
    (transport or publish_to_relay)(cfg.control_relay, event)
    return event


# --------------------------------------------------------------------------- #
# entry points shared with the CLI

def state_dir_from_env() -> Path:
    return Path(os.environ.get("NOSTRHOST_STATE_DIR", DEFAULT_STATE_DIR))


def default_repo() -> StateRepo:
    _require_bootstrapped()
    cfg = _operator_config()
    return StateRepo(state_dir_from_env(), cfg.server_pubkey)


def default_recorder(repo: StateRepo | None = None) -> StateRecorder:
    """The production recorder: semantic snapshots plus, when a restic config
    exists, an automatic data snapshot before data-affecting operations. A
    missing/empty restic config degrades to a config-only recorder (the hook
    returns ""), so backups are additive, never a hard dependency."""
    from .nostr_restic import restic_snapshot_hook

    return StateRecorder(repo or default_repo(), restic_hook=restic_snapshot_hook())