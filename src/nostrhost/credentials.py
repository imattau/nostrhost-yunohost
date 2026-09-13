"""DNS credential broker (W4 Phase B).

Provider tokens live in root-owned mode-600 files under
``/var/lib/nostrhost/credentials``, namespaced ``dns/<provider>/<name>``.
Provider resources reference them as ``secret:dns/<provider>/<name>`` and
resolve the file themselves (see :func:`resolve` / :func:`read_secret`) so
operators and agents never see the token. The directory layout reuses the
existing systemd-credential store from :class:`SecretProvider` (same
``credentials`` dir, ``dns/`` namespace).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from .dns.models import PROVIDER_TYPES

_REF_RE = re.compile(r"^secret:dns/([a-zA-Z0-9_-]+)/([a-zA-Z0-9_.-]+)$")
_SAFE_PART = re.compile(r"^[a-zA-Z0-9_.-]+$")


class CredentialError(ValueError):
    pass


def credentials_dir(state_dir: Path | None = None) -> Path:
    """The broker root: the shared systemd-credential store.

    Credentials are a sibling of the state dir (``/var/lib/nostrhost/
    credentials`` next to ``.../state``); when a test state_dir is passed the
    store is ``<state_dir>.parent/credentials`` so tests stay self-contained.
    """
    if state_dir is not None:
        return state_dir.parent / "credentials"
    return Path("/var/lib/nostrhost/credentials")


def parse_ref(ref: str) -> tuple[str, str]:
    """Split a ``secret:dns/<provider>/<name>`` ref into (provider, name)."""
    match = _REF_RE.match(ref)
    if not match:
        raise CredentialError(f"malformed DNS credential reference {ref!r} (expected secret:dns/<provider>/<name>)")
    provider, name = match.groups()
    if provider not in PROVIDER_TYPES:
        raise CredentialError(f"unknown DNS provider {provider!r} in credential reference")
    return provider, name


def credential_path(ref: str, *, state_dir: Path | None = None, dir: Path | None = None) -> Path:
    """Absolute path behind ``ref``; validates the reference and traversal."""
    provider, name = parse_ref(ref)
    base = dir or credentials_dir(state_dir)
    path = base / "dns" / provider / name
    if ".." in path.parts or not _SAFE_PART.fullmatch(provider) or not _SAFE_PART.fullmatch(name):
        raise CredentialError(f"unsafe credential path for {ref!r}")
    return path


def exists(ref: str, *, state_dir: Path | None = None, dir: Path | None = None) -> bool:
    return credential_path(ref, state_dir=state_dir, dir=dir).is_file()


def resolve(ref: str, *, state_dir: Path | None = None, dir: Path | None = None) -> Path:
    """Resolve ``ref`` to its file, raising if the credential is missing."""
    path = credential_path(ref, state_dir=state_dir, dir=dir)
    if not path.is_file():
        raise CredentialError(f"DNS credential {ref!r} is not configured (use credential.set)")
    return path


def read_secret(ref: str, *, state_dir: Path | None = None, dir: Path | None = None) -> str:
    """Read the token behind ``ref``. The value never leaves the process."""
    path = resolve(ref, state_dir=state_dir, dir=dir)
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError as exc:  # pragma: no cover - defensive
        raise CredentialError(f"cannot read DNS credential {ref!r}: {exc}") from exc


def set_secret(ref: str, value: str, *, state_dir: Path | None = None, dir: Path | None = None) -> dict[str, Any]:
    """Write/replace a credential file (atomic, mode 600, owner-only dirs)."""
    if not value:
        raise CredentialError("credential value must not be empty")
    path = credential_path(ref, state_dir=state_dir, dir=dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    _harden(path.parent)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(value, encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    return {"ref": ref, "path": str(path), "set": True}


def remove_secret(ref: str, *, state_dir: Path | None = None, dir: Path | None = None) -> dict[str, Any]:
    """Delete a credential file; idempotent."""
    path = credential_path(ref, state_dir=state_dir, dir=dir)
    existed = path.is_file()
    path.unlink(missing_ok=True)
    return {"ref": ref, "removed": existed}


def list_secrets(provider: str | None = None, *, state_dir: Path | None = None, dir: Path | None = None) -> list[dict[str, str]]:
    """Enumerate configured DNS credentials as refs (names only, never values)."""
    base = (dir or credentials_dir(state_dir)) / "dns"
    if not base.is_dir():
        return []
    refs: list[dict[str, str]] = []
    for prov_dir in sorted(base.iterdir()):
        if not prov_dir.is_dir() or (provider is not None and prov_dir.name != provider):
            continue
        if prov_dir.name not in PROVIDER_TYPES:
            continue
        for name_file in sorted(prov_dir.glob("*")):
            if name_file.is_file():
                refs.append({"ref": f"secret:dns/{prov_dir.name}/{name_file.name}"})
    return refs


def _harden(directory: Path) -> None:
    """Lock the namespace directories down to root (0755/0700 chain)."""
    directory.chmod(0o700)
    parent = directory.parent
    if parent.name == "dns":
        parent.chmod(0o700)
    grandparent = parent.parent
    if grandparent.name == "credentials":
        grandparent.chmod(0o700)
    if not (Path("/var/lib/nostrhost") / "credentials").is_dir():
        return
    (Path("/var/lib/nostrhost") / "credentials").chmod(0o700)


def __getattr__(name: str) -> Any:  # pragma: no cover - import shim
    if name == "load_credentials_json":
        raise AttributeError("load_credentials_json removed; use set_secret/read_secret")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
