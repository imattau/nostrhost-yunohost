"""npack integration: stage verified .npk artifacts and load their manifests.

This is the transport/integrity layer of the hybrid staged store. The npack
binary (see the ``forks/npack`` submodule) resolves publisher-signed kind-9900
release events, downloads the NIP-94 artifact, verifies its SHA-256, and
installs the payload into an isolated ``--store`` prefix with host-relative
paths. This module turns that staged store into a native-plan envelope: it
reads the canonical manifest embedded at ``.npack/nostrhost/manifest.json`` and
returns the provenance block the resource engine binds into the approved plan.

Nothing here mutates the host; staging writes only to the isolated store.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from .package_engine import PackageError, _canonical_json

NPK_STORE_DEFAULT = Path("/var/lib/nostrhost/npack-store")
NPK_NATIVE_MANIFEST = ".npack/nostrhost/manifest.json"
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_COORDINATE = re.compile(r"^(npub1[a-z0-9]+|npub1[a-z0-9]+/\S+|npub1[a-z0-9]+/\S+@\S+|[0-9a-fA-F]{64}/[A-Za-z0-9._-]+(?:@\S+)?)$")


def _npack_binary(npack_bin: str = "") -> str:
    return npack_bin or os.environ.get("NPACK_BIN", "npack")


def _run(binary: str, args: list[str], *, store: Path | None = None) -> subprocess.CompletedProcess[str]:
    command = [binary, *args]
    if store is not None:
        command += ["--store", str(store)]
    try:
        return subprocess.run(command, text=True, capture_output=True, check=False)
    except OSError as exc:
        raise PackageError(f"could not run npack: {exc}") from exc


def normalize_publisher(publisher: str) -> str:
    """Accept npub or hex; return canonical lowercase hex."""
    value = publisher.strip()
    if _HEX64.fullmatch(value):
        return value.lower()
    if value.startswith("npub1"):
        # npack accepts npub directly for resolution; keep it for display, the
        # resolved provenance carries the canonical hex.
        return value
    raise PackageError(f"publisher must be an npub or 64-character hex public key: {publisher}")


def parse_coordinate(coordinate: str) -> tuple[str, str, str | None]:
    """Split ``<publisher>/<name>[@<version>]`` into (publisher, name, version)."""
    coordinate = coordinate.strip()
    if not coordinate or "/" not in coordinate:
        raise PackageError(f"npack coordinate must be <publisher>/<name>[@version]: {coordinate}")
    publisher, _, rest = coordinate.partition("/")
    name, _, version = rest.partition("@")
    if not publisher or not name:
        raise PackageError(f"npack coordinate must be <publisher>/<name>[@version]: {coordinate}")
    return normalize_publisher(publisher), name, version or None


def resolve(coordinate: str, *, relay: str = "", npack_bin: str = "") -> dict[str, Any]:
    """Resolve and verify a package's release metadata without installing it.

    Runs ``npack resolve`` (the same relay discovery, signature/revocation and
    hash verification remote install uses) and returns the parsed JSON, which
    includes ``publisher``, ``name``, ``version``, ``sha256``, candidate
    artifact URLs and a ``verification`` summary.
    """
    binary = _npack_binary(npack_bin)
    args = ["resolve", coordinate]
    if relay:
        args += ["--relay", relay]
    result = _run(binary, args)
    if result.returncode != 0:
        raise PackageError(f"npack resolve failed: {result.stderr.strip() or result.stdout.strip()}")
    try:
        body = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise PackageError(f"npack resolve returned invalid JSON: {result.stdout.strip()[:200]}") from exc
    verification = body.get("verification", {})
    if not verification.get("release_signature_valid") or not verification.get("artifact_event_signature_valid"):
        raise PackageError(f"npack release failed signature verification: {verification}")
    if verification.get("revoked"):
        raise PackageError("npack release has been revoked")
    if not verification.get("publisher_trusted"):
        raise PackageError("npack publisher is not trusted by this host")
    if not _HEX64.fullmatch(str(body.get("publisher", ""))) or not _HEX64.fullmatch(str(body.get("sha256", ""))):
        raise PackageError("npack resolve returned an unexpected publisher or artifact hash")
    return body


def stage(coordinate: str, *, store: Path = NPK_STORE_DEFAULT, relay: str = "", npack_bin: str = "") -> dict[str, Any]:
    """Stage a verified package into the isolated store and return its layout.

    Returns ``{publisher, name, version, artifact_sha256, store, payload_root,
    embedded_manifest}`` where ``payload_root`` is the directory whose files
    sit at host-relative paths (the input to the resource engine's
    ``payload.sync`` provider).
    """
    binary = _npack_binary(npack_bin)
    resolved = resolve(coordinate, relay=relay, npack_bin=binary)
    publisher = resolved["publisher"].lower()
    name = resolved["name"]
    version = resolved["version"]
    artifact_sha256 = resolved["sha256"].lower()

    install = _run(binary, ["install", coordinate], store=store)
    if install.returncode != 0:
        raise PackageError(f"npack install failed: {install.stderr.strip() or install.stdout.strip()}")

    payload_root = store / "packages" / publisher / name / version / "payload"
    if not (payload_root / NPK_NATIVE_MANIFEST).is_file():
        raise PackageError(f"staged artifact has no embedded native manifest: {payload_root}")
    return {
        "publisher": publisher,
        "name": name,
        "version": version,
        "artifact_sha256": artifact_sha256,
        "store": str(store),
        "payload_root": str(payload_root),
        "embedded_manifest": NPK_NATIVE_MANIFEST,
    }


def load_embedded_manifest(payload_root: str | Path) -> dict[str, Any]:
    """Read the canonical native manifest embedded in a staged artifact."""
    path = Path(payload_root) / NPK_NATIVE_MANIFEST
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PackageError(f"cannot read embedded native manifest: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("app"), dict):
        raise PackageError(f"{path} is not a native package manifest (missing [app])")
    return data


def provenance(npack: dict[str, Any]) -> dict[str, Any]:
    """Return the envelope npack provenance block for a staged layout."""
    return {
        "publisher": npack["publisher"],
        "name": npack["name"],
        "version": npack["version"],
        "artifact_sha256": npack["artifact_sha256"],
        "payload_root": npack["payload_root"],
    }


def verify_embedded_matches(package_data: dict[str, Any], npack: dict[str, Any]) -> None:
    """Refuse to plan an embedded manifest whose canonical digest does not
    match the resolved artifact's expected payload. The payload root is staged
    from the same artifact whose sha256 the resolver verified, so a mismatch
    here means the store or the embedded manifest is out of sync."""
    expected = npack.get("manifest_sha256")
    if not expected:
        return
    actual = __import__("hashlib").sha256(_canonical_json(package_data)).hexdigest()
    if actual.lower() != str(expected).lower():
        raise PackageError(f"embedded native manifest hash mismatch: expected {expected}, got {actual}")
