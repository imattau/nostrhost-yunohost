"""System-wide public Nostr relay and Blossom defaults.

The local control relay is deliberately not part of this model: it carries
machine approvals and audit events, while this module describes public
network destinations used for discovery, publishing, catalogue exchange and
Nsite manifests.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field


DEFAULT_RELAYS = [
    "wss://purplepag.es",
    "wss://nos.lol",
    "wss://relay.damus.io",
]
DEFAULT_DISCOVERY_RELAYS = ["wss://user.kindpag.es"]
DEFAULT_BLOSSOM_SERVERS = [
    "https://blossom.primal.net",
    "https://blossom.band",
]
PURPOSES = ("lookup", "publish", "catalogue", "nsite")


class ConnectivityOverrides(BaseModel):
    lookup: list[str] | None = None
    publish: list[str] | None = None
    catalogue: list[str] | None = None
    nsite: list[str] | None = None


class ConnectivityConfig(BaseModel):
    version: int = 1
    default_relays: list[str] = Field(default_factory=lambda: list(DEFAULT_RELAYS))
    default_blossom_servers: list[str] = Field(default_factory=lambda: list(DEFAULT_BLOSSOM_SERVERS))
    additional_discovery_relays: list[str] = Field(default_factory=lambda: list(DEFAULT_DISCOVERY_RELAYS))
    overrides: ConnectivityOverrides = Field(default_factory=ConnectivityOverrides)


class ConnectivityError(ValueError):
    pass


def _state_dir() -> Path:
    try:
        from yunohost.nostr_state import state_dir_from_env

        return state_dir_from_env()
    except Exception:  # noqa: BLE001 - usable in the standalone test environment
        return Path(os.environ.get("NOSTRHOST_STATE_DIR", "/var/lib/nostrhost/state"))


def config_path(state_dir: Path | None = None) -> Path:
    return (state_dir or _state_dir()) / "system" / "connectivity.json"


def _normalise_urls(values: Any, *, kind: Literal["relay", "blossom"], allow_empty: bool = False) -> list[str]:
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        raise ConnectivityError(f"{kind} destinations must be a list of URLs")
    output: list[str] = []
    seen: set[str] = set()
    expected = "wss" if kind == "relay" else "https"
    for raw in values:
        value = raw.strip().rstrip("/")
        parsed = urlsplit(value)
        if parsed.scheme != expected or not parsed.netloc or parsed.username or parsed.password or parsed.fragment:
            raise ConnectivityError(f"{kind} URL must use {expected}:// and include a public hostname: {raw!r}")
        key = value.casefold()
        if key not in seen:
            seen.add(key)
            output.append(value)
    if not output and not allow_empty:
        raise ConnectivityError(f"at least one {kind} destination is required")
    if len(output) > 20:
        raise ConnectivityError(f"at most 20 {kind} destinations are allowed")
    return output


def validate_config(value: dict[str, Any] | ConnectivityConfig) -> ConnectivityConfig:
    try:
        cfg = value if isinstance(value, ConnectivityConfig) else ConnectivityConfig.model_validate(value)
    except Exception as exc:  # noqa: BLE001 - converted into a stable domain error
        raise ConnectivityError(f"invalid Nostr settings: {exc}") from exc
    if cfg.version != 1:
        raise ConnectivityError("unsupported Nostr settings version")
    cfg.default_relays = _normalise_urls(cfg.default_relays, kind="relay")
    cfg.default_blossom_servers = _normalise_urls(cfg.default_blossom_servers, kind="blossom")
    cfg.additional_discovery_relays = _normalise_urls(
        cfg.additional_discovery_relays, kind="relay", allow_empty=True
    )
    for purpose in PURPOSES:
        values = getattr(cfg.overrides, purpose)
        if values is not None:
            setattr(cfg.overrides, purpose, _normalise_urls(values, kind="relay"))
    return cfg


def load_config(state_dir: Path | None = None) -> ConnectivityConfig:
    path = config_path(state_dir)
    if not path.is_file():
        return ConnectivityConfig()
    try:
        return validate_config(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConnectivityError(f"could not read Nostr settings: {exc}") from exc


def save_config(config: ConnectivityConfig, state_dir: Path | None = None) -> Path:
    config = validate_config(config)
    path = config_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(config.model_dump(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o640)
    temporary.replace(path)
    return path


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def effective(config: ConnectivityConfig | None = None) -> dict[str, Any]:
    cfg = config or load_config()
    relays: dict[str, list[str]] = {}
    sources: dict[str, str] = {}
    for purpose in PURPOSES:
        override = getattr(cfg.overrides, purpose)
        relays[purpose] = list(override if override is not None else cfg.default_relays)
        sources[purpose] = "override" if override is not None else "system-default"
    relays["lookup"] = _dedupe(relays["lookup"] + cfg.additional_discovery_relays)
    relays["nsite_lookup"] = _dedupe(relays["nsite"] + cfg.additional_discovery_relays)
    return {
        "relays": relays,
        "blossom_servers": list(cfg.default_blossom_servers),
        "sources": {**sources, "blossom": "system-default"},
    }


def public_view(*, control_relay: str = "") -> dict[str, Any]:
    cfg = load_config()
    return {
        "configured": cfg.model_dump(),
        "effective": effective(cfg),
        "control_relay": {"url": control_relay, "editable": False},
    }


def plan_config(value: dict[str, Any]) -> dict[str, Any]:
    before = load_config()
    after = validate_config(value)
    envelope: dict[str, Any] = {
        "action": "nostr.connectivity.set",
        "risk": "medium",
        "reversibility": "reversible",
        "before": before.model_dump(),
        "after": after.model_dump(),
        "effective": effective(after),
        "affected_services": ["nostrhost-catalog", "nostrhost-nsite"],
    }
    payload = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    envelope["plan_sha256"] = hashlib.sha256(payload).hexdigest()
    return envelope


def apply_config(value: dict[str, Any]) -> dict[str, Any]:
    before = load_config()
    cfg = validate_config(value)
    path = save_config(cfg)
    _project_nsite(before, cfg)
    _project_catalogue(cfg)
    return {
        "action": "nostr.connectivity.set",
        "configured": cfg.model_dump(),
        "effective": effective(cfg),
        "state": str(path),
        "ok": True,
    }


def _project_nsite(before: ConnectivityConfig, after: ConnectivityConfig) -> None:
    """Refresh inherited gateway values without overwriting custom gateway choices."""
    from .nsites.models import GatewayConfig
    from .nsites.service import NsiteService, load_gateway, save_gateway

    state_dir = _state_dir()
    state = load_gateway(state_dir)
    if not state or not state.get("config"):
        return
    current = GatewayConfig(**state["config"])
    before_effective = effective(before)
    after_effective = effective(after)
    legacy_lookup = ["wss://purplepag.es", "wss://user.kindpag.es"]
    if current.relays.lookup in (legacy_lookup, before_effective["relays"]["nsite_lookup"]):
        current.relays.lookup = list(after_effective["relays"]["nsite_lookup"])
    if current.blossom.fallback_servers in (DEFAULT_BLOSSOM_SERVERS, before_effective["blossom_servers"]):
        current.blossom.fallback_servers = list(after_effective["blossom_servers"])
    service = NsiteService(state_dir=state_dir)
    service.render_config(current)
    save_gateway(state_dir, {"enabled": bool(state.get("enabled")), "config": current.dict()})
    if state.get("enabled"):
        service._reload()


def _project_catalogue(config: ConnectivityConfig) -> None:
    """Keep the synchroniser's local relay and add the effective public targets."""
    path = Path(os.environ.get("NOSTRHOST_CATALOGUE_ENV", "/etc/nostrhost/catalogue.env"))
    if not path.is_file():
        return
    targets = ["ws://127.0.0.1:4848", *effective(config)["relays"]["catalogue"]]
    replacement = "NOSTRHOST_CATALOG_RELAYS=" + ",".join(dict.fromkeys(targets))
    lines = path.read_text(encoding="utf-8").splitlines()
    updated = False
    for index, line in enumerate(lines):
        if line.startswith("NOSTRHOST_CATALOG_RELAYS="):
            lines[index] = replacement
            updated = True
            break
    if not updated:
        lines.append(replacement)
    temporary = path.with_suffix(".tmp")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    subprocess.run(
        ["systemctl", "--no-block", "try-restart", "nostrhost-catalog.service"],
        capture_output=True,
        text=True,
        check=False,
    )


def check_destinations(relays: list[str], servers: list[str]) -> dict[str, Any]:
    checked_relays = _normalise_urls(relays, kind="relay", allow_empty=True)[:10]
    checked_servers = _normalise_urls(servers, kind="blossom", allow_empty=True)[:10]
    from .nsites.service import NsiteService

    return NsiteService().reachability(relays=checked_relays, servers=checked_servers, timeout=5.0)
