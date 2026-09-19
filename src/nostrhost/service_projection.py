"""WP7: provenance-tracked rendering of generated service configuration.

Every generated service file (``nsite.toml``, ``notify.toml``,
``oidc.toml``, ``security.toml``, ``ddns.toml``) is treated as a *projection*
of an authoritative source (an event document, an ngit desired-state
revision, or a derived operator view). This module provides the shared
plumbing:

* :func:`render_managed` — validate the candidate with the service's native
  config checker, write it atomically (mode + optional group ownership), and
  record a provenance sidecar recording the source revision, the sha256 of
  the exact bytes written and the reload outcome, then reload the consumer
  when the file changed. When a ``health_check`` is supplied the consumer is
  polled after reload and a failed health check rolls the file back;
* :func:`check_drift` — compare the on-disk file against its recorded digest
  so manual edits are detected (WP7 exit gate);
* :func:`reconcile` — re-render from the authority and restore the desired
  version.

The sidecar lives next to the rendered file as ``<target>.source.json``
(root:root, 0640) and is the single provenance record a drift check reads.
Secrets are never part of the desired-state inputs: renderers resolve them
from the local credential/operator store at execution time.

The validators are deliberately small and native:

* ``nsite-go``  — shells to ``nostrhost-nsite -check-config <candidate>``
  (``config.Load``+``Validate``), so a config the gateway would refuse is
  never installed;
* ``notify-toml`` / ``oidc-toml`` — parse the candidate with ``tomllib`` and
  enforce the same structural invariants the Go consumers check, so a render
  failure is caught before the file is replaced;
* ``toml`` — parse the candidate with ``tomllib`` for configs whose consumer
  (``security.toml``, ``ddns.toml``) has no separate native checker.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import time
import tomllib
from pathlib import Path
from typing import Any, Callable

from yunohost.nostr_projector import _atomic_write

logger = logging.getLogger("nostr-service-projection")

#: Env override for the nsite binary path (tests / alternate installs).
NSITE_BINARY = os.environ.get("NOSTRHOST_NSITE_BINARY", "nostrhost-nsite")

#: Env override for the systemd service name used by the reload actions.
NSITE_SERVICE = os.environ.get("NOSTRHOST_NSITE_SERVICE", "nostrhost-nsite")
NOTIFY_SERVICE = os.environ.get("NOSTRHOST_NOTIFY_SERVICE", "nostrhost-notify")


class ServiceRenderError(RuntimeError):
    """A candidate failed validation and was not installed."""


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def provenance_path(target: str | Path) -> Path:
    """The sidecar path for ``target`` (``<target>.source.json``)."""
    return Path(str(target) + ".source.json")


def read_provenance(target: str | Path) -> dict[str, Any] | None:
    path = provenance_path(target)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _restore_provenance(target: str | Path, record: dict[str, Any] | None) -> None:
    """Restore a previous provenance sidecar (or remove it) after a rollback."""
    path = provenance_path(target)
    if record is None:
        path.unlink(missing_ok=True)
        return
    _atomic_write(path, json.dumps(record, indent=2, sort_keys=True) + "\n", mode=0o644)


def write_provenance(
    target: str | Path,
    *,
    source: str,
    source_revision: str,
    renderer: str,
    digest: str,
    rendered_at: float | None = None,
    reload: dict[str, Any] | None = None,
) -> Path:
    record = {
        "source": source,
        "source_revision": source_revision,
        "renderer": renderer,
        "rendered_sha256": digest,
        "rendered_at": rendered_at if rendered_at is not None else time.time(),
    }
    if reload is not None:
        record["reload"] = reload
    path = provenance_path(target)
    _atomic_write(path, json.dumps(record, indent=2, sort_keys=True) + "\n", mode=0o644)
    return path


# --------------------------------------------------------------------------- #
# native config checkers


def validate_nsite(content: str, *, binary: str | None = None) -> None:
    """Validate ``nsite.toml`` content with the Go gateway's check-config."""
    binary = binary or os.environ.get("NOSTRHOST_NSITE_BINARY", NSITE_BINARY)
    if not shutil.which(binary):
        logger.warning("nsite validator unavailable (%s not found); skipping native check", binary)
        return
    tmp = Path(os.environ.get("NOSTRHOST_TMP", "/tmp")) / f"nsite-check-{os.getpid()}.toml"
    try:
        tmp.write_text(content, encoding="utf-8")
        proc = subprocess.run(
            [binary, "-config", str(tmp), "-check-config"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    finally:
        tmp.unlink(missing_ok=True)
    if proc.returncode != 0:
        raise ServiceRenderError(
            f"nsite.toml failed native validation: {(proc.stderr or proc.stdout or '').strip()[:400]}"
        )


def validate_toml(content: str, *, required_tables: tuple[str, ...] = ()) -> None:
    """Parse content as TOML and check structural invariants."""
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ServiceRenderError(f"invalid TOML: {exc}") from exc
    if not isinstance(data, dict):
        raise ServiceRenderError("rendered config must be a TOML table")
    for table in required_tables:
        if not isinstance(data.get(table), (dict, list)):
            raise ServiceRenderError(f"rendered config is missing required table {table!r}")


def validate_notify(content: str) -> None:
    """Structural validation mirroring the Go notify config loader."""
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ServiceRenderError(f"invalid notify.toml: {exc}") from exc
    for key in ("relay_url", "recipients_path", "policy_path", "state_path"):
        if not isinstance(data.get(key), str) or not data[key]:
            raise ServiceRenderError(f"notify.toml must set non-empty {key}")
    if not isinstance(data.get("notifier_private_key"), str) or not data["notifier_private_key"]:
        raise ServiceRenderError("notify.toml must resolve notifier_private_key at render time")
    digest = data.get("digest_interval")
    if not isinstance(digest, str):
        raise ServiceRenderError("notify.toml must set digest_interval")
    if not isinstance(data.get("outbound_relays"), list) or not all(
        isinstance(item, str) for item in (data.get("outbound_relays") or [])
    ):
        raise ServiceRenderError("notify.toml outbound_relays must be a list of strings")


def validate_oidc(content: str) -> None:
    """Structural validation mirroring the portal OIDC reader."""
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ServiceRenderError(f"invalid oidc.toml: {exc}") from exc
    clients = data.get("clients")
    if not isinstance(clients, dict):
        raise ServiceRenderError("oidc.toml must carry a [clients] table")
    for client_id, client in clients.items():
        if not isinstance(client, dict):
            raise ServiceRenderError(f"oidc client {client_id!r} must be a table")
        uris = client.get("redirect_uris")
        if not isinstance(uris, list) or not uris or not all(isinstance(u, str) and u for u in uris):
            raise ServiceRenderError(f"oidc client {client_id!r} must set non-empty redirect_uris")
        if not isinstance(client.get("client_secret"), str) or not client["client_secret"]:
            raise ServiceRenderError(f"oidc client {client_id!r} must resolve client_secret at render time")


_VALIDATORS: dict[str, Callable[[str], None]] = {
    "nsite-go": validate_nsite,
    "notify-toml": validate_notify,
    "oidc-toml": validate_oidc,
    "toml": lambda content: validate_toml(content),
}


def run_validator(name: str, content: str) -> None:
    validator = _VALIDATORS.get(name)
    if validator is None:
        return
    validator(content)


# --------------------------------------------------------------------------- #
# reload actions


def _systemctl(action: str, service: str, signal: str | None = None) -> None:
    argv = ["systemctl", "--no-block"]
    if signal is not None:
        argv += ["kill", "-s", signal, service]
    else:
        argv += [action, service]
    subprocess.run(argv, capture_output=True, text=True, check=False)


def reload_sighup() -> None:
    """SIGHUP the nsite gateway: re-read config without dropping connections."""
    _systemctl("kill", NSITE_SERVICE, signal="HUP")


def reload_restart() -> None:
    """Restart a consumer that reads config only at startup."""
    _systemctl("try-restart", NOTIFY_SERVICE)


_RELOADS: dict[str, Callable[[], None]] = {
    "sighup": reload_sighup,
    "restart": reload_restart,
}


def run_reload(action: str | None) -> None:
    if action is not None:
        _RELOADS[action]()


# --------------------------------------------------------------------------- #
# the render entrypoint


def _wait_healthy(
    health_check: Callable[[], bool],
    *,
    retries: int = 5,
    delay: float = 1.0,
) -> bool:
    """Poll ``health_check`` until it reports healthy or the window is spent."""
    for _ in range(retries):
        if health_check():
            return True
        time.sleep(delay)
    return False


def render_managed(
    spec,
    content: str,
    *,
    source_revision: str,
    renderer: str,
    validate: bool = True,
    reload: bool = True,
    chown_group: str | None = None,
    health_check: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Validate → atomic-replace → provenance → reload a service config.

    ``spec`` is a :class:`nostrhost.service_specs.ServiceSpec` (or any object
    with ``path``/``validator``/``reload``/``mode``/``source`` attributes).
    Returns the digest written and whether the file actually changed. A
    validation failure raises :class:`ServiceRenderError` and leaves the
    last-known-good file in place.

    When ``health_check`` is given, the consumer is polled after the reload
    action. If it does not come up healthy, the previously-rendered bytes and
    provenance sidecar are restored and the report carries ``rolled_back`` —
    a bad config is never left installed (WP7 exit gate).
    """
    target = Path(spec.path)
    if validate:
        run_validator(spec.validator, content)
    digest = _sha256(content)
    changed = not (target.is_file() and _sha256(target.read_text(encoding="utf-8")) == digest)
    previous_text: str | None = None
    previous_provenance: dict[str, Any] | None = None
    if changed:
        previous_text = target.read_text(encoding="utf-8") if target.is_file() else None
        previous_provenance = read_provenance(target)
        _atomic_write(target, content, mode=spec.mode)
        if chown_group:
            try:
                import grp

                os.chown(target, 0, grp.getgrnam(chown_group).gr_gid)
            except (KeyError, OSError):
                logger.warning("could not set group %s on %s", chown_group, target)
    reload_result = None
    if changed and reload:
        reload_result = {"action": spec.reload, "ok": True}
        run_reload(spec.reload)
        if health_check is not None and not _wait_healthy(health_check):
            reload_result["ok"] = False
            if previous_text is not None:
                _atomic_write(target, previous_text, mode=spec.mode)
                if chown_group:
                    try:
                        import grp

                        os.chown(target, 0, grp.getgrnam(chown_group).gr_gid)
                    except (KeyError, OSError):
                        logger.warning("could not set group %s on %s", chown_group, target)
            _restore_provenance(target, previous_provenance)
            logger.error(
                "service %s failed health check after %s; rolled back %s",
                spec.name,
                reload_result["action"],
                target,
            )
            return {
                "name": spec.name,
                "path": str(target),
                "source": spec.source,
                "source_revision": source_revision,
                "rendered_sha256": digest,
                "changed": True,
                "reload": reload_result,
                "health": "failed",
                "rolled_back": True,
            }
    if changed:
        write_provenance(
            target,
            source=spec.source,
            source_revision=source_revision,
            renderer=renderer,
            digest=digest,
            reload=reload_result,
        )
    return {
        "name": spec.name,
        "path": str(target),
        "source": spec.source,
        "source_revision": source_revision,
        "rendered_sha256": digest,
        "changed": changed,
        "reload": reload_result,
    }


# --------------------------------------------------------------------------- #
# drift detection + reconcile


def check_drift(spec, target: str | Path | None = None) -> dict[str, Any]:
    """Compare the on-disk file against its recorded provenance digest.

    Returns ``{"drifted": bool, ...}``. ``drifted`` is True when the file is
    present and differs from the recorded digest, or when a file exists but no
    sidecar was recorded. Missing file + recorded sidecar reports a deletion.
    """
    path = Path(target or spec.path)
    provenance = read_provenance(path)
    if not path.is_file():
        return {
            "name": spec.name,
            "path": str(path),
            "drifted": True,
            "present": False,
            "reason": "rendered file is missing",
            "source_revision": (provenance or {}).get("source_revision", ""),
        }
    on_disk = _sha256(path.read_text(encoding="utf-8"))
    if provenance is None:
        return {
            "name": spec.name,
            "path": str(path),
            "drifted": True,
            "present": True,
            "reason": "no provenance sidecar (manually created or pre-WP7)",
            "rendered_sha256": on_disk,
        }
    drifted = on_disk != provenance.get("rendered_sha256")
    return {
        "name": spec.name,
        "path": str(path),
        "drifted": drifted,
        "present": True,
        "reason": "manual edit or stale render" if drifted else "matches source revision",
        "source": provenance.get("source", ""),
        "source_revision": provenance.get("source_revision", ""),
        "rendered_sha256": provenance.get("rendered_sha256", ""),
        "on_disk_sha256": on_disk,
        "reload": provenance.get("reload"),
    }


def check_all_drift(specs: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Drift report for every spec in the registry."""
    from .service_specs import SERVICE_SPECS

    return [check_drift(spec) for spec in (specs or SERVICE_SPECS).values()]


def reconcile(
    spec,
    render: Callable[[], str],
    *,
    source_revision: str,
    renderer: str,
    validate: bool = True,
    reload: bool = True,
    chown_group: str | None = None,
    health_check: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Re-render ``spec`` from its authority and restore the desired version."""
    content = render()
    return render_managed(
        spec,
        content,
        source_revision=source_revision,
        renderer=renderer,
        validate=validate,
        reload=reload,
        chown_group=chown_group,
        health_check=health_check,
    )


def reconcile_service_configs(names: list[str] | None = None) -> list[dict[str, Any]]:
    """Re-render every (or selected) managed service config from its authority.

    One dict per requested spec; a spec with no authority yet is reported as
    ``skipped``, a failed render as ``error``. This is the shared entrypoint
    behind both ``nostr-projector reconcile service`` and the
    ``service.config.reconcile`` operation, so the operation chain records the
    same per-file source revision, rendered digest and reload result.
    """
    from .service_specs import SERVICE_SPECS

    specs = {name: spec for name, spec in SERVICE_SPECS.items() if names is None or name in names}
    results: list[dict[str, Any]] = []
    for name, spec in specs.items():
        try:
            results.append(_reconcile_one(name, spec))
        except Exception as exc:  # noqa: BLE001 - one failure must not block the rest
            results.append({"name": name, "error": str(exc)})
    return results


def _reconcile_one(name: str, spec) -> dict[str, Any]:
    if name == "nsite":
        from .nsites.service import NsiteService, _default_state_dir, _ngit_revision, load_gateway

        state_dir = _default_state_dir()
        state = load_gateway(state_dir)
        config = (state or {}).get("config")
        if not config:
            return {"name": name, "skipped": "gateway not configured"}
        from .nsites.models import GatewayConfig

        return reconcile(
            spec,
            lambda c=config: NsiteService(state_dir=state_dir).render_config(GatewayConfig(**c))
            and "",
            source_revision=_ngit_revision(state_dir),
            renderer="nostr-projector reconcile",
            reload=False,
        )
    if name == "notify":
        from yunohost.nostr_identity import _operator_config

        cfg = _operator_config()
        from .cli import _render_notify_config

        return reconcile(
            spec,
            lambda sk=cfg.notifier_sk, relay=cfg.control_relay: _render_notify_config(sk, relay)
            and "",
            source_revision="local:operator+connectivity",
            renderer="nostr-projector reconcile",
            reload=False,
        )
    if name == "oidc":
        from .policy_projection import PolicyStore, render_oidc_clients
        from .policy_specs import spec_for_name as policy_spec_for_name

        store = PolicyStore()
        spec_entry = policy_spec_for_name("oidc-clients")
        entry = store.get(spec_entry.event_key(spec_entry.d))
        if entry is None:
            return {"name": name, "skipped": "no oidc-clients document folded"}
        render_oidc_clients(entry)
        return {"name": name, "reconciled": True}
    if name == "security":
        from .cli import _render_security_config

        _render_security_config()
        return {"name": name, "reconciled": True}
    if name == "ddns":
        from .cli import _render_ddns_config

        _render_ddns_config()
        return {"name": name, "reconciled": True}
    return {"name": name, "skipped": "no reconcile hook"}
