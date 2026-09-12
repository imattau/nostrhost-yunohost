"""Native ``nostrhost`` CLI.

The NostrHost administration CLI -- Typer commands over the native operation
surface.  No YunoHost/actionsmap compatibility: users are Nostr identities
(npubs), writes are the native resource-engine/control-plane tools, and
authorisation is capability-based.

Command groups:

    system      read-only system/package version info
    service     status / restart / control a service
    app         list / remove an installed app
    package     plan / reconcile a native package operation plan
    rollback    apply an assisted rollback plan
    state       apply a reconciliation plan
    identity    npub-based user identities (link / revoke / list / resolve)
    capability  grant / delegate / revoke capabilities to an npub
    postinstall first-run bootstrap / restore (new / restore / status)

The CLI runs as the authorized admin: read tools execute directly, and write
tools execute through their safe handlers here (the local admin is the
operator).  Remote agents route writes through the operation chain
(``nostr-opctl`` request/approve + ``nostr-operationsd``).  Keys and the
control relay are read from the operator config or overridden with
``--operator-sk`` / ``--admin-sk`` / ``--control-relay``.

Exit codes: 0 on success, 1 on any error, 2 on usage errors.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

import typer

from . import ui
from .core import NostrHostError
from yunohost.nostr_identity import (
    OPERATOR_CONFIG,
    IdentityError,
    _is_hex64,
    _npub,
    _parse_pubkey,
    link_identity,
    list_identities,
    list_identities_for_username,
    resolve_pubkey,
    resolve_username,
    revoke_identity,
)
from yunohost.nostr_operations import (
    OperationError,
    _safe_app_list,
    _safe_app_remove,
    _safe_package_plan,
    _safe_package_reconcile,
    _safe_reconcile_apply,
    _safe_rollback_apply,
    _safe_service_control,
    _safe_service_restart,
    _safe_service_status,
    _safe_system_version,
    delegate_capability,
    grant_capability,
    revoke_delegation,
)

EXIT_OK = 0
EXIT_ERR = 1

DESCRIPTION = (
    "NostrHost administration CLI: native tools, npub identities and "
    "capabilities. e.g. 'nostrhost system version', "
    "'nostrhost identity link alice npub1...', 'nostrhost service restart caddy'."
)

# Tool name -> safe handler (the ToolSpec registry is the source of truth).
_TOOL_HANDLERS: dict[str, Callable[..., Any]] = {
    "system.version": _safe_system_version,
    "service.status": _safe_service_status,
    "service.restart": _safe_service_restart,
    "service.control": _safe_service_control,
    "app.list": _safe_app_list,
    "app.remove": _safe_app_remove,
    "package.plan": _safe_package_plan,
    "package.reconcile": _safe_package_reconcile,
    "rollback.apply": _safe_rollback_apply,
    "state.reconcile": _safe_reconcile_apply,
}

VALID_SIGNER_TYPES = ("nip07", "nip46", "passkey", "unknown")


class _State:
    """Per-invocation global options shared with commands."""

    def __init__(self) -> None:
        self.output_as: str | None = None
        self.control_relay: str | None = None
        self.operator_sk: str | None = None
        self.admin_sk: str | None = None
        self.debug = False


def _print_error(exc: Exception) -> None:
    print(f"error: {exc}", file=sys.stderr)


def _run_tool(name: str, args: dict[str, Any]) -> Any:
    handler = _TOOL_HANDLERS[name]
    return handler(**args)


# --------------------------------------------------------------------------- #
# native app lifecycle (ALPHA-PLAN Workstream 3)

PACKAGE_CACHE = Path("/var/cache/nostrhost/catalogue")
SYSTEM_BACKUP_PATHS = ("/etc", "/home", "/opt", "/var/www", "/var/lib/nostrhost")


def _coordinate_for(
    app_id: str,
    *,
    repository: str | None = None,
    revision: str | None = None,
    package_path: str | None = None,
    manifest_sha256: str | None = None,
) -> dict[str, Any] | None:
    """Resolve the catalogue coordinate for ``app_id`` (per-field overridable)."""
    try:
        from nostr_catalog_provider import native_catalog_coordinate

        coordinate = native_catalog_coordinate(app_id) or {}
    except Exception:  # noqa: BLE001 - the catalogue is an optional source
        coordinate = {}
    for key, value in (
        ("repository", repository),
        ("revision", revision),
        ("package_path", package_path),
        ("manifest_sha256", manifest_sha256),
    ):
        if value:
            coordinate[key] = value
    return coordinate or None


def _load_package_data(source: Path | None, coordinate: dict[str, Any] | None) -> dict[str, Any]:
    """Return the resolved package.toml dict for an install/upgrade.

    ``--source`` may be a directory containing ``package_path`` (default
    ``package.toml``) or the manifest file itself. Without a local source the
    package is fetched from the coordinate's git repository at the pinned
    revision into the package cache."""
    import tomllib

    package_path = (coordinate or {}).get("package_path") or "package.toml"
    if source is not None:
        target = source / package_path if source.is_dir() else source
    else:
        coordinate = coordinate or {}
        repository = coordinate.get("repository")
        revision = coordinate.get("revision")
        if not repository or not revision:
            raise NostrHostError("no --source given and the catalogue coordinate lacks repository@revision")
        target = _fetch_catalogue_file(repository, revision, package_path)
    try:
        with target.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise NostrHostError(f"cannot load package {target}: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("app"), dict):
        raise NostrHostError(f"{target} is not a native package.toml (missing [app])")
    return raw


def _fetch_catalogue_file(repository: str, revision: str, package_path: str) -> Path:
    """Best-effort git checkout of ``repository@revision`` into the cache."""
    slug = hashlib.sha256(f"{repository}:{revision}".encode()).hexdigest()[:16]
    checkout = PACKAGE_CACHE / slug
    if not checkout.is_dir():
        PACKAGE_CACHE.mkdir(parents=True, exist_ok=True)
        temporary = checkout.with_suffix(".tmp")
        subprocess.run(["git", "clone", "--no-checkout", repository, str(temporary)], check=True, capture_output=True, text=True)
        temporary.rename(checkout)
    if not revision.startswith("refs/"):
        subprocess.run(["git", "-C", str(checkout), "checkout", "-q", revision], check=True, capture_output=True, text=True)
    return checkout / package_path


def _verify_package(package_data: dict[str, Any], coordinate: dict[str, Any] | None) -> None:
    """Refuse to plan a package whose canonical digest differs from the signed
    catalogue declaration's ``manifest_sha256``."""
    expected = (coordinate or {}).get("manifest_sha256")
    if not expected:
        return  # nothing to verify against
    from nostrhost.package_engine import _canonical_json

    actual = hashlib.sha256(_canonical_json(package_data)).hexdigest()
    if actual.lower() != str(expected).lower():
        raise NostrHostError(f"package manifest hash mismatch: expected {expected}, got {actual}")


def _plan_envelope(package_data: dict[str, Any], coordinate: dict[str, Any] | None) -> dict[str, Any]:
    from nostrhost.package_engine import package_plan_envelope

    return package_plan_envelope(package_data, catalogue=coordinate)


def _run_lifecycle(tool: str, args: dict[str, Any], *, state: _State) -> dict[str, Any]:
    from nostr_operations import run_signed_chain

    return run_signed_chain(
        tool,
        args,
        operator_sk=state.operator_sk,
        control_relay=state.control_relay,
    )


def _lifecycle_report(action: str, envelope: dict[str, Any], body: dict[str, Any], *, previous: str | None = None) -> dict[str, Any]:
    result = body.get("result") or {}
    rows = (result.get("results") if isinstance(result, dict) else None) or []
    health = next((row for row in rows if isinstance(row, dict) and row.get("operation") == "health.http.check"), None)
    changed = sum(1 for row in rows if isinstance(row, dict))
    report: dict[str, Any] = {
        "action": action,
        "package": envelope.get("package"),
        "plan_sha256": envelope.get("plan_sha256"),
        "operations": len(envelope.get("operations", [])),
        "applied": changed,
        "results": rows,
        "request_id": body.get("request_id"),
        "ok": bool(body.get("ok")),
    }
    if health is not None:
        report["health"] = health.get("result")
    if previous is not None:
        report["previous_version"] = previous
    return report


def _installed_manifest(app_id: str) -> dict[str, Any]:
    from nostrhost.native_providers import installed_package_manifest

    manifest = installed_package_manifest(app_id)
    if manifest is None:
        raise NostrHostError(f"{app_id} is not installed as a native app (no recorded manifest)")
    return manifest


def _removal_envelope(package_data: dict[str, Any]) -> dict[str, Any]:
    from nostrhost.package_engine import (
        PackageManifest,
        operation_plan_digest,
        plan_package_removal,
        validate_package,
    )

    package = validate_package(PackageManifest.parse_obj(package_data))
    operations = plan_package_removal(package)
    return {
        "schema": 1,
        "package": {"id": package.app.id, "version": package.app.version},
        "manifest_sha256": "",
        "plan_sha256": operation_plan_digest(operations),
        "operations": [operation.json_dict() for operation in operations],
    }


def _web_change_envelope(app_id: str, package_data: dict[str, Any], domain: str | None, path: str | None) -> dict[str, Any]:
    from nostrhost.package_engine import (
        PackageManifest,
        Operation,
        operation_plan_digest,
        validate_package,
    )

    package = validate_package(PackageManifest.parse_obj(package_data))
    if package.web is None:
        raise NostrHostError(f"{app_id} declares no web route to move")
    args = package.web.dict()
    if domain:
        args["domain"] = domain
    if path:
        args["path"] = path
    operation = Operation(
        name="web.route.ensure",
        resource=f"{app_id}:web",
        args={**args, "app": app_id},
        risk="medium",
        reverse="web.route.remove",
        summary=f"move {app_id} web route",
    )
    return {
        "schema": 1,
        "package": {"id": app_id, "version": package.app.version},
        "manifest_sha256": "",
        "plan_sha256": operation_plan_digest([operation]),
        "operations": [operation.json_dict()],
    }


def _restic_client() -> Any:
    from nostr_restic import ResticClient, load_restic_config

    conf = load_restic_config()
    if conf is None:
        raise NostrHostError("restic is not configured (missing " + "/etc/nostrhost/restic.toml)")
    return ResticClient(repo=conf.repo, password=conf.password, binary=conf.binary, host=conf.host, tag=conf.tag, timeout=conf.timeout)


def _app_backup_paths(app_id: str) -> list[str]:
    from nostrhost.package_engine import PackageManifest, validate_package

    package = validate_package(PackageManifest.parse_obj(_installed_manifest(app_id)))
    if not package.backup or not package.backup.paths:
        raise NostrHostError(f"{app_id} declares no backup paths in its package.toml")
    return [str(path) for path in package.backup.paths]


# --------------------------------------------------------------------------- #
# native postinstall (ALPHA-PLAN Workstream 2)

POSTINSTALL_UNITS = [
    "caddy",
    "nostrhost-control",
    "nostr-identityd",
    "nostr-operationsd",
    "nostr-securityd",
    "nostr-api",
    "nostrhost-certd.timer",
]

CADDY_BASE_DIR = "/etc/caddy"
CADDY_CONF_DIR = "/etc/caddy/conf.d"
CADDY_TEMPLATE_DIR = "/usr/share/yunohost/conf/caddy"
POLICY_CONFIG = "/etc/nostrhost/policy.toml"
RELAY_CONFIG = "/etc/nostrhost/relay.toml"
INSTALLED_MARKER = "/etc/yunohost/installed"


def _write_policy_toml(operator_npub: str) -> Path:
    """Write the editable shared host policy (defaults apply for unlisted
    keys; the ``[owner]`` block documents the operator identity)."""
    path = Path(POLICY_CONFIG)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "# NostrHost shared host policy (nostrhost_policy.policy.rules).\n"
        "# Any [policy.<key>] section overrides the built-in default for that\n"
        "# key only; unlisted keys keep their built-in default. Owner\n"
        "# enforcement uses operator.toml's operator_pubkey; [owner] below is\n"
        "# the documented identity.\n"
        f'\n[owner]\nowner_npub = "{operator_npub}"\n'
        "\n[policy.apps.upgrade]\n"
        'require_backup = true\nminimum_free_space = "2GB"\n'
        "\n[policy.apps.remove]\n"
        'require_confirmation = true\nrequire_backup = true\nmax_backup_age = "24h"\n'
        "\n[policy.backups.restore]\n"
        "require_confirmation = true\nrequire_owner_signature = true\n"
        "\n[policy.system.upgrade]\n"
        "require_confirmation = true\nrequire_owner_signature = true\n"
        "\n[policy.firewall.write]\n"
        "require_confirmation = true\nrequire_owner_signature = true\n"
    )
    os.chmod(path, 0o644)
    return path


def _render_caddy_base(domain: str) -> None:
    """Render the base Caddyfile + one per-domain snippet directly.

    The native path renders ``/etc/caddy`` from the shipped templates;
    regenconf's ``15-caddy`` category tracks the same files so later domain
    adds / drift detection keep working. Uses plain string substitution for
    ``{{ domain }}`` — the snippet's only variable."""
    Path(CADDY_BASE_DIR).mkdir(parents=True, exist_ok=True)
    Path(CADDY_CONF_DIR).mkdir(parents=True, exist_ok=True)
    template_dir = Path(CADDY_TEMPLATE_DIR)
    caddyfile = template_dir / "Caddyfile.template"
    domain_tpl = template_dir / "caddy_domain.conf"
    if not caddyfile.exists() or not domain_tpl.exists():
        raise NostrHostError(f"caddy templates not found in {CADDY_TEMPLATE_DIR}")
    Path(CADDY_BASE_DIR, "Caddyfile").write_text(caddyfile.read_text(encoding="utf-8"))
    conf = domain_tpl.read_text(encoding="utf-8").replace("{{ domain }}", domain)
    Path(CADDY_CONF_DIR, f"{domain}.conf").write_text(conf)


def _systemctl(*args: str) -> None:
    subprocess.run(["systemctl", *args], check=False, capture_output=True, text=True)


def _enable_postinstall_daemons() -> list[str]:
    """daemon-reload + enable --now the native stack. Returns the units that
    did not reach an active/activating state (best-effort — surfaced in the
    summary, never fatal here)."""
    _systemctl("daemon-reload")
    failed: list[str] = []
    for unit in POSTINSTALL_UNITS:
        _systemctl("enable", unit)
        _systemctl("start", unit)
        res = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True)
        if res.stdout.strip() not in ("active", "activating"):
            failed.append(unit)
    return failed


def _prepare_node(domain: str, operator_npub: str) -> None:
    """Shared postinstall base configuration (both --new and --restore)."""
    Path("/var/lib/nostrhost").mkdir(parents=True, exist_ok=True)
    Path("/var/lib/caddy").mkdir(parents=True, exist_ok=True)
    Path("/var/log/caddy").mkdir(parents=True, exist_ok=True)
    _write_policy_toml(operator_npub)
    _render_caddy_base(domain)
    Path("/etc/yunohost/current_host").write_text(domain + "\n")


def _publish_initial_capability(operator_pubkey: str) -> dict[str, Any] | None:
    """Grant the operator the full scope set (published to the control relay
    as the operator; non-fatal when the relay is not yet up)."""
    from yunohost.nostr_operations import KNOWN_SCOPES, grant_capability

    try:
        return grant_capability(operator_pubkey, list(KNOWN_SCOPES), type_="admin")
    except Exception as exc:  # noqa: BLE001 - surfaced in the summary
        return {"error": str(exc)}


def _postinstall_new(domain: str | None, admin_npub: str | None, force: bool) -> dict[str, Any]:
    """Fresh bootstrap: generate the node identity, stand up the native stack
    and record state S0. This is the canonical first-run path (the legacy
    interactive tools_postinstall wizard is not involved)."""
    from yunohost.nostr_identity import _init_headless_yunohost, bootstrap_node
    from yunohost.nostr_state import (
        StateRepo,
        YunohostBackend,
        announce_state_repository,
        export_state,
        state_dir_from_env,
    )

    if os.geteuid() != 0:
        raise NostrHostError("postinstall must be run as root")
    if Path(INSTALLED_MARKER).exists() and not force:
        raise NostrHostError(
            f"{INSTALLED_MARKER} exists — the node is already postinstalled "
            "(pass --force to re-run)"
        )

    _init_headless_yunohost()
    domain = domain or socket.getfqdn()

    boot = bootstrap_node(admins=[admin_npub] if admin_npub else None, force=force, write_relay=RELAY_CONFIG)
    operator_npub = _npub(boot["operator_pubkey"])
    _prepare_node(domain, operator_npub)

    failed = _enable_postinstall_daemons()
    grant = _publish_initial_capability(boot["operator_pubkey"])

    repo = StateRepo(state_dir_from_env(), boot["server_pubkey"])
    tree = export_state(YunohostBackend())
    rev = repo.commit(tree, known_good=True, health="passed", message="initial state (postinstall --new)")

    announce: dict[str, Any] | str | None = None
    try:
        announce_state_repository()
        announce = "published"
    except Exception as exc:  # noqa: BLE001 - non-fatal
        announce = str(exc)

    Path(INSTALLED_MARKER).touch()

    return {
        "domain": domain,
        "operator_npub": operator_npub,
        "operator_pubkey": boot["operator_pubkey"],
        "server_npub": _npub(boot["server_pubkey"]),
        "control_relay": boot["control_relay"],
        "state_revision": rev[:16],
        "policy_file": POLICY_CONFIG,
        "relay_config": RELAY_CONFIG,
        "state_announcement": announce,
        "capability_grant": "ok" if isinstance(grant, dict) and "error" not in grant else str(grant or ""),
        "daemons_failed": failed or "none",
        "note": "operator_npub is the owner identity; log in via the portal and link it.",
    }


def _postinstall_restore(
    operator_sk: str,
    server_sk: str | None,
    notice_sk: str | None,
    domain: str | None,
    bundle: Path | None,
    state_relay: str | None,
    restic: str | None,
    force: bool,
) -> dict[str, Any]:
    """Restore a node from its state repository: recover the identity, restore
    the known-good state (bundle or discovered/cloned repo), restore the
    linked Restic data snapshot, reconcile, and stand the stack back up."""
    from yunohost.nostr_identity import _init_headless_yunohost, bootstrap_node
    from yunohost.nostr_operationsd import YnhExecutorBackend
    from yunohost.nostr_restic import ResticError, restic_client
    from yunohost.nostr_state import (
        StateRepo,
        YunohostBackend,
        announce_state_repository,
        apply_reconciliation_plan,
        clone_state_repository,
        export_state,
        state_dir_from_env,
    )

    if os.geteuid() != 0:
        raise NostrHostError("postinstall must be run as root")
    if not operator_sk or not _is_hex64(operator_sk):
        raise NostrHostError("restore requires --operator-sk (the recovered admin key)")
    if bundle is None and not state_relay:
        raise NostrHostError("restore needs a state source: --bundle PATH or --state-relay URL")
    if Path(INSTALLED_MARKER).exists() and not force:
        raise NostrHostError(
            f"{INSTALLED_MARKER} exists — the node is already postinstalled "
            "(pass --force to re-run)"
        )

    _init_headless_yunohost()
    domain = domain or socket.getfqdn()

    boot = bootstrap_node(
        operator_sk=operator_sk,
        server_sk=server_sk or operator_sk,
        notice_sk=notice_sk,
        force=force,
        write_relay=RELAY_CONFIG,
    )
    _prepare_node(domain, _npub(boot["operator_pubkey"]))

    # restore the state repository
    state_dir = state_dir_from_env()
    if bundle is not None:
        StateRepo.verify_bundle(bundle)
        restored = StateRepo.restore_bundle(bundle, state_dir)
        repo = StateRepo(restored, boot["server_pubkey"])
        restored_from = f"bundle:{bundle}"
    else:
        assert state_relay is not None
        clone_state_repository(state_relay, server_pubkey=boot["server_pubkey"], destination=state_dir)
        repo = StateRepo(state_dir, boot["server_pubkey"])
        restored_from = f"relay:{state_relay}"

    target = repo.known_good_revision() or repo.revision()
    if not target:
        raise NostrHostError("restored state repository has no revisions to restore")

    manifest = repo.manifest_for(target)
    snapshot_id = restic or manifest.get("restic_snapshot") or ""
    data_restore: dict[str, Any] = {"snapshot": snapshot_id or "none"}
    if snapshot_id:
        try:
            restic_client().restore(snapshot_id, target=None)
            data_restore["status"] = "restored"
        except (ResticError, Exception) as exc:  # noqa: BLE001 - report, do not abort
            data_restore["status"] = "failed"
            data_restore["error"] = str(exc)

    failed = _enable_postinstall_daemons()
    grant = _publish_initial_capability(boot["operator_pubkey"])

    # reconcile: converge live state to the restored desired state (bounded)
    reconcile: dict[str, Any] = {"target": target[:16]}
    try:
        plan = repo.reconciliation_plan(export_state(YunohostBackend()))
        report = apply_reconciliation_plan(plan, backend=YnhExecutorBackend(), approve=True, repo=repo)
        reconcile["changes"] = sum(1 for row in report if row["status"] == "executed")
        reconcile["report"] = report
    except Exception as exc:  # noqa: BLE001 - report, do not abort
        reconcile["error"] = str(exc)

    announce: dict[str, Any] | str | None = None
    try:
        announce_state_repository()
        announce = "published"
    except Exception as exc:  # noqa: BLE001 - non-fatal
        announce = str(exc)

    rev = repo.commit(
        export_state(YunohostBackend()),
        known_good=False,
        health="passed",
        restic_snapshot=snapshot_id,
        message=f"post-restore reconcile from {restored_from}",
    )
    Path(INSTALLED_MARKER).touch()

    return {
        "domain": domain,
        "restored_from": restored_from,
        "operator_npub": _npub(boot["operator_pubkey"]),
        "operator_pubkey": boot["operator_pubkey"],
        "server_npub": _npub(boot["server_pubkey"]),
        "restored_revision": target[:16],
        "data_restore": data_restore,
        "reconcile": reconcile,
        "state_revision": rev[:16],
        "policy_file": POLICY_CONFIG,
        "state_announcement": announce,
        "capability_grant": "ok" if isinstance(grant, dict) and "error" not in grant else str(grant or ""),
        "daemons_failed": failed or "none",
    }


def _postinstall_status() -> dict[str, Any]:
    from yunohost.nostr_identity import is_bootstrapped
    from yunohost.nostr_state import StateRepo, state_dir_from_env

    bootstrapped = is_bootstrapped()
    state_dir = state_dir_from_env()
    revision = ""
    known_good = ""
    if bootstrapped and state_dir.exists():
        from yunohost.nostr_identity import _operator_config

        cfg = _operator_config()
        repo = StateRepo(state_dir, cfg.server_pubkey)
        revision = repo.revision()[:16] or ""
        known_good = repo.known_good_revision()[:16] or ""
    return {
        "installed": Path(INSTALLED_MARKER).exists(),
        "bootstrapped": bootstrapped,
        "operator_config": OPERATOR_CONFIG if bootstrapped else None,
        "state_revision": revision or None,
        "known_good": known_good or None,
    }


def build_app(*, prog: str = "nostrhost", state: _State | None = None) -> typer.Typer:
    app = typer.Typer(name=prog, help=DESCRIPTION, no_args_is_help=True)
    state = state or _State()

    @app.callback()
    def _root(
        output_as: str = typer.Option(None, "--output-as", help="Output result in another format (json/plain/none)"),
        debug: bool = typer.Option(False, "--debug", help="Enable debug output"),
        control_relay: str = typer.Option(None, "--control-relay", help="Nostr control relay URL"),
        operator_sk: str = typer.Option(None, "--operator-sk", help="operator secret key (hex)"),
        admin_sk: str = typer.Option(None, "--admin-sk", help="admin secret key (hex)"),
    ) -> None:
        state.output_as = output_as
        state.debug = debug
        state.control_relay = control_relay
        state.operator_sk = operator_sk
        state.admin_sk = admin_sk

    def _emit(result: Any, output_as: str | None = None) -> None:
        ui.format_result(result, output_as or state.output_as)

    def _guard(fn: Callable[[], Any], output_as: str | None = None) -> None:
        try:
            _emit(fn(), output_as)
        except (NostrHostError, OperationError, IdentityError) as exc:
            _print_error(exc)
            raise typer.Exit(EXIT_ERR)
        except Exception as exc:  # noqa: BLE001 - CLI is the last error boundary
            _print_error(exc)
            raise typer.Exit(EXIT_ERR)

    # -- system -------------------------------------------------------------

    system = typer.Typer(name="system", help="system information", no_args_is_help=True)

    @system.command("version")
    def system_version(output_as: str = typer.Option(None, "--output-as")) -> None:
        """Read-only OS/package version information."""
        _guard(lambda: _run_tool("system.version", {}), output_as)

    @system.command("regen-conf")
    def system_regen_conf(
        names: str = typer.Option("", "--names", help="comma-separated regenconf categories (default: all)"),
        force: bool = typer.Option(False, "--force", help="override manual modifications"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Regenerate system configuration files (regenconf categories).

        Used by the package upgrade path and available to operators; renders
        pending tracked config (base Caddyfile, per-domain snippets, and the
        YunoHost compatibility categories) from the current templates."""
        from yunohost.tools import tools_regen_conf

        def run() -> Any:
            categories = [item.strip() for item in names.split(",") if item.strip()]
            return tools_regen_conf(names=categories, force=force)

        _guard(run, output_as)

    # -- service ------------------------------------------------------------

    service = typer.Typer(name="service", help="service management", no_args_is_help=True)

    @service.command("status")
    def service_status(
        names: list[str] = typer.Argument(None, help="service names (default: all)"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Status of running services."""
        _guard(lambda: _run_tool("service.status", {"names": names} if names else {}), output_as)

    @service.command("restart")
    def service_restart(
        name: str = typer.Argument(..., help="service name"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Restart one named service (write operation)."""
        _guard(lambda: _run_tool("service.restart", {"name": name}), output_as)

    @service.command("control")
    def service_control(
        name: str = typer.Argument(..., help="service name"),
        action: str = typer.Argument(..., help="start | stop | restart"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Start/stop/restart one named service (write operation)."""
        _guard(lambda: _run_tool("service.control", {"name": name, "action": action}), output_as)

    # -- app ----------------------------------------------------------------

    app_group = typer.Typer(name="app", help="application management", no_args_is_help=True)

    @app_group.command("list")
    def app_list(output_as: str = typer.Option(None, "--output-as")) -> None:
        """List installed applications."""
        _guard(lambda: _run_tool("app.list", {}), output_as)

    @app_group.command("install")
    def app_install(
        coordinate: str = typer.Argument(..., help="catalogue app id (coordinate)"),
        source: Path = typer.Option(None, "--source", help="local checkout/dir containing package.toml, or the file itself"),
        repository: str = typer.Option(None, "--repository", help="override the catalogue git repository"),
        revision: str = typer.Option(None, "--revision", help="override the catalogue git revision"),
        package_path: str = typer.Option(None, "--package-path", help="override the catalogue package.toml path"),
        manifest_sha256: str = typer.Option(None, "--manifest-sha256", help="override the expected manifest sha256"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Install a native app through the signed operation chain.

        Resolves the catalogue coordinate, fetches and verifies package.toml
        (manifest_sha256), plans the resource-engine operations and runs them
        through the signed request -> policy -> approval -> execute chain.
        """
        def run() -> Any:
            resolved = _coordinate_for(coordinate, repository=repository, revision=revision, package_path=package_path, manifest_sha256=manifest_sha256)
            package_data = _load_package_data(source, resolved)
            _verify_package(package_data, resolved)
            envelope = _plan_envelope(package_data, resolved)
            body = _run_lifecycle("package.reconcile", {"plan": envelope}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"install rejected: {body.get('reason') or body.get('state')}")
            return _lifecycle_report("installed", envelope, body)
        _guard(run, output_as)

    @app_group.command("upgrade")
    def app_upgrade(
        coordinate: str = typer.Argument(..., help="catalogue app id (coordinate)"),
        source: Path = typer.Option(None, "--source", help="local checkout/dir containing package.toml, or the file itself"),
        repository: str = typer.Option(None, "--repository", help="override the catalogue git repository"),
        revision: str = typer.Option(None, "--revision", help="override the catalogue git revision"),
        package_path: str = typer.Option(None, "--package-path", help="override the catalogue package.toml path"),
        manifest_sha256: str = typer.Option(None, "--manifest-sha256", help="override the expected manifest sha256"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Upgrade a native app to the resolved catalogue version.

        Conservative by construction: the resource engine re-applies only the
        operations whose current state no longer satisfies the new manifest,
        so data resources are left alone unless the manifest changes them.
        """
        def run() -> Any:
            installed = _installed_manifest(coordinate)
            resolved = _coordinate_for(coordinate, repository=repository, revision=revision, package_path=package_path, manifest_sha256=manifest_sha256)
            package_data = _load_package_data(source, resolved)
            _verify_package(package_data, resolved)
            envelope = _plan_envelope(package_data, resolved)
            body = _run_lifecycle("package.reconcile", {"plan": envelope}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"upgrade rejected: {body.get('reason') or body.get('state')}")
            previous = (installed.get("app") or {}).get("version")
            return _lifecycle_report("upgraded", envelope, body, previous=previous)
        _guard(run, output_as)

    @app_group.command("remove")
    def app_remove(
        app: str = typer.Argument(..., help="app id"),
        purge: bool = typer.Option(False, "--purge", help="purge app data (legacy fallback only)"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Remove one installed app.

        Native apps are removed by reversing their recorded manifest through
        the signed chain (plan_package_removal); apps without a recorded
        native manifest fall back to the legacy removal tool.
        """
        def run() -> Any:
            from nostrhost.native_providers import installed_package_manifest

            manifest = installed_package_manifest(app)
            if manifest is None:
                return _run_tool("app.remove", {"app": app, "purge": purge})
            envelope = _removal_envelope(manifest)
            body = _run_lifecycle("package.reconcile", {"plan": envelope}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"removal rejected: {body.get('reason') or body.get('state')}")
            return _lifecycle_report("removed", envelope, body)
        _guard(run, output_as)

    @app_group.command("change-url")
    def app_change_url(
        app: str = typer.Argument(..., help="app id"),
        domain: str = typer.Option(None, "--domain", help="new domain"),
        path: str = typer.Option(None, "--path", help="new URL path (must start with '/')"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Move an app to a new domain and/or URL path (Caddy route update)."""
        def run() -> Any:
            if not domain and not path:
                raise NostrHostError("change-url requires --domain and/or --path")
            installed = _installed_manifest(app)
            envelope = _web_change_envelope(app, installed, domain, path)
            body = _run_lifecycle("package.reconcile", {"plan": envelope}, state=state)
            if not body.get("ok"):
                raise NostrHostError(f"change-url rejected: {body.get('reason') or body.get('state')}")
            return _lifecycle_report("change-url", envelope, body)
        _guard(run, output_as)

    @app_group.command("backup")
    def app_backup(
        app: str = typer.Argument(..., help="app id"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Back up an installed native app's declared paths (Restic snapshot)."""
        def run() -> Any:
            paths = _app_backup_paths(app)
            snapshot = _restic_client().snapshot(paths, tag=app)
            return {"app": app, "paths": paths, "snapshot": snapshot}
        _guard(run, output_as)

    @app_group.command("restore")
    def app_restore(
        app: str = typer.Argument(..., help="app id"),
        snapshot: str = typer.Argument(..., help="Restic snapshot id to restore"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Restore an installed native app's data from a Restic snapshot."""
        def run() -> Any:
            paths = _app_backup_paths(app)
            client = _restic_client()
            return {"app": app, "snapshot": snapshot, "paths": paths, "result": client.restore(snapshot, "/", include=paths)}
        _guard(run, output_as)

    # -- backup -----------------------------------------------------------

    backup = typer.Typer(name="backup", help="host backup (Restic + state)", no_args_is_help=True)

    @backup.command("create")
    def backup_create(output_as: str = typer.Option(None, "--output-as")) -> None:
        """Create a full host Restic snapshot (satisfies policy backup gates)."""
        def run() -> Any:
            client = _restic_client()
            snapshot = client.snapshot(list(SYSTEM_BACKUP_PATHS), tag="system")
            return {"snapshot": snapshot, "paths": list(SYSTEM_BACKUP_PATHS)}
        _guard(run, output_as)

    @backup.command("list")
    def backup_list(output_as: str = typer.Option(None, "--output-as")) -> None:
        """List Restic snapshots on this host."""
        def run() -> Any:
            return {"snapshots": _restic_client().snapshots()}
        _guard(run, output_as)

    # -- package ------------------------------------------------------------

    package = typer.Typer(name="package", help="native package planning", no_args_is_help=True)

    @package.command("plan")
    def package_plan(
        package_file: Path = typer.Argument(..., help="package manifest JSON"),
        catalogue_file: Path = typer.Option(None, "--catalogue-file", help="catalogue provenance JSON"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Validate and plan a native package."""
        def run() -> Any:
            package = json.loads(package_file.read_text(encoding="utf-8"))
            catalogue = json.loads(catalogue_file.read_text(encoding="utf-8")) if catalogue_file else None
            return _run_tool("package.plan", {"package": package, "catalogue": catalogue})
        _guard(run, output_as)

    @package.command("reconcile")
    def package_reconcile(
        plan_file: Path = typer.Argument(..., help="plan envelope JSON"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Apply an approved native package operation plan (write operation)."""
        def run() -> Any:
            plan = json.loads(plan_file.read_text(encoding="utf-8"))
            return _run_tool("package.reconcile", {"plan": plan})
        _guard(run, output_as)

    # -- rollback / state ---------------------------------------------------

    rollback = typer.Typer(name="rollback", help="assisted rollback", no_args_is_help=True)

    @rollback.command("apply")
    def rollback_apply(
        plan_file: Path = typer.Argument(..., help="rollback plan JSON"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Execute an assisted rollback plan (write operation)."""
        def run() -> Any:
            plan = json.loads(plan_file.read_text(encoding="utf-8"))
            return _run_tool("rollback.apply", {"plan": plan})
        _guard(run, output_as)

    state_group = typer.Typer(name="state", help="state reconciliation", no_args_is_help=True)

    @state_group.command("reconcile")
    def state_reconcile(
        plan_file: Path = typer.Argument(..., help="reconciliation plan JSON"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Apply an approved, bounded reconciliation plan (write operation)."""
        def run() -> Any:
            plan = json.loads(plan_file.read_text(encoding="utf-8"))
            return _run_tool("state.reconcile", {"plan": plan})
        _guard(run, output_as)

    # -- identity (npub user model) ------------------------------------------

    identity = typer.Typer(name="identity", help="npub identities (the NostrHost user model)", no_args_is_help=True)

    @identity.command("link")
    def identity_link(
        username: str = typer.Argument(..., help="account username to bind"),
        pubkey_or_npub: str = typer.Argument(..., help="pubkey (64-hex) or npub"),
        signer_type: str = typer.Option("unknown", "--signer-type", help=f"one of {', '.join(VALID_SIGNER_TYPES)}"),
        label: str = typer.Option(None, "--label", help="human label for the identity"),
        disabled: bool = typer.Option(False, "--disabled", help="link as disabled"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Link an npub to an account (publishes kind 31102 as the operator)."""
        def run() -> Any:
            return link_identity(
                username,
                pubkey_or_npub,
                operator_sk=state.operator_sk,
                control_relay=state.control_relay,
                signer_type=signer_type,
                label=label,
                enabled=not disabled,
            )
        _guard(run, output_as)

    @identity.command("revoke")
    def identity_revoke(
        pubkey_or_npub: str = typer.Argument(..., help="pubkey (64-hex) or npub"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Revoke an identity (publishes enabled:false)."""
        def run() -> Any:
            return revoke_identity(
                pubkey_or_npub,
                operator_sk=state.operator_sk,
                control_relay=state.control_relay,
            )
        _guard(run, output_as)

    @identity.command("list")
    def identity_list(
        username: str = typer.Option(None, "--username", help="list identities for one account"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """List identities (optionally for one username)."""
        def run() -> Any:
            if username:
                return [_identity_dict(i) for i in list_identities_for_username(username)]
            return [_identity_dict(i) for i in list_identities()]
        _guard(run, output_as)

    @identity.command("resolve")
    def identity_resolve(
        pubkey_or_npub_or_username: str = typer.Argument(..., help="pubkey, npub, or username"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Resolve a pubkey/npub to its account, or list identities of a username."""
        def run() -> Any:
            value = pubkey_or_npub_or_username
            if _parse_pubkey is not None and (value.startswith("npub1") or (len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value))):
                identity = resolve_pubkey(_parse_pubkey(value))
                return _identity_dict(identity) if identity else None
            return [_identity_dict(i) for i in resolve_username(value)]
        _guard(run, output_as)

    # -- capability ----------------------------------------------------------

    capability = typer.Typer(name="capability", help="npub capabilities", no_args_is_help=True)

    @capability.command("grant")
    def capability_grant(
        pubkey: str = typer.Argument(..., help="subject pubkey (64-hex)"),
        scopes: list[str] = typer.Argument(..., help="scopes, e.g. apps.read services.write"),
        type_: str = typer.Option("agent", "--type", help="agent | admin"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Grant capabilities to an npub (publishes kind 31100 as admin)."""
        def run() -> Any:
            return grant_capability(
                pubkey,
                scopes,
                type_=type_,
                admin_sk=state.admin_sk,
                control_relay=state.control_relay,
            )
        _guard(run, output_as)

    @capability.command("delegate")
    def capability_delegate(
        pubkey: str = typer.Argument(..., help="delegate pubkey (64-hex)"),
        scopes: list[str] = typer.Argument(..., help="scopes, e.g. apps.read"),
        expires_at: int = typer.Option(..., "--expires-at", help="expiry as Unix timestamp"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Publish a signed, expiring delegation to an npub."""
        def run() -> Any:
            return delegate_capability(
                pubkey,
                scopes,
                expires_at,
                delegator_sk=state.operator_sk,
                control_relay=state.control_relay,
            )
        _guard(run, output_as)

    @capability.command("revoke")
    def capability_revoke(
        delegation_id: str = typer.Argument(..., help="delegation event id"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Revoke a delegation event."""
        def run() -> Any:
            return revoke_delegation(
                delegation_id,
                delegator_sk=state.operator_sk,
                control_relay=state.control_relay,
            )
        _guard(run, output_as)

    # -- operation chain ---------------------------------------------------------

    op_group = typer.Typer(name="op", help="operation chain (follow/status)", no_args_is_help=True)

    @op_group.command("follow")
    def op_follow(
        request_id: str = typer.Argument(..., help="operation request id"),
        timeout: float = typer.Option(60.0, "--timeout", help="seconds to keep waiting"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Stream an operation's progress/result events until it finishes."""
        def run() -> None:
            for event in _stream_events(request_id, state.control_relay, timeout):
                _render_operation_event(event, output_as or state.output_as)
        _guard(run, output_as)

    @op_group.command("status")
    def op_status(
        request_id: str = typer.Argument(..., help="operation request id"),
        timeout: float = typer.Option(5.0, "--timeout", help="seconds to wait for the result"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Print the latest chain event for an operation."""
        def run() -> None:
            last = None
            for event in _stream_events(request_id, state.control_relay, timeout):
                _render_operation_event(event, output_as or state.output_as)
                last = event
            if last is None:
                print(f"{request_id[:16]} … no chain events (pending or unknown)")
        _guard(run, output_as)

    # -- postinstall --------------------------------------------------------

    postinstall = typer.Typer(name="postinstall", help="first-run bootstrap / restore", no_args_is_help=True)

    @postinstall.command("new")
    def postinstall_new(
        domain: str = typer.Option(None, "--domain", help="primary domain (default: hostname)"),
        admin_npub: str = typer.Option(None, "--admin-npub", help="operator admin npub (default: the generated operator)"),
        force: bool = typer.Option(False, "--force", help="re-run even if /etc/yunohost/installed exists"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Bootstrap a fresh node: generate the identity, stand up the native
        stack (relay, daemons, Caddy) and record state S0."""
        _guard(lambda: _postinstall_new(domain, admin_npub, force), output_as)

    @postinstall.command("restore")
    def postinstall_restore(
        operator_sk: str = typer.Option(..., "--operator-sk", help="recovered admin secret key (64-hex)"),
        server_sk: str = typer.Option(None, "--server-sk", help="recovered server key (default: operator key)"),
        notice_sk: str = typer.Option(None, "--notice-sk", help="recovered portal notice key"),
        domain: str = typer.Option(None, "--domain", help="primary domain (default: hostname)"),
        bundle: Path = typer.Option(None, "--bundle", help="state-replica bundle to restore (nostrhost-state replicate)"),
        state_relay: str = typer.Option(None, "--state-relay", help="relay to discover the kind-30617 state repo on"),
        restic: str = typer.Option(None, "--restic", help="override the restic snapshot id"),
        force: bool = typer.Option(False, "--force", help="re-run even if /etc/yunohost/installed exists"),
        output_as: str = typer.Option(None, "--output-as"),
    ) -> None:
        """Restore a node: recover identity + state, restore the linked Restic
        snapshot, reconcile and stand the stack back up."""
        _guard(lambda: _postinstall_restore(operator_sk, server_sk, notice_sk, domain, bundle, state_relay, restic, force), output_as)

    @postinstall.command("status")
    def postinstall_status(output_as: str = typer.Option(None, "--output-as")) -> None:
        """Show bootstrap / postinstall state."""
        _guard(_postinstall_status, output_as)

    for group in (system, service, app_group, package, rollback, state_group, identity, capability, op_group, postinstall):
        app.add_typer(group, name=group.info.name)

    return app


# --------------------------------------------------------------------------- #
# operation chain subscription

def _stream_events(request_id: str, relay: str | None, timeout: float):
    from . import events as events_module

    return events_module.stream_operation_events(
        request_id,
        relay_url=relay or "ws://127.0.0.1:4848",
        timeout=timeout,
    )


def _render_operation_event(event: dict[str, Any], output_as: str | None) -> None:
    """Print one chain event: JSON when requested, else a short human line."""
    kind = int(event.get("kind", 0))
    if output_as == "json":
        print(json.dumps(event, default=str))
        return
    request_id = next(
        (tag[1] for tag in event.get("tags") or [] if len(tag) >= 2 and tag[0] == "e"),
        event.get("id", ""),
    )[:16]
    if kind == 2203:
        print(f"{request_id} … started")
    elif kind == 2205:
        try:
            body = json.loads(event.get("content") or "{}")
        except (TypeError, json.JSONDecodeError):
            body = {}
        pct = f" {body['progress'] * 100:.0f}%" if "progress" in body else ""
        print(f"{request_id} … [{body.get('stage', '?')}]{pct}{' ' + body['message'] if body.get('message') else ''}")
    elif kind == 2204:
        try:
            body = json.loads(event.get("content") or "{}")
        except (TypeError, json.JSONDecodeError):
            body = {}
        print(f"{request_id} … {'done: ok' if body.get('ok') else 'failed'}"
              + (f" ({body.get('error')})" if body.get("error") else ""))
    else:
        print(f"{request_id} … kind {kind}")


def _identity_dict(identity: Any) -> dict[str, Any]:
    return {
        "pubkey": identity.pubkey,
        "username": identity.ynh_username,
        "signer_type": identity.signer_type,
        "label": identity.label,
        "enabled": identity.enabled,
        "created_at": identity.created_at,
        "last_used": identity.last_used,
    }


def run(argv: list[str], *, app: typer.Typer | None = None, state: _State | None = None) -> int:
    """Run the CLI against ``argv`` (injectable for tests)."""
    from typer.testing import CliRunner

    if app is None:
        app = build_app(state=state)
    result = CliRunner().invoke(app, argv)
    return result.exit_code


def main(argv: list[str] | None = None) -> int:
    """Programmatic entry point used by ``bin/nostrhost``."""
    app = build_app()
    if argv is None:
        argv = sys.argv[1:]
    try:
        app(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_ERR
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover - exercised through bin/nostrhost
    raise SystemExit(main())
