"""Declarative registry of generated service-config files (WP7).

WP7 makes the rendered service configuration a *provenance-tracked
projection*: each generated file records which source it was rendered from
(the event document, the ngit desired-state revision, or a derived operator
view), which renderer produced it, and the sha256 of the exact bytes written.
The registry entry for each file carries the native validator (``nsite-go``
shells to the gateway's ``check-config`` subcommand) and the reload action
(``sighup`` vs ``restart``) used before/after an atomic replace.

See ``docs/RELAY-STATE-MIGRATION-PLAN.md`` §WP7 and
``docs/dev/authority-register.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Validator = Literal["nsite-go", "notify-toml", "oidc-toml", "toml"]
Reload = Literal["sighup", "restart"]


@dataclass(frozen=True)
class ServiceSpec:
    """One generated service-config file and how it is kept in sync.

    ``source`` is a human/operator-facing authority label of the form
    ``event:31101:nostrhost:<family>``, ``ngit:<section>`` or
    ``derived:<inputs>``. ``validator`` names the native config checker to run
    on the candidate before an atomic replace (``None`` = render-only with no
    independent checker). ``reload`` is the action taken after a *changed*
    render (``None`` = consumers read the file on demand, no reload needed).
    """

    name: str
    path: str
    source: str
    validator: Validator | None = None
    reload: Reload | None = None
    mode: int = 0o640
    description: str = ""

    def provenance_path(self) -> str:
        return self.path + ".source.json"


#: Files rendered by WP7. Secrets are never part of these entries: a spec
#: only knows the file path and how to validate/reload it.
SERVICE_SPECS: dict[str, ServiceSpec] = {
    "nsite": ServiceSpec(
        name="nsite",
        path="/etc/nostrhost/nsite.toml",
        source="ngit:state/nsites",
        validator="nsite-go",
        reload="sighup",
        mode=0o640,
        description="Nsites gateway config (domain, mode, relays, blossom, limits, sites, custom domains). Validated by `nostrhost-nsite -check-config` and hot-reloaded on SIGHUP.",
    ),
    "notify": ServiceSpec(
        name="notify",
        path="/etc/nostrhost/notify.toml",
        source="derived:operator+connectivity",
        validator="notify-toml",
        mode=0o600,
        description="Notification service config (relay, paths, digest interval, outbound relays). The notifier private key is resolved from the local secret store at render time, never carried in desired state.",
    ),
    "oidc": ServiceSpec(
        name="oidc",
        path="/etc/nostrhost/oidc.toml",
        source="event:31101:nostrhost:oidc-clients",
        validator="oidc-toml",
        mode=0o600,
        description="Non-secret OIDC client registrations rendered from the kind-31101 oidc-clients document; each client_secret is resolved from the local credential store at render time.",
    ),
    "security": ServiceSpec(
        name="security",
        path="/etc/nostrhost/security.toml",
        source="derived:operator",
        validator="toml",
        mode=0o640,
        description="nostr-securityd schedule + severity mapping (severity_default, severity_recurring, interval, max_alerts). No secrets; rendered provenance-tracked from operator defaults.",
    ),
    "ddns": ServiceSpec(
        name="ddns",
        path="/etc/nostrhost/ddns.toml",
        source="derived:operator",
        validator="toml",
        mode=0o640,
        description="nostr-ddnswatchd desired schedule ([watch] interval). Provider tokens stay in the credential store; only the non-secret schedule is rendered here.",
    ),
}


def spec_for_name(name: str) -> ServiceSpec:
    try:
        return SERVICE_SPECS[name]
    except KeyError as exc:  # pragma: no cover - programming error
        raise KeyError(f"unknown service config: {name}") from exc
