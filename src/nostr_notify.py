"""Publish NostrHost system/service notices (roadmap §18.1 / §18.2).

Phase 2 of mail-stack retirement (umbrella repo `docs/MAIL-RETIREMENT.md`):
internal notification producers that used to *only* send local mail
(certificate renewal failures, automatic-diagnosis issues, and eventually
backup/cron output) now also publish a structured kind-2210 "system event"
notice on the local control relay. `nostrhost-notify`
(`nostrhost-control`'s notification service) subscribes to these and
delivers a human-readable summary to configured npubs as an encrypted Nostr
DM (NIP-17/59) — see the umbrella repo's `docs/NOTIFICATION-SERVICE.md`.

The content convention (`class`/`severity`/`summary`) matches
`nostrhost-control`'s `EVENT-PROTOCOL.md` §2.3 exactly, so no schema
translation happens on the relay side.

This is additive, not a replacement: the existing mail path in
`certificate.py`/`diagnosis.py` keeps working as-is (the mail stack is still
installed by default at this phase — see roadmap §18.7's implementation
sequence). Publishing failures are swallowed, matching the existing
"never let a notification failure break the underlying operation" posture
those mail helpers already have.
"""

from __future__ import annotations

import json
from logging import getLogger
from typing import Any

from .nostr_identity import _operator_config, _sign_event, publish_to_relay
from .nostr_operations import _control_relay, _derive_pubkey

logger = getLogger("yunohost.nostr_notify")

# Must match nostrhost-control's eventmodel.KindSystemEvent /
# eventmodel.KindServiceEvent (EVENT-PROTOCOL.md §2.3).
KIND_SYSTEM_EVENT = 2210
KIND_SERVICE_EVENT = 2211

SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"
KNOWN_SEVERITIES = (SEVERITY_INFO, SEVERITY_WARNING, SEVERITY_CRITICAL)


def publish_notice(
    class_: str,
    severity: str,
    summary: str,
    *,
    kind: int = KIND_SYSTEM_EVENT,
    extra: dict[str, Any] | None = None,
    server_sk: str | None = None,
    control_relay: str | None = None,
    transport=None,
) -> dict[str, Any] | None:
    """Publish a system/service notice signed by the server key.

    Server-signed (not operator-signed): these are machine-generated
    observations about system state, the same authorship as execution
    results (2203/2204) — see EVENT-PROTOCOL.md §7. Pass ``server_sk`` to
    override the configured key (tests; a caller that already has it).

    Returns the published event, or ``None`` if publishing failed (a node
    that isn't bootstrapped yet, or an unreachable control relay, must never
    prevent the underlying certificate/diagnosis operation from completing).
    """
    if severity not in KNOWN_SEVERITIES:
        raise ValueError(
            f"severity must be one of {KNOWN_SEVERITIES}, got {severity!r}"
        )

    content: dict[str, Any] = {
        "class": class_,
        "severity": severity,
        "summary": summary,
    }
    if extra:
        content.update(extra)

    try:
        sk = server_sk
        if sk is None:
            cfg = _operator_config(None, control_relay)
            sk = cfg.server_sk
        pubkey = _derive_pubkey(sk)
        event = _sign_event(sk, pubkey, kind, json.dumps(content), [])
        (transport or publish_to_relay)(_control_relay(control_relay), event)
        return event
    except Exception as e:
        logger.warning(f"Failed to publish {class_!r} notice to the control relay: {e}")
        return None
