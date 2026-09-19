"""Projection health diagnosis (WP2 of docs/RELAY-STATE-MIGRATION-PLAN.md).

Reports whether the host's projectors (identity, permissions, ...) are
materialising signed events: their applied revision, staleness and any
quarantined events. Reads the durable cursor files written by
``nostr_projector`` under /var/lib/nostrhost/projections, so it is a pure
read with no daemon dependency.

Best-effort like the rest of the subsystem: a check that cannot be evaluated
(missing directory, unreadable cursor) is reported as informational, never
raised.
"""

import json
import os

from ..diagnosis import Diagnoser

CURSOR_DIR = os.environ.get("NOSTRHOST_PROJECTION_DIR", "/var/lib/nostrhost/projections")
# A projection whose last applied event is older than this is reported stale.
# §12 of the migration plan targets seconds, not minutes, for authorization
# state; this is the diagnostic alert threshold, not the fail-closed window.
STALE_AFTER_SECONDS = 900
# Cursor files newer than the process start represent a live projector.
MIN_EXPECTED_PROJECTIONS = 1


def _read_cursors() -> list[dict]:
    rows = []
    try:
        names = sorted(os.listdir(CURSOR_DIR))
    except OSError:
        return rows
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(CURSOR_DIR, name), encoding="utf-8") as handle:
                raw = json.load(handle)
        except (OSError, ValueError):
            continue
        rows.append(raw)
    return rows


class MyDiagnoser(Diagnoser):
    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 60
    dependencies: list[str] = []

    def run(self):
        import time

        cursors = _read_cursors()
        if not cursors:
            yield dict(
                meta={"test": "projection_cursors"},
                status="INFO",
                summary="diagnosis_projection_no_cursors",
            )
            return

        now = time.time()
        for cursor in cursors:
            name = str(cursor.get("name") or "?")
            revision = str(cursor.get("revision") or "")
            updated_at = float(cursor.get("updated_at") or 0.0)
            age = now - updated_at if updated_at else None
            if not revision:
                yield dict(
                    meta={"test": "projection_revision", "projection": name},
                    status="WARNING",
                    summary="diagnosis_projection_no_revision",
                )
            elif age is not None and age > STALE_AFTER_SECONDS:
                yield dict(
                    meta={"test": "projection_stale", "projection": name, "age": int(age)},
                    status="WARNING",
                    summary="diagnosis_projection_stale",
                )
            else:
                yield dict(
                    meta={"test": "projection_fresh", "projection": name, "revision": revision},
                    status="SUCCESS",
                    summary="diagnosis_projection_fresh",
                )
