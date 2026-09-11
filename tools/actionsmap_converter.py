#!/usr/bin/env python3
"""actionsmap_converter — convert actionsmap.yml into an operation-schema catalog.

Stage 0 of the moulinette-removal plan. Reads the fork's action maps
(`share/actionsmap.yml`, `share/actionsmap-portal.yml`) and emits a
machine-readable catalog describing every action as a NostrHost operation:

    {
      "name": "user.create",            # category.subcategory.action (dotted)
      "cli_path": ["user", "create"],   # CLI invocation segments
      "function": "user_create",        # backing Python function (user_<action>)
      "module": "user",                 # module the function lives in
      "api": {"method": "GET", "path": "/users"},
      "auth": "ldap_admin" | "ldap_ynhuser" | null,
      "help": "Create user",
      "args": [
        {"flag": "username", "kind": "positional", "required": true,
         "pattern": "^[a-z0-9][-a-z0-9_\\.]*$", "password": false,
         "ask": null, "default": null, "nargs": null, "action": null}
      ]
    }

This is the migration bridge (Stage 3/4 of the removal plan): instead of
manually rewriting hundreds of endpoints, the OperationRegistry is generated
from this catalog, and the arg metadata (pattern/required/password/ask)
becomes the source for Pydantic field definitions.

The parsing logic lives in ``nostrhost.models.OperationCatalog.from_actionsmap``
(single source of truth); this tool is a thin CLI over it that emits the
JSON artifact and/or the summary the audit uses.

Usage:
    actionsmap_converter.py [--map share/actionsmap.yml ...] [--json OUT]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from nostrhost.models import OperationCatalog  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--map", action="append", default=[],
                    help="actionsmap YAML to convert (repeatable)")
    ap.add_argument("--json", default=None, help="write catalog JSON here")
    ap.add_argument("--stats", action="store_true", help="print per-category stats")
    args = ap.parse_args()

    maps = args.map or ["share/actionsmap.yml", "share/actionsmap-portal.yml"]
    existing = [m for m in maps if Path(m).is_file()]
    if len(existing) != len(maps):
        for m in maps:
            if not Path(m).is_file():
                print(f"warning: {m} not found", file=sys.stderr)
    catalog = OperationCatalog.from_actionsmap(existing)

    if args.stats:
        counts = Counter(op.module for op in catalog.operations)
        total = len(catalog.operations)
        api = sum(1 for op in catalog.operations if op.api)
        print(f"total operations: {total}; with API route: {api}")
        for mod, n in sorted(counts.items()):
            print(f"  {mod:20} {n}")
    else:
        print(json.dumps(catalog.to_dict(), indent=2, sort_keys=True))
    if args.json:
        Path(args.json).write_text(
            json.dumps(catalog.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
        )
        print(f"wrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
