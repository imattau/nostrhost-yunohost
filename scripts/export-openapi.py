#!/usr/bin/env python3
"""Export the native admin API's OpenAPI schema to a JSON file.

A1 typed API contracts: the exported schema (with typed request bodies) is the
single source the admin SPA's Orval client is generated from. Run during
packaging so the committed client and the live schema cannot drift:

    PYTHONPATH=src python3 scripts/export-openapi.py openapi.json
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
_pkg = types.ModuleType("yunohost")
_pkg.__path__ = [str(_SRC)]  # type: ignore[attr-defined]
sys.modules["yunohost"] = _pkg
sys.path.insert(0, str(_SRC))

from nostrhost.api import build_app_with_openapi


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: export-openapi.py <output.json>", file=sys.stderr)
        return 2
    app = build_app_with_openapi()
    schema = app.openapi()
    out = Path(sys.argv[1])
    out.write_text(json.dumps(schema, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(schema.get('paths', {}))} paths)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
