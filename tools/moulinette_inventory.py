#!/usr/bin/env python3
"""moulinette_inventory — categorized report of the moulinette import surface.

Stage 0 of the moulinette-removal plan (see docs/ROADMAP.md §22 / the
packaging branch). This is a report-only tool: it scans the fork's Python
source for every `moulinette.*` import and call site, classifies each symbol
against the NostrHost replacement, and prints a summary plus a machine-readable
JSON catalog so the mechanical removal (Stage 2) and the converter (Stage 0)
can be driven from one source of truth.

Classifications (symbol -> NostrHost replacement):

  m18n.n / m18n.g / set_locale / set_locales_dir  -> nostrhost.i18n.tr / set_locale
  Moulinette.prompt / display / confirm           -> nostrhost.ui (CLI-only shim)
  Moulinette.interface / _interface               -> nostrhost.core interface object
  MoulinetteLock                                  -> nostrhost.locking.LockManager
  MoulinetteError / AuthenticationError           -> nostrhost.core.NostrHostError hierarchy
  BaseAuthenticator                               -> nostrhost.auth.authenticator (native)
  colorize / get_locale                           -> nostrhost.i18n colorize / get_locale
  getActionLogger                                 -> nostrhost.logging.getActionLogger

Usage:
    moulinette_inventory.py [--src SRC] [--json OUT]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# symbol -> replacement module.function
REPLACEMENTS = {
    "m18n.n": "nostrhost.i18n.tr",
    "m18n.g": "nostrhost.i18n.tr",
    "m18n.set_locale": "nostrhost.i18n.set_locale",
    "m18n.set_locales_dir": "nostrhost.i18n.set_locales_dir",
    "Moulinette.prompt": "nostrhost.ui.prompt",
    "Moulinette.display": "nostrhost.ui.display",
    "Moulinette.confirm": "nostrhost.ui.confirm",
    "Moulinette.ask": "nostrhost.ui.ask",
    "Moulinette.interface": "nostrhost.core.interface",
    "Moulinette._interface": "nostrhost.core.interface",
    "MoulinetteLock": "nostrhost.locking.LockManager",
    "MoulinetteError": "nostrhost.core.NostrHostError",
    "MoulinetteAuthenticationError": "nostrhost.core.AuthenticationError",
    "BaseAuthenticator": "nostrhost.auth.authenticator.BaseAuthenticator",
    "colorize": "nostrhost.i18n.colorize",
    "get_locale": "nostrhost.i18n.get_locale",
    "getActionLogger": "nostrhost.logging.getActionLogger",
}

IMPORT_RE = re.compile(r"^\s*(?:from moulinette(?:\.\S+)* import |import moulinette)")
# Call-site matching requires the opening paren so doc/comment mentions like
# "m18n.n (namespace)" are not counted as real calls. `Moulinette.interface` is
# an attribute read, not a call, so it matches without a paren.
CALL_RE = re.compile(r"\b(m18n\.(?:n|g|set_locale|set_locales_dir)\(|"
                     r"Moulinette\.(?:prompt|display|confirm|ask)\(|"
                     r"Moulinette\.(?:interface|_interface)\b|"
                     r"MoulinetteLock\(|MoulinetteError|MoulinetteAuthenticationError|"
                     r"BaseAuthenticator|colorize\(|get_locale\(|getActionLogger\()")


def scan(src: Path) -> dict:
    files: list[dict] = []
    symbol_counts: Counter = Counter()
    import_lines: Counter = Counter()
    per_symbol_files: defaultdict = defaultdict(list)

    for path in sorted(src.rglob("*.py")):
        if "tests" in path.parts or path.name == "conftest.py":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "moulinette" not in text:
            continue

        rel = str(path.relative_to(src))
        imports = [line.strip() for line in text.splitlines() if IMPORT_RE.match(line)]
        hits = CALL_RE.findall(text)
        norm_hits = [h.rstrip("(") for h in hits]
        entry = {
            "path": rel,
            "imports": imports,
            "m18n_calls": norm_hits.count("m18n.n") + norm_hits.count("m18n.g"),
            "moulinette_prompt_display": sum(1 for h in norm_hits if h.startswith("Moulinette.")),
            "symbols": sorted(set(norm_hits)),
        }
        files.append(entry)
        for line in imports:
            import_lines[line] += 1
        for h in norm_hits:
            symbol_counts[h] += 1
            per_symbol_files[h].append(rel)

    return {
        "source": str(src),
        "files_total": len(files),
        "symbols": {
            "total_calls": sum(symbol_counts.values()),
            "m18n_n": symbol_counts.get("m18n.n", 0),
            "m18n_g": symbol_counts.get("m18n.g", 0),
            "moulinette_prompt_display": sum(
                v for k, v in symbol_counts.items() if k.startswith("Moulinette.")
            ),
            "moulinette_interface_refs": symbol_counts.get("Moulinette.interface", 0)
            + symbol_counts.get("Moulinette._interface", 0),
        },
        "import_lines": dict(import_lines.most_common()),
        "per_symbol_files": {k: sorted(v) for k, v in per_symbol_files.items()},
        "files": files,
        "replacement_map": REPLACEMENTS,
    }


def print_report(report: dict) -> None:
    s = report["symbols"]
    print(f"moulinette inventory: {report['files_total']} source files import moulinette")
    print(f"  m18n.n calls:        {s['m18n_n']}")
    print(f"  m18n.g calls:        {s['m18n_g']}")
    print(f"  Moulinette prompt/display/confirm: {s['moulinette_prompt_display']}")
    print(f"  Moulinette.interface refs: {s['moulinette_interface_refs']}")
    print(f"  total symbol hits:   {s['total_calls']}")
    print()
    print("per-symbol file counts (Stage 2 mechanical replacement):")
    for sym in sorted(REPLACEMENTS):
        files = report["per_symbol_files"].get(sym, [])
        print(f"  {sym:36} -> {REPLACEMENTS[sym]:40} {len(files)} files")
    print()
    print("import lines (distinct):")
    for line, count in report["import_lines"].items():
        print(f"  {count:3}  {line}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="src")
    ap.add_argument("--json", default=None, help="write machine-readable catalog to this path")
    args = ap.parse_args()

    report = scan(Path(args.src).resolve())
    print_report(report)
    if args.json:
        Path(args.json).write_text(
            json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
        )
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())