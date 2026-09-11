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

Usage:
    actionsmap_converter.py [--map share/actionsmap.yml ...] [--json OUT]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("actionsmap_converter: PyYAML is required (python3-yaml)")

# Arg shapes that imply a boolean store_true flag vs a value argument.
FLAG_ACTIONS = {"store_true", "store_false"}
# Arg kinds inferred from the flag name shape / presence of full alias.
POSITIONAL_KEYS = {"username", "domain", "app", "groupname", "permission",
                   "name", "target", "category", "port", "protocol", "path",
                   "new_main_domain", "domain_list", "usernames", "names",
                   "key", "action", "policy", "rule", "time", "token",
                   "credential", "storage", "disk", "group", "alias",
                   "types", "checks", "format", "fields"}


def _pattern(value: Any) -> str | None:
    """extras.pattern is `[regex, "i18n_key"]` or a list of such; take the
    first regex string. Also handles `!!str` scalar patterns."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, list) and value:
        first = value[0]
        return str(first) if first is not None else None
    if isinstance(value, dict):
        return value.get("pattern")
    return None


def _arg_kind(name: str, data: dict) -> str:
    if data.get("action") in FLAG_ACTIONS:
        return "flag"
    if name.startswith("-"):
        return "option"
    return "positional"


def _extract_args(arguments: dict[str, Any] | None) -> list[dict]:
    out: list[dict] = []
    for name, data in (arguments or {}).items():
        if not isinstance(data, dict):
            continue
        extra = data.get("extra") or {}
        out.append({
            "flag": name,
            "kind": _arg_kind(name, data),
            "required": bool(extra.get("required", False)),
            "pattern": _pattern(extra.get("pattern")),
            "password": bool(extra.get("password")),
            "ask": extra.get("ask"),
            "default": data.get("default"),
            "nargs": data.get("nargs"),
            "action": data.get("action"),
            "choices": data.get("choices"),
            "autocomplete": extra.get("autocomplete"),
            "help": data.get("help"),
        })
    return out


def _function(cli_seg: list[str]) -> str:
    """Backing Python function for a CLI path.

    Action keys use dashes (add-mailalias -> add_mailalias); the function
    name is the dotted cli path with '-' normalized to '_'.
    """
    return "_".join(seg.replace("-", "_") for seg in cli_seg)


def _walk(prefix: str, cli: list[str], module: str, node: dict,
          out: list[dict], default_auth: str | None) -> None:
    """Recursively walk categories -> subcategories -> actions.

    `node` may be (a) a subcategory block whose `actions:` container holds the
    actions directly (group, permission, ssh, ...), or (b) a bare actions
    container. Either way the container key is not part of the dotted
    operation name: subcategory `group` + action `add` -> `user.group.add`.
    """
    actions = node.get("actions") if isinstance(node, dict) else None
    if isinstance(actions, dict):
        for act_name, act in actions.items():
            if not isinstance(act, dict):
                continue
            api = act.get("api")
            api_route = api if isinstance(api, str) else None
            dotted = f"{prefix}.{act_name}" if prefix else act_name
            cli_seg = cli + [act_name]
            out.append({
                "name": dotted,
                "cli_path": cli_seg,
                "function": _function(cli_seg),
                "module": module,
                "api": _api_route(api_route, act),
                "auth": _auth(act, default_auth),
                "help": act.get("action_help"),
                "args": _extract_args(act.get("arguments")),
            })
        return

    for name, sub in (node or {}).items():
        if not isinstance(sub, dict):
            continue
        _walk(f"{prefix}.{name}" if prefix else name, cli + [name], module,
              sub, out, default_auth)


def _api_route(route: str | None, act: dict) -> dict | None:
    """Return {method, path} when the action declares an API route."""
    if route is None:
        return None
    if not isinstance(route, str):
        return None
    parts = route.split(" ", 1)
    if len(parts) == 2 and parts[0] in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
        return {"method": parts[0], "path": parts[1]}
    # bare path with no verb (defaults to the action's own method)
    return {"method": "GET", "path": route}


def _auth(act: dict, default: str | None) -> str | None:
    auth = act.get("authentication")
    if isinstance(auth, dict):
        return auth.get("api") or auth.get("cli")
    return default


def convert(path: Path, default_auth: str | None) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    global_conf = data.pop("_global", {}) or {}
    auth = default_auth or (global_conf.get("authentication") or {}).get("api")

    out: list[dict] = []
    # Top level is category -> actions (with optional subcategories).
    for category, cat_node in data.items():
        if not isinstance(cat_node, dict):
            continue
        actions = cat_node.get("actions") or {}
        subcategories = cat_node.get("subcategories") or {}
        for act_name, act in (actions or {}).items():
            if not isinstance(act, dict):
                continue
            cli_seg = [category, act_name]
            out.append({
                "name": f"{category}.{act_name}",
                "cli_path": cli_seg,
                "function": _function(cli_seg),
                "module": category,
                "api": _api_route(act.get("api"), act),
                "auth": _auth(act, auth),
                "help": act.get("action_help"),
                "args": _extract_args(act.get("arguments")),
            })
        for sub_name, sub_node in (subcategories or {}).items():
            _walk(f"{category}.{sub_name}", [category, sub_name], category,
                  sub_node, out, auth)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--map", action="append", default=[],
                    help="actionsmap YAML to convert (repeatable)")
    ap.add_argument("--json", default=None, help="write catalog JSON here")
    ap.add_argument("--stats", action="store_true", help="print per-category stats")
    args = ap.parse_args()

    maps = args.map or ["share/actionsmap.yml", "share/actionsmap-portal.yml"]
    catalog: dict[str, Any] = {"version": 1, "operations": [], "sources": maps}
    seen = set()
    for m in maps:
        p = Path(m)
        if not p.is_file():
            print(f"warning: {p} not found", file=sys.stderr)
            continue
        ops = convert(p, None)
        for op in ops:
            if op["name"] in seen:
                continue
            seen.add(op["name"])
            catalog["operations"].append(op)

    if args.stats:
        from collections import Counter
        counts = Counter(op["module"] for op in catalog["operations"])
        total = len(catalog["operations"])
        api = sum(1 for op in catalog["operations"] if op["api"])
        print(f"total operations: {total}; with API route: {api}")
        for mod, n in sorted(counts.items()):
            print(f"  {mod:20} {n}")
    else:
        print(json.dumps(catalog, indent=2, sort_keys=True))
    if args.json:
        Path(args.json).write_text(
            json.dumps(catalog, indent=2, sort_keys=True), encoding="utf-8"
        )
        print(f"wrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())