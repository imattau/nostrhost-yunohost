"""Typed operation schemas (Moulinette ``actionsmap`` replacement).

The operation registry is NostrHost's authoritative interface description:
from a single ``OperationSpec`` the CLI, HTTP API, MCP schema, admin form and
AI tool contract are derived (see the moulinette-removal plan).  Stage 1 ships
the pydantic models plus a loader for the catalog JSON the converter
(``tools/actionsmap_converter.py``) emits from ``share/actionsmap.yml``.
``OperationCatalog.from_actionsmap`` (Stage 3) builds the catalog directly
from the action maps so the runtime ``OperationRegistry`` has a single source
of truth without a separate build step; the converter tool delegates to the
same code.

``OperationResult`` is the envelope result models the executor produces for
the operation event stream (REQUESTED/APPROVED/EXECUTING/SUCCEEDED/FAILED),
independent of any particular transport.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Literal

try:  # Keep the package stable on both the declared v1 and transitional v2 hosts.
    from pydantic.v1 import BaseModel, Field, root_validator, validator
except ImportError:  # pragma: no cover - exercised on Pydantic v1 installations
    from pydantic import BaseModel, Field, root_validator, validator

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH"}

OperationStatus = Literal[
    "REQUESTED", "APPROVED", "EXECUTING", "SUCCEEDED", "FAILED"
]

_SAFE_SEGMENT = re.compile(r"^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$")
_DOTTED_NAME = re.compile(r"^[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_.-]+)+$")

# Actions whose backing function lives in a different module than the
# category name (the derived module/function would not import).
OPERATION_OVERRIDES: dict[str, dict[str, str]] = {
    "app.catalog": {"module": "app_catalog", "function": "app_catalog"},
    "app.search": {"module": "app_catalog", "function": "app_search"},
}

# Actions declared in the maps but not yet implemented upstream (FIXME
# stubs); the registry marks them non-executable.
UNIMPLEMENTED_OPERATIONS: frozenset[str] = frozenset({
    "portal.apps",
    "portal.reset_password",
    "portal.register",
})

# Arg shapes that imply a boolean store_true flag vs a value argument.
FLAG_ACTIONS = {"store_true", "store_false"}


def _pattern(value: Any) -> str | None:
    """``extra.pattern`` is ``[regex, "i18n_key"]`` or a list of such; take the
    first regex string. Also handles ``!!str`` scalar patterns."""
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


def _arg_kind(name: str, data: dict[str, Any]) -> Literal["positional", "option", "flag"]:
    if data.get("action") in FLAG_ACTIONS:
        return "flag"
    if name.startswith("-"):
        return "option"
    return "positional"


def _extract_args(arguments: dict[str, Any] | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for name, data in (arguments or {}).items():
        if not isinstance(data, dict):
            continue
        extra = data.get("extra") or {}
        out.append({
            "flag": name,
            "full": data.get("full"),
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
    """Backing Python function for a CLI path (dashes normalized)."""
    return "_".join(seg.replace("-", "_") for seg in cli_seg)


def _api_route(route: str | None) -> ApiRoute | None:
    if not isinstance(route, str):
        return None
    parts = route.split(" ", 1)
    if len(parts) == 2 and parts[0] in HTTP_METHODS:
        return ApiRoute(method=parts[0], path=parts[1])  # type: ignore[arg-type]
    # bare path with no verb (defaults to the action's own method)
    return ApiRoute(method="GET", path=route)  # type: ignore[arg-type]


def _auth(act: dict[str, Any], default: str | None) -> str | None:
    auth = act.get("authentication")
    if isinstance(auth, dict):
        return auth.get("api") or auth.get("cli")
    return default


class ApiRoute(BaseModel):
    """An HTTP route exposed by an operation."""

    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH"]
    path: str

    @validator("path")
    def valid_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("api path must start with '/'")
        return value


class ArgumentSpec(BaseModel):
    """One declared argument of an operation.

    Mirrors the fields the converter extracts from an actionsmap action, which
    in turn mirror moulinette's argument machinery (required/pattern/password/
    ask/nargs/action/choices/autocomplete).
    """

    flag: str = ""
    full: str | None = None
    kind: Literal["positional", "option", "flag"] = "option"
    required: bool = False
    pattern: str | None = None
    password: bool = False
    ask: str | None = None
    default: Any = None
    nargs: str | None = None
    action: str | None = None
    choices: list[str] | None = None
    autocomplete: Any = None
    help: str | None = None

    @property
    def is_positional(self) -> bool:
        return self.kind == "positional"


class OperationSpec(BaseModel):
    """A single operation: CLI path, backing function, API route, auth, args.

    This is the unit the registry dispatches on.  ``cli_path`` is the dotted
    CLI invocation (``user group add``), ``function`` the backing Python
    function (``user_group_add``), ``module`` the module that owns it.
    """

    name: str
    cli_path: list[str]
    function: str
    module: str
    api: ApiRoute | None = None
    auth: str | None = None
    help: str | None = None
    args: list[ArgumentSpec] = Field(default_factory=list)
    implemented: bool = True

    @validator("name")
    def valid_name(cls, value: str) -> str:
        if not _DOTTED_NAME.fullmatch(value):
            raise ValueError(f"operation name must be dotted: {value!r}")
        return value

    @validator("cli_path")
    def valid_cli_path(cls, value: list[str]) -> list[str]:
        if not value or any(not _SAFE_SEGMENT.fullmatch(seg) for seg in value):
            raise ValueError(f"unsafe cli_path: {value!r}")
        return value

    @validator("function")
    def valid_function(cls, value: str) -> str:
        if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", value):
            raise ValueError(f"unsafe function name: {value!r}")
        return value

    @validator("module")
    def valid_module(cls, value: str) -> str:
        if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", value):
            raise ValueError(f"unsafe module name: {value!r}")
        return value

    @root_validator
    def function_matches_cli_path(cls, values: dict[str, Any]) -> dict[str, Any]:
        cli_path = values.get("cli_path")
        function = values.get("function")
        if cli_path and function:
            expected = "_".join(seg.replace("-", "_") for seg in cli_path)
            if function != expected:
                raise ValueError(
                    f"function {function!r} does not match cli_path {cli_path!r} "
                    f"(expected {expected!r})"
                )
        return values


class OperationCatalog(BaseModel):
    """The full registry: every operation declared by the action maps."""

    version: int = 1
    sources: list[str] = Field(default_factory=list)
    operations: list[OperationSpec] = Field(default_factory=list)

    @validator("operations")
    def names_are_unique(cls, value: list[OperationSpec]) -> list[OperationSpec]:
        seen: set[str] = set()
        for op in value:
            if op.name in seen:
                raise ValueError(f"duplicate operation name: {op.name}")
            seen.add(op.name)
        return value

    def by_name(self, name: str) -> OperationSpec | None:
        return next((op for op in self.operations if op.name == name), None)

    def with_api_route(self) -> list[OperationSpec]:
        return [op for op in self.operations if op.api is not None]

    def modules(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for op in self.operations:
            counts[op.module] = counts.get(op.module, 0) + 1
        return dict(sorted(counts.items()))

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.json())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "OperationCatalog":
        return cls.parse_obj(data)

    @classmethod
    def load(cls, path: str | Path) -> "OperationCatalog":
        """Load a catalog JSON artifact written by the converter."""
        with open(path, encoding="utf-8") as fh:
            return cls.parse_obj(json.load(fh))

    @classmethod
    def from_actionsmap(
        cls,
        paths: list[str | Path],
        *,
        apply_overrides: bool = True,
    ) -> "OperationCatalog":
        """Build the catalog directly from ``actionsmap.yml`` files.

        This is the Stage-3 single source of truth: the runtime registry and
        the ``actionsmap_converter`` tool both consume it, so the parsed
        operations (name, cli path, function, module, api route, auth, args)
        never drift between the build artifact and the running system.

        ``OPERATION_OVERRIDES`` corrects the module/function derivation for
        actions whose backing function lives in a different module, and
        ``UNIMPLEMENTED_OPERATIONS`` marks declared-but-not-implemented
        actions (FIXME stubs) so the registry refuses to dispatch them.
        """
        import yaml  # type: ignore[import-untyped]  # noqa: PLC0415 - only needed when building from YAML

        operations: list[OperationSpec] = []
        seen: set[str] = set()
        for path in paths:
            with open(path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            global_conf = data.get("_global") or {}
            auth = (global_conf.get("authentication") or {}).get("api")
            for category, cat_node in data.items():
                if category == "_global" or not isinstance(cat_node, dict):
                    continue
                actions = cat_node.get("actions") or {}
                subcategories = cat_node.get("subcategories") or {}
                for act_name, act in (actions or {}).items():
                    if not isinstance(act, dict):
                        continue
                    op = cls._spec(f"{category}.{act_name}", [category, act_name], act, auth)
                    if op.name not in seen:
                        seen.add(op.name)
                        operations.append(op)
                for sub_name, sub_node in (subcategories or {}).items():
                    cls._walk(
                        f"{category}.{sub_name}",
                        [category, sub_name],
                        category,
                        sub_node,
                        auth,
                        operations,
                        seen,
                    )
        if apply_overrides:
            operations = cls._apply_overrides(operations)
        return cls(
            version=1,
            sources=[str(p) for p in paths],
            operations=operations,
        )

    @staticmethod
    def _spec(name: str, cli_seg: list[str], act: dict[str, Any], auth: str | None) -> OperationSpec:
        return OperationSpec(
            name=name,
            cli_path=cli_seg,
            function=_function(cli_seg),
            module=cli_seg[0],
            api=_api_route(act.get("api")),
            auth=_auth(act, auth),
            help=act.get("action_help"),
            args=[ArgumentSpec.parse_obj(a) for a in _extract_args(act.get("arguments"))],
        )

    @staticmethod
    def _walk(prefix: str, cli: list[str], module: str, node: dict[str, Any],
              auth: str | None, out: list[OperationSpec], seen: set[str]) -> None:
        actions = node.get("actions") if isinstance(node, dict) else None
        if isinstance(actions, dict):
            for act_name, act in actions.items():
                if not isinstance(act, dict):
                    continue
                op = OperationCatalog._spec(f"{prefix}.{act_name}", cli + [act_name], act, auth)
                if op.name not in seen:
                    seen.add(op.name)
                    out.append(op)
            return
        for name, sub in (node or {}).items():
            if not isinstance(sub, dict):
                continue
            OperationCatalog._walk(
                f"{prefix}.{name}" if prefix else name,
                cli + [name],
                module,
                sub,
                auth,
                out,
                seen,
            )

    @staticmethod
    def _apply_overrides(operations: list[OperationSpec]) -> list[OperationSpec]:
        updated: list[OperationSpec] = []
        for op in operations:
            override = OPERATION_OVERRIDES.get(op.name)
            data = op.dict()
            if override:
                data["module"] = override["module"]
                data["function"] = override["function"]
            if op.name in UNIMPLEMENTED_OPERATIONS:
                data["implemented"] = False
            updated.append(OperationSpec.parse_obj(data))
        return updated


class OperationResult(BaseModel):
    """Envelope for an operation's lifecycle result.

    ``status`` follows the executor event stream; ``error`` carries a
    machine-readable ``{code, message_key, ...}`` body on FAILED rather than
    a rendered string, so each transport (CLI/Admin/MCP/Nostr) can translate
    at the boundary.
    """

    operation: str
    status: OperationStatus = "REQUESTED"
    actor: str | None = None
    resource: str | None = None
    result: Any = None
    error: dict[str, Any] | None = None

    @validator("resource")
    def valid_resource(cls, value: str | None) -> str | None:
        if value is not None and ".." in value:
            raise ValueError(f"unsafe resource name: {value!r}")
        return value

    def failed(self) -> bool:
        return self.status == "FAILED"

    def succeeded(self) -> bool:
        return self.status == "SUCCEEDED"
