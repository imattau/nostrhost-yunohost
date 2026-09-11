"""Typed operation schemas (Moulinette ``actionsmap`` replacement).

The operation registry is NostrHost's authoritative interface description:
from a single ``OperationSpec`` the CLI, HTTP API, MCP schema, admin form and
AI tool contract are derived (see the moulinette-removal plan).  Stage 1
ships the pydantic models plus a loader for the catalog JSON the converter
(``tools/actionsmap_converter.py``) emits from ``share/actionsmap.yml``; it
does not yet change how the fork dispatches actions.

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
