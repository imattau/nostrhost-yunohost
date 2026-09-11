"""The runtime OperationRegistry (Moulinette ``ActionsMap`` replacement).

Stage 3 of the moulinette removal.  The registry is the authoritative
interface description generated from ``share/actionsmap.yml``: every
operation carries its CLI path, backing function, API route, authentication
profile and argument metadata (pattern/required/password/ask/nargs/choices),
and the registry turns that into typed Pydantic request models, resolves the
real ``yunohost`` function lazily, and dispatches with validation.

From a single ``OperationSpec`` the CLI, HTTP API, MCP schema, admin form and
AI tool contract are derived -- the property that let us delete ActionsMap
instead of re-implementing it.  The registry deliberately does NOT re-implement
moulinette's CLI-to-argparse emulation: the API and CLI adapters (Stages 4-5)
validate against the generated request models directly.

``scope`` maps an operation to the nostrhost-policy vocabulary
(``apps.read`` / ``apps.write`` / ``users.write`` / ...) and ``risk`` is a
low/medium/high classification the policy engine consumes; both are initial
heuristics refined at policy integration time.
"""

from __future__ import annotations

import importlib
import re
from typing import Any, Callable, TypeVar

try:  # Keep the package stable on both the declared v1 and transitional v2 hosts.
    from pydantic.v1 import Field as PydField
    from pydantic.v1 import ValidationError as PydanticValidationError
    from pydantic.v1 import constr
    from pydantic.v1 import create_model
except ImportError:  # pragma: no cover - exercised on Pydantic v1 installations
    from pydantic import Field as PydField
    from pydantic import ValidationError as PydanticValidationError
    from pydantic import constr
    from pydantic import create_model

from .core import NostrHostValidationError
from .models import (
    ArgumentSpec,
    OperationCatalog,
    OperationSpec,
    Path,
)

__all__ = [
    "OperationError",
    "OperationNotImplementedError",
    "OperationResolutionError",
    "OperationRegistry",
]

T = TypeVar("T")

# Category -> policy scope domain.
SCOPE_DOMAINS = {
    "app": "apps",
    "backup": "backups",
    "diagnosis": "diagnosis",
    "domain": "domains",
    "dyndns": "dyndns",
    "firewall": "firewall",
    "hook": "hooks",
    "log": "logs",
    "portal": "portal",
    "service": "services",
    "settings": "settings",
    "storage": "storage",
    "tools": "tools",
    "user": "users",
}

# Categories whose operations are read-mostly when they have no API route
# (a GET route already marks read).
READ_CATEGORIES = frozenset({"diagnosis", "log", "settings", "storage", "hook"})

# High-risk operations (destructive or wide-reaching); everything else write
# is medium, reads are low.
HIGH_RISK_OPERATIONS = frozenset({
    "app.install", "app.remove", "app.upgrade", "app.change-url",
    "backup.restore", "backup.remove",
    "domain.remove",
    "firewall.close",
    "service.stop",
    "tools.postinstall", "tools.shutdown", "tools.reboot",
    "user.delete", "user.update",
})

_FIELD_NAME_RE = re.compile(r"[^a-zA-Z0-9_]")


class OperationError(ValueError):
    """The operation is unknown or could not be dispatched."""


class OperationNotImplementedError(OperationError):
    """The operation is declared in the action map but not implemented."""


class OperationResolutionError(OperationError):
    """The backing function/module could not be resolved."""


def _field_name(arg: ArgumentSpec) -> str:
    """Dest-style field name for an argument.

    Options use their long form (``--fullname`` -> ``fullname``); positional
    arguments keep their key.  Dashes become underscores like argparse dests.
    """
    raw = arg.full or arg.flag
    raw = raw.lstrip("-")
    raw = raw.split("=", 1)[0]
    return _FIELD_NAME_RE.sub("_", raw).strip("_")


def _field_type(arg: ArgumentSpec) -> tuple[Any, Any]:
    """Return ``(type, default)`` for a request-model field.

    ``nargs`` maps to lists; ``store_true``/``store_false`` to bools; the
    rest are strings.  Positional arguments are required by default (argparse
    semantics) unless they carry optional ``nargs`` or an explicit default;
    options are required only when the action map marks them so.
    """
    if arg.kind == "flag":
        default = arg.default if arg.default is not None else (arg.action == "store_false")
        return bool, default
    if arg.nargs in ("+", "*"):
        required = arg.nargs == "+" and (arg.required or arg.kind == "positional")
        field_type = list if required else (list | None)
        default = arg.default if arg.default is not None else (() if required else None)
        return field_type, default
    if arg.nargs == "?":
        return str | None, (arg.default if arg.default is not None else None)
    required = arg.required or (arg.kind == "positional" and arg.default is None)
    if required:
        return str, ...
    return str | None, (arg.default if arg.default is not None else None)


class OperationRegistry:
    """Indexed, executable view over an ``OperationCatalog``."""

    def __init__(self, catalog: OperationCatalog, module_factory: Callable[[str], Any] | None = None) -> None:
        self.catalog = catalog
        self._module_factory = module_factory or (lambda mod: importlib.import_module(f"yunohost.{mod}"))
        self._by_name: dict[str, OperationSpec] = {op.name: op for op in catalog.operations}
        self._by_cli: dict[tuple[str, ...], OperationSpec] = {
            tuple(op.cli_path): op for op in catalog.operations
        }
        self._by_route: dict[tuple[str, str], OperationSpec] = {
            (op.api.method, op.api.path): op for op in catalog.operations if op.api
        }
        self._models: dict[str, Any] = {}

    # -- construction --------------------------------------------------------

    @classmethod
    def from_actionsmap(
        cls,
        paths: list[str | Path] | None = None,
        module_factory: Callable[[str], Any] | None = None,
    ) -> "OperationRegistry":
        if paths is None:
            fork = Path(__file__).resolve().parent.parent.parent
            paths = [fork / "share" / "actionsmap.yml", fork / "share" / "actionsmap-portal.yml"]
        return cls(OperationCatalog.from_actionsmap(list(paths)), module_factory=module_factory)

    @classmethod
    def from_json(cls, path: str | Path, module_factory: Callable[[str], Any] | None = None) -> "OperationRegistry":
        return cls(OperationCatalog.load(path), module_factory=module_factory)

    # -- lookup --------------------------------------------------------------

    def operations(self) -> list[OperationSpec]:
        return list(self.catalog.operations)

    def executable_operations(self) -> list[OperationSpec]:
        return [op for op in self.catalog.operations if op.implemented]

    def by_name(self, name: str) -> OperationSpec | None:
        return self._by_name.get(name)

    def by_cli_path(self, path: list[str]) -> OperationSpec | None:
        return self._by_cli.get(tuple(path))

    def by_route(self, method: str, path: str) -> OperationSpec | None:
        return self._by_route.get((method, path))

    def with_api_route(self) -> list[OperationSpec]:
        return [op for op in self.catalog.operations if op.api]

    def modules(self) -> dict[str, int]:
        return self.catalog.modules()

    def is_implemented(self, name: str) -> bool:
        op = self.by_name(name)
        return bool(op and op.implemented)

    # -- resolution ----------------------------------------------------------

    def resolve(self, name: str) -> Callable[..., Any]:
        """Import ``yunohost.<module>`` and return the backing function."""
        op = self._require(name)
        if not op.implemented:
            raise OperationNotImplementedError(
                f"operation {name} is declared but not implemented"
            )
        try:
            module = self._module_factory(op.module)
            function = getattr(module, op.function)
        except ImportError as exc:
            raise OperationResolutionError(
                f"cannot import module {op.module} for operation {name}: {exc}"
            ) from exc
        except AttributeError as exc:
            raise OperationResolutionError(
                f"module {op.module} has no function {op.function} for operation {name}"
            ) from exc
        if not callable(function):
            raise OperationResolutionError(
                f"{op.module}.{op.function} is not callable (operation {name})"
            )
        return function

    def _require(self, name: str) -> OperationSpec:
        op = self.by_name(name)
        if op is None:
            raise OperationError(f"unknown operation: {name}")
        return op

    # -- request models ------------------------------------------------------

    def request_model(self, name: str) -> Any:
        """Build (and cache) a Pydantic request model for ``name``.

        Field types, requiredness, defaults and regex patterns come from the
        action map's argument metadata; ``secret``/``choices``/``ask`` are
        carried as field extras for the UI/API adapters.
        """
        op = self._require(name)
        if name in self._models:
            return self._models[name]
        fields: dict[str, tuple[Any, Any]] = {}
        for arg in op.args:
            field_name = _field_name(arg)
            field_type, default = _field_type(arg)
            kwargs: dict[str, Any] = {}
            if arg.pattern:
                if arg.nargs in ("+", "*"):
                    # Pydantic v1 cannot enforce regex on a list field itself;
                    # apply it to the element type instead.
                    element = constr(regex=arg.pattern)  # type: ignore[call-arg,valid-type]
                    if arg.nargs == "+" and (arg.required or arg.kind == "positional"):
                        field_type = list[element]  # type: ignore[valid-type]
                    else:
                        field_type = list[element] | None  # type: ignore[valid-type]
                else:
                    kwargs["regex"] = arg.pattern
            if arg.password:
                kwargs["secret"] = True
            if arg.choices:
                kwargs["choices"] = arg.choices
            if arg.ask:
                kwargs["ask"] = arg.ask
            kwargs["description"] = arg.help or arg.flag
            fields[field_name] = (field_type, PydField(default, **kwargs))
        model_name = f"Operation{''.join(s.capitalize() for s in re.split(r'[^a-zA-Z0-9]+', name))}Request"
        # type ignore: pydantic create_model accepts **field_definitions; the
        # v1/v2 shim makes the resolved signature differ per interpreter.
        model = create_model(model_name, **fields)  # type: ignore[call-arg,arg-type]
        self._models[name] = model
        return model

    def request_json_schema(self, name: str) -> dict[str, Any]:
        return self.request_model(name).schema()

    # -- scope / risk --------------------------------------------------------

    def scope(self, name: str) -> str:
        """Policy scope for an operation, e.g. ``users.write``."""
        op = self._require(name)
        domain = SCOPE_DOMAINS.get(op.cli_path[0], op.cli_path[0])
        method = op.api.method if op.api else None
        if method == "GET" or (method is None and op.cli_path[0] in READ_CATEGORIES):
            return f"{domain}.read"
        return f"{domain}.write"

    def risk(self, name: str) -> str:
        """Low/medium/high risk classification for an operation."""
        if name in HIGH_RISK_OPERATIONS:
            return "high"
        if self.scope(name).endswith(".read"):
            return "low"
        return "medium"

    # -- dispatch ------------------------------------------------------------

    def validate(self, name: str, request: dict[str, Any]) -> dict[str, Any]:
        """Validate a request dict against the generated model."""
        op = self._require(name)
        model = self.request_model(name)
        try:
            validated = model.parse_obj(request)
        except PydanticValidationError as exc:
            raise NostrHostValidationError(
                "invalid_arguments", error_details=str(exc), raw_msg=False
            ) from exc
        data = dict(validated)
        for arg in op.args:
            value = data.get(_field_name(arg))
            if arg.choices and value is not None and value not in arg.choices:
                raise NostrHostValidationError(
                    "invalid_choice", raw_msg=True
                )
        return data

    def execute(self, name: str, request: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """Validate and run an operation's backing function.

        ``request`` may be a dict of argument values, or ``**kwargs``.  The
        function is called with keyword arguments keyed by the dest-style
        field names (matching the fork's function signatures).
        """
        if request is not None and kwargs:
            raise OperationError("pass either request= or kwargs, not both")
        payload = dict(request) if request is not None else dict(kwargs)
        data = self.validate(name, payload)
        function = self.resolve(name)
        return function(**data)
