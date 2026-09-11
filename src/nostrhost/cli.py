"""Native ``nostrhost`` CLI (Moulinette CLI replacement, Stage 4).

The CLI is a Typer adapter over the ``OperationRegistry``: every operation in
the catalog becomes a ``typer.Typer`` command whose signature (arguments,
options, flags, help) is generated from the typed ``OperationSpec`` -- the
same single source of truth the API and MCP schemas derive from.  Typer (built
on Click) gives rich help and shell completion (``--install-completion``).

The command surface is the *compatibility/migration* layer: it mirrors the
``actionsmap.yml`` operations so ``nostrhost user create ...`` behaves like
``yunohost user create ...`` (exit codes, output formats) while the dispatcher
is native.  This includes the legacy password/LDAP ``user.create``: the
NostrHost *native* user model is the npub identity (see
``yunohost.nostr_identity`` / ``nostrhost-auth``), which is exposed through the
identity/capability operations rather than this compat surface.

Exit codes match ``yunohost``/``nostr-opctl`` conventions: 0 on success, 1 on
any error, 2 on usage errors (Click's convention).
"""

from __future__ import annotations

import inspect
import sys
from typing import Any, List

import typer

from . import ui
from .core import AuthenticationError, NostrHostError, NostrHostValidationError
from .models import ArgumentSpec, OperationSpec
from .operations import (
    OperationError,
    OperationRegistry,
    _field_name,
)

EXIT_OK = 0
EXIT_ERR = 1

OUTPUT_CHOICES = ("json", "plain", "none")

DESCRIPTION = (
    "NostrHost administration CLI. Invoke an operation from the catalog, "
    "e.g. 'nostrhost user create alice' or 'nostrhost app list --output-as json'. "
    "Operations mirror the compatibility action map; native identity/capability "
    "operations are npub-based (see nostr-identity-admin)."
)


def _option_strings(arg: ArgumentSpec) -> list[str]:
    """Typer/Click option strings for an option/flag argument."""
    strings: list[str] = []
    if arg.flag.startswith("-") and not arg.flag.startswith("--"):
        strings.append(arg.flag)
    if arg.full:
        strings.append(arg.full)
    elif arg.flag.startswith("--"):
        strings.append(arg.flag)
    if not strings:
        strings = [arg.flag]
    return strings


def _typer_default(arg: ArgumentSpec) -> Any:
    """Build the Typer default (Argument/Option) for an argument."""
    help_text = arg.help or arg.flag
    if arg.kind == "positional":
        return typer.Argument(None, help=help_text)
    strings = _option_strings(arg)
    if arg.kind == "flag":
        # Typer infers the boolean flag from the `bool` annotation.
        return typer.Option(False, *strings, help=help_text)
    return typer.Option(None, *strings, help=help_text)


def _annotation(arg: ArgumentSpec) -> Any:
    if arg.nargs in ("+", "*"):
        return List[str]
    if arg.kind == "flag":
        return bool
    return str


class _State:
    """Per-invocation holder for global options shared with commands."""

    def __init__(self) -> None:
        self.output_as: str | None = None
        self.debug = False


def build_app(
    registry: OperationRegistry,
    *,
    prog: str = "nostrhost",
    state: _State | None = None,
) -> typer.Typer:
    """Build a Typer app: one command per operation, nested by category and
    subcategory (``nostrhost user create``, ``nostrhost user group add``)."""
    state = state or _State()
    app = typer.Typer(name=prog, help=DESCRIPTION, no_args_is_help=True)

    @app.callback()
    def _root(
        output_as: str = typer.Option(None, "--output-as", help="Output result in another format (json/plain/none)"),
        debug: bool = typer.Option(False, "--debug", help="Enable debug output"),
    ) -> None:
        state.output_as = output_as
        state.debug = debug

    def add_command(parent: typer.Typer, op: OperationSpec) -> None:
        params: list[inspect.Parameter] = []
        for arg in op.args:
            name = _field_name(arg)
            kind = (
                inspect.Parameter.POSITIONAL_OR_KEYWORD
                if arg.kind == "positional"
                else inspect.Parameter.KEYWORD_ONLY
            )
            params.append(
                inspect.Parameter(name, kind, default=_typer_default(arg), annotation=_annotation(arg))
            )
        # --output-as/--debug may also be given after the command name.
        params.append(
            inspect.Parameter(
                "output_as",
                inspect.Parameter.KEYWORD_ONLY,
                default=typer.Option(None, "--output-as", help="Output result in another format"),
                annotation=str,
            )
        )
        params.append(
            inspect.Parameter(
                "debug",
                inspect.Parameter.KEYWORD_ONLY,
                default=typer.Option(False, "--debug", help="Enable debug output"),
                annotation=bool,
            )
        )
        params.sort(key=lambda p: p.kind != inspect.Parameter.POSITIONAL_OR_KEYWORD)

        def _cmd(**kwargs: Any) -> None:
            output_as = kwargs.pop("output_as", None) or state.output_as
            kwargs.pop("debug", None)
            request = {k: v for k, v in kwargs.items() if v is not None}
            try:
                op_spec = registry.by_name(op.name)
                assert op_spec is not None
                _fill_required_and_prompts(op_spec, request)
                result = registry.execute(op.name, request)
            except (NostrHostError, AuthenticationError, OperationError) as exc:
                _print_error(exc)
                raise typer.Exit(EXIT_ERR)
            except Exception as exc:  # noqa: BLE001 - CLI is the last error boundary
                _print_error(exc)
                raise typer.Exit(EXIT_ERR)
            ui.format_result(result, output_as)

        _cmd.__signature__ = inspect.Signature(params)  # type: ignore[attr-defined]
        _cmd.__name__ = op.cli_path[-1]
        parent.command(name=op.cli_path[-1], help=op.help)(_cmd)

    def add_group(parent: typer.Typer, tree: dict[str, Any]) -> None:
        for key in sorted(tree):
            entry = tree[key]
            if isinstance(entry, OperationSpec):
                add_command(parent, entry)
            else:
                subgroup = typer.Typer(name=key, no_args_is_help=True)
                parent.add_typer(subgroup, name=key)
                add_group(subgroup, entry)

    tree: dict[str, Any] = {}
    for op in registry.operations():
        node = tree
        for seg in op.cli_path[:-1]:
            node = node.setdefault(seg, {})
        node[op.cli_path[-1]] = op

    add_group(app, tree)
    return app


def _fill_required_and_prompts(op: OperationSpec, request: dict[str, Any]) -> None:
    """Prompt for missing ``ask`` arguments; enforce required-ness.

    Matches moulinette's post-parse check (``argument_required``) and its
    ``extra.ask`` interactive prompting for the few arguments that declare it.
    """
    for arg in op.args:
        dest = _field_name(arg)
        value = request.get(dest)
        if arg.required and arg.default is None and value in (None, ""):
            if arg.ask:
                request[dest] = ui.prompt(
                    arg.help or arg.flag,
                    is_password=arg.password,
                )
            else:
                raise NostrHostValidationError(
                    "argument_required", argument=arg.flag, raw_msg=False
                )


def _print_error(exc: Exception) -> None:
    print(f"error: {exc}", file=sys.stderr)


def run(
    argv: list[str],
    registry: OperationRegistry | None = None,
    *,
    app: typer.Typer | None = None,
) -> int:
    """Run the CLI against ``argv`` (injectable for tests)."""
    if registry is None:
        registry = OperationRegistry.from_actionsmap()
    if app is None:
        app = build_app(registry)
    from typer.testing import CliRunner

    result = CliRunner().invoke(app, argv)
    return result.exit_code


def main(argv: list[str] | None = None) -> int:
    """Programmatic entry point used by ``bin/nostrhost``."""
    app = build_app(OperationRegistry.from_actionsmap())
    if argv is None:
        argv = sys.argv[1:]
    try:
        app(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_ERR
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover - exercised through bin/nostrhost
    raise SystemExit(main())
