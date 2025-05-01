from __future__ import annotations

import argparse
import errno
import inspect
import json
import os
import sys
import textwrap
import urllib.parse
from functools import wraps
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from dissect.target.helpers import docs, keychain
from dissect.target.helpers.docs import get_docstring
from dissect.target.loader import LOADERS_BY_SCHEME
from dissect.target.plugin import (
    FunctionDescriptor,
    Plugin,
    find_functions,
    get_external_module_paths,
    load_modules_from_paths,
)
from dissect.target.tools.logging import configure_logging

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

    from dissect.target.target import Target


def configure_generic_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-K", "--keychain-file", type=Path, help="keychain file in CSV format")
    parser.add_argument("-Kv", "--keychain-value", help="passphrase, recovery key or key file path value")
    parser.add_argument("-L", "--loader", action="store", help="select a specific loader (i.e. vmx, raw)")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase output verbosity")
    parser.add_argument("--version", action="store_true", help="print version")
    parser.add_argument("-q", "--quiet", action="store_true", help="do not output logging information")
    parser.add_argument(
        "--plugin-path",
        action="store",
        nargs="+",
        type=Path,
        help="a file or directory containing plugins and extensions",
    )


def process_generic_arguments(args: argparse.Namespace, rest: list[str]) -> None:
    configure_logging(args.verbose, args.quiet, as_plain_text=True)

    if args.version:
        try:
            print("dissect.target version " + version("dissect.target"))
        except PackageNotFoundError:
            print("unable to determine version")
        sys.exit(0)

    targets = args.targets if hasattr(args, "targets") else [args.target] if hasattr(args, "target") else []
    if targets and args.loader:
        targets = args_to_uri(targets, args.loader, rest)

    if hasattr(args, "targets"):
        args.targets = targets
    elif hasattr(args, "target"):
        args.target = targets[0]

    if args.keychain_file:
        keychain.register_keychain_file(args.keychain_file)

    if args.keychain_value:
        keychain.register_wildcard_value(args.keychain_value)

    paths = get_external_module_paths(args.plugin_path or [])
    load_modules_from_paths(paths)


def generate_argparse_for_bound_method(
    method: Callable,
    usage_tmpl: str | None = None,
) -> argparse.ArgumentParser:
    """Generate an ``argparse.ArgumentParser`` for a bound ``Plugin`` class method."""

    # allow functools.partial wrapped method
    while hasattr(method, "func"):
        method = method.func

    if not inspect.ismethod(method):
        raise ValueError(f"Value `{method}` is not a bound plugin instance method")

    unbound_method = method.__func__
    return generate_argparse_for_unbound_method(unbound_method, usage_tmpl=usage_tmpl)


def generate_argparse_for_unbound_method(
    method: Callable,
    usage_tmpl: str | None = None,
) -> argparse.ArgumentParser:
    """Generate an ``argparse.ArgumentParser`` for an unbound ``Plugin`` class method."""

    if not inspect.isfunction(method):
        raise ValueError(f"Value `{method}` is not an unbound plugin method")

    desc = method.__doc__ or docs.get_func_description(method, with_docstrings=True)

    if "\n" in desc:
        desc = inspect.cleandoc(desc)

    help_formatter = argparse.RawDescriptionHelpFormatter
    parser = argparse.ArgumentParser(description=desc, formatter_class=help_formatter, conflict_handler="resolve")

    _add_args_to_parser(parser, getattr(method, "__args__", []))

    usage = parser.format_usage()
    offset = usage.find(parser.prog) + len(parser.prog)
    func_name = method.__name__
    usage_tmpl = usage_tmpl or "{prog} {usage}"
    parser.usage = usage_tmpl.format(prog=parser.prog, name=func_name, usage=usage[offset:])

    return parser


def generate_argparse_for_plugin_class(
    plugin_cls: type[Plugin],
    usage_tmpl: str | None = None,
) -> argparse.ArgumentParser:
    """Generate an ``argparse.ArgumentParser`` for a ``Plugin`` class."""

    if not isinstance(plugin_cls, type) or not issubclass(plugin_cls, Plugin):
        raise TypeError(f"`plugin_cls` must be a valid plugin class, not `{plugin_cls}`")

    method_name = plugin_cls.__namespace__
    desc = docs.get_plugin_overview(plugin_cls, with_plugin_desc=True, with_func_docstrings=True)

    help_formatter = argparse.RawDescriptionHelpFormatter
    parser = argparse.ArgumentParser(description=desc, formatter_class=help_formatter, conflict_handler="resolve")

    _add_args_to_parser(parser, getattr(plugin_cls.__call__, "__args__", []))

    usage = parser.format_usage()
    offset = usage.find(parser.prog) + len(parser.prog)
    usage_tmpl = usage_tmpl or "{prog} {usage}"

    parser.usage = usage_tmpl.format(prog=parser.prog, name=method_name, usage=usage[offset:])

    return parser


def _add_args_to_parser(
    parser: argparse.ArgumentParser,
    fargs: list[tuple[list[str], dict[str, Any]]],
) -> None:
    groups = {}
    default_group_options = {"required": False}
    for args, kwargs in fargs:
        if "group" in kwargs:
            group_name = kwargs.pop("group")
            options = kwargs.pop("group_options") if "group_options" in kwargs else default_group_options
            if group_name not in groups:
                group = parser.add_mutually_exclusive_group(**options)
                groups[group_name] = group
            else:
                group = groups[group_name]

            group.add_argument(*args, **kwargs)
        else:
            parser.add_argument(*args, **kwargs)


def generate_argparse_for_plugin(
    plugin_instance: Plugin,
    usage_tmpl: str | None = None,
) -> argparse.ArgumentParser:
    """Generate an ``argparse.ArgumentParser`` for a ``Plugin`` instance."""

    if not isinstance(plugin_instance, Plugin):
        raise TypeError(f"`plugin_instance` must be a valid plugin instance, not `{plugin_instance}`")

    if not hasattr(plugin_instance, "__namespace__"):
        raise ValueError(f"Plugin `{plugin_instance}` is not a namespace plugin and is not callable")

    return generate_argparse_for_plugin_class(plugin_instance.__class__, usage_tmpl=usage_tmpl)


def execute_function_on_target(
    target: Target,
    func: FunctionDescriptor,
    arguments: list[str] | None = None,
) -> tuple[str, Any, list[str]]:
    """Execute function on provided target with provided arguments."""

    arguments = arguments or []

    func_cls, func_obj = target.get_function(func.name)
    plugin_method, parser = plugin_function_with_argparser(func_obj)

    if parser:
        known_args, rest = parser.parse_known_args(arguments)
        value = plugin_method(**vars(known_args))
    elif isinstance(func_obj, property):
        rest = arguments
        value = func_obj.__get__(func_cls)
    else:
        rest = arguments
        value = func_obj

    output_type = getattr(plugin_method, "__output__", "default") if plugin_method else "default"
    return (output_type, value, rest)


def plugin_function_with_argparser(
    target_attr: Plugin | Callable,
) -> tuple[Callable | None, argparse.ArgumentParser | None]:
    """Resolves which plugin function to execute, and creates the argument parser for said plugin."""
    plugin_method = None
    parser = None

    # goes first because plugins are callable
    if isinstance(target_attr, Plugin):
        plugin_obj = target_attr

        if not plugin_obj.__namespace__:
            raise ValueError(f"Plugin {plugin_obj} is not callable")

        plugin_method = plugin_obj.__call__
        parser = generate_argparse_for_plugin(plugin_obj)
    elif callable(target_attr):
        plugin_method = target_attr
        parser = generate_argparse_for_bound_method(target_attr)
    return plugin_method, parser


def persist_execution_report(output_dir: Path, report_data: dict, timestamp: datetime) -> Path:
    timestamp = timestamp.strftime("%Y-%m-%d-%H%M%S")
    report_filename = f"target-report-{timestamp}.json"
    report_full_path = output_dir / report_filename
    report_full_path.write_text(json.dumps(report_data, sort_keys=True, indent=4))
    return report_full_path


def catch_sigpipe(func: Callable) -> Callable:
    """Catches ``KeyboardInterrupt`` and ``BrokenPipeError`` (``OSError 22`` on Windows)."""

    @wraps(func)
    def wrapper(*args, **kwargs) -> int:
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt:
            print("Aborted!", file=sys.stderr)
            return 1
        except OSError as e:
            # Only catch BrokenPipeError or OSError 22
            if e.errno in (errno.EPIPE, errno.EINVAL):
                devnull = os.open(os.devnull, os.O_WRONLY)
                os.dup2(devnull, sys.stdout.fileno())
                return 1
            # Raise other exceptions
            raise

    return wrapper


def args_to_uri(targets: list[str], loader_name: str, rest: list[str]) -> list[str]:
    """Converts argument-style ``-L`` to URI-style.

    Turns:
        ``target-query /evtxs/* -L log --log-hint="evtx" -f evtx``
    into:
        ``target-query "log:///evtxs/*?hint=evtx" -f evtx``

    For loaders providing ``@arg()`` arguments.
    """
    loader = LOADERS_BY_SCHEME.get(loader_name, None)

    parser = argparse.ArgumentParser(
        argument_default=argparse.SUPPRESS, description="\n".join(textwrap.wrap(get_docstring(loader)))
    )
    for load_arg in getattr(loader, "__args__", []):
        parser.add_argument(*load_arg[0], **load_arg[1])
    args = vars(parser.parse_known_args(rest)[0])
    return [f"{loader_name}://{target}" + (("?" + urllib.parse.urlencode(args)) if args else "") for target in targets]


def find_and_filter_plugins(
    functions: str, target: Target, excluded_func_paths: set[str] | None = None
) -> Iterator[FunctionDescriptor]:
    # Keep a set of plugins that were already executed on the target.
    executed_plugins = set()
    excluded_func_paths = excluded_func_paths or set()

    func_defs, _ = find_functions(functions, target)

    for func_def in func_defs:
        if func_def.path in excluded_func_paths:
            continue

        # Avoid executing same plugin for multiple OSes (like hostname)
        if func_def.name in executed_plugins:
            continue

        executed_plugins.add(func_def.name)

        yield func_def


def escape_str(value: str) -> str:
    """Escape non-ASCII, unicode characters and bytes to a printable form."""
    return repr(value)[1:-1]
