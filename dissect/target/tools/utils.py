import argparse
import inspect
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Type

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers import docs, keychain
from dissect.target.loaders.targetd import TargetdLoader
from dissect.target.plugin import (
    OSPlugin,
    Plugin,
    PluginFunction,
    get_external_module_paths,
    load_modules_from_paths,
)
from dissect.target.tools.logging import configure_logging


def configure_generic_arguments(args_parser: argparse.ArgumentParser) -> None:
    args_parser.add_argument("-K", "--keychain-file", type=Path, help="keychain file in CSV format")
    args_parser.add_argument("-Kv", "--keychain-value", help="passphrase, recovery key or key file path value")
    args_parser.add_argument("-v", "--verbose", action="count", default=0, help="increase output verbosity")
    args_parser.add_argument("-q", "--quiet", action="store_true", help="do not output logging information")
    args_parser.add_argument(
        "--plugin-path",
        action="store",
        nargs="+",
        type=Path,
        help="a file or directory containing plugins and extensions",
    )


def process_generic_arguments(args: argparse.Namespace) -> None:
    configure_logging(args.verbose, args.quiet, as_plain_text=True)

    if args.keychain_file:
        keychain.register_keychain_file(args.keychain_file)

    if args.keychain_value:
        keychain.register_wildcard_value(args.keychain_value)

    paths = get_external_module_paths(args.plugin_path or [])
    load_modules_from_paths(paths)


def generate_argparse_for_bound_method(
    method: Callable,
    usage_tmpl: Optional[str] = None,
) -> argparse.ArgumentParser:
    """Generate an `argparse.ArgumentParser` for a bound `Plugin` class method"""

    # allow functools.partial wrapped method
    while hasattr(method, "func"):
        method = method.func

    if not inspect.ismethod(method):
        raise ValueError(f"Value `{method}` is not a bound plugin instance method")

    unbound_method = method.__func__
    return generate_argparse_for_unbound_method(unbound_method, usage_tmpl=usage_tmpl)


def generate_argparse_for_unbound_method(
    method: Callable,
    usage_tmpl: Optional[str] = None,
) -> argparse.ArgumentParser:
    """Generate an `argparse.ArgumentParser` for an unbound `Plugin` class method"""

    if not inspect.isfunction(method):
        raise ValueError(f"Value `{method}` is not an unbound plugin method")

    desc = docs.get_func_description(method, with_docstrings=True)
    help_formatter = argparse.RawDescriptionHelpFormatter
    parser = argparse.ArgumentParser(description=desc, formatter_class=help_formatter, conflict_handler="resolve")

    fargs = getattr(method, "__args__", [])
    for args, kwargs in fargs:
        parser.add_argument(*args, **kwargs)

    usage = parser.format_usage()
    offset = usage.find(parser.prog) + len(parser.prog)

    func_name = method.__name__
    usage_tmpl = usage_tmpl or "{prog} {usage}"
    parser.usage = usage_tmpl.format(prog=parser.prog, name=func_name, usage=usage[offset:])

    return parser


def generate_argparse_for_plugin_class(
    plugin_cls: Type[Plugin],
    usage_tmpl: Optional[str] = None,
) -> argparse.ArgumentParser:
    """Generate an `argparse.ArgumentParser` for a `Plugin` class"""

    if not isinstance(plugin_cls, type) or not issubclass(plugin_cls, Plugin):
        raise ValueError(f"`plugin_cls` must be a valid plugin class, not `{plugin_cls}`")

    method_name = plugin_cls.__namespace__
    desc = docs.get_plugin_overview(plugin_cls, with_plugin_desc=True, with_func_docstrings=True)

    help_formatter = argparse.RawDescriptionHelpFormatter
    parser = argparse.ArgumentParser(description=desc, formatter_class=help_formatter, conflict_handler="resolve")

    usage = parser.format_usage()
    offset = usage.find(parser.prog) + len(parser.prog)
    usage_tmpl = usage_tmpl or "{prog} {usage}"

    parser.usage = usage_tmpl.format(prog=parser.prog, name=method_name, usage=usage[offset:])

    return parser


def generate_argparse_for_plugin(
    plugin_instance: Plugin,
    usage_tmpl: Optional[str] = None,
) -> argparse.ArgumentParser:
    """Generate an `argparse.ArgumentParser` for a `Plugin` instance"""

    if not isinstance(plugin_instance, Plugin):
        raise ValueError(f"`plugin_instance` must be a valid plugin instance, not `{plugin_instance}`")

    if not hasattr(plugin_instance, "__namespace__"):
        raise ValueError(f"Plugin `{plugin_instance}` is not a namespace plugin and is not callable")

    return generate_argparse_for_plugin_class(plugin_instance.__class__, usage_tmpl=usage_tmpl)


def plugin_factory(target: Target, plugin_class: type, funcname: str) -> tuple[Plugin, str]:
    if TargetdLoader.instance:
        return target.get_function(funcname)
    else:
        plugin_obj = plugin_class(target)
    target_attr = getattr(plugin_obj, funcname)
    return plugin_obj, target_attr


def execute_function_on_target(
    target: Target,
    func: PluginFunction,
    cli_params: Optional[List[str]] = None,
) -> Tuple[str, Any, List[str]]:
    """
    Execute function `func` on provided target `target` with provided `cli_params` list.
    """

    cli_params = cli_params or []

    plugin_class = func.class_object

    if issubclass(plugin_class, OSPlugin):
        # OS plugin does not need to be added
        plugin_class = target._os_plugin
    else:
        try:
            target.add_plugin(plugin_class)
        except UnsupportedPluginError as e:
            raise UnsupportedPluginError(
                f"Unsupported function `{func.method_name}` for target with plugin {func.class_object}", cause=e
            )

    plugin_obj, target_attr = plugin_factory(target, plugin_class, func.method_name)
    plugin_method = None
    parser = None

    # goes first because plugins are callable
    if isinstance(target_attr, Plugin):
        plugin_obj = target_attr

        if not plugin_obj.__namespace__:
            raise ValueError(f"Plugin {plugin_obj} is not callable")

        plugin_method = plugin_obj.get_all_records
        parser = generate_argparse_for_plugin(plugin_obj)
    elif callable(target_attr):
        plugin_method = target_attr
        parser = generate_argparse_for_bound_method(target_attr)

    if parser:
        parsed_params, cli_params = parser.parse_known_args(cli_params)
        method_kwargs = vars(parsed_params)
        value = plugin_method(**method_kwargs)
    else:
        value = target_attr

    output_type = getattr(plugin_method, "__output__", "default") if plugin_method else "default"
    return (output_type, value, cli_params)


def persist_execution_report(output_dir: Path, report_data: Dict, timestamp: datetime) -> Path:
    timestamp = timestamp.strftime("%Y-%m-%d-%H%M%S")
    report_filename = f"target-report-{timestamp}.json"
    report_full_path = output_dir / report_filename
    report_full_path.write_text(json.dumps(report_data, sort_keys=True, indent=4))
    return report_full_path
