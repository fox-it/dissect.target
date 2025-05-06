#!/usr/bin/env python
from __future__ import annotations

import argparse
import logging
import pathlib
import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Callable

from flow.record import Record, RecordPrinter, RecordStreamWriter, RecordWriter

from dissect.target.exceptions import (
    FatalError,
    PluginNotFoundError,
    TargetError,
    UnsupportedPluginError,
)
from dissect.target.helpers import cache, record_modifier
from dissect.target.plugin import (
    PLUGINS,
    FunctionDescriptor,
    OSPlugin,
    Plugin,
    find_functions,
)
from dissect.target.plugins.general.plugins import (
    _get_default_functions,
    generate_functions_json,
    generate_functions_overview,
)
from dissect.target.target import Target, plugin
from dissect.target.tools.report import ExecutionReport
from dissect.target.tools.utils import (
    catch_sigpipe,
    configure_generic_arguments,
    execute_function_on_target,
    find_and_filter_plugins,
    generate_argparse_for_bound_method,
    generate_argparse_for_plugin_class,
    generate_argparse_for_unbound_method,
    persist_execution_report,
    process_generic_arguments,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from flow.record.adapter import AbstractWriter

log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False


USAGE_FORMAT_TMPL = "{prog} -f {name}{usage}"


def record_output(strings: bool = False, json: bool = False) -> AbstractWriter:
    if json:
        return RecordWriter("jsonfile://-")

    fp = sys.stdout.buffer

    if strings or fp.isatty():
        return RecordPrinter(fp)

    return RecordStreamWriter(fp)


def list_plugins(
    targets: list[str] | None = None,
    patterns: str = "",
    include_children: bool = False,
    as_json: bool = False,
    argv: list[str] | None = None,
) -> None:
    collected = set()
    if targets:
        for target in Target.open_all(targets, include_children):
            funcs, _ = find_functions(patterns, target, compatibility=True, show_hidden=True)
            collected.update(funcs)
    elif patterns:
        funcs, _ = find_functions(patterns, Target(), show_hidden=True)
        collected.update(funcs)
    else:
        collected.update(_get_default_functions())

    target = Target()
    fparser = generate_argparse_for_bound_method(target.plugins, usage_tmpl=USAGE_FORMAT_TMPL)
    fargs, rest = fparser.parse_known_args(argv or [])

    # Display in a user friendly manner
    if collected:
        if as_json:
            print('{"plugins": ', end="")
            print(generate_functions_json(collected), end="")
        else:
            print(generate_functions_overview(collected, include_docs=fargs.print_docs))

    # No real targets specified, show the available loaders
    if not targets:
        fparser = generate_argparse_for_bound_method(target.loaders, usage_tmpl=USAGE_FORMAT_TMPL)
        fargs, rest = fparser.parse_known_args(rest)
        del fargs.as_json
        if as_json:
            print(', "loaders": ', end="")
        target.loaders(**vars(fargs), as_json=as_json)

    if as_json:
        print("}")


@catch_sigpipe
def main() -> int:
    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        description="dissect.target",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
        add_help=False,
    )
    parser.add_argument("targets", metavar="TARGETS", nargs="*", help="Targets to load")
    parser.add_argument("-f", "--function", help="function to execute")
    parser.add_argument("-xf", "--excluded-functions", help="functions to exclude from execution", default="")
    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="do not execute the functions, but just print which functions would be executed",
    )
    parser.add_argument("--child", help="load a specific child path or index")
    parser.add_argument("--children", action="store_true", help="include children")
    parser.add_argument(
        "-l",
        "--list",
        action="store",
        nargs="?",
        const="",
        default=None,
        help="list (matching) available plugins and loaders",
    )
    parser.add_argument("--direct", action="store_true", help="treat TARGETS as paths to pass to plugins directly")

    parser.add_argument("-s", "--strings", action="store_true", help="print output as string")
    parser.add_argument("-d", "--delimiter", default=" ", action="store", metavar="','")
    parser.add_argument("-j", "--json", action="store_true", help="output records as json")

    parser.add_argument("--limit", type=int, help="limit number of produced records")
    parser.add_argument("--no-cache", "--ignore-cache", action="store_true", help="do not use file based caching")
    parser.add_argument(
        "--only-read-cache",
        action="store_true",
        help="only read cache files, never write them (has no effect if --no-cache is specified",
    )
    parser.add_argument(
        "--rewrite-cache",
        action="store_true",
        help=(
            "force cache files to be rewritten (has no effect if either --no-cache or --only-read-cache are specified)"
        ),
    )
    parser.add_argument("--cmdb", action="store_true")
    parser.add_argument("--hash", action="store_true", help="hash all paths in records")
    parser.add_argument("--resolve", action="store_true", help="resolve all paths in records")
    parser.add_argument(
        "--report-dir",
        type=pathlib.Path,
        help="write the query report file to the given directory",
    )
    configure_generic_arguments(parser)

    args, rest = parser.parse_known_args()

    # Show help for target-query
    if not args.function and ("-h" in rest or "--help" in rest):
        parser.print_help()
        return 0

    process_generic_arguments(args, rest)

    if args.no_cache:
        cache.IGNORE_CACHE = True

    if args.only_read_cache:
        cache.ONLY_READ_CACHE = True
        if args.no_cache:
            log.warning("The --only-read-cache option will be ignored as --no-cache is specified")

    if args.rewrite_cache:
        cache.REWRITE_CACHE = True
        if args.no_cache or args.only_read_cache:
            log.warning(
                "The --rewrite-cache option will be ignored as --no-cache or --only-read-cache are specified",
            )

    # Show help for a function or in general
    if "-h" in rest or "--help" in rest:
        found_functions, _ = find_functions(args.function)
        if not len(found_functions):
            parser.error("function(s) not found, see -l for available plugins")

        func = found_functions[0]
        plugin_class = plugin.load(func)
        if issubclass(plugin_class, OSPlugin):
            obj = getattr(OSPlugin, func.method_name)
        else:
            obj = getattr(plugin_class, func.method_name)

        if isinstance(obj, type) and issubclass(obj, Plugin):
            parser = generate_argparse_for_plugin_class(obj, usage_tmpl=USAGE_FORMAT_TMPL)
        elif isinstance(obj, (Callable, property)):
            parser = generate_argparse_for_unbound_method(getattr(obj, "fget", obj), usage_tmpl=USAGE_FORMAT_TMPL)
        else:
            parser.error(f"can't find plugin with function `{func.method_name}`")
        parser.print_help()
        return 0

    # Show the list of available plugins for the given optional target and optional
    # search pattern, only display plugins that can be applied to ANY targets
    if args.list is not None:
        list_plugins(args.targets, args.list, args.children, args.json, rest)
        return 0

    if not args.targets:
        parser.error("too few arguments")

    if not args.function:
        parser.error("argument -f/--function is required")

    if args.report_dir and not args.report_dir.is_dir():
        parser.error(f"--report-dir {args.report_dir} is not a valid directory")

    funcs, invalid_funcs = find_functions(args.function)
    if any(invalid_funcs):
        parser.error(f"argument -f/--function contains invalid plugin(s): {', '.join(invalid_funcs)}")

    excluded_funcs, invalid_excluded_funcs = find_functions(args.excluded_functions)
    if any(invalid_excluded_funcs):
        parser.error(
            f"argument -xf/--excluded-functions contains invalid plugin(s): {', '.join(invalid_excluded_funcs)}",
        )

    # Verify uniformity of output types, otherwise default to records.
    # Note that this is a heuristic, the targets are not opened yet because of
    # performance, so it might generate a false positive
    # (os.* on Windows includes other OS plugins),
    # however this is highly hypothetical, most plugins across OSes have
    # the same output types and most output types are records anyway.
    # Furthermore we really want the notification at the top, so this is the only
    # way forward. In the very unlikely case you have a
    # collection of non-record plugins that have record counterparts for
    # other OSes just refine the wildcard to exclude other OSes.
    # The only scenario that might cause this is with
    # custom plugins with idiosyncratic output across OS-versions/branches.
    output_types = set()
    excluded_func_paths = {excluded_func.path for excluded_func in excluded_funcs}

    for func in funcs:
        if func.path in excluded_func_paths:
            continue
        output_types.add(func.output)

    default_output_type = None

    if len(output_types) > 1:
        # Give this warning beforehand, if mixed, set default to record (no errors)
        log.warning("Mixed output types detected: %s, only outputting records", ",".join(output_types))
        default_output_type = "record"

    execution_report = ExecutionReport()
    execution_report.set_cli_args(args)
    execution_report.set_event_callbacks(Target)

    try:
        targets = [Target.open_direct(args.targets)] if args.direct else Target.open_all(args.targets, args.children)

        for target in targets:
            if args.child:
                try:
                    target = target.open_child(args.child)
                except Exception as e:
                    target.log.exception("Exception while opening child %r: %s", args.child, e)  # noqa: TRY401
                    target.log.debug("", exc_info=e)

            if args.dry_run:
                print(f"Dry run on: {target}")

            record_entries: list[tuple[FunctionDescriptor, Iterator[Record]]] = []
            basic_entries = []
            yield_entries = []

            first_seen_output_type = default_output_type

            for func_def in find_and_filter_plugins(args.function, target, excluded_func_paths):
                # If the default type is record (meaning we skip everything else)
                # and actual output type is not record, continue.
                # We perform this check here because plugins that require output files/dirs
                # will exit if we attempt to exec them without (because they are implied by the wildcard).
                # Also this saves cycles of course.
                if default_output_type == "record" and func_def.output != "record":
                    continue

                if args.dry_run:
                    print(f"  execute: {func_def.name} ({func_def.path})")
                    continue

                try:
                    output_type, result, rest = execute_function_on_target(target, func_def, rest)
                except UnsupportedPluginError as e:
                    target.log.error(  # noqa: TRY400
                        "Unsupported plugin for %s: %s",
                        func_def.name,
                        e.root_cause_str(),
                    )

                    target.log.debug("%s", func_def, exc_info=e)
                    continue
                except PluginNotFoundError:
                    target.log.error("Cannot find plugin `%s`", func_def)  # noqa: TRY400
                    continue
                except FatalError as e:
                    e.emit_last_message(target.log.error)
                    return 1
                except Exception as e:
                    target.log.error("Exception while executing function %s (%s): %s", func_def.name, func_def.path, e)  # noqa: TRY400
                    target.log.debug("", exc_info=e)
                    target.log.debug("Function info: %s", func_def)
                    continue

                if first_seen_output_type and output_type != first_seen_output_type:
                    target.log.error(
                        (
                            "Can't mix functions that generate different outputs: output type `%s` from `%s` "
                            "does not match first seen output `%s`."
                        ),
                        output_type,
                        func_def,
                        first_seen_output_type,
                    )
                    return 0

                if not first_seen_output_type:
                    first_seen_output_type = output_type

                if output_type == "record":
                    record_entries.append((func_def, result))
                elif output_type == "yield":
                    yield_entries.append(result)
                elif output_type == "none":
                    target.log.info("No result for function `%s` (output type is set to 'none')", func_def)
                    continue
                else:
                    basic_entries.append(result)

            # Write basic functions
            if len(basic_entries) > 0:
                basic_entries_delim = args.delimiter.join(map(str, basic_entries))
                if not args.cmdb:
                    print(f"{target} {basic_entries_delim}")
                else:
                    print(f"{target.path}{args.delimiter}{basic_entries_delim}")

            # Write yield functions
            for entry in yield_entries:
                for e in entry:
                    print(e)

            # Write records
            count = 0
            break_out = False

            modifier_type = None

            if args.resolve:
                modifier_type = record_modifier.Modifier.RESOLVE

            if args.hash:
                modifier_type = record_modifier.Modifier.HASH

            modifier_func = record_modifier.get_modifier_function(modifier_type)

            if not record_entries:
                continue

            rs = record_output(args.strings, args.json)
            for func_def, record_generator in record_entries:
                try:
                    for record in record_generator:
                        rs.write(modifier_func(target, record))
                        count += 1
                        if args.limit is not None and count >= args.limit:
                            break_out = True
                            break

                except Exception as e:
                    # Ignore errors if multiple functions or multiple targets
                    if len(record_entries) > 1 or len(args.targets) > 1:
                        target.log.error(  # noqa: TRY400
                            "Exception occurred while processing output of %s.%s: %s",
                            func_def.qualname,
                            func_def.name,
                            e,
                        )
                        target.log.debug("", exc_info=e)
                    else:
                        raise

                if break_out:
                    break

    except TargetError as e:
        log.error(e)  # noqa: TRY400
        log.debug("", exc_info=e)
        return 1

    timestamp = datetime.now(tz=timezone.utc)

    execution_report.set_plugin_stats(PLUGINS)
    log.debug("%s", execution_report.get_formatted_report())
    if args.report_dir:
        persist_execution_report(
            args.report_dir,
            {
                "timestamp": timestamp.isoformat(),
                **execution_report.as_dict(),
            },
            timestamp=timestamp,
        )

    return 0


if __name__ == "__main__":
    main()
