#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import logging
import pathlib
import sys
from datetime import datetime
from typing import Callable

from flow.record import RecordPrinter, RecordStreamWriter, RecordWriter

from dissect.target import Target
from dissect.target.exceptions import (
    FatalError,
    PluginNotFoundError,
    UnsupportedPluginError,
)
from dissect.target.helpers import cache, hashutil
from dissect.target.loaders.targetd import ProxyLoader
from dissect.target.plugin import PLUGINS, OSPlugin, Plugin, find_plugin_functions
from dissect.target.report import ExecutionReport
from dissect.target.tools.utils import (
    catch_sigpipe,
    configure_generic_arguments,
    execute_function_on_target,
    generate_argparse_for_bound_method,
    generate_argparse_for_plugin_class,
    generate_argparse_for_unbound_method,
    persist_execution_report,
    process_generic_arguments,
)

log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False


USAGE_FORMAT_TMPL = "{prog} -f {name}{usage}"


def record_output(strings=False, json=False):
    if json:
        return RecordWriter("jsonfile://-")

    fp = sys.stdout.buffer

    if strings or fp.isatty():
        return RecordPrinter(fp)

    return RecordStreamWriter(fp)


@catch_sigpipe
def main():
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
        const="*",
        default=None,
        help="list (matching) available plugins and loaders",
    )
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
            "force cache files to be rewritten (has no effect if either --no-cache "
            "or --only-read-cache are specified)"
        ),
    )
    parser.add_argument("--cmdb", action="store_true")
    parser.add_argument("--hash", action="store_true", help="hash all uri paths in records")
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
        parser.exit()

    process_generic_arguments(args)

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
        found_functions, _ = find_plugin_functions(Target(), args.function, False)
        if not len(found_functions):
            parser.error("function(s) not found, see -l for available plugins")
        func = found_functions[0]
        if issubclass(func.class_object, OSPlugin):
            obj = getattr(OSPlugin, func.method_name)
        else:
            obj = getattr(func.class_object, func.method_name)
        if isinstance(obj, type) and issubclass(obj, Plugin):
            parser = generate_argparse_for_plugin_class(obj, usage_tmpl=USAGE_FORMAT_TMPL)
        elif isinstance(obj, Callable) or isinstance(obj, property):
            parser = generate_argparse_for_unbound_method(getattr(obj, "fget", obj), usage_tmpl=USAGE_FORMAT_TMPL)
        else:
            parser.error(f"can't find plugin with function `{func.method_name}`")
        parser.print_help()
        parser.exit()

    # Show the list of available plugins for the given optional target and optional
    # search pattern, only display plugins that can be applied to ANY targets
    if args.list:
        collected_plugins = {}

        if args.targets:
            for target in args.targets:
                plugin_target = Target.open(target)
                if isinstance(plugin_target._loader, ProxyLoader):
                    parser.error("can't list compatible plugins for remote targets.")
                funcs, _ = find_plugin_functions(plugin_target, args.list, True, show_hidden=True)
                for func in funcs:
                    collected_plugins[func.path] = func.plugin_desc
        else:
            funcs, _ = find_plugin_functions(Target(), args.list, False, show_hidden=True)
            for func in funcs:
                collected_plugins[func.path] = func.plugin_desc

        # Display in a user friendly manner
        target = Target()
        fparser = generate_argparse_for_bound_method(target.plugins, usage_tmpl=USAGE_FORMAT_TMPL)
        fargs, rest = fparser.parse_known_args(rest)

        if collected_plugins:
            target.plugins(list(collected_plugins.values()))

        # No real targets specified, show the available loaders
        if not args.targets:
            fparser = generate_argparse_for_bound_method(target.loaders, usage_tmpl=USAGE_FORMAT_TMPL)
            fargs, rest = fparser.parse_known_args(rest)
            target.loaders(**vars(fargs))
        parser.exit()

    if not args.targets:
        parser.error("too few arguments")

    if not args.function:
        parser.error("argument -f/--function is required")

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
    funcs, invalid_funcs = find_plugin_functions(Target(), args.function, compatibility=False)

    if any(invalid_funcs):
        parser.error(f"argument -f/--function contains invalid plugin(s): {', '.join(invalid_funcs)}")

    excluded_funcs, invalid_excluded_funcs = find_plugin_functions(
        Target(),
        args.excluded_functions,
        compatibility=False,
    )

    if any(invalid_excluded_funcs):
        parser.error(
            f"argument -xf/--excluded-functions contains invalid plugin(s): {', '.join(invalid_excluded_funcs)}",
        )

    excluded_func_names = {excluded_func.name for excluded_func in excluded_funcs}

    for func in funcs:
        if func.name in excluded_func_names:
            continue
        output_types.add(func.output_type)

    default_output_type = None

    if len(output_types) > 1:
        # Give this warning beforehand, if mixed, set default to record (no errors)
        log.warning("Mixed output types detected: %s. Only outputting records.", ",".join(output_types))
        default_output_type = "record"

    if args.report_dir and not args.report_dir.is_dir():
        parser.error(f"--report-dir {args.report_dir} is not a valid directory")

    execution_report = ExecutionReport()
    execution_report.set_cli_args(args)
    execution_report.set_event_callbacks(Target)

    for target in Target.open_all(args.targets, args.children):
        if args.child:
            try:
                target = target.open_child(args.child)
            except Exception:
                target.log.exception("Exception while opening child '%s'", args.child)

        if args.dry_run:
            print(f"Dry run on: {target}")

        record_entries = []
        basic_entries = []
        yield_entries = []

        # Keep a set of plugins that were already executed on the target.
        executed_plugins = set()

        first_seen_output_type = default_output_type
        cli_params_unparsed = rest

        func_defs, _ = find_plugin_functions(target, args.function, compatibility=False)
        excluded_funcs, _ = find_plugin_functions(target, args.excluded_functions, compatibility=False)
        excluded_func_names = {excluded_func.name for excluded_func in excluded_funcs}

        for func_def in func_defs:
            if func_def.name in excluded_func_names:
                continue

            # Avoid executing same plugin for multiple OSes (like hostname)
            if func_def.name in executed_plugins:
                continue
            executed_plugins.add(func_def.name)

            # If the default type is record (meaning we skip everything else)
            # and actual output type is not record, continue.
            # We perform this check here because plugins that require output files/dirs
            # will exit if we attempt to exec them without (because they are implied by the wildcard).
            # Also this saves cycles of course.
            if default_output_type == "record" and func_def.output_type != "record":
                continue

            if args.dry_run:
                print(f"  execute: {func_def.name} ({func_def.path})")
                continue

            try:
                output_type, result, cli_params_unparsed = execute_function_on_target(
                    target, func_def, cli_params_unparsed
                )
            except UnsupportedPluginError as e:
                target.log.error(
                    "Unsupported plugin for %s: %s",
                    func_def.name,
                    e.root_cause_str(),
                )

                target.log.debug("%s", func_def, exc_info=e)
                continue
            except PluginNotFoundError:
                target.log.error("Cannot find plugin `%s`", func_def)
                continue
            except FatalError as fatal:
                fatal.emit_last_message(target.log.error)
                parser.exit(1)
            except Exception:
                target.log.error("Exception while executing function `%s`", func_def, exc_info=True)
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
                parser.exit()

            if not first_seen_output_type:
                first_seen_output_type = output_type

            if output_type == "record":
                record_entries.append(result)
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
        if len(record_entries):
            rs = record_output(args.strings, args.json)
            for entry in record_entries:
                try:
                    for record_entries in entry:
                        if args.hash:
                            rs.write(hashutil.hash_path_records(target, record_entries))
                        else:
                            rs.write(record_entries)
                        count += 1
                        if args.limit is not None and count >= args.limit:
                            break_out = True
                            break
                except Exception as e:
                    # Ignore errors if multiple functions
                    if len(funcs) > 1:
                        target.log.error(f"Exception occurred while processing output of {func}", exc_info=e)
                        pass
                    else:
                        raise e

                if break_out:
                    break

    timestamp = datetime.utcnow()

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


if __name__ == "__main__":
    main()
