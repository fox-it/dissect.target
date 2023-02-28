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
from dissect.target.exceptions import PluginNotFoundError, UnsupportedPluginError
from dissect.target.helpers import cache, hashutil
from dissect.target.plugin import PLUGINS, OSPlugin, Plugin, find_plugin_functions
from dissect.target.report import ExecutionReport
from dissect.target.tools.utils import (
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
        found_functions = find_plugin_functions(Target(), args.function, False)
        if not len(found_functions):
            parser.error("function(s) not found, see -l for available plugins")
        func = found_functions[0]
        if issubclass(func.class_object, OSPlugin):
            func.class_object = OSPlugin
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
                funcs = find_plugin_functions(plugin_target, args.list, True)
                for func in funcs:
                    collected_plugins[func.name] = func.plugin_desc
        else:
            funcs = find_plugin_functions(Target(), args.list, False)
            for func in funcs:
                collected_plugins[func.name] = func.plugin_desc

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

    # Verify uniformity of output types, otherwise default to records
    output_types = set()
    funcs = find_plugin_functions(Target(), args.function, False)
    for func in funcs:
        output_types.add(func.output_type)

    default_output_type = None
    if len(output_types) > 1:
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

        record_entries = []
        basic_entries = []
        yield_entries = []

        first_seen_output_type = default_output_type
        cli_params_unparsed = rest

        for func_def in funcs:
            try:
                output_type, result, cli_params_unparsed = execute_function_on_target(
                    target, func_def, cli_params_unparsed
                )
            except UnsupportedPluginError as e:
                target.log.error(
                    "Unsupported plugin for `%s`: %s",
                    func,
                    e.root_cause_str(),
                )

                target.log.debug("", exc_info=e)
                continue
            except PluginNotFoundError:
                target.log.error("Cannot find plugin `%s`", func)
                continue
            except Exception:
                target.log.error("Exception while executing function `%s`", func, exc_info=True)
                continue

            if first_seen_output_type and output_type != first_seen_output_type:
                # if default is set to record, we already know so continue... (probably a wildcard)
                if default_output_type == "record":
                    continue
                target.log.error(
                    (
                        "Can't mix functions that generate different outputs: output type `%s` from `%s` "
                        "does not match first seen output `%s`."
                    ),
                    output_type,
                    func,
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
                target.log.info("No result for function `%s` (output type is set to 'none')", func)
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
                            rs.write(hashutil.hash_uri_records(target, record_entries))
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
