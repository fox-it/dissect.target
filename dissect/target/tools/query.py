#!/usr/bin/env python
from __future__ import annotations

import argparse
import logging
import pathlib
import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING

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
)
from dissect.target.target import Target
from dissect.target.tools.report import ExecutionReport
from dissect.target.tools.utils import (
    catch_sigpipe,
    configure_generic_arguments,
    configure_plugin_arguments,
    execute_function_on_target,
    find_and_filter_plugins,
    open_targets,
    persist_execution_report,
    process_generic_arguments,
    process_plugin_arguments,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from flow.record.adapter import AbstractWriter

log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False


def record_output(strings: bool = False, json: bool = False) -> AbstractWriter:
    if json:
        return RecordWriter("jsonfile://-")

    fp = sys.stdout.buffer

    if strings or fp.isatty():
        return RecordPrinter(fp)

    return RecordStreamWriter(fp)


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
    parser.add_argument("--child", help="load a specific child path or index")
    parser.add_argument("--children", action="store_true", help="include children")
    parser.add_argument("--direct", action="store_true", help="treat TARGETS as paths to pass to plugins directly")

    configure_plugin_arguments(parser)

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

    different_output_types = process_plugin_arguments(parser, args, rest)

    if not args.targets:
        parser.error("too few arguments")

    if args.report_dir and not args.report_dir.is_dir():
        parser.error(f"--report-dir {args.report_dir} is not a valid directory")

    default_output_type = None
    if len(different_output_types) > 1:
        log.warning("Mixed output types detected: %s, only outputting records", ",".join(different_output_types))
        default_output_type = "record"

    execution_report = ExecutionReport()
    execution_report.set_cli_args(args)
    execution_report.set_event_callbacks(Target)

    try:
        for target in open_targets(args):
            record_entries: list[tuple[FunctionDescriptor, Iterator[Record]]] = []
            basic_entries = []
            yield_entries = []

            first_seen_output_type = default_output_type

            for func_def in find_and_filter_plugins(args.function, target, args.excluded_functions):
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
                    output_type, result = execute_function_on_target(target, func_def)
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
