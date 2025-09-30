#!/usr/bin/env python
from __future__ import annotations

import argparse
import itertools
import sys
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from dissect.target.exceptions import FatalError, PluginNotFoundError, UnsupportedPluginError
from dissect.target.target import Target
from dissect.target.tools.dump.state import (
    DumpState,
    create_state,
    load_state,
    persisted_state,
)
from dissect.target.tools.dump.utils import (
    Compression,
    Serialization,
    cached_sink_writers,
)
from dissect.target.tools.utils import (
    FunctionDescriptor,
    configure_generic_arguments,
    configure_plugin_arguments,
    execute_function_on_target,
    find_and_filter_plugins,
    open_targets,
    process_generic_arguments,
    process_plugin_arguments,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from flow.record import Record

    from dissect.target.helpers.record import TargetRecordDescriptor

log = structlog.get_logger("dissect.target.tools.dump.run")


@dataclass
class RecordStreamElement:
    target: Target
    func: FunctionDescriptor
    record: Record
    end_pos: int | None = None
    sink_path: Path | None = None


def get_targets(targets: list[str]) -> Iterator[Target]:
    """Return a generator with :class:`Target` objects for provided paths."""
    yield from Target.open_all(targets)


def execute_function(
    target: Target, function: FunctionDescriptor, dry_run: bool, arguments: list[str]
) -> Iterator[TargetRecordDescriptor]:
    """Execute function ``function`` on provided target ``target`` and return a generator
    with the records produced.

    Only output type ``record`` is supported for plugin functions.
    """

    local_log = log.bind(func=function, target=target)
    local_log.debug("Function execution")

    if dry_run:
        print(f"  execute: {function.name} ({function.path})")
        return

    if function.output != "record":
        local_log.info(
            "Skipping target/func pair since its output type is not a record",
            target=target.path,
            func=function.name,
        )
        return
    try:
        _, target_attr = execute_function_on_target(target, function)
    except UnsupportedPluginError as e:
        local_log.error("Unsupported plugin for %s: %s", function.name, e.root_cause_str())
        local_log.debug("%s", function, exc_info=e)
        return
    except PluginNotFoundError:
        local_log.error("Cannot find plugin `%s`", function)
        return
    except FatalError as e:
        e.emit_last_message(local_log.error)
        sys.exit(1)
    except Exception as e:
        local_log.error("Exception while executing function %s (%s): %s", function.name, function.path, e)
        local_log.debug("", exc_info=e)
        local_log.debug("Function info: %s", function)
        return

    # no support for function-specific arguments
    result = target_attr() if callable(target_attr) else target_attr

    try:
        yield from result
    except Exception as e:
        local_log.error("Error occurred while processing output of %s.%s: %s", function.qualname, function.name, e)
        local_log.debug("", exc_info=e)
        return


def produce_target_func_pairs(
    targets: Iterable[Target],
    state: DumpState,
) -> Iterator[tuple[Target, FunctionDescriptor]]:
    """Return a generator with target and function pairs for execution.

    Target and function pairs that correspond to finished sinks in provided state ``state`` are skipped.
    """
    pairs_to_skip = set()
    if state:
        pairs_to_skip.update((str(sink.target_path), sink.func) for sink in state.finished_sinks)

    for target in targets:
        for func_def in find_and_filter_plugins(state.functions, target, state.excluded_functions):
            if state and (target.path, func_def.name) in pairs_to_skip:
                log.info(
                    "Skipping target/func pair since its marked as done in provided state",
                    target=target.path,
                    func=func_def.name,
                    state=state.path,
                )
                continue

            yield (target, func_def)
            state.mark_as_finished(target, func_def.name)


def execute_functions(
    target_func_stream: Iterable[tuple[Target, FunctionDescriptor]], dry_run: bool, arguments: list[str]
) -> Iterator[RecordStreamElement]:
    """Execute a function on a target for target / function pairs in the stream.

    Returns a generator of ``RecordStreamElement`` objects.
    """
    for target, func in target_func_stream:
        for record in execute_function(target, func, dry_run, arguments):
            yield RecordStreamElement(target=target, func=func, record=record)


def log_progress(stream: Iterable[Any], step_size: int = 1000) -> Iterator[Any]:
    """Log a number of items that went though the generator stream after
    every N element (N is configured in ``step_size``).
    """
    i = 0
    targets = set()
    sinks = set()
    for i, element in enumerate(stream, start=1):
        yield element

        if i % step_size == 0:
            log.info("Processing status", processed=i, last=element)

        targets.add(element.target)
        if element.sink_path:
            sinks.add(element.sink_path)

    log.info("Pipeline stats", elements=i, targets=len(targets), sinks=len(sinks))


def sink_records(
    record_stream: Iterable[RecordStreamElement],
    state: DumpState,
) -> Iterator[RecordStreamElement]:
    """Persist records from the stream into appropriate sinks, per serialization, compression and record type."""
    with cached_sink_writers(state) as write_element:
        for element in record_stream:
            write_element(element)
            yield element


def persist_processing_state(
    record_stream: Iterable[RecordStreamElement],
    state: DumpState,
) -> Iterator[RecordStreamElement]:
    """Keep track of the pipeline state in a persistent state object."""
    with persisted_state(state) as save_state_periodically:
        for element in record_stream:
            save_state_periodically()
            yield element


def configure_state(args: argparse.Namespace) -> DumpState | None:
    state = None if args.restart else load_state(output_dir=args.output)

    if state:
        log.info("Resuming state", output=args.output, state=state.path)

        if (
            state.serialization != args.serialization
            or state.compression != args.compression
            or state.functions != args.function
            or state.excluded_functions != args.excluded_functions
            or state.target_paths != args.targets
        ):
            log.error(
                "Configuration of the existing state conflicts with parameters provided",
                state_serialization=state.serialization,
                state_compression=state.compression,
                state_targets=state.target_paths,
                state_functions=state.functions,
                state_excluded_fucntions=state.excluded_functions,
                targets=args.targets,
                functions=args.function,
                serialization=args.serialization,
                compression=args.compression,
                state_path=state.path,
            )
            return None
    else:
        state = create_state(
            output_dir=args.output,
            target_paths=args.targets,
            functions=args.function,
            excluded_functions=args.excluded_functions,
            serialization=args.serialization,
            compression=args.compression,
        )
        log.info("New state created", restart=args.restart, state=state.path)

    return state


def execute_pipeline(
    state: DumpState,
    targets: Iterator[Target],
    dry_run: bool,
    arguments: list[str],
    limit: int | None = None,
) -> None:
    """Run the record generation, processing and sinking pipeline."""

    target_func_pairs_stream = produce_target_func_pairs(targets, state)
    record_stream = itertools.islice(execute_functions(target_func_pairs_stream, dry_run, arguments), limit)
    record_stream = sink_records(record_stream, state)
    record_stream = log_progress(record_stream)
    record_stream = persist_processing_state(record_stream, state)

    # exhaust the generator, executing all pipeline steps
    deque(record_stream, maxlen=0)

    log.info("Pipeline has finished")


def parse_arguments() -> tuple[argparse.Namespace, list[str]]:
    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        description="dissect.target",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
        add_help=False,
    )
    parser.add_argument("targets", metavar="TARGET", nargs="*", help="targets to load")

    configure_plugin_arguments(parser)

    parser.add_argument(
        "-c",
        "--compression",
        choices=[c.value for c in Compression if c is not Compression.NONE],
        type=Compression,
        help="compression method",
        default=Compression.NONE,
    )
    parser.add_argument(
        "--restart",
        action="store_true",
        help="restart the session and overwrite the state file if it exists",
    )
    parser.add_argument(
        "-s",
        "--serialization",
        choices=[s.value for s in Serialization],
        default=Serialization.JSONLINES,
        type=Serialization,
        help="serialization method",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=".",
        required=True,
        help="output directory",
    )
    parser.add_argument("--limit", type=int, help="limit number of records produced")

    configure_generic_arguments(parser)

    args, rest = parser.parse_known_args()
    process_generic_arguments(args)

    if not args.function and ("-h" in rest or "--help" in rest):
        parser.print_help()
        parser.exit(0)

    process_plugin_arguments(parser, args, rest)

    return args, rest


def main() -> None:
    args, rest = parse_arguments()

    try:
        state = configure_state(args)
        if state is None:
            # Error was already shown above, stopping execution
            return
        targets = open_targets(args)
        execute_pipeline(
            state=state,
            targets=targets,
            arguments=rest,
            dry_run=args.dry_run,
            limit=args.limit,
        )
    except Exception:
        log.exception("Exception while running the pipeline")
        sys.exit(1)


if __name__ == "__main__":
    main()
