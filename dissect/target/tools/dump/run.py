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

from dissect.target.exceptions import PluginError, UnsupportedPluginError
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
    execute_function_on_target,
    find_and_filter_plugins,
    process_generic_arguments,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from flow.record import Record

    from dissect.target.helpers.record import TargetRecordDescriptor

log = structlog.get_logger("dissect.target.tools.dump.run")


@dataclass
class RecordStreamElement:
    target: Target
    func: str
    record: Record
    end_pos: int | None = None
    sink_path: Path | None = None


def get_targets(targets: list[str]) -> Iterator[Target]:
    """Return a generator with :class:`Target` objects for provided paths."""
    yield from Target.open_all(targets)


def execute_function(target: Target, function: FunctionDescriptor) -> TargetRecordDescriptor:
    """Execute function ``function`` on provided target ``target`` and return a generator
    with the records produced.

    Only output type ``record`` is supported for plugin functions.
    """

    local_log = log.bind(func=function, target=target)
    local_log.debug("Function execution")

    try:
        output_type, target_attr, _ = execute_function_on_target(target, function)
    except UnsupportedPluginError:
        local_log.error("Function is not supported for target", exc_info=True)
        return
    except PluginError:
        local_log.error("Plugin error while executing function for target", exc_info=True)
        return

    if output_type != "record":
        local_log.warn("Output format is not supported", output=output_type)
        return

    # no support for function-specific arguments
    result = target_attr() if callable(target_attr) else target_attr

    try:
        yield from result
    except Exception:
        local_log.error("Error while executing function", exc_info=True)
        return


def produce_target_func_pairs(
    targets: Iterable[Target],
    functions: str,
    state: DumpState,
) -> Iterator[tuple[Target, FunctionDescriptor]]:
    """Return a generator with target and function pairs for execution.

    Target and function pairs that correspond to finished sinks in provided state ``state`` are skipped.
    """
    pairs_to_skip = set()
    if state:
        pairs_to_skip.update((str(sink.target_path), sink.func) for sink in state.finished_sinks)

    for target in targets:
        for func_def in find_and_filter_plugins(functions, target):
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


def execute_functions(target_func_stream: Iterable[tuple[Target, str]]) -> Iterator[RecordStreamElement]:
    """Execute a function on a target for target / function pairs in the stream.

    Returns a generator of ``RecordStreamElement`` objects.
    """
    for target, func in target_func_stream:
        for record in execute_function(target, func):
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


def execute_pipeline(
    targets: list[str],
    functions: str,
    output_dir: Path,
    serialization: Serialization,
    compression: Compression | None = None,
    restart: bool | None = False,
    limit: int | None = None,
) -> None:
    """Run the record generation, processing and sinking pipeline."""

    compression = compression or Compression.NONE

    state = None if restart else load_state(output_dir=output_dir)

    if state:
        log.info("Resuming state", output=output_dir, state=state.path)

        if (
            state.serialization != serialization
            or state.compression != compression
            or state.functions != functions
            or state.target_paths != targets
        ):
            log.error(
                "Configuration of the existing state conflicts with parameters provided",
                state_serialization=state.serialization,
                state_compression=state.compression,
                state_targets=state.target_paths,
                state_functions=state.functions,
                targets=targets,
                functions=functions,
                serialization=serialization,
                compression=compression,
                state_path=state.path,
            )
            return
    else:
        state = create_state(
            output_dir=output_dir,
            target_paths=targets,
            functions=functions,
            serialization=serialization,
            compression=compression,
        )
        log.info("New state created", restart=restart, state=state.path)

    targets_stream = get_targets(targets)
    target_func_pairs_stream = produce_target_func_pairs(targets_stream, functions, state)
    record_stream = execute_functions(target_func_pairs_stream)

    if limit:
        record_stream = itertools.islice(record_stream, limit)

    record_stream = sink_records(record_stream, state)
    record_stream = log_progress(record_stream)
    record_stream = persist_processing_state(record_stream, state)

    # exhaust the generator, executing all pipeline steps
    deque(record_stream, maxlen=0)

    log.info("Pipeline has finished")


def parse_arguments() -> argparse.Namespace:
    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        description="dissect.target",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
        add_help=True,
    )
    parser.add_argument("targets", metavar="TARGET", nargs="+", help="targets to load")
    parser.add_argument("-f", "--function", required=True, help="one or more comma separated functions to execute")

    parser.add_argument(
        "-c",
        "--compression",
        choices=[c.value for c in Compression if c is not Compression.NONE],
        help="compression method",
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
        default=Serialization.JSONLINES.value,
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
    process_generic_arguments(args, rest)

    return args


def main() -> None:
    args = parse_arguments()

    try:
        execute_pipeline(
            targets=args.targets,
            functions=args.function,
            output_dir=args.output,
            serialization=Serialization(args.serialization),
            compression=Compression(args.compression),
            restart=args.restart,
            limit=args.limit,
        )
    except Exception:
        log.exception("Exception while running the pipeline")
        sys.exit(1)


if __name__ == "__main__":
    main()
