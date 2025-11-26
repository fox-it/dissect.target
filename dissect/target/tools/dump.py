#!/usr/bin/env python
from __future__ import annotations

import argparse
import bz2
import dataclasses
import datetime
import enum
import functools
import gzip
import itertools
import json
import sys
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, TextIO

import structlog
from flow.record import Record, RecordDescriptor, RecordStreamWriter
from flow.record.adapter.jsonfile import JsonfileWriter
from flow.record.jsonpacker import JsonRecordPacker

try:
    import lz4.frame

    HAS_LZ4 = True
except ImportError:
    HAS_LZ4 = False


try:
    if sys.version_info >= (3, 14):
        from compression import zstd
    else:
        from backports import zstd

    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False

from dissect.target.exceptions import FatalError, PluginNotFoundError, UnsupportedPluginError
from dissect.target.target import Target
from dissect.target.tools.utils.cli import (
    configure_generic_arguments,
    configure_plugin_arguments,
    execute_function_on_target,
    find_and_filter_plugins,
    open_targets,
    process_generic_arguments,
    process_plugin_arguments,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator

    from flow.record import Record
    from typing_extensions import Self

    from dissect.target.helpers.record import TargetRecordDescriptor
    from dissect.target.plugin import FunctionDescriptor

log = structlog.get_logger(__name__)


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


STATE_FILE_NAME = "target-dump.state.json"

PENDING_UPDATES_LIMIT = 10


@dataclass
class Sink:
    target_path: str
    func: str
    path: Path
    is_dirty: bool = True
    record_count: int = 0
    size_bytes: int = 0

    def __post_init__(self):
        self.func = getattr(self.func, "name", self.func)


@dataclass
class DumpState:
    target_paths: list[str]
    functions: str
    excluded_functions: list[str]
    serialization: str
    compression: str
    start_time: datetime.datetime
    last_update_time: datetime.datetime

    sinks: list[Sink] = dataclasses.field(default_factory=list)

    # Volatile properties
    output_dir: Path | None = None
    pending_updates_count: int | None = 0

    @property
    def record_count(self) -> int:
        return sum(s.record_count for s in self.sinks)

    @property
    def finished_sinks(self) -> list[Sink]:
        return [sink for sink in self.sinks if not sink.is_dirty]

    @property
    def path(self) -> Path:
        return DumpState.get_state_path(self.output_dir)

    @classmethod
    def get_state_path(cls, output_dir: Path) -> Path:
        return output_dir / STATE_FILE_NAME

    def get_full_sink_path(self, sink: Sink) -> Path:
        if not self.output_dir:
            raise ValueError("Output directory is unknown for the state")
        return self.output_dir / sink.path

    def get_sink(self, path: Path) -> Sink | None:
        for sink in self.sinks:
            if sink.path == path:
                return sink
        return None

    def serialize(self) -> str:
        """Serialize state instance into a JSON formatted string."""
        state_dict = dataclasses.asdict(self)
        state_dict.pop("output_dir")
        state_dict.pop("pending_updates_count")
        return json.dumps(
            state_dict,
            default=serialize_obj,
            indent=4,
            sort_keys=True,
        )

    def persist(self, fh: TextIO) -> None:
        """Write serialized state instance into profided ``fh`` byte stream, overwriting it from the beginning."""
        fh.seek(0)
        fh.write(self.serialize())
        fh.flush()
        self.pending_updates_count = 0
        log.debug("State flushed")

    def mark_as_finished(self, target: Target, func: str) -> None:
        """Mark sinks that match provided ``target`` and ``func`` pair as not dirty."""
        matching_sinks = [
            sink for sink in self.sinks if str(sink.target_path) == str(target.path) and sink.func == func
        ]
        for sink in matching_sinks:
            sink.is_dirty = False

    def create_sink(self, sink_path: Path, stream_element: RecordStreamElement) -> Sink:
        """Create a sink instance for provided ``sink_path`` and ``stream_element``
        (from which ``target`` and ``func`` properties are used).
        """
        sink = Sink(
            path=sink_path,
            target_path=str(stream_element.target.path),
            func=stream_element.func,
        )
        self.sinks.append(sink)
        return sink

    def update(self, stream_element: RecordStreamElement, fp_position: int) -> None:
        """Update a sink instance for provided ``stream_element``."""
        sink = self.get_sink(stream_element.sink_path)

        sink.record_count += 1
        sink.size_bytes = fp_position
        self.last_update_time = get_current_utc_time()

        self.pending_updates_count += 1
        log.debug("State updated", records=self.record_count, sinks=len(self.sinks), path=self.path)

    @classmethod
    def from_dict(cls, state_dict: dict) -> Self:
        """Deserialize state instance from provided dictionary."""
        return cls(
            target_paths=state_dict["target_paths"],
            functions=state_dict["functions"],
            excluded_functions=state_dict["excluded_functions"],
            serialization=Serialization(state_dict["serialization"]),
            compression=Compression(state_dict["compression"]),
            start_time=parse_datetime_iso(state_dict["start_time"]),
            last_update_time=parse_datetime_iso(state_dict["last_update_time"]),
            sinks=[
                Sink(
                    target_path=sink["target_path"],
                    path=Path(sink["path"]),
                    func=sink["func"],
                    record_count=sink["record_count"],
                    size_bytes=sink["size_bytes"],
                    is_dirty=sink["is_dirty"],
                )
                for sink in state_dict["sinks"]
            ],
        )

    @classmethod
    def from_path(cls, output_dir: Path) -> Self | None:
        """Deserialize state instance from a file in the provided output directory path."""
        state_path = cls.get_state_path(output_dir)
        if not state_path.exists():
            return None

        with state_path.open(mode="r") as fh:
            try:
                state_dict = json.load(fh)
            except ValueError as e:
                log.warning("Can not load state from path", path=state_path, exc=e)
                return None

        state = cls.from_dict(state_dict)
        state.output_dir = output_dir
        return state

    def get_invalid_sinks(self) -> list[Sink]:
        """Return sinks that have a mismatch between recorded size and a real file size."""
        invalid_sinks = []
        for sink in self.sinks:
            # sink file does not exist
            if not self.get_full_sink_path(sink).exists():
                invalid_sinks.append(sink)
                continue

            # recorded file size for a clean sink is incorrect
            if not sink.is_dirty and sink.size_bytes != sink.path.stat().st_size:
                invalid_sinks.append(sink)
                continue

        return invalid_sinks

    def drop_invalid_sinks(self) -> None:
        """Remove sinks that have a mismatch between recorded size and a real file size from the list of sinks."""
        for invalid_sink in self.get_invalid_sinks():
            self.sinks.remove(invalid_sink)
            log.debug("Ignoring invalid sink", sink=invalid_sink.path)

    def drop_dirty_sinks(self) -> None:
        """Drop sinks that are marked as "dirty" in the current state from the list of sinks."""
        dirty_sinks = [s for s in self.sinks if s.is_dirty]
        for dirty_sink in dirty_sinks:
            self.sinks.remove(dirty_sink)
            log.debug("Ignoring dirty sink", sink=dirty_sink.path)


def create_state(
    *,
    output_dir: Path,
    target_paths: list[str],
    functions: str,
    excluded_functions: list[str],
    serialization: Serialization,
    compression: Compression = None,
) -> DumpState:
    """Create a ``DumpState`` instance with provided properties."""
    current_time = get_current_utc_time()
    return DumpState(
        target_paths=target_paths,
        functions=functions,
        excluded_functions=excluded_functions,
        serialization=serialization,
        compression=compression,
        start_time=current_time,
        last_update_time=current_time,
        output_dir=output_dir,
    )


@contextmanager
def persisted_state(state: DumpState) -> Iterator[Callable]:
    """Return a context manager for persisting ``DumpState`` instance."""

    def save_state(fh: TextIO) -> None:
        state.persist(fh)
        state.pending_updates_count = 0

    def save_state_when_over_limit(fh: TextIO) -> None:
        if state.pending_updates_count >= PENDING_UPDATES_LIMIT:
            save_state(fh)

    state.path.parent.mkdir(parents=True, exist_ok=True)

    with state.path.open(mode="w") as fh:
        try:
            yield functools.partial(save_state_when_over_limit, fh)
        finally:
            save_state(fh)


def load_state(output_dir: Path) -> DumpState | None:
    """Load persisted ``DumpState`` instance from provided ``output_dir`` path and perform sink validation."""
    state = DumpState.from_path(output_dir)

    if not state:
        return None

    # Dropping sinks that are marked as finished (clean) but the file
    # size on the disk is different from the one stored in the state object.
    state.drop_invalid_sinks()

    # Since there are no guarantees about the order of produced records
    # and the records themselves do not have unique IDs, we can not easily verify
    # what records are already stored in the dirty sink.
    # It is easier to just restart all dirty sinks.
    state.drop_dirty_sinks()

    return state


def serialize_obj(obj: Any) -> str:
    """JSON serializer for object types not serializable by ``json`` library."""
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, enum.Enum):
        return obj.value
    raise TypeError(f"Type {type(obj)} not serializable")


class Compression(str, enum.Enum):
    """Supported compression types."""

    BZIP2 = "bzip2"
    GZIP = "gzip"
    LZ4 = "lz4"
    ZSTD = "zstandard"
    NONE = None


class Serialization(str, enum.Enum):
    """Supported serialization methods."""

    JSONLINES = "jsonlines"
    MSGPACK = "msgpack"


COMPRESSION_TO_EXT = {
    Compression.BZIP2: "bz2",
    Compression.GZIP: "gz",
    Compression.LZ4: "lz4",
    Compression.ZSTD: "zstd",
    Compression.NONE: "",
}


DEST_DIR_CACHE_SIZE = 10
DEST_FILENAME_CACHE_SIZE = 10
OPEN_WRITERS_LIMIT = 10


def get_nested_attr(obj: Any, nested_attr: str) -> Any:
    parts = nested_attr.split(".")
    return functools.reduce(getattr, [obj, *parts])


@functools.lru_cache(maxsize=DEST_DIR_CACHE_SIZE)
def get_sink_dir_by_target(target: Target, function: FunctionDescriptor) -> Path:
    func_first_name, _, _ = function.name.partition(".")
    return Path(target.name) / func_first_name


@functools.lru_cache(maxsize=DEST_DIR_CACHE_SIZE)
def get_sink_dir_by_func(target: Target, function: FunctionDescriptor) -> Path:
    func_first_name, _, _ = function.name.partition(".")
    return Path(func_first_name) / target.name


def slugify_descriptor_name(descriptor_name: str) -> str:
    return descriptor_name.replace("/", "_")


@functools.lru_cache(maxsize=DEST_FILENAME_CACHE_SIZE)
def get_sink_filename(
    record_descriptor: RecordDescriptor,
    serialization: Serialization,
    compression: Compression | None = None,
) -> str:
    """Return a sink filename for provided record descriptor, serialization and compression."""
    record_type = slugify_descriptor_name(record_descriptor.name)

    serialization_details = SERIALIZERS[serialization]
    serialization_ext = serialization_details["ext"]

    parts = [record_type, serialization_ext]

    compression_ext = COMPRESSION_TO_EXT[compression]
    if compression_ext:
        parts.append(compression_ext)

    return ".".join(parts)


def get_relative_sink_path(
    element: RecordStreamElement, serialization: str, compression: Compression | None = None
) -> Path:
    """Return a sink path relative to an output directory."""
    sink_dir = get_sink_dir_by_target(element.target, element.func)
    sink_filename = get_sink_filename(element.record._desc, serialization, compression)
    return sink_dir / sink_filename


def open_path(path: Path, mode: str, compression: Compression | None = None) -> BinaryIO:
    """Open ``path`` using ``mode``, with specified ``compression`` and return a file object."""
    if compression == Compression.GZIP:
        fh = gzip.open(path, mode)  # noqa: SIM115
    elif compression == Compression.BZIP2:
        fh = bz2.open(path, mode)  # noqa: SIM115
    elif compression == Compression.LZ4:
        if not HAS_LZ4:
            raise ValueError("Python module lz4 is not available")
        fh = lz4.frame.open(path, mode)
    elif compression == Compression.ZSTD:
        if not HAS_ZSTD:
            raise ValueError("Python module backport.zstd is not available")
        fh = zstd.open(path, mode)
    elif compression == Compression.NONE:
        fh = path.open(mode)
    else:
        raise ValueError(f"Unrecognised compression method: {compression}")
    return fh


class JsonLinesWriter(JsonfileWriter):
    def __init__(self, fp: TextIO, **kwargs):
        self.fp = fp
        self.packer = SortedKeysJsonRecordPacker(indent=None)
        self.packer.on_descriptor.add_handler(self.packer_on_new_descriptor)

    def _write(self, obj: Record | RecordDescriptor) -> None:
        record_json = self.packer.pack(obj)
        line = record_json + "\n"
        line = line.encode("utf-8")
        self.fp.write(line)

    def flush(self) -> None:
        if not self.fp.closed:
            self.fp.flush()

    def close(self) -> None:
        self.fp.close()


class SortedKeysJsonRecordPacker(JsonRecordPacker):
    def pack(self, obj: Record | RecordDescriptor) -> str:
        return json.dumps(
            obj,
            default=self.pack_obj,
            indent=self.indent,
            sort_keys=True,
        )


SERIALIZERS = {
    Serialization.JSONLINES: {
        "writer": JsonLinesWriter,
        "ext": "jsonl",
    },
    Serialization.MSGPACK: {
        "writer": RecordStreamWriter,
        "ext": "rec",
    },
}


def get_sink_writer(
    full_sink_path: Path,
    serialization: Serialization,
    compression: Compression | None = None,
    new_sink: bool = True,
) -> JsonfileWriter | RecordStreamWriter:
    # create parent directories if they are missing
    full_sink_path.parent.mkdir(parents=True, exist_ok=True)

    mode = "wb" if new_sink else "ab"

    fh = open_path(full_sink_path, mode=mode, compression=compression)
    writer_cls = SERIALIZERS[serialization]["writer"]
    return writer_cls(fh)


@contextmanager
def cached_sink_writers(state: DumpState) -> Iterator[Callable]:
    # Poor man's cache that cleans up when it hits the limit of `OPEN_WRITERS_LIMIT`.
    # The cache is needed to reduce file handler open/close flickering for unsorted records stream.
    writers_cache = {}

    def close_writers() -> None:
        for path, writer in writers_cache.items():
            writer.close()
            log.debug("Sink writer closed", writer=writer, path=path)
        writers_cache.clear()

    def write_element(element: RecordStreamElement) -> int:
        sink_path = get_relative_sink_path(
            element,
            state.serialization,
            compression=state.compression,
        )
        element.sink_path = sink_path
        sink = state.get_sink(sink_path)

        new_sink = False
        if sink and not sink.is_dirty:
            log.error("Can not write to a clean finished sink", sink=sink, state=state.path)
            raise ValueError("Can not write to a clean finished sink")
        if not sink:
            sink = state.create_sink(sink_path, element)
            new_sink = True

        if sink.path in writers_cache:
            writer = writers_cache[sink.path]
        else:
            writer = writers_cache[sink.path] = get_sink_writer(
                state.get_full_sink_path(sink),
                state.serialization,
                compression=state.compression,
                new_sink=new_sink,
            )
            log.debug("Sink writer opened", writer=writer, path=sink.path)

        writer.write(element.record)
        fh_position = writer.fp.tell()

        state.update(element, fh_position)

        log.debug(
            "Record written to sink",
            sink_path=sink.path,
            record=element.record,
            writer=writer.__class__.__name__,
            position_bytes=fh_position,
            new_sink=new_sink,
        )

        if len(writers_cache) >= OPEN_WRITERS_LIMIT:
            close_writers()

        return fh_position

    try:
        yield write_element
    finally:
        close_writers()


def get_current_utc_time() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def parse_datetime_iso(datetime_str: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(datetime_str)


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
    process_generic_arguments(parser, args)

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
