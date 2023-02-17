import bz2
import datetime
import enum
import functools
import gzip
import json
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterator, Optional, Union

import structlog

try:
    import lz4.frame

    HAS_LZ4 = True
except ImportError:
    HAS_LZ4 = False


try:
    import zstandard

    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False


from flow.record import RecordDescriptor, RecordStreamWriter
from flow.record.adapter.jsonfile import JsonfileWriter
from flow.record.jsonpacker import JsonRecordPacker

from dissect.target import Target

log = structlog.get_logger(__name__)


class Compression(enum.Enum):
    BZIP2 = "bzip2"
    GZIP = "gzip"
    LZ4 = "lz4"
    ZSTD = "zstandard"
    NONE = None


class Serialization(enum.Enum):
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
    return functools.reduce(getattr, [obj] + parts)


@lru_cache(maxsize=DEST_DIR_CACHE_SIZE)
def get_sink_dir_by_target(target: Target, function: str) -> Path:
    func_first_name, _, _ = function.partition(".")
    return Path(target.name) / func_first_name


@functools.lru_cache(maxsize=DEST_DIR_CACHE_SIZE)
def get_sink_dir_by_func(target: Target, function: str) -> Path:
    func_first_name, _, _ = function.partition(".")
    return Path(func_first_name) / target.name


def slugify_descriptor_name(descriptor_name: str) -> str:
    return descriptor_name.replace("/", "_")


@functools.lru_cache(maxsize=DEST_FILENAME_CACHE_SIZE)
def get_sink_filename(
    record_descriptor: RecordDescriptor,
    serialization: Serialization,
    compression: Optional[Compression] = None,
) -> str:
    """
    Return a sink filename for provided record descriptor, serialization
    and compression.
    """
    record_type = slugify_descriptor_name(record_descriptor.name)

    serialization_details = SERIALIZERS[serialization]
    serialization_ext = serialization_details["ext"]

    parts = [record_type, serialization_ext]

    compression_ext = COMPRESSION_TO_EXT[compression]
    if compression_ext:
        parts.append(compression_ext)

    return ".".join(parts)


def get_relative_sink_path(element, serialization, compression=None):
    """
    Return a sink path relative to an output directory.
    """
    sink_dir = get_sink_dir_by_target(element.target, element.func)
    sink_filename = get_sink_filename(element.record._desc, serialization, compression)
    return sink_dir / sink_filename


def open_path(path: Path, mode: str, compression: Optional[Compression] = None) -> BinaryIO:
    """Open `path` using `mode`, with specified `compression` and return a file object"""
    if compression == Compression.GZIP:
        fh = gzip.open(path, mode)
    elif compression == Compression.BZIP2:
        fh = bz2.open(path, mode)
    elif compression == Compression.LZ4:
        if not HAS_LZ4:
            raise ValueError("Python module lz4 is not available")
        fh = lz4.frame.open(path, mode)
    elif compression == Compression.ZSTD:
        if not HAS_ZSTD:
            raise ValueError("Python module zstandard is not available")
        cctx = zstandard.ZstdCompressor()
        fh = cctx.stream_writer(open(path, mode))
    elif compression == Compression.NONE:
        fh = open(path, mode)
    else:
        raise ValueError(f"Unrecognised compression method: {compression}")
    return fh


class JsonLinesWriter(JsonfileWriter):
    def __init__(self, fp, **kwargs):
        self.fp = fp
        self.packer = SortedKeysJsonRecordPacker(indent=None)
        self.packer.on_descriptor.add_handler(self.packer_on_new_descriptor)

    def _write(self, obj):
        record_json = self.packer.pack(obj)
        line = record_json + "\n"
        line = line.encode("utf-8")
        self.fp.write(line)

    def flush(self):
        if not self.fp.closed:
            self.fp.flush()

    def close(self):
        self.fp.close()


class SortedKeysJsonRecordPacker(JsonRecordPacker):
    def pack(self, obj):
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
    compression: Optional[Compression] = None,
    new_sink: bool = True,
) -> Union[JsonfileWriter, RecordStreamWriter]:
    # create parent directories if they are missing
    full_sink_path.parent.mkdir(parents=True, exist_ok=True)

    mode = "wb" if new_sink else "ab"

    fh = open_path(full_sink_path, mode=mode, compression=compression)
    writer_cls = SERIALIZERS[serialization]["writer"]
    writer = writer_cls(fh)
    return writer


@contextmanager
def cached_sink_writers(state) -> Iterator[Callable]:
    # Poor man's cache that cleans up when it hits the limit of `OPEN_WRITERS_LIMIT`.
    # The cache is needed to reduce file handler open/close flickering for unsorted records stream.
    writers_cache = {}

    def close_writers():
        for path, writer in writers_cache.items():
            writer.close()
            log.debug("Sink writer closed", writer=writer, path=path)
        writers_cache.clear()

    def write_element(element) -> int:
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
        elif not sink:
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
