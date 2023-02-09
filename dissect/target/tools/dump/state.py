import dataclasses
import datetime
import enum
import functools
import json
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, List, Optional, TextIO

import structlog

from dissect.target import Target
from dissect.target.tools.dump.utils import (
    Compression,
    Serialization,
    get_current_utc_time,
    parse_datetime_iso,
)

log = structlog.get_logger(__name__)


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


@dataclass
class DumpState:
    target_paths: List[str]
    functions: List[str]
    serialization: str
    compression: str
    start_time: datetime.datetime
    last_update_time: datetime.datetime

    sinks: List[Sink] = dataclasses.field(default_factory=list)

    # Volatile properties
    output_dir: Optional[Path] = None
    pending_updates_count: Optional[int] = 0

    @property
    def record_count(self) -> int:
        return sum(s.record_count for s in self.sinks)

    @property
    def finished_sinks(self) -> List[Sink]:
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

    def get_sink(self, path: Path) -> Optional[Sink]:
        for sink in self.sinks:
            if sink.path == path:
                return sink

    def serialize(self) -> str:
        """Serialize state instance into a JSON formatted string"""
        state_dict = dataclasses.asdict(self)
        state_dict.pop("output_dir")
        state_dict.pop("pending_updates_count")
        serialized = json.dumps(
            state_dict,
            default=serialize_obj,
            indent=4,
            sort_keys=True,
        )
        return serialized

    def persist(self, fh: TextIO) -> None:
        """
        Write serialized state instance into profided `fh` byte stream,
        overwriting it from the beginning
        """
        fh.seek(0)
        fh.write(self.serialize())
        fh.flush()
        self.pending_updates_count = 0
        log.debug("State flushed")

    def mark_as_finished(self, target: Target, func: str) -> None:
        """
        Mark sinks that match provided `target` and `func` pair as not dirty.
        """
        matching_sinks = [
            sink for sink in self.sinks if str(sink.target_path) == str(target.path) and sink.func == func
        ]
        for sink in matching_sinks:
            sink.is_dirty = False

    def create_sink(self, sink_path: Path, stream_element) -> Sink:
        """
        Create a sink instance for provided `sink_path` and `stream_element`
        (from which `target` and `func` properties are used).
        """
        sink = Sink(
            path=sink_path,
            target_path=str(stream_element.target.path),
            func=stream_element.func,
        )
        self.sinks.append(sink)
        return sink

    def update(self, stream_element, fp_position: int) -> None:
        """
        Update a sink instance for provided `stream_element`.
        """
        sink = self.get_sink(stream_element.sink_path)

        sink.record_count += 1
        sink.size_bytes = fp_position
        self.last_update_time = get_current_utc_time()

        self.pending_updates_count += 1
        log.debug("State updated", records=self.record_count, sinks=len(self.sinks), path=self.path)

    @classmethod
    def from_dict(cls, state_dict: dict) -> "DumpState":
        """Deserialize state instance from provided dict"""
        return DumpState(
            target_paths=state_dict["target_paths"],
            functions=state_dict["functions"],
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
    def from_path(cls, output_dir: Path) -> Optional["DumpState"]:
        """Deserialize state instance from a file in the provided output directory path"""
        state_path = DumpState.get_state_path(output_dir)
        if not state_path.exists():
            return

        with state_path.open(mode="r") as fh:
            try:
                state_dict = json.load(fh)
            except ValueError as e:
                log.warning("Can not load state from path", path=state_path, exc=e)
                return

        state = DumpState.from_dict(state_dict)
        state.output_dir = output_dir
        return state

    def get_invalid_sinks(self) -> List[Sink]:
        """Return sinks that have a mismatch between recorded size and a real file size"""
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
        """
        Remove sinks that have a mismatch between recorded size and
        a real file size from the list of sinks.
        """
        for invalid_sink in self.get_invalid_sinks():
            self.sinks.remove(invalid_sink)
            log.debug("Ignoring invalid sink", sink=invalid_sink.path)

    def drop_dirty_sinks(self) -> None:
        """Drop sinks that are marked as "dirty" in the current state from the list of sinks"""
        dirty_sinks = [s for s in self.sinks if s.is_dirty]
        for dirty_sink in dirty_sinks:
            self.sinks.remove(dirty_sink)
            log.debug("Ignoring dirty sink", sink=dirty_sink.path)


def create_state(
    *,
    output_dir: Path,
    target_paths: List[str],
    functions: List[str],
    serialization: Serialization,
    compression: Compression = None,
) -> DumpState:
    """Create a `DumpState` instance with provided properties"""
    current_time = get_current_utc_time()
    return DumpState(
        target_paths=target_paths,
        functions=functions,
        serialization=serialization,
        compression=compression,
        start_time=current_time,
        last_update_time=current_time,
        output_dir=output_dir,
    )


@contextmanager
def persisted_state(state: DumpState) -> Iterator[Callable]:
    """Return a context manager for persisting `DumpState` instance"""

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


def load_state(output_dir: Path) -> Optional[DumpState]:
    """
    Load persisted `DumpState` instance from provided `output_dir` path
    and perform sink validation.
    """
    state = DumpState.from_path(output_dir)

    if not state:
        return

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
    """JSON serializer for object types not serializable by `json` lib"""
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, enum.Enum):
        return obj.value
    raise TypeError("Type %s not serializable" % type(obj))
