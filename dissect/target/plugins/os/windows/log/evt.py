from __future__ import annotations

import fnmatch
import re
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.eventlog import evt

from dissect.target.exceptions import (
    FilesystemError,
    PluginError,
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
    UnsupportedPluginError,
)
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from flow.record import Record

re_illegal_characters = re.compile(r"[\(\): \.\-#]")

EvtRecordDescriptor = TargetRecordDescriptor(
    "filesystem/windows/evt",
    [
        ("datetime", "ts"),
        ("datetime", "TimeGenerated"),
        ("datetime", "TimeWritten"),
        ("string", "SourceName"),
        ("varint", "EventID"),
        ("varint", "EventCode"),
        ("varint", "EventFacility"),
        ("varint", "EventCustomerFlag"),
        ("varint", "EventSeverity"),
        ("varint", "EventType"),
        ("varint", "EventCategory"),
        ("string", "Computername"),
        ("string", "UserSid"),
        ("string[]", "Strings"),
        ("bytes", "Data"),
    ],
)


EVT_GLOB = "*.evt"


class WindowsEventlogsMixin:
    EVENTLOG_REGISTRY_KEY = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Eventlog"
    LOGS_DIR_PATH = None

    def _get_paths(self) -> Iterator[Path]:
        seen = self.get_logs_from_dir(self.LOGS_DIR_PATH)
        yield from seen

        if self.EVENTLOG_REGISTRY_KEY:
            for reg_path in self.get_logs_from_registry():
                # We can't filter duplicates on file path alone, since "sysvol" and "C:" can show up interchangeably.
                try:
                    if any(fpath.samefile(reg_path) for fpath in seen):
                        continue
                except FilesystemError:
                    pass

                yield reg_path

    def get_logs(self, filename_glob: str = "*") -> list[Path]:
        re_filename = re.compile(fnmatch.translate(filename_glob), re.IGNORECASE)
        return [path for path in self.get_paths() if re_filename.match(str(path))]

    def get_logs_from_dir(self, logs_dir: str, filename_glob: str = "*") -> list[Path]:
        if (path := self.target.fs.path(logs_dir)).exists():
            file_paths = list(path.glob(filename_glob))

            self.target.log.debug("Log files found in '%s': %d", self.LOGS_DIR_PATH, len(file_paths))
            return file_paths

        return []

    def get_logs_from_registry(self, filename_glob: str = "*") -> list[Path]:
        file_paths = []

        try:
            subkeys = self.target.registry.key(self.EVENTLOG_REGISTRY_KEY).subkeys()
        except RegistryKeyNotFoundError:
            self.target.log.warning("No eventlog registry key %s found", self.EVENTLOG_REGISTRY_KEY)
            return []
        except PluginError:
            self.target.log.warning("Cannot access registry in target")
            return []

        for subkey in subkeys:
            try:
                subkey_value = subkey.value("File")
            except RegistryValueNotFoundError:
                continue

            # resolve aliases (like `%systemroot%`) in the paths
            file_paths.append(self.target.resolve(subkey_value.value))

        return file_paths

    def check_compatible(self) -> None:
        if not self.target.fs.path(self.LOGS_DIR_PATH).exists():
            raise UnsupportedPluginError(f'Event log directory "{self.LOGS_DIR_PATH}" not found')


class EvtPlugin(WindowsEventlogsMixin, Plugin):
    """Windows ``.evt`` event log plugin."""

    LOGS_DIR_PATH = "sysvol/windows/system32/config"

    NEEDLE = b"LfLe"
    CHUNK_SIZE = 0x10000

    @arg("--logs-dir", help="logs directory to scan")
    @arg("--log-file-glob", default=EVT_GLOB, help="glob pattern to match a log file name")
    @export(record=EvtRecordDescriptor)
    def evt(self, log_file_glob: str = EVT_GLOB, logs_dir: str | None = None) -> Iterator[EvtRecordDescriptor]:
        """Parse Windows Eventlog files (``*.evt``).

        Yields dynamically created records based on the fields in the event.
        At least contains the following fields:

        .. code-block:: text

            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The TimeCreated_SystemTime field of the event.
            Provider_Name (string): The Provider_Name field of the event.
            EventID (int): The EventID of the event.
        """
        if logs_dir:
            log_paths = self.get_logs_from_dir(logs_dir, filename_glob=log_file_glob)
        else:
            log_paths = self.get_logs(filename_glob=log_file_glob)

        for entry in log_paths:
            if not entry.exists():
                self.target.log.warning("Event log file does not exist: %s", entry)
                continue

            try:
                entry_data = entry.open()
            except FilesystemError:
                self.target.log.exception("Failed to open event log: %s", entry)
                continue

            for record in evt.Evt(entry_data):
                yield self._build_record(record)

    def _build_record(self, record: Any) -> Record:
        return EvtRecordDescriptor(
            ts=record.TimeGenerated,
            TimeGenerated=record.TimeGenerated,
            TimeWritten=record.TimeWritten,
            SourceName=record.SourceName,
            EventID=record.EventID,
            EventCode=record.EventCode,
            EventFacility=record.EventFacility,
            EventCustomerFlag=record.EventCustomerFlag,
            EventSeverity=record.EventSeverity,
            EventType=record.EventType,
            EventCategory=record.EventCategory,
            Computername=record.Computername,
            Strings=record.Strings,
            Data=record.Data,
            _target=self.target,
        )

    @export(record=EvtRecordDescriptor)
    def scraped_evt(self) -> Iterator[EvtRecordDescriptor]:
        """Yields EVT log file records scraped from target disks."""
        yield from self.target.scrape.scrape_chunks_from_disks(
            needle=self.NEEDLE,
            chunk_size=self.CHUNK_SIZE,
            chunk_parser=self._parse_chunk,
            chunk_reader=self._read_chunk,
        )

    def _read_chunk(self, fh: BinaryIO, needle: bytes, offset: int, chunk_size: int) -> bytes:
        # Needle is a 2nd field in EVT header, so we need to back up
        # by 4 bytes to get to the start of the the record.
        fh.seek(offset - 4)
        return fh.read(chunk_size)

    def _parse_chunk(self, needle: bytes, chunk: bytes) -> Iterator[Record]:
        for record in evt.parse_chunk(chunk):
            yield self._build_record(record)
