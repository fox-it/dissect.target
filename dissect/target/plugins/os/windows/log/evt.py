import fnmatch
import re

from typing import Generator, BinaryIO, Any, List, Optional
from pathlib import Path

from flow.record import Record

from dissect.eventlog import evt
from dissect.target import plugin
from dissect.target.exceptions import (
    FilesystemError,
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
    UnsupportedPluginError,
)
from dissect.target.helpers.record import TargetRecordDescriptor

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

    @plugin.internal
    def get_logs(self, filename_glob="*") -> List[Path]:
        file_paths = []
        file_paths.extend(self.get_logs_from_dir(self.LOGS_DIR_PATH, filename_glob=filename_glob))

        if self.EVENTLOG_REGISTRY_KEY:
            for reg_path in self.get_logs_from_registry(filename_glob=filename_glob):
                # We can't filter duplicates on file path alone, since "sysvol" and "C:" can show up interchangeably.
                try:
                    if any(fpath.samefile(reg_path) for fpath in file_paths):
                        continue
                except FilesystemError:
                    pass

                file_paths.append(reg_path)

        return file_paths

    @plugin.internal
    def get_logs_from_dir(self, logs_dir: str, filename_glob: str = "*") -> List[Path]:
        file_paths = []
        logs_dir = self.target.fs.path(logs_dir)
        if logs_dir.exists():
            file_paths.extend(list(logs_dir.glob(filename_glob)))

        self.target.log.debug("Log files found in '%s': %d", self.LOGS_DIR_PATH, len(file_paths))
        return file_paths

    @plugin.internal
    def get_logs_from_registry(self, filename_glob: str = "*") -> List[Path]:
        # compile glob into case-insensitive regex
        filename_regex = re.compile(fnmatch.translate(filename_glob), re.IGNORECASE)

        file_paths = []

        try:
            subkeys = self.target.registry.key(self.EVENTLOG_REGISTRY_KEY).subkeys()
        except RegistryKeyNotFoundError:
            self.target.log.warning("No eventlog registry key %s found", self.EVENTLOG_REGISTRY_KEY)
            return []

        for subkey in subkeys:
            try:
                subkey_value = subkey.value("File")
            except RegistryValueNotFoundError:
                continue
            file_paths.append(subkey_value.value)

        # resolve aliases (like `%systemroot%`) in the paths
        file_paths = [self.target.resolve(p) for p in file_paths]
        file_paths = [self.target.fs.path(path) for path in file_paths if filename_regex.match(path)]

        self.target.log.debug("Log files found in '%s': %d", self.EVENTLOG_REGISTRY_KEY, len(file_paths))

        return file_paths

    def check_compatible(self):
        if not self.target.fs.path(self.LOGS_DIR_PATH).exists():
            raise UnsupportedPluginError(f'Event log directory "{self.LOGS_DIR_PATH}" not found')


class EvtPlugin(WindowsEventlogsMixin, plugin.Plugin):
    LOGS_DIR_PATH = "sysvol/windows/system32/config"

    NEEDLE = b"LfLe"
    CHUNK_SIZE = 0x10000

    @plugin.arg("--logs-dir", help="logs directory to scan")
    @plugin.arg("--log-file-glob", default=EVT_GLOB, help="glob pattern to match a log file name")
    @plugin.export(record=EvtRecordDescriptor)
    def evt(self, log_file_glob: str = EVT_GLOB, logs_dir: Optional[str] = None) -> Generator[Record, None, None]:
        """Parse Windows Eventlog files (*.evt).

        Yields dynamically created records based on the fields in the event.
        At least contains the following fields:
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

    @plugin.export(record=EvtRecordDescriptor)
    def scraped_evt(self) -> Generator[Record, None, None]:
        """Yields EVT log file records scraped from target disks"""
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

    def _parse_chunk(self, _, chunk: bytes) -> Generator[Record, None, None]:
        for record in evt.parse_chunk(chunk):
            yield self._build_record(record)
