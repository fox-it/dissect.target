from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING, BinaryIO, Final

from dissect.etl.etl import ETL, Event
from flow.record.base import Record

from dissect.target.exceptions import FilesystemError, UnsupportedPluginError
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.windows.datetime import parse_tzi

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from flow.record import Record

    from dissect.target.target import Target


class EtlRecordBuilder:
    RECORD_NAME = "filesystem/windows/etl"

    def __init__(self):
        self._create_event_descriptor = lru_cache(4096)(self._create_event_descriptor)

    def _build_record(self, etl_event: Event, etl_path: Path, target: Target) -> Record:
        """Builds an ETL event record."""

        record_values = {}
        record_fields = [
            ("datetime", "ts"),
            ("path", "path"),
            ("string", "ProviderName"),
            ("string", "ProviderId"),
            ("string", "EventType"),
        ]
        record_values["ts"] = etl_event.ts()
        record_values["path"] = etl_path
        record_values["ProviderName"] = etl_event.provider_name()
        record_values["ProviderId"] = etl_event.provider_id()
        record_values["EventType"] = etl_event.symbol()
        record_values["_target"] = target

        for key, value in etl_event.event_values().items():
            record_type = "bytes"
            if key == "TimeZoneInformation":
                # Pretty print TimezoneInformation
                value = parse_tzi(bytes(value))
                record_type = "string"
            elif isinstance(value, list):
                record_type = "string[]"
            elif isinstance(value, int):
                record_type = "varint"
            elif isinstance(value, str):
                record_type = "string"

            record_fields.append((record_type, key))
            record_values[key] = value

        # tuple conversion here is needed for lru_cache
        desc = self._create_event_descriptor(tuple(record_fields))
        return desc(**record_values)

    def _create_event_descriptor(self, record_fields: list[tuple[str, str]]) -> TargetRecordDescriptor:
        return TargetRecordDescriptor(self.RECORD_NAME, record_fields)

    def read_etl_records(self, fh: BinaryIO, path: Path, target: Target) -> Iterator[Record]:
        etl_file = ETL(fh)
        for buffer in etl_file.buffers():
            for event_records in buffer:
                yield self._build_record(event_records.event, path, target)


class EtlPlugin(Plugin):
    """Plugin for parsing Windows ETL Files (``*.etl``)."""

    __namespace__ = "etl"

    PATHS: Final[dict[str, list[str]]] = {
        "boot": [
            "sysvol/windows/system32/wdi/logfiles/bootckcl.etl",
            "sysvol/windows/system32/wdi/logfiles/bootperfdiaglogger.etl",
        ],
        "shutdown": [
            "sysvol/windows/system32/wdi/logfiles/shutdownckcl.etl",
            "sysvol/windows/system32/wdi/logfiles/shutdownperfdiaglogger.etl",
        ],
    }

    def __init__(self, target: Target):
        super().__init__(target)
        self._etl_record_builder = EtlRecordBuilder()

    def check_compatible(self) -> None:
        etl_paths = (etl_file for etl_paths in self.PATHS.values() for etl_file in etl_paths)
        plugin_target_folders = [self.target.fs.path(file).exists() for file in etl_paths]
        if not any(plugin_target_folders):
            raise UnsupportedPluginError("No ETL paths found")

    def read_etl_files(self, etl_paths: list[str]) -> Iterator[Record]:
        """Read ETL files using an EtlReader."""
        for etl_path in etl_paths:
            entry = self.target.fs.path(etl_path)
            if not entry.exists():
                self.target.log.warning("ETL file does not exist: %s", entry)
                continue

            try:
                entry_data = entry.open()
            except FilesystemError:
                self.target.log.exception("Failed to open ETL file: %s", entry)
                continue

            etl_records = self._etl_record_builder.read_etl_records(entry_data, entry, self.target)
            yield from etl_records

    @export(record=DynamicDescriptor(["datetime"]))
    def etl(self) -> Iterator[DynamicDescriptor]:
        """Return the contents of the ETL files generated at last boot and last shutdown.

        An event trace log (.etl) file, also known as a trace log, stores the trace messages generated during one or
        more trace sessions. A trace session is period in which a trace provider (a component of a user-mode
        application or kernel-mode driver that uses Event Tracing for Windows (ETW) technology to generate trace
        messages or trace events) is generating trace messages.

        References:
            - https://www.hecfblog.com/2018/06/etw-event-tracing-for-windows-and-etl.html
            - https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/trace-log

        Yields dynamically created records based on the fields inside an ETL event.
        At least contains the following fields:

        .. code-block:: text

            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The TimeCreated_SystemTime field of the event.
            Provider_Name (string): The Provider_Name field of the event.
            EventType (string): The type of the event defined by the manifest file.
        """
        for etl_plugin in self.PATHS:
            yield from getattr(self, etl_plugin)()

    @export(record=DynamicDescriptor(["datetime"]))
    def shutdown(self) -> Iterator[DynamicDescriptor]:
        """Return the contents of the ETL files created at last shutdown.

        The plugin reads the content from the ShutdownCKCL.etl file or the ShutdownPerfDiagLogger.etl file (depending
        on the Windows version).

        Yields dynamically created records based on the fields inside an ETL event.
        At least contains the following fields:

        .. code-block:: text

            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The TimeCreated_SystemTime field of the event.
            Provider_Name (string): The Provider_Name field of the event.
            EventType (string): The type of the event defined by the manifest file.
        """
        yield from self.read_etl_files(self.PATHS["shutdown"])

    @export(record=DynamicDescriptor(["datetime"]))
    def boot(self) -> Iterator[DynamicDescriptor]:
        """Return the contents of the ETL files created at last boot.

        The plugin reads the content from the BootCKCL.etl file or the BootPerfDiagLogger.etl file (depending
        on the Windows version).

        Yields dynamically created records based on the fields inside an ETL event.
        At least contains the following fields:

        .. code-block:: text

            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The TimeCreated_SystemTime field of the event.
            Provider_Name (string): The Provider_Name field of the event.
            EventType (string): The type of the event defined by the manifest file.
        """
        yield from self.read_etl_files(self.PATHS["boot"])
