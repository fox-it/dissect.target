from functools import lru_cache
from typing import List

from dissect.etl.etl import ETL, Event

from dissect.target import Target
from dissect.target.exceptions import FilesystemError
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.plugin import Plugin, export


class EtlRecordBuilder:
    RECORD_NAME = "filesystem/windows/etl"

    def _build_record(self, etl_event: Event, etl_path: str, target: Target):
        """Builds an ETL event record"""

        record_values = {}
        record_fields = [
            ("datetime", "ts"),
            ("uri", "path"),
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
            if isinstance(value, list):
                record_fields.append(("string[]", key))
            elif isinstance(value, int):
                record_fields.append(("varint", key))
            else:
                record_fields.append(("string", key))
            record_values[key] = value

        # tuple conversion here is needed for lru_cache
        desc = self._create_event_descriptor(tuple(record_fields))
        return desc(**record_values)

    @lru_cache(maxsize=4096)
    def _create_event_descriptor(self, record_fields):
        return TargetRecordDescriptor(self.RECORD_NAME, record_fields)

    def read_etl_records(self, etl_file_stream, etl_path, target):
        etl_file = ETL(etl_file_stream)
        for buffer in etl_file.buffers():
            for event_records in buffer:
                yield self._build_record(event_records.event, etl_path, target)


class EtlPlugin(Plugin):
    """Plugin for fetching and parsing Windows ETL Files (*.etl)"""

    __namespace__ = "etl"

    PATHS = {
        "boot": [
            "sysvol/windows/system32/wdi/logfiles/bootckcl.etl",
            "sysvol/windows/system32/wdi/logfiles/bootperfdiaglogger.etl",
        ],
        "shutdown": [
            "sysvol/windows/system32/wdi/logfiles/shutdownckcl.etl",
            "sysvol/windows/system32/wdi/logfiles/shutdownperfdiaglogger.etl",
        ],
    }

    def __init__(self, target):
        super().__init__(target)
        self._etl_record_builder = EtlRecordBuilder()

    def check_compatible(self):
        etl_paths = (etl_file for etl_paths in self.PATHS.values() for etl_file in etl_paths)
        plugin_target_folders = [self.target.fs.path(file).exists() for file in etl_paths]
        return any(plugin_target_folders)

    def read_etl_files(self, etl_paths: List[str]):
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

            etl_records = self._etl_record_builder.read_etl_records(entry_data, f"{entry}", self.target)
            yield from etl_records

    @export(record=DynamicDescriptor(["datetime"]))
    def etl(self):
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
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The TimeCreated_SystemTime field of the event.
            Provider_Name (string): The Provider_Name field of the event.
            EventType (string): The type of the event defined by the manifest file.
        """
        for etl_plugin in self.PATHS.keys():
            yield from getattr(self, etl_plugin)()

    @export(record=DynamicDescriptor(["datetime"]))
    def shutdown(self):
        """Return the contents of the ETL files created at last shutdown.

        The plugin reads the content from the ShutdownCKCL.etl file or the ShutdownPerfDiagLogger.etl file (depending
        on the Windows version).

        Yields dynamically created records based on the fields inside an ETL event.
        At least contains the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The TimeCreated_SystemTime field of the event.
            Provider_Name (string): The Provider_Name field of the event.
            EventType (string): The type of the event defined by the manifest file.
        """
        yield from self.read_etl_files(self.PATHS["boot"])

    @export(record=DynamicDescriptor(["datetime"]))
    def boot(self):
        """Return the contents of the ETL files created at last boot.

        The plugin reads the content from the BootCKCL.etl file or the BootPerfDiagLogger.etl file (depending
        on the Windows version).

        Yields dynamically created records based on the fields inside an ETL event.
        At least contains the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The TimeCreated_SystemTime field of the event.
            Provider_Name (string): The Provider_Name field of the event.
            EventType (string): The type of the event defined by the manifest file.
        """
        yield from self.read_etl_files(self.PATHS["boot"])
