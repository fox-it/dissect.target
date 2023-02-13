import datetime
import re
from functools import lru_cache
from typing import Any, Generator, Optional

from dissect.eventlog import evtx
from dissect.eventlog.exceptions import MalformedElfChnkException
from flow.record import Record, utils

from dissect.target import plugin
from dissect.target.exceptions import FilesystemError
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.plugins.os.windows.log.evt import WindowsEventlogsMixin

re_illegal_characters = re.compile(r"[\(\): \.\-#\/]")


EVTX_GLOB = "*.evtx"


class EvtxPlugin(WindowsEventlogsMixin, plugin.Plugin):
    """Plugin for fetching and parsing Windows Eventlog Files (*.evtx)"""

    RECORD_NAME = "filesystem/windows/evtx"
    LOGS_DIR_PATH = "sysvol/windows/system32/winevt/logs"

    NEEDLE = b"ElfChnk\x00"
    CHUNK_SIZE = 0x10000

    def __init__(self, target):
        super().__init__(target)

    @plugin.arg("--logs-dir", help="logs directory to scan")
    @plugin.arg("--log-file-glob", default=EVTX_GLOB, help="glob pattern to match a log file name")
    @plugin.export(record=DynamicDescriptor(["datetime"]))
    def evtx(self, log_file_glob: str = EVTX_GLOB, logs_dir: Optional[str] = None) -> Generator[Record, None, None]:
        """Return entries from Windows Event log files (*.evtx).

        Windows Event log is a detailed record of system, security and application notifications. It can be used to
        diagnose a system or find future issues. Up until Windows XP the extension .evt was used, hereafter .evtx
        became the new standard.

        Sources:
            - https://www.techtarget.com/searchwindowsserver/definition/Windows-event-log
            - https://serverfault.com/questions/441050/what-are-the-differences-between-windows-evt-and-evtx-log-files

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

            for event in evtx.Evtx(entry_data):
                yield self._build_record(event)

    @plugin.export(record=DynamicDescriptor(["datetime"]))
    def scraped_evtx(self) -> Generator[Record, None, None]:
        """Return EVTX log file records scraped from target disks"""
        yield from self.target.scrape.scrape_chunks_from_disks(
            needle=self.NEEDLE,
            chunk_size=self.CHUNK_SIZE,
            chunk_parser=self._parse_chunk,
        )

    def _parse_chunk(self, _, chunk: bytes) -> Generator[Any, None, None]:
        chnk = evtx.ElfChnk(chunk)
        try:
            for event in chnk.read():
                yield self._build_record(event)
        except MalformedElfChnkException:
            pass

    def _build_record(self, evtx_record) -> Record:
        # predictable order of fields in the list is important, since we'll
        # be constructing a record descriptor from it.
        evtx_record_fields = sorted(evtx_record.items())

        record_values = {"_target": self.target}
        record_fields = [
            ("datetime", "ts"),
            ("string", "Provider_Name"),
            ("uint32", "EventID"),
        ]
        unk_fields = 0

        for key, value in evtx_record_fields:
            key = re_illegal_characters.sub("_", key).strip("_")
            value = format_value(value)

            if not key.isprintable():
                self.target.log.warning(
                    f"Skipped possibly corrupt field record containing non-printable characters: {key}"
                )
                continue

            if key == "TimeCreated_SystemTime":
                record_values["ts"] = value
                continue

            if isinstance(value, list):
                for idx, v in enumerate(value):
                    k = f"{key}_{idx}"
                    record_values[k] = format_value(v)
                    record_fields.append(("string", k))
            else:
                is_invalid = False
                try:
                    key.encode("utf8")
                except UnicodeEncodeError:
                    is_invalid = True
                if not key or key[0].isdigit() or is_invalid:
                    key = f"unknown_{unk_fields}"
                    unk_fields += 1

                if key == "EventID":
                    value = int(value)

                record_values[key] = value

                if key in ("Provider_Name", "EventID"):
                    continue

                record_fields.append(("string", key))

        # tuple conversion here is needed for lru_cache
        desc = self._create_event_descriptor(tuple(record_fields))
        return desc(**record_values)

    @lru_cache(maxsize=4096)
    def _create_event_descriptor(self, record_fields) -> TargetRecordDescriptor:
        return TargetRecordDescriptor(self.RECORD_NAME, record_fields)


def format_value(value: Any) -> Any:
    if value is None:
        return

    if isinstance(value, evtx.BxmlSub):
        value = value.get()

    if isinstance(value, (datetime.datetime, list)):
        return value

    try:
        return utils.to_str(value)
    except UnicodeDecodeError:
        return repr(value)
