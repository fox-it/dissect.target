from __future__ import annotations
import re
from datetime import datetime
from typing import TYPE_CHECKING, Iterator
import logging

from dissect.target.plugin import Plugin, export
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.exceptions import UnsupportedPluginError

if TYPE_CHECKING:
    from dissect.target import Target

log = logging.getLogger(__name__)

IntuneManagementExtensionLogRecord = TargetRecordDescriptor(
    "IntuneManagementExtension/log",
    [
        ("datetime", "timestamp"),
        ("string", "component"),
        ("string", "thread"),
        ("string", "type"),
        ("string", "message"),
        ("string", "file_origin"),
    ],
)

LOG_PATTERN = re.compile(
    r'<!\[LOG\[(?P<message>.*?)\]LOG\]!>'
    r'<time="(?P<hms>\d{2}:\d{2}:\d{2})(?:\.(?P<fractional_seconds>\d+))?"\s+'
    r'date="(?P<date>[\d-]+)"\s+component="(?P<component>[^"]+)"'
    r'\s+context="[^"]*"\s+type="(?P<type>\d+)"\s+thread="(?P<thread>\d+)"\s+file="(?P<file_origin>[^"]*)"',
    re.DOTALL | re.IGNORECASE,
)

class IntuneManagementExtensionLogParserPlugin(Plugin):
    """Parse Microsoft Intune Management Extension logs (including rotated logs).

    This plugin processes both the primary `IntuneManagementExtension.log` file and
    any timestamped rotated versions (e.g. `IntuneManagementExtension-20251009-135155.log`).

    Each parsed entry includes metadata such as timestamp, log type, thread ID,
    component name, and message content.
    """

    LOG_DIR = "sysvol/ProgramData/Microsoft/IntuneManagementExtension/Logs"

    def check_compatible(self) -> None:
        """Verify that the Intune Management Extension logs exist in the target.

        Raises:
            UnsupportedPluginError: If the log directory or log files are missing.
        """
        log_dir = self.target.fs.path(self.LOG_DIR)
        if not log_dir.exists():
            raise UnsupportedPluginError(
                f"Intune Management Extension log directory not found: {self.LOG_DIR}"
            )

        has_logs = any(
            p.name.lower().startswith("intunemanagementextension") and p.name.lower().endswith(".log")
            for p in log_dir.iterdir()
        )
        if not has_logs:
            raise UnsupportedPluginError("No Intune Management Extension logs found in target.")

    @export(record=IntuneManagementExtensionLogRecord)
    def intunemanagementextension(self) -> Iterator[IntuneManagementExtensionLogRecord]:
        """Parse Intune Management Extension log files.

        Yields:
            IntuneManagementExtensionLogRecord: One record per parsed log line.
        """
        log_dir = self.target.fs.path(self.LOG_DIR)
        log_files = [
            p for p in log_dir.iterdir()
            if p.name.lower().startswith("intunemanagementextension") and p.name.lower().endswith(".log")
        ]

        if not log_files:
            log.warning(f"No Intune Management Extension log files found under {self.LOG_DIR}")
            return

        for log_path in log_files:
            try:
                with log_path.open("r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                log.exception(f"Failed to open log file {log_path}: {e}")
                continue

            match_count = 0
            for match in LOG_PATTERN.finditer(content):
                match_count += 1

                msg = match.group("message").replace("\r", "").replace("\n", " ").strip()

                date_str = match.group("date")
                hms_str = match.group("hms")
                fractional_seconds_str = match.group("fractional_seconds")

                micro_str = (fractional_seconds_str or "000000")[:6].ljust(6, "0")
                time_str = f"{hms_str}.{micro_str}"

                timestamp = None
                for fmt in ("%m-%d-%Y %H:%M:%S.%f", "%d-%m-%Y %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S.%f"):
                    try:
                        timestamp = datetime.strptime(f"{date_str} {time_str}", fmt)
                        break
                    except ValueError:
                        continue
                if not timestamp:
                    continue

                log_type = match.group("type")

                yield IntuneManagementExtensionLogRecord(
                    timestamp=timestamp.isoformat(timespec="microseconds"),
                    component=match.group("component"),
                    thread=match.group("thread"),
                    type=log_type,
                    message=msg,
                    file_origin=f"{log_path.name}:{match.group('file_origin')}",
                    _target=self.target,
                )

            if match_count == 0:
                log.warning(f"No log entries matched regex in {log_path}")
