from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

IntuneManagementExtensionLogRecord = TargetRecordDescriptor(
    "windows/intune/managementextension/log",
    [
        ("datetime", "ts"),
        ("string", "component"),
        ("string", "thread"),
        ("string", "type"),
        ("string", "context"),
        ("string", "message"),
        ("string", "file_origin"),
    ],
)

LOG_PATTERN = re.compile(
    r"""
        <!\[LOG\[(?P<message>.*?)\]LOG\]!>
        <time="(?P<hms>\d{2}:\d{2}:\d{2})
            (?:\.(?P<fractional_seconds>\d+))?"
        \s+
        date="(?P<date>[\d-]+)"
        \s+
        component="(?P<component>[^"]+)"
        \s+
        context="(?P<context>[^"]*)"
        \s+
        type="(?P<type>\d+)"
        \s+
        thread="(?P<thread>\d+)"
        \s+
        file="(?P<file_origin>[^"]*)"
    """,
    re.DOTALL | re.IGNORECASE | re.VERBOSE,
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
            raise UnsupportedPluginError(f"Intune Management Extension log directory not found: {self.LOG_DIR}")

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
            p
            for p in log_dir.iterdir()
            if p.name.lower().startswith("intunemanagementextension") and p.name.lower().endswith(".log")
        ]

        if not log_files:
            self.target.log.warning("No Intune Management Extension log files found under %s", self.LOG_DIR)
            return

        for log_path in log_files:
            try:
                content = log_path.read_text()
            except Exception:
                self.target.log.exception("Failed to open log file %s", log_path)
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
                        timestamp = datetime.strptime(f"{date_str} {time_str}", fmt).replace(tzinfo=timezone.utc)
                        break
                    except ValueError:
                        continue
                if not timestamp:
                    continue

                yield IntuneManagementExtensionLogRecord(
                    ts=timestamp,
                    component=match.group("component"),
                    thread=match.group("thread"),
                    type=match.group("type"),
                    context=match.group("context"),
                    message=msg,
                    file_origin=f"{log_path.name}:{match.group('file_origin')}",
                    _target=self.target,
                )

            if match_count == 0:
                self.target.log.warning("No log entries matched regex in %s", log_path)
