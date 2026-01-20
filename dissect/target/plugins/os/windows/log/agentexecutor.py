from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

AgentExecutorLogRecord = TargetRecordDescriptor(
    "windows/intune/agentexecutor/log",
    [
        ("datetime", "timestamp"),
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
            (?:\.(?P<fractional_seconds>\d{1,7}))?"
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
        (?:
            \s+file="(?P<file_origin>[^"]*)"
        )?
    """,
    re.DOTALL | re.IGNORECASE | re.VERBOSE,
)


class AgentExecutorLogPlugin(Plugin):
    """Parse Microsoft Intune AgentExecutor logs.

    The AgentExecutor log file captures script execution and system management
    activity from the Microsoft Intune Management Extension agent.
    This plugin parses structured entries and converts them into records suitable
    for timeline and forensic analysis.
    """

    DEFAULT_LOG_PATH = "sysvol/ProgramData/Microsoft/IntuneManagementExtension/Logs/AgentExecutor.log"

    def check_compatible(self) -> None:
        """Verify that the AgentExecutor log file exists within the target.

        Raises:
            UnsupportedPluginError: If the expected log file does not exist.
        """
        if not self.target.fs.path(self.DEFAULT_LOG_PATH).exists():
            raise UnsupportedPluginError(f"AgentExecutor.log not found at {self.DEFAULT_LOG_PATH}")

    @export(record=AgentExecutorLogRecord)
    def agentexecutor(self) -> Iterator[AgentExecutorLogRecord]:
        """Parse the AgentExecutor.log and yield structured records.

        Extracts timestamp, message, context, thread, and type information from
        the AgentExecutor log and yields normalized structured records.

        Yields:
            AgentExecutorLogRecord: A structured representation of each log entry.
        """
        log_path = self.target.fs.path(self.DEFAULT_LOG_PATH)

        try:
            content = log_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            self.target.log.exception("Failed to open log file %s", log_path)
            return

        match_count = 0

        for match in LOG_PATTERN.finditer(content):
            match_count += 1

            msg = match.group("message").replace("\r", "").strip()
            date_str = match.group("date")
            hms_str = match.group("hms")
            fractional_seconds_str = match.group("fractional_seconds")

            micro_str = (fractional_seconds_str or "000000")[:6].ljust(6, "0")
            time_str = f"{hms_str}.{micro_str}"

            timestamp = None
            for fmt in ("%m-%d-%Y %H:%M:%S.%f", "%d-%m-%Y %H:%M:%S.%f"):
                try:
                    timestamp = datetime.strptime(f"{date_str} {time_str}", fmt).replace(tzinfo=timezone.utc)
                    break
                except ValueError:
                    continue

            if not timestamp:
                self.target.log.debug("Could not parse datetime from %s %s", date_str, time_str)
                continue

            log_type = match.group("type")

            yield AgentExecutorLogRecord(
                timestamp=timestamp,
                component=match.group("component"),
                thread=match.group("thread"),
                type=log_type,
                context=match.group("context"),
                message=msg,
                file_origin=match.group("file_origin") or "AgentExecutor.log",
                _target=self.target,
            )

        if match_count == 0:
            self.target.log.warning("No log entries matched the regex in %s", log_path)
